//! The gRPC service. Bodies are passed on chunk by chunk, and the response is read from
//! the broker only as the caller reads it, so backpressure carries end to end.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{Stream, StreamExt, stream};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use seal_broker::audit::{AuditRecord, AuditSink, Outcome};
use seal_broker::client::RequestBody;
use seal_broker::{
    Broker, BrokerError, ConnectRequest, ErrorCode, Presented, SendRequest, VerifyRequest,
};
use seal_format::{Envelope, FieldName, ItemId, KeysetId};
use seal_keys::{KeyError, Keyring};
use seal_proto::v1::seal_server::Seal;
use seal_proto::v1::{
    ConnectIn, ConnectOut, Empty, Header, InfoReply, KeysetRequest, PublicKey, PublicKeysReply,
    ResponseHead, SendHead, SendIn, SendOut, Trailer, VerifyIn, VerifyReply, WrappedKeyReply,
    connect_in, connect_out, send_in, send_out, verify_in,
};
use seal_proto::v1::{PresignReply, PresignRequest};
use seal_proto::{ERROR_CODE_METADATA, MAX_BODY_CHUNK};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::{Request, Response, Status, Streaming};

use crate::callers::{Caller, CallerMap, Identity};
use crate::config::Rate;
use crate::limits::RateLimiter;

/// What the service reports in `Info`.
#[derive(Clone, Debug)]
pub struct ServiceInfo {
    /// `unix` or `mtls`.
    pub mode: &'static str,
    /// The largest capped buffer.
    pub buffer_cap: u64,
}

/// The service's parts.
pub struct Service {
    broker: Arc<Broker>,
    keyring: Keyring,
    callers: Arc<CallerMap>,
    audit: Arc<dyn AuditSink>,
    streams: Arc<Semaphore>,
    per_caller: RateLimiter<String>,
    per_keyset: RateLimiter<KeysetId>,
    info: ServiceInfo,
}

/// The rates and concurrency the service enforces.
#[derive(Clone, Copy, Debug)]
pub struct ServiceLimits {
    /// The most `send` streams at once.
    pub max_concurrent_streams: usize,
    /// Requests per caller.
    pub rate_per_caller: Rate,
    /// Requests per keyset.
    pub rate_per_keyset: Rate,
    /// How many keysets' rate buckets to keep.
    pub max_tracked_keysets: usize,
}

impl Service {
    /// Assembles the service.
    #[must_use]
    pub fn new(
        broker: Arc<Broker>,
        keyring: Keyring,
        callers: Arc<CallerMap>,
        audit: Arc<dyn AuditSink>,
        limits: ServiceLimits,
        info: ServiceInfo,
    ) -> Self {
        Self {
            broker,
            keyring,
            callers: Arc::clone(&callers),
            audit,
            streams: Arc::new(Semaphore::new(limits.max_concurrent_streams)),
            per_caller: RateLimiter::new(limits.rate_per_caller, 4096),
            per_keyset: RateLimiter::new(limits.rate_per_keyset, limits.max_tracked_keysets),
            info,
        }
    }

    fn caller<T>(&self, request: &Request<T>) -> Result<Caller, Status> {
        request
            .extensions()
            .get::<Identity>()
            .and_then(|identity| self.callers.get(identity))
            .cloned()
            .ok_or_else(|| refusal(ErrorCode::CallerDenied, "the caller is not known"))
    }

    /// The caller, if it may make administrative calls. One that may not is refused
    /// with an audit record, within its rate, so that it cannot fill the log.
    fn admin(&self, op: &'static str, request: &Request<KeysetRequest>) -> Result<Caller, Status> {
        let caller = self.caller(request)?;
        if caller.admin {
            return Ok(caller);
        }
        if !self.per_caller.allow(&caller.name) {
            return Err(refusal(ErrorCode::LimitExceeded, "over the caller's rate"));
        }
        // Only a keyset that is an identifier goes in the record.
        let keyset = KeysetId::new(request.get_ref().keyset.clone())
            .map(|keyset| keyset.to_string())
            .unwrap_or_default();
        Err(self.denied(
            op,
            &caller,
            &keyset,
            "administrative calls need an admin caller",
        ))
    }

    /// Refuses a caller something it is not allowed, and leaves an audit record: what
    /// a compromised application tried is what an operator looks for afterwards.
    /// Rate limits are not recorded, and they bound how many of these there can be.
    fn denied(
        &self,
        op: &'static str,
        caller: &Caller,
        keyset: &str,
        detail: &'static str,
    ) -> Status {
        match self.audit_admin(op, caller, keyset, Some(ErrorCode::CallerDenied)) {
            Ok(()) => refusal(ErrorCode::CallerDenied, detail),
            Err(status) => status,
        }
    }

    fn audit_admin(
        &self,
        op: &'static str,
        caller: &Caller,
        keyset: &str,
        error: Option<ErrorCode>,
    ) -> Result<(), Status> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let record = AuditRecord {
            ts,
            op,
            caller: caller.name.clone(),
            keyset: keyset.to_owned(),
            item: String::new(),
            fields: Vec::new(),
            shared: Vec::new(),
            rules: Vec::new(),
            method: String::new(),
            host: None,
            path: None,
            status: None,
            bytes_in: 0,
            bytes_out: 0,
            ms: 0,
            outcome: if error.is_some() {
                Outcome::Refused
            } else {
                Outcome::Ok
            },
            code: error.map(ErrorCode::as_str),
            pg_auth: None,
            verified: None,
            expires_s: None,
        };
        self.audit
            .record(&record)
            .map_err(|_| refusal(ErrorCode::Internal, "could not write the audit record"))
    }

    async fn keyset_operation(
        &self,
        op: &'static str,
        request: Request<KeysetRequest>,
    ) -> Result<Response<WrappedKeyReply>, Status> {
        let caller = self.admin(op, &request)?;
        let name = request.into_inner().keyset;
        let keyset = KeysetId::new(name.clone())
            .map_err(|_| refusal(ErrorCode::BadRequest, "the keyset is not valid"))?;
        let result = match op {
            "generate" => self.keyring.generate(&keyset).await,
            _ => self.keyring.rotate(&keyset).await,
        };
        self.audit_admin(
            op,
            &caller,
            &name,
            result.as_ref().err().map(|error| key_code(*error)),
        )?;
        let key = result.map_err(key_status)?;
        Ok(Response::new(WrappedKeyReply {
            keyset: key.keyset.to_string(),
            kid: key.kid.to_string(),
            public: key.public,
            created: key.created,
            wrap_id: key.wrap_id,
            wrapped: key.wrapped,
        }))
    }
}

/// A refusal before a response head: a gRPC status, with the code in metadata.
#[must_use]
pub fn refusal(code: ErrorCode, detail: &str) -> Status {
    let grpc = match code {
        ErrorCode::CallerDenied => tonic::Code::PermissionDenied,
        ErrorCode::BadRequest => tonic::Code::InvalidArgument,
        ErrorCode::KeysetUnknown => tonic::Code::NotFound,
        ErrorCode::KeysUnavailable
        | ErrorCode::UpstreamConnect
        | ErrorCode::UpstreamTls
        | ErrorCode::UpstreamReset => tonic::Code::Unavailable,
        ErrorCode::UpstreamTimeout => tonic::Code::DeadlineExceeded,
        ErrorCode::BodyTooLarge | ErrorCode::ResponseTooLarge | ErrorCode::LimitExceeded => {
            tonic::Code::ResourceExhausted
        }
        ErrorCode::Internal => tonic::Code::Internal,
        _ => tonic::Code::FailedPrecondition,
    };
    let mut status = Status::new(grpc, detail.to_owned());
    if let Ok(value) = code.as_str().parse() {
        status.metadata_mut().insert(ERROR_CODE_METADATA, value);
    }
    status
}

fn broker_status(error: &BrokerError) -> Status {
    refusal(error.code(), error.detail())
}

fn key_code(error: KeyError) -> ErrorCode {
    match error {
        KeyError::UnknownKeyset => ErrorCode::KeysetUnknown,
        KeyError::AlreadyExists | KeyError::TooManyKeys => ErrorCode::Conflict,
        KeyError::Invalid(_) => ErrorCode::BadRequest,
        _ => ErrorCode::KeysUnavailable,
    }
}

fn key_status(error: KeyError) -> Status {
    refusal(key_code(error), &error.to_string())
}

fn bad(detail: &'static str) -> Status {
    refusal(ErrorCode::BadRequest, detail)
}

/// What a message after the head is, in a stream that carries a body.
enum Part {
    Chunk(Vec<u8>),
    End,
    Other,
}

/// The caller's body, from the messages that follow the head.
fn request_body(inbound: Streaming<SendIn>) -> RequestBody {
    body_of(inbound, |message| match message.f {
        Some(send_in::F::Body(chunk)) => Part::Chunk(chunk),
        Some(send_in::F::End(_)) => Part::End,
        _ => Part::Other,
    })
}

/// The message to verify, from the messages that follow the head.
fn message_body(inbound: Streaming<VerifyIn>) -> RequestBody {
    body_of(inbound, |message| match message.f {
        Some(verify_in::F::Message(chunk)) => Part::Chunk(chunk),
        Some(verify_in::F::End(_)) => Part::End,
        _ => Part::Other,
    })
}

fn body_of<M: Send + 'static>(inbound: Streaming<M>, part: fn(M) -> Part) -> RequestBody {
    let frames = stream::unfold((inbound, false), move |(mut inbound, done)| async move {
        if done {
            return None;
        }
        let item = match inbound.message().await.map(|message| message.map(part)) {
            Ok(Some(Part::Chunk(chunk))) => {
                if chunk.len() > MAX_BODY_CHUNK {
                    Err(BrokerError::new(
                        ErrorCode::BadRequest,
                        "a body chunk is too large",
                    ))
                } else {
                    Ok(Frame::data(Bytes::from(chunk)))
                }
            }
            Ok(Some(Part::End)) => return None,
            Ok(Some(Part::Other)) => Err(BrokerError::new(
                ErrorCode::BadRequest,
                "a head after the body started",
            )),
            // A stream that stops without `end` was cut off, so the body is incomplete.
            Ok(None) | Err(_) => Err(BrokerError::new(
                ErrorCode::BadRequest,
                "the caller's body ended early",
            )),
        };
        let stop = item.is_err();
        Some((item, (inbound, stop)))
    });
    StreamBody::new(frames).boxed_unsync()
}

fn header_map(headers: Vec<Header>) -> Result<HeaderMap, Status> {
    let mut map = HeaderMap::with_capacity(headers.len());
    for header in headers {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| bad("a header name is not valid"))?;
        let value = HeaderValue::from_bytes(&header.value)
            .map_err(|_| bad("a header value is not valid"))?;
        map.append(name, value);
    }
    Ok(map)
}

fn named<T>(
    entries: std::collections::HashMap<String, String>,
    convert: impl Fn(String) -> Result<T, Status>,
) -> Result<BTreeMap<FieldName, T>, Status> {
    entries
        .into_iter()
        .map(|(name, value)| {
            let name = FieldName::new(name).map_err(|_| bad("a field name is not valid"))?;
            Ok((name, convert(value)?))
        })
        .collect()
}

/// A `SendHead`, checked: everything a request needs but its body.
#[derive(Debug)]
pub struct ParsedHead {
    /// The keyset.
    pub keyset: KeysetId,
    /// The item.
    pub item: ItemId,
    /// The sealed values.
    pub sealed: BTreeMap<FieldName, Presented>,
    /// The plain fields.
    pub plain: BTreeMap<FieldName, String>,
    /// The method.
    pub method: Method,
    /// The URL, as sent; the broker parses it.
    pub url: String,
    /// The headers.
    pub headers: HeaderMap,
}

/// Checks a `SendHead` from a caller, who may send anything.
///
/// # Errors
///
/// A `BAD_REQUEST` status for anything malformed.
pub fn parse_send_head(head: SendHead) -> Result<ParsedHead, Status> {
    Ok(ParsedHead {
        keyset: KeysetId::new(head.keyset).map_err(|_| bad("the keyset is not valid"))?,
        item: ItemId::new(head.item).map_err(|_| bad("the item is not valid"))?,
        sealed: presented(head.sealed, head.items)?,
        plain: named(head.plain, Ok)?,
        method: Method::from_bytes(head.method.as_bytes())
            .map_err(|_| bad("the method is not valid"))?,
        url: head.url,
        headers: header_map(head.headers)?,
    })
}

/// The sealed values, each with its own item if the head names one.
fn presented(
    sealed: std::collections::HashMap<String, String>,
    mut items: std::collections::HashMap<String, String>,
) -> Result<BTreeMap<FieldName, Presented>, Status> {
    let values = named(sealed, |json| {
        Envelope::from_json(json.as_bytes()).map_err(|_| bad("an envelope is not valid"))
    })?;
    let presented = values
        .into_iter()
        .map(|(name, envelope)| {
            let item = items
                .remove(name.as_str())
                .map(|item| ItemId::new(item).map_err(|_| bad("an item is not valid")))
                .transpose()?;
            Ok((name, Presented { envelope, item }))
        })
        .collect::<Result<_, Status>>()?;
    if !items.is_empty() {
        return Err(bad("an item names no sealed value"));
    }
    Ok(presented)
}

type SendStream = Pin<Box<dyn Stream<Item = Result<SendOut, Status>> + Send>>;
type ConnectStream = Pin<Box<dyn Stream<Item = Result<ConnectOut, Status>> + Send>>;

/// The response, as messages: the head, then body chunks of at most 64 KiB, then a
/// trailer if the body failed. The stream permit is held until it ends.
fn response_stream(
    response: seal_broker::SendResponse,
    permit: OwnedSemaphorePermit,
) -> SendStream {
    let head = SendOut {
        f: Some(send_out::F::Head(ResponseHead {
            status: u32::from(response.status.as_u16()),
            headers: response
                .headers
                .iter()
                .map(|(name, value)| Header {
                    name: name.as_str().to_owned(),
                    value: value.as_bytes().to_vec(),
                })
                .collect(),
            sealed_fields: response
                .sealed_fields
                .iter()
                .filter_map(|(name, envelope)| Some((name.to_string(), envelope.to_json().ok()?)))
                .collect(),
            claims: response
                .claims
                .iter()
                .map(|(name, claims)| (name.to_string(), claims.clone()))
                .collect(),
        })),
    };
    let body = stream::unfold(
        (Some(response.body), Bytes::new(), permit),
        |(body, mut pending, permit)| async move {
            let mut body = body?;
            loop {
                if !pending.is_empty() {
                    let chunk = pending.split_to(pending.len().min(MAX_BODY_CHUNK));
                    let out = SendOut {
                        f: Some(send_out::F::Body(chunk.to_vec())),
                    };
                    return Some((Ok(out), (Some(body), pending, permit)));
                }
                match body.frame().await {
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            pending = data;
                        }
                    }
                    Some(Err(error)) => {
                        let trailer = SendOut {
                            f: Some(send_out::F::Trailer(Trailer {
                                code: seal_proto::v1::ErrorCode::from_str_name(
                                    error.code().as_str(),
                                )
                                .map_or(0, |code| code as i32),
                                detail: error.detail().to_owned(),
                            })),
                        };
                        return Some((Ok(trailer), (None, Bytes::new(), permit)));
                    }
                    None => return None,
                }
            }
        },
    );
    Box::pin(stream::once(async move { Ok(head) }).chain(body))
}

/// Runs a session, with the caller's messages as its input and its output as
/// messages. A failure after the session started ends the stream with a trailer.
fn session_stream(
    session: seal_broker::pg::session::PgSession,
    mut inbound: Streaming<ConnectIn>,
    permit: OwnedSemaphorePermit,
) -> ConnectStream {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const CHUNK: usize = 64 * 1024;
    let (seal_end, bridge) = tokio::io::duplex(CHUNK);
    let (mut from_session, mut to_session) = tokio::io::split(bridge);
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<ConnectOut, Status>>(4);
    tokio::spawn(async move {
        let _permit = permit;
        let pump_in = tokio::spawn(async move {
            while let Ok(Some(message)) = inbound.message().await {
                if let Some(connect_in::F::Data(data)) = message.f
                    && to_session.write_all(&data).await.is_err()
                {
                    break;
                }
            }
            // The caller is done: the session sees the end of its input.
            let _ = to_session.shutdown().await;
        });
        let output = sender.clone();
        let pump_out = async move {
            let mut buffer = vec![0; CHUNK];
            loop {
                match from_session.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        let out = ConnectOut {
                            f: Some(connect_out::F::Data(buffer[..read].to_vec())),
                        };
                        if output.send(Ok(out)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        };
        let (result, ()) = tokio::join!(session.run(seal_end), pump_out);
        pump_in.abort();
        if let Err(error) = result {
            let trailer = ConnectOut {
                f: Some(connect_out::F::Trailer(Trailer {
                    code: seal_proto::v1::ErrorCode::from_str_name(error.code().as_str())
                        .map_or(0, |code| code as i32),
                    detail: error.detail().to_owned(),
                })),
            };
            let _ = sender.send(Ok(trailer)).await;
        }
    });
    Box::pin(stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    }))
}

#[tonic::async_trait]
impl Seal for Service {
    type SendStream = SendStream;
    type ConnectStream = ConnectStream;

    async fn send(
        &self,
        request: Request<Streaming<SendIn>>,
    ) -> Result<Response<SendStream>, Status> {
        let caller = self.caller(&request)?;
        let permit = Arc::clone(&self.streams)
            .try_acquire_owned()
            .map_err(|_| refusal(ErrorCode::LimitExceeded, "too many streams"))?;
        if !self.per_caller.allow(&caller.name) {
            return Err(refusal(ErrorCode::LimitExceeded, "over the caller's rate"));
        }
        let mut inbound = request.into_inner();
        let head = match inbound.message().await {
            Ok(Some(SendIn {
                f: Some(send_in::F::Head(head)),
            })) => head,
            _ => return Err(bad("the first message must be the head")),
        };
        let ParsedHead {
            keyset,
            item,
            sealed,
            plain,
            method,
            url,
            headers,
        } = parse_send_head(head)?;
        if !caller.may_use(&keyset) {
            return Err(self.denied(
                "send",
                &caller,
                keyset.as_str(),
                "the caller may not use this keyset",
            ));
        }
        if !self.per_keyset.allow(&keyset) {
            return Err(refusal(ErrorCode::LimitExceeded, "over the keyset's rate"));
        }
        // A shared value comes from another keyset, which the caller must be allowed too.
        if sealed
            .values()
            .any(|value| !caller.may_use(value.envelope.keyset()))
        {
            return Err(self.denied(
                "send",
                &caller,
                keyset.as_str(),
                "the caller may not use a value's keyset",
            ));
        }
        let send = SendRequest {
            caller: caller.name,
            keyset,
            item,
            sealed,
            plain,
            method,
            url,
            headers,
            body: request_body(inbound),
        };
        let response = self
            .broker
            .send(send)
            .await
            .map_err(|error| broker_status(&error))?;
        Ok(Response::new(response_stream(response, permit)))
    }

    async fn connect(
        &self,
        request: Request<Streaming<ConnectIn>>,
    ) -> Result<Response<ConnectStream>, Status> {
        let caller = self.caller(&request)?;
        let permit = Arc::clone(&self.streams)
            .try_acquire_owned()
            .map_err(|_| refusal(ErrorCode::LimitExceeded, "too many streams"))?;
        if !self.per_caller.allow(&caller.name) {
            return Err(refusal(ErrorCode::LimitExceeded, "over the caller's rate"));
        }
        let mut inbound = request.into_inner();
        let head = match inbound.message().await {
            Ok(Some(ConnectIn {
                f: Some(connect_in::F::Head(head)),
            })) => head,
            _ => return Err(bad("the first message must be the head")),
        };
        let keyset = KeysetId::new(head.keyset).map_err(|_| bad("the keyset is not valid"))?;
        if !caller.may_use(&keyset) {
            return Err(self.denied(
                "connect",
                &caller,
                keyset.as_str(),
                "the caller may not use this keyset",
            ));
        }
        if !self.per_keyset.allow(&keyset) {
            return Err(refusal(ErrorCode::LimitExceeded, "over the keyset's rate"));
        }
        let sealed = presented(head.sealed, head.items)?;
        if sealed
            .values()
            .any(|value| !caller.may_use(value.envelope.keyset()))
        {
            return Err(self.denied(
                "connect",
                &caller,
                keyset.as_str(),
                "the caller may not use a value's keyset",
            ));
        }
        let request = ConnectRequest {
            caller: caller.name,
            keyset,
            item: ItemId::new(head.item).map_err(|_| bad("the item is not valid"))?,
            sealed,
            plain: named(head.plain, Ok)?,
            host: head.host,
            port: u16::try_from(head.port).map_err(|_| bad("the port is not valid"))?,
        };
        // Refusals that need no network come back as a status, before any bytes.
        let session = self
            .broker
            .open_session(request)
            .await
            .map_err(|error| broker_status(&error))?;
        Ok(Response::new(session_stream(session, inbound, permit)))
    }

    async fn verify(
        &self,
        request: Request<Streaming<VerifyIn>>,
    ) -> Result<Response<VerifyReply>, Status> {
        let caller = self.caller(&request)?;
        // Held to the end: the message is buffered while this call lasts.
        let _permit = Arc::clone(&self.streams)
            .try_acquire_owned()
            .map_err(|_| refusal(ErrorCode::LimitExceeded, "too many streams"))?;
        if !self.per_caller.allow(&caller.name) {
            return Err(refusal(ErrorCode::LimitExceeded, "over the caller's rate"));
        }
        let mut inbound = request.into_inner();
        let head = match inbound.message().await {
            Ok(Some(VerifyIn {
                f: Some(verify_in::F::Head(head)),
            })) => head,
            _ => return Err(bad("the first message must be the head")),
        };
        let keyset = KeysetId::new(head.keyset).map_err(|_| bad("the keyset is not valid"))?;
        if !caller.may_use(&keyset) {
            return Err(self.denied(
                "verify",
                &caller,
                keyset.as_str(),
                "the caller may not use this keyset",
            ));
        }
        if !self.per_keyset.allow(&keyset) {
            return Err(refusal(ErrorCode::LimitExceeded, "over the keyset's rate"));
        }
        let envelope = Envelope::from_json(head.sealed.as_bytes())
            .map_err(|_| bad("an envelope is not valid"))?;
        // A shared value comes from another keyset, which the caller must be allowed too.
        if !caller.may_use(envelope.keyset()) {
            return Err(self.denied(
                "verify",
                &caller,
                keyset.as_str(),
                "the caller may not use a value's keyset",
            ));
        }
        let value_item = (!head.value_item.is_empty())
            .then(|| ItemId::new(head.value_item).map_err(|_| bad("an item is not valid")))
            .transpose()?;
        let valid = self
            .broker
            .verify(VerifyRequest {
                caller: caller.name,
                keyset,
                item: ItemId::new(head.item).map_err(|_| bad("the item is not valid"))?,
                field: FieldName::new(head.field).map_err(|_| bad("a field name is not valid"))?,
                value: Presented {
                    envelope,
                    item: value_item,
                },
                message: message_body(inbound),
                mac: head.mac,
            })
            .await
            .map_err(|error| broker_status(&error))?;
        Ok(Response::new(VerifyReply { valid }))
    }

    async fn presign(
        &self,
        request: Request<PresignRequest>,
    ) -> Result<Response<PresignReply>, Status> {
        let caller = self.caller(&request)?;
        if !self.per_caller.allow(&caller.name) {
            return Err(refusal(ErrorCode::LimitExceeded, "over the caller's rate"));
        }
        let request = request.into_inner();
        let keyset = KeysetId::new(request.keyset).map_err(|_| bad("the keyset is not valid"))?;
        if !caller.may_use(&keyset) {
            return Err(self.denied(
                "presign",
                &caller,
                keyset.as_str(),
                "the caller may not use this keyset",
            ));
        }
        if !self.per_keyset.allow(&keyset) {
            return Err(refusal(ErrorCode::LimitExceeded, "over the keyset's rate"));
        }
        let sealed = presented(request.sealed, request.items)?;
        // A shared value comes from another keyset, which the caller must be allowed too.
        if sealed
            .values()
            .any(|value| !caller.may_use(value.envelope.keyset()))
        {
            return Err(self.denied(
                "presign",
                &caller,
                keyset.as_str(),
                "the caller may not use a value's keyset",
            ));
        }
        let url = self
            .broker
            .presign(seal_broker::PresignRequest {
                caller: caller.name,
                keyset,
                item: ItemId::new(request.item).map_err(|_| bad("the item is not valid"))?,
                sealed,
                plain: named(request.plain, Ok)?,
                method: Method::from_bytes(request.method.as_bytes())
                    .map_err(|_| bad("the method is not valid"))?,
                url: request.url,
                expires_s: request.expires_s,
            })
            .await
            .map_err(|error| broker_status(&error))?;
        Ok(Response::new(PresignReply { url }))
    }

    async fn generate_keyset(
        &self,
        request: Request<KeysetRequest>,
    ) -> Result<Response<WrappedKeyReply>, Status> {
        self.keyset_operation("generate", request).await
    }

    async fn rotate(
        &self,
        request: Request<KeysetRequest>,
    ) -> Result<Response<WrappedKeyReply>, Status> {
        self.keyset_operation("rotate", request).await
    }

    async fn public_keys(
        &self,
        request: Request<KeysetRequest>,
    ) -> Result<Response<PublicKeysReply>, Status> {
        let caller = self.admin("public_keys", &request)?;
        let name = request.into_inner().keyset;
        let keyset = KeysetId::new(name.clone()).map_err(|_| bad("the keyset is not valid"))?;
        let result = self.keyring.public_keys(&keyset).await;
        self.audit_admin(
            "public_keys",
            &caller,
            &name,
            result.as_ref().err().map(|error| key_code(*error)),
        )?;
        let keys = result.map_err(key_status)?;
        Ok(Response::new(PublicKeysReply {
            keys: keys
                .into_iter()
                .map(|key| PublicKey {
                    kid: key.kid.to_string(),
                    public: key.public.to_base64url(),
                    created: key.created,
                })
                .collect(),
        }))
    }

    async fn info(&self, request: Request<Empty>) -> Result<Response<InfoReply>, Status> {
        self.caller(&request)?;
        Ok(Response::new(InfoReply {
            mode: self.info.mode.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            buffer_cap: self.info.buffer_cap,
            max_body_chunk: MAX_BODY_CHUNK as u64,
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::HashMap;

    use seal_format::{Binding, KeyId, PrivateKey};

    use super::*;

    fn envelope_json() -> String {
        let (_, public) = PrivateKey::generate();
        let (keyset, item, field) = (
            KeysetId::new("platform").unwrap(),
            ItemId::new("oauth-app").unwrap(),
            FieldName::new("client_secret").unwrap(),
        );
        let binding = Binding {
            keyset: &keyset,
            item: &item,
            field: &field,
        };
        let policy = seal_format::policy::builder::oauth_client(
            &seal_format::policy::builder::OAuthConfig {
                token_url: "https://auth.example.com/token".to_owned(),
                revoke_url: None,
                api_base: "https://api.example.com/".to_owned(),
                auth: seal_format::policy::builder::OAuthClientAuth::ClientSecretPost,
                response_format: seal_format::policy::ResponseFormat::Json,
                shared: true,
                access_token_claims: Vec::new(),
            },
        )
        .unwrap()
        .client;
        seal_format::seal(&public, &KeyId::new("k1").unwrap(), binding, b"s", &policy)
            .unwrap()
            .to_json()
            .unwrap()
    }

    #[test]
    fn each_value_gets_its_own_item_and_a_stray_item_is_refused() {
        let json = envelope_json();
        let sealed = HashMap::from([
            ("client_secret".to_owned(), json.clone()),
            ("refresh_token".to_owned(), json.clone()),
        ]);
        let items = HashMap::from([("client_secret".to_owned(), "oauth-app".to_owned())]);
        let values = presented(sealed.clone(), items).unwrap();
        let item = |name: &str| values[&FieldName::new(name).unwrap()].item.clone();
        assert_eq!(
            item("client_secret"),
            Some(ItemId::new("oauth-app").unwrap())
        );
        assert_eq!(item("refresh_token"), None);

        let stray = HashMap::from([("password".to_owned(), "oauth-app".to_owned())]);
        assert!(presented(sealed.clone(), stray).is_err());
        let bad_item = HashMap::from([("client_secret".to_owned(), String::new())]);
        assert!(presented(sealed, bad_item).is_err());
    }
}
