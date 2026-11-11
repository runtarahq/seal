//! seal as a service, over a Unix socket or mutual TLS.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{StreamExt, stream};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use seal_format::{Envelope, FieldName, KeysetId};
use seal_proto::v1::seal_client::SealClient as Generated;
use seal_proto::v1::{
    ConnectHead, ConnectIn, ConnectOut, Empty, Header, KeysetRequest, SendHead, SendIn, SendOut,
    VerifyHead, VerifyIn, connect_in, connect_out, send_in, send_out, verify_in,
};
use seal_proto::{ERROR_CODE_METADATA, MAX_BODY_CHUNK};
use tokio::net::{TcpStream, UnixStream};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::ServiceExt;

use crate::{
    Body, ConnectRequest, ErrorCode, Info, Mode, PgStream, PresignRequest, PublicKeyInfo,
    SealClient, SealError, SendRequest, SendResponse, VerifyRequest, WrappedKey,
};

/// How to reach seal over mutual TLS.
#[derive(Clone, Debug)]
pub struct ClientTls {
    /// The CA that issued seal's certificate, in PEM.
    pub ca_pem: String,
    /// The application's certificate and chain, in PEM.
    pub cert_pem: String,
    /// The application's key, in PEM.
    pub key_pem: String,
    /// The name seal's certificate is for.
    pub server_name: String,
}

/// How to reach one seal endpoint.
#[derive(Clone)]
enum Connector {
    Unix(Arc<PathBuf>),
    Tls {
        address: Arc<String>,
        tls: tokio_rustls::TlsConnector,
        name: ServerName<'static>,
    },
}

impl Connector {
    /// Connects now, so that a dead endpoint is found before anything is sent.
    async fn connect(&self) -> Result<Channel, tonic::transport::Error> {
        match self.clone() {
            Self::Unix(path) => {
                endpoint()
                    .connect_with_connector(tower::service_fn(move |_: Uri| {
                        let path = Arc::clone(&path);
                        async move {
                            Ok::<_, std::io::Error>(TokioIo::new(
                                UnixStream::connect(&*path).await?,
                            ))
                        }
                    }))
                    .await
            }
            Self::Tls { address, tls, name } => {
                endpoint()
                    .connect_with_connector(tower::service_fn(move |_: Uri| {
                        let (address, tls, name) =
                            (Arc::clone(&address), tls.clone(), name.clone());
                        async move {
                            let stream = TcpStream::connect(&*address).await?;
                            stream.set_nodelay(true)?;
                            let stream = tls.connect(name, stream).await?;
                            Ok::<_, std::io::Error>(TokioIo::new(stream))
                        }
                    }))
                    .await
            }
        }
    }
}

/// seal over gRPC, with failover between endpoints. seal is stateless, so any instance
/// serves any request. A request moves to another endpoint only if it never reached
/// seal: if an endpoint cannot be connected to.
pub struct GrpcClient {
    mode: Mode,
    connectors: Vec<Connector>,
    channels: Vec<tokio::sync::Mutex<Option<Channel>>>,
    preferred: AtomicUsize,
}

fn transport(detail: &'static str) -> SealError {
    SealError::new(ErrorCode::Transport, detail)
}

/// Connects to seal on a Unix socket. Connections are made lazily, as needed.
///
/// # Errors
///
/// Returns [`ErrorCode::Transport`] if there are no paths.
pub fn unix(paths: &[PathBuf]) -> Result<GrpcClient, SealError> {
    let connectors = paths
        .iter()
        .map(|path| Connector::Unix(Arc::new(path.clone())))
        .collect();
    GrpcClient::new(Mode::Unix, connectors)
}

/// Connects to seal over TLS 1.3 with a client certificate. Connections are made
/// lazily, as needed.
///
/// # Errors
///
/// Returns [`ErrorCode::Transport`] if a certificate or key is not valid, or there are
/// no addresses.
pub fn mtls(addresses: &[String], tls: &ClientTls) -> Result<GrpcClient, SealError> {
    let mut roots = rustls::RootCertStore::empty();
    for ca in CertificateDer::pem_slice_iter(tls.ca_pem.as_bytes()) {
        roots
            .add(ca.map_err(|_| transport("seal's CA is not valid"))?)
            .map_err(|_| transport("seal's CA is not valid"))?;
    }
    let chain = CertificateDer::pem_slice_iter(tls.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| transport("the client certificate is not valid"))?;
    let key = PrivateKeyDer::from_pem_slice(tls.key_pem.as_bytes())
        .map_err(|_| transport("the client key is not valid"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| transport("TLS 1.3 is not available"))?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|_| transport("the client certificate and key do not match"))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(tls.server_name.clone())
        .map_err(|_| transport("the server name is not valid"))?;

    let connectors = addresses
        .iter()
        .map(|address| Connector::Tls {
            address: Arc::new(address.clone()),
            tls: connector.clone(),
            name: name.clone(),
        })
        .collect();
    GrpcClient::new(Mode::Mtls, connectors)
}

fn endpoint() -> Endpoint {
    // The URI only names the connection; the connector decides where it goes.
    Endpoint::from_static("http://seal.invalid")
        .connect_timeout(Duration::from_secs(5))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .initial_stream_window_size(Some(256 * 1024))
}

impl GrpcClient {
    fn new(mode: Mode, connectors: Vec<Connector>) -> Result<Self, SealError> {
        if connectors.is_empty() {
            return Err(transport("there are no endpoints"));
        }
        Ok(Self {
            mode,
            channels: connectors
                .iter()
                .map(|_| tokio::sync::Mutex::new(None))
                .collect(),
            connectors,
            preferred: AtomicUsize::new(0),
        })
    }

    /// A connected channel, starting with the last endpoint that worked. Nothing has been
    /// sent while connecting, so moving on to the next endpoint is safe.
    async fn ready(&self) -> Result<(usize, Generated<Channel>), SealError> {
        let count = self.connectors.len();
        let start = self.preferred.load(Ordering::Relaxed);
        for offset in 0..count {
            let index = (start + offset) % count;
            let mut cached = self.channels[index].lock().await;
            let channel = match cached.as_ref() {
                Some(channel) => channel.clone(),
                None => match self.connectors[index].connect().await {
                    Ok(channel) => {
                        *cached = Some(channel.clone());
                        channel
                    }
                    Err(_) => continue,
                },
            };
            drop(cached);
            if let Ok(channel) = channel.ready_oneshot().await {
                self.preferred.store(index, Ordering::Relaxed);
                let client = Generated::new(channel)
                    .max_decoding_message_size(4 * MAX_BODY_CHUNK)
                    .max_encoding_message_size(1 << 20);
                return Ok((index, client));
            }
            *self.channels[index].lock().await = None;
        }
        Err(transport("no seal endpoint could be reached"))
    }

    /// After a transport failure, forgets the connection, so the next call reconnects
    /// or moves on to another endpoint.
    async fn forget(&self, index: usize, error: &SealError) {
        if error.code == ErrorCode::Transport {
            *self.channels[index].lock().await = None;
        }
    }

    async fn call<T, F, Fut>(&self, call: F) -> Result<T, SealError>
    where
        F: FnOnce(Generated<Channel>) -> Fut,
        Fut: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        let (index, client) = self.ready().await?;
        match call(client).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                let error = status_error(&status);
                self.forget(index, &error).await;
                Err(error)
            }
        }
    }
}

/// The error a status carries: seal's code from metadata, or `Transport`.
fn status_error(status: &tonic::Status) -> SealError {
    let code = status
        .metadata()
        .get(ERROR_CODE_METADATA)
        .and_then(|value| value.to_str().ok())
        .and_then(ErrorCode::from_name);
    match code {
        Some(code) => SealError::new(code, status.message()),
        None => SealError::new(ErrorCode::Transport, "seal did not complete the call"),
    }
}

fn to_headers(headers: &http::HeaderMap) -> Vec<Header> {
    headers
        .iter()
        .map(|(name, value)| Header {
            name: name.as_str().to_owned(),
            value: value.as_bytes().to_vec(),
        })
        .collect()
}

fn named_envelopes(
    entries: std::collections::HashMap<String, String>,
) -> Result<std::collections::BTreeMap<FieldName, Envelope>, SealError> {
    entries
        .into_iter()
        .map(|(name, json)| {
            let name =
                FieldName::new(name).map_err(|_| transport("seal returned a bad field name"))?;
            let envelope = Envelope::from_json(json.as_bytes())
                .map_err(|_| transport("seal returned a bad envelope"))?;
            Ok((name, envelope))
        })
        .collect()
}

/// The request as messages: the head, body chunks of at most 64 KiB, then the end. If
/// the body fails, the stream stops without an end, so seal sees an incomplete body.
fn outbound(
    head: SendHead,
    body: Body,
) -> impl futures_util::Stream<Item = SendIn> + Send + 'static {
    let chunks = stream::unfold(
        (Some(body), Bytes::new()),
        |(body, mut pending)| async move {
            let mut body = body?;
            loop {
                if !pending.is_empty() {
                    let chunk = pending.split_to(pending.len().min(MAX_BODY_CHUNK));
                    let message = SendIn {
                        f: Some(send_in::F::Body(chunk.to_vec())),
                    };
                    return Some((message, (Some(body), pending)));
                }
                match body.frame().await {
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            pending = data;
                        }
                    }
                    Some(Err(_)) => return None,
                    None => {
                        let end = SendIn {
                            f: Some(send_in::F::End(Empty {})),
                        };
                        return Some((end, (None, Bytes::new())));
                    }
                }
            }
        },
    );
    // The body is wrapped so the stream is `Sync`, which tonic requires.
    let chunks = SyncStream(std::sync::Mutex::new(Box::pin(chunks)));
    stream::once(async move {
        SendIn {
            f: Some(send_in::F::Head(head)),
        }
    })
    .chain(chunks)
}

struct SyncStream<S>(std::sync::Mutex<std::pin::Pin<Box<S>>>);

impl<S: futures_util::Stream> futures_util::Stream for SyncStream<S> {
    type Item = S::Item;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<S::Item>> {
        let mut inner = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.as_mut().poll_next(cx)
    }
}

#[async_trait]
impl SealClient for GrpcClient {
    fn mode(&self) -> Mode {
        self.mode
    }

    async fn send(&self, request: SendRequest) -> Result<SendResponse, SealError> {
        let SendRequest {
            keyset,
            item,
            sealed,
            plain,
            request,
        } = request;
        let (parts, body) = request.into_parts();
        let head = SendHead {
            keyset: keyset.to_string(),
            item: item.to_string(),
            items: sealed
                .iter()
                .filter_map(|(name, value)| {
                    let item = value.item.as_ref()?;
                    Some((name.to_string(), item.to_string()))
                })
                .collect(),
            sealed: sealed
                .iter()
                .map(|(name, value)| {
                    value
                        .envelope
                        .to_json()
                        .map(|json| (name.to_string(), json))
                        .map_err(|_| transport("an envelope could not be written"))
                })
                .collect::<Result<_, _>>()?,
            plain: plain
                .into_iter()
                .map(|(name, value)| (name.to_string(), value))
                .collect(),
            method: parts.method.to_string(),
            url: parts.uri.to_string(),
            headers: to_headers(&parts.headers),
            options: None,
        };
        let (index, mut client) = self.ready().await?;
        let mut inbound = match client.send(outbound(head, body)).await {
            Ok(response) => response.into_inner(),
            Err(status) => {
                let error = status_error(&status);
                self.forget(index, &error).await;
                return Err(error);
            }
        };

        let head = match inbound.message().await {
            Ok(Some(SendOut {
                f: Some(send_out::F::Head(head)),
            })) => head,
            Ok(Some(SendOut {
                f: Some(send_out::F::Trailer(trailer)),
            })) => {
                return Err(trailer_error(&trailer));
            }
            Ok(_) => return Err(transport("seal's reply had no head")),
            Err(status) => return Err(status_error(&status)),
        };
        let mut builder = http::Response::builder().status(
            u16::try_from(head.status).map_err(|_| transport("seal returned a bad status"))?,
        );
        for header in &head.headers {
            builder = builder.header(header.name.as_str(), header.value.as_slice());
        }
        let frames = stream::unfold(Some(inbound), |inbound| async move {
            let mut inbound = inbound?;
            match inbound.message().await {
                Ok(Some(SendOut {
                    f: Some(send_out::F::Body(chunk)),
                })) => Some((Ok(Frame::data(Bytes::from(chunk))), Some(inbound))),
                Ok(Some(SendOut {
                    f: Some(send_out::F::Trailer(trailer)),
                })) => Some((Err(trailer_error(&trailer)), None)),
                Ok(None) => None,
                Ok(Some(_)) => Some((Err(transport("seal's reply was malformed")), None)),
                Err(status) => Some((Err(status_error(&status)), None)),
            }
        });
        let response = builder
            .body(StreamBody::new(frames).boxed_unsync())
            .map_err(|_| transport("seal returned a bad header"))?;
        Ok(SendResponse {
            response,
            sealed_fields: named_envelopes(head.sealed_fields)?,
            claims: head
                .claims
                .into_iter()
                .map(|(name, claims)| {
                    FieldName::new(name)
                        .map(|name| (name, claims))
                        .map_err(|_| transport("seal returned a bad field name"))
                })
                .collect::<Result<_, _>>()?,
        })
    }

    async fn presign(&self, request: PresignRequest) -> Result<Zeroizing<String>, SealError> {
        let message = seal_proto::v1::PresignRequest {
            keyset: request.keyset.to_string(),
            item: request.item.to_string(),
            items: request
                .sealed
                .iter()
                .filter_map(|(name, value)| {
                    let item = value.item.as_ref()?;
                    Some((name.to_string(), item.to_string()))
                })
                .collect(),
            sealed: request
                .sealed
                .iter()
                .map(|(name, value)| {
                    value
                        .envelope
                        .to_json()
                        .map(|json| (name.to_string(), json))
                        .map_err(|_| transport("an envelope could not be written"))
                })
                .collect::<Result<_, _>>()?,
            plain: request
                .plain
                .into_iter()
                .map(|(name, value)| (name.to_string(), value))
                .collect(),
            method: request.method.to_string(),
            url: request.url,
            expires_s: request.expires_s,
        };
        let mut reply = self
            .call(|mut client| async move { client.presign(message).await })
            .await?;
        // Moved out, and the reply wipes what is left of itself.
        Ok(Zeroizing::new(std::mem::take(&mut reply.url)))
    }

    async fn verify(&self, request: VerifyRequest) -> Result<bool, SealError> {
        let head = VerifyHead {
            keyset: request.keyset.to_string(),
            item: request.item.to_string(),
            field: request.field.to_string(),
            sealed: request
                .value
                .envelope
                .to_json()
                .map_err(|_| transport("an envelope could not be written"))?,
            value_item: request
                .value
                .item
                .map(|item| item.to_string())
                .unwrap_or_default(),
            mac: request.mac,
        };
        let message = request.message;
        // The head, the message in chunks of at most 64 KiB, then the end.
        let chunks = (0..message.len())
            .step_by(MAX_BODY_CHUNK)
            .map(move |start| {
                let end = message.len().min(start + MAX_BODY_CHUNK);
                verify_in::F::Message(message[start..end].to_vec())
            });
        let parts = std::iter::once(verify_in::F::Head(head))
            .chain(chunks)
            .chain(std::iter::once(verify_in::F::End(Empty {})))
            .map(|part| VerifyIn { f: Some(part) });
        let reply = self
            .call(|mut client| async move { client.verify(stream::iter(parts)).await })
            .await?;
        Ok(reply.valid)
    }

    async fn connect_pg(&self, request: ConnectRequest) -> Result<PgStream, SealError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let ConnectRequest {
            keyset,
            item,
            sealed,
            plain,
            host,
            port,
        } = request;
        let head = ConnectHead {
            keyset: keyset.to_string(),
            item: item.to_string(),
            items: sealed
                .iter()
                .filter_map(|(name, value)| {
                    let item = value.item.as_ref()?;
                    Some((name.to_string(), item.to_string()))
                })
                .collect(),
            sealed: sealed
                .iter()
                .map(|(name, value)| {
                    value
                        .envelope
                        .to_json()
                        .map(|json| (name.to_string(), json))
                        .map_err(|_| transport("an envelope could not be written"))
                })
                .collect::<Result<_, _>>()?,
            plain: plain
                .into_iter()
                .map(|(name, value)| (name.to_string(), value))
                .collect(),
            host,
            port: u32::from(port),
        };
        let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
        let outbound = connect_outbound(head, receiver);

        // seal answers once the values have opened and the policy allows the server;
        // a refusal before then is a status.
        let (index, mut client) = self.ready().await?;
        let mut inbound = match client.connect(outbound).await {
            Ok(response) => response.into_inner(),
            Err(status) => {
                let error = status_error(&status);
                self.forget(index, &error).await;
                return Err(error);
            }
        };

        let (application, bridge) = tokio::io::duplex(crate::PG_BUFFER);
        let (mut from_application, mut to_application) = tokio::io::split(bridge);
        tokio::spawn(async move {
            let mut buffer = vec![0; crate::PG_BUFFER];
            loop {
                match from_application.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if sender.send(buffer[..read].to_vec()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        tokio::spawn(async move {
            // A trailer's failure was already told to the application as a Postgres
            // error; the stream just ends.
            while let Ok(Some(ConnectOut {
                f: Some(connect_out::F::Data(data)),
            })) = inbound.message().await
            {
                if to_application.write_all(&data).await.is_err() {
                    break;
                }
            }
            let _ = to_application.shutdown().await;
        });
        Ok(PgStream::new(application))
    }

    async fn info(&self) -> Result<Info, SealError> {
        let reply = self
            .call(|mut client| async move { client.info(Empty {}).await })
            .await?;
        Ok(Info {
            mode: reply.mode,
            version: reply.version,
            buffer_cap: reply.buffer_cap,
        })
    }

    async fn generate_keyset(&self, keyset: &KeysetId) -> Result<WrappedKey, SealError> {
        let request = KeysetRequest {
            keyset: keyset.to_string(),
        };
        let reply = self
            .call(|mut client| async move { client.generate_keyset(request).await })
            .await?;
        Ok(wrapped(reply))
    }

    async fn rotate(&self, keyset: &KeysetId) -> Result<WrappedKey, SealError> {
        let request = KeysetRequest {
            keyset: keyset.to_string(),
        };
        let reply = self
            .call(|mut client| async move { client.rotate(request).await })
            .await?;
        Ok(wrapped(reply))
    }

    async fn public_keys(&self, keyset: &KeysetId) -> Result<Vec<PublicKeyInfo>, SealError> {
        let request = KeysetRequest {
            keyset: keyset.to_string(),
        };
        let reply = self
            .call(|mut client| async move { client.public_keys(request).await })
            .await?;
        Ok(reply
            .keys
            .into_iter()
            .map(|key| PublicKeyInfo {
                kid: key.kid,
                public: key.public,
                created: key.created,
            })
            .collect())
    }

    async fn destroy_keyset(&self, keyset: &KeysetId) -> Result<(), SealError> {
        let request = KeysetRequest {
            keyset: keyset.to_string(),
        };
        self.call(|mut client| async move { client.destroy_keyset(request).await })
            .await?;
        Ok(())
    }
}

fn wrapped(reply: seal_proto::v1::WrappedKeyReply) -> WrappedKey {
    WrappedKey {
        keyset: reply.keyset,
        kid: reply.kid,
        public: reply.public,
        created: reply.created,
        wrap_id: reply.wrap_id,
        wrapped: reply.wrapped,
    }
}

fn trailer_error(trailer: &seal_proto::v1::Trailer) -> SealError {
    let code = seal_proto::v1::ErrorCode::try_from(trailer.code)
        .ok()
        .and_then(|code| ErrorCode::from_name(code.as_str_name()))
        .unwrap_or(ErrorCode::Transport);
    SealError::new(code, trailer.detail.clone())
}

/// The head, then whatever the application writes, as `connect` messages.
fn connect_outbound(
    head: ConnectHead,
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> impl futures_util::Stream<Item = ConnectIn> + Send + 'static {
    let head = ConnectIn {
        f: Some(connect_in::F::Head(head)),
    };
    let data = stream::unfold(receiver, next_data);
    stream::once(async move { head }).chain(data)
}

async fn next_data(
    mut receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> Option<(ConnectIn, tokio::sync::mpsc::Receiver<Vec<u8>>)> {
    let data = receiver.recv().await?;
    let message = ConnectIn {
        f: Some(connect_in::F::Data(data)),
    };
    Some((message, receiver))
}
