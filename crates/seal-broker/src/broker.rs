//! The broker: opens values, checks the policy, sends the request, seals the response.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method as HttpMethod, Request, StatusCode};
use http_body_util::BodyExt;
use seal_format::policy::{Method, RuleLimits};
use seal_format::{Binding, Envelope, FieldName, ItemId, KeysetId, Secret, seal as seal_value};
use seal_keys::{KeyError, Keys};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, sleep_until};

use crate::address::NetworkPolicy;
use crate::audit::{AuditGuard, AuditRecord, AuditSink, Clock, Outcome, SystemClock};
use crate::body::{
    Finish, Progress, ReflectionScan, ResponseBody, ResponseStream, TrackedRequestBody,
    read_capped, wiped_body,
};
use crate::client::{ClientConfig, ConnectLimits, HttpClient, RequestBody, body_error};
use crate::error::{BrokerError, ErrorCode};
use crate::identity::ClientIdentity;
use crate::inject::{Signing, Sources, apply_to_body, build_head, sigv4};
use crate::matcher::{Endpoint, RequestHead, ResponseSealing, decide};
use crate::net::{Connect, DnsResolver, Resolve, TcpConnector};
use crate::pg::session::PgSession;
use crate::relay::RelayLimits;
use crate::response_seal::seal_response_fields;
use crate::target::Target;

/// The default for most timeouts and caps matches the configuration reference in
/// `docs/operations.md`.
const MEGABYTE: u64 = 1024 * 1024;

/// Global limits. A rule can only tighten them.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// How many requests may hold a capped buffer at once.
    pub max_concurrent_buffered: usize,
    /// The largest buffered body or response.
    pub buffer_cap: u64,
    /// How long a transfer may make no progress in either direction.
    pub idle_timeout: Duration,
    /// How long a connection may take, including TLS.
    pub connect_timeout: Duration,
    /// How long the first response byte may take, once the request is sent.
    pub first_byte_timeout: Duration,
    /// The total deadline for a request holding a capped buffer.
    pub buffered_total_timeout: Duration,
    /// The total deadline for a streamed request, if there is one.
    pub max_stream_duration: Option<Duration>,
    /// The longest a Postgres session may last.
    pub pg_max_session: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_concurrent_buffered: 64,
            buffer_cap: MEGABYTE,
            idle_timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(10),
            first_byte_timeout: Duration::from_secs(60),
            buffered_total_timeout: Duration::from_secs(60),
            max_stream_duration: None,
            pg_max_session: Duration::from_secs(8 * 3600),
        }
    }
}

impl Limits {
    /// These limits, tightened by a request's matched rules. A rule can never relax one.
    #[must_use]
    pub fn tightened_by(&self, rule: &RuleLimits) -> Self {
        let seconds = |current: Duration, limit: Option<u32>| {
            limit.map_or(current, |limit| {
                current.min(Duration::from_secs(u64::from(limit)))
            })
        };
        Self {
            max_concurrent_buffered: self.max_concurrent_buffered,
            buffer_cap: rule
                .buffer_cap_bytes
                .map_or(self.buffer_cap, |limit| self.buffer_cap.min(limit)),
            idle_timeout: seconds(self.idle_timeout, rule.idle_timeout_s),
            connect_timeout: seconds(self.connect_timeout, rule.connect_timeout_s),
            first_byte_timeout: seconds(self.first_byte_timeout, rule.first_byte_timeout_s),
            buffered_total_timeout: seconds(
                self.buffered_total_timeout,
                rule.buffered_total_timeout_s,
            ),
            max_stream_duration: match (self.max_stream_duration, rule.max_stream_duration_s) {
                (Some(global), Some(limit)) => {
                    Some(global.min(Duration::from_secs(u64::from(limit))))
                }
                (Some(global), None) => Some(global),
                (None, limit) => limit.map(|limit| Duration::from_secs(u64::from(limit))),
            },
            pg_max_session: seconds(self.pg_max_session, rule.pg_max_session_s),
        }
    }
}

/// The broker's configuration.
#[derive(Clone, Debug)]
pub struct BrokerConfig {
    /// Which addresses may be connected to.
    pub network: NetworkPolicy,
    /// Connection limits.
    pub client: ClientConfig,
    /// Request limits.
    pub limits: Limits,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            network: NetworkPolicy::default(),
            client: ClientConfig {
                max_upstream_connections: 1024,
                max_idle_per_host: 8,
                idle_timeout: Duration::from_secs(90),
                per_stream_buffer: 256 * 1024,
                extra_roots: Vec::new(),
                max_client_cert_identities: 256,
            },
            limits: Limits::default(),
        }
    }
}

/// What a broker needs from outside: the network, audit records and the time.
pub struct Environment {
    /// Looks up host names.
    pub resolve: Arc<dyn Resolve>,
    /// Opens connections.
    pub connect: Arc<dyn Connect>,
    /// Takes audit records.
    pub audit: Arc<dyn AuditSink>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl Environment {
    /// The system's DNS, TCP and clock.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Internal`] if the DNS configuration cannot be read.
    pub fn production(audit: Arc<dyn AuditSink>) -> Result<Self, BrokerError> {
        let resolver = DnsResolver::from_system().map_err(|_| {
            BrokerError::new(ErrorCode::Internal, "could not read the DNS configuration")
        })?;
        Ok(Self {
            resolve: Arc::new(resolver),
            connect: Arc::new(TcpConnector),
            audit,
            clock: Arc::new(SystemClock),
        })
    }
}

/// A sealed value presented with a request.
///
/// It opens against its envelope's keyset and, unless it names one, the request's item.
/// A value bound to anything other than the request's record must be shared: a
/// platform credential its sealer marked as usable with any record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presented {
    /// The sealed value.
    pub envelope: Envelope,
    /// The record it is bound to, if not the request's.
    pub item: Option<ItemId>,
}

impl From<Envelope> for Presented {
    fn from(envelope: Envelope) -> Self {
        Self {
            envelope,
            item: None,
        }
    }
}

/// A request to send. It holds no credentials.
pub struct SendRequest {
    /// Who is asking, for the audit record.
    pub caller: String,
    /// The keyset the values are sealed to.
    pub keyset: KeysetId,
    /// The record the values belong to.
    pub item: ItemId,
    /// The sealed values, by field name.
    pub sealed: BTreeMap<FieldName, Presented>,
    /// Plain parts of a credential, by field name.
    pub plain: BTreeMap<FieldName, String>,
    /// The method.
    pub method: HttpMethod,
    /// The URL, which is refused if a parser would rewrite it.
    pub url: String,
    /// The headers, which may not set anything an injection sets.
    pub headers: HeaderMap,
    /// The body, which streams unless an injection has to modify it.
    pub body: RequestBody,
}

/// A Postgres session to open. It holds no credentials.
pub struct ConnectRequest {
    /// Who is asking, for the audit record.
    pub caller: String,
    /// The keyset the values are sealed to.
    pub keyset: KeysetId,
    /// The record the values belong to.
    pub item: ItemId,
    /// The sealed values, by field name.
    pub sealed: BTreeMap<FieldName, Presented>,
    /// Plain parts of a credential, by field name.
    pub plain: BTreeMap<FieldName, String>,
    /// The server's host, as the policy names it.
    pub host: String,
    /// The server's port.
    pub port: u16,
}

/// A URL to presign, for a request the caller could have sent through seal. It holds
/// no credentials; what comes back is one.
pub struct PresignRequest {
    /// Who is asking, for the audit record.
    pub caller: String,
    /// The keyset the values are sealed to.
    pub keyset: KeysetId,
    /// The record the values belong to.
    pub item: ItemId,
    /// The sealed values, by field name.
    pub sealed: BTreeMap<FieldName, Presented>,
    /// Plain parts of a credential, by field name.
    pub plain: BTreeMap<FieldName, String>,
    /// The method the URL is for: `GET`, `HEAD`, `PUT` or `DELETE`.
    pub method: HttpMethod,
    /// The URL of the object, which is refused if a parser would rewrite it.
    pub url: String,
    /// How long the URL is to last, in seconds, within what the rule allows.
    pub expires_s: u32,
}

/// A message to check against a sealed secret: a webhook and its signature. It holds
/// no credentials.
pub struct VerifyRequest {
    /// Who is asking, for the audit record.
    pub caller: String,
    /// The keyset the request is for.
    pub keyset: KeysetId,
    /// The record the request is for.
    pub item: ItemId,
    /// The field the value is sealed as.
    pub field: FieldName,
    /// The sealed secret.
    pub value: Presented,
    /// The message, as the provider signed it. It is read whole, up to the buffer cap.
    pub message: RequestBody,
    /// The code that came with the message, as bytes.
    pub mac: Vec<u8>,
}

/// What came back.
pub struct SendResponse {
    /// The status. A redirect is returned, never followed.
    pub status: StatusCode,
    /// The headers.
    pub headers: HeaderMap,
    /// Values sealed from the response, by field name, so that a caller need not
    /// parse the body to find them.
    pub sealed_fields: BTreeMap<FieldName, Envelope>,
    /// Claims of sealed values that are JWTs, in plaintext, where the policy names
    /// them: by field name, each a JSON object.
    pub claims: BTreeMap<FieldName, String>,
    /// The body.
    pub body: ResponseBody,
}

/// Opens values, checks the policy, sends the request and seals the response.
pub struct Broker {
    limits: Limits,
    keys: Arc<dyn Keys>,
    client: Arc<HttpClient>,
    buffers: Arc<Semaphore>,
    audit: Arc<dyn AuditSink>,
    clock: Arc<dyn Clock>,
}

impl Broker {
    /// Creates a broker. Needs a Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Internal`] if TLS cannot be configured.
    pub fn new(
        config: BrokerConfig,
        keys: Arc<dyn Keys>,
        environment: Environment,
    ) -> Result<Self, BrokerError> {
        Ok(Self {
            limits: config.limits,
            keys,
            client: Arc::new(HttpClient::new(
                environment.resolve,
                environment.connect,
                config.network,
                config.client,
            )?),
            buffers: Arc::new(Semaphore::new(config.limits.max_concurrent_buffered)),
            audit: environment.audit,
            clock: environment.clock,
        })
    }

    /// Opens a Postgres session: the values open and the policy allows the server, with
    /// no network traffic yet. The session then runs over the caller's stream.
    ///
    /// # Errors
    ///
    /// Returns a [`BrokerError`] with the reason, which never includes a value. A refusal
    /// is audited.
    pub async fn open_session(&self, request: ConnectRequest) -> Result<PgSession, BrokerError> {
        let ts = self
            .clock
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let mut record = AuditRecord {
            ts,
            op: "connect",
            caller: request.caller.clone(),
            keyset: request.keyset.to_string(),
            item: request.item.to_string(),
            fields: request.sealed.keys().map(ToString::to_string).collect(),
            shared: Vec::new(),
            rules: Vec::new(),
            method: String::new(),
            host: Some(format!("{}:{}", request.host, request.port)),
            path: None,
            status: None,
            bytes_in: 0,
            bytes_out: 0,
            ms: 0,
            outcome: Outcome::Refused,
            code: None,
            pg_auth: None,
            verified: None,
            expires_s: None,
        };
        match self.prepare_session(request, &mut record).await {
            Ok(session) => Ok(session),
            Err(error) => {
                record.code = Some(error.code().as_str());
                // The caller hears the refusal either way.
                let _ = self.audit.record(&record);
                Err(error)
            }
        }
    }

    async fn prepare_session(
        &self,
        request: ConnectRequest,
        record: &mut AuditRecord,
    ) -> Result<PgSession, BrokerError> {
        let ConnectRequest {
            keyset,
            item,
            sealed,
            plain,
            host,
            port,
            ..
        } = request;
        let (secrets, policies, _) = self.open_all(&keyset, &item, &sealed).await?;
        let names: BTreeSet<FieldName> = plain.keys().cloned().collect();
        let plan = decide(
            &policies,
            &RequestHead {
                endpoint: Endpoint::Postgres { host: &host, port },
                method: seal_format::policy::Method::Get,
                header_names: &[],
                plain: &names,
                copy_source: None,
            },
        )?;
        record.rules = plan.rules.values().copied().collect();
        let terms = crate::matcher::postgres_terms(&policies, &plan)?;
        drop(policies);
        let sources = Sources {
            secrets: &secrets,
            plain: &plain,
        };
        let user = String::from_utf8(sources.part(&terms.user)?.to_vec())
            .map_err(|_| BrokerError::new(ErrorCode::BadRequest, "the user is not UTF-8"))?;
        let password = terms
            .password
            .as_ref()
            .map(|password| sources.part(&seal_format::policy::Part::Field(password.field.clone())))
            .transpose()?;
        let client_cert = match &terms.client_cert {
            Some((
                field,
                seal_format::policy::Inject::ClientCert {
                    cert,
                    chain,
                    ca,
                    server_name,
                },
            )) => {
                let key = sources.part(&seal_format::policy::Part::Field(field.clone()))?;
                let cert = sources.part(cert)?;
                let chain = chain
                    .as_ref()
                    .map(|chain| sources.part(chain))
                    .transpose()?;
                Some(crate::identity::ClientCertMaterial::parse(
                    field,
                    &key,
                    &cert,
                    chain.as_deref().map(Vec::as_slice),
                    ca.as_deref(),
                    server_name.as_ref().map(seal_format::policy::Host::as_str),
                )?)
            }
            _ => None,
        };
        drop(secrets);
        let limits = self.limits.tightened_by(&plan.limits);
        let mut record = record.clone();
        record.outcome = Outcome::Cancelled;
        Ok(PgSession {
            host,
            port,
            user,
            databases: terms.databases,
            allow_replication: terms.allow_replication,
            tls: terms.tls,
            allow_md5: terms
                .password
                .as_ref()
                .is_some_and(|password| password.allow_md5),
            allow_cleartext: terms
                .password
                .as_ref()
                .is_some_and(|password| password.allow_cleartext),
            require_channel_binding: terms
                .password
                .as_ref()
                .is_some_and(|password| password.require_channel_binding),
            password,
            client_cert,
            allow_private: plan.allow_private_destination,
            connect_timeout: limits.connect_timeout,
            relay: RelayLimits {
                idle: limits.idle_timeout,
                max_session: limits.pg_max_session,
                buffer: self.client.per_stream_buffer().max(8192),
            },
            client: Arc::clone(&self.client),
            audit: Arc::clone(&self.audit),
            record: Some(record),
            started: tokio::time::Instant::now(),
        })
    }

    /// Presigns a URL: an S3 presigned URL or a Blob shared access signature for one
    /// object, where the value's rule sets `allow_presign`. The caller can copy what
    /// comes back and use it without seal until it expires, so this is refused unless
    /// the rule allows it, for this long, for a request it would let seal send. Every
    /// call leaves one audit record, with the lifetime.
    ///
    /// # Errors
    ///
    /// Returns a [`BrokerError`] with the reason, which never includes a value or the
    /// URL.
    pub async fn presign(
        &self,
        request: PresignRequest,
    ) -> Result<zeroize::Zeroizing<String>, BrokerError> {
        let mut record = self.first_record(
            "presign",
            &request.caller,
            &request.keyset,
            &request.item,
            &request.sealed,
        );
        request.method.as_str().clone_into(&mut record.method);
        record.expires_s = Some(request.expires_s);
        let mut audit = AuditGuard::new(Arc::clone(&self.audit), record, Arc::new(Progress::new()));
        match self.presign_audited(request, &mut audit).await {
            Ok(url) => {
                audit.finish(Outcome::Ok, None).map_err(|_| {
                    BrokerError::new(ErrorCode::Internal, "could not write the audit record")
                })?;
                Ok(url)
            }
            Err(error) => {
                // The caller hears the refusal either way.
                let _ = audit.finish(Outcome::Refused, Some(error.code()));
                Err(error)
            }
        }
    }

    async fn presign_audited(
        &self,
        request: PresignRequest,
        audit: &mut AuditGuard,
    ) -> Result<zeroize::Zeroizing<String>, BrokerError> {
        let PresignRequest {
            keyset,
            item,
            sealed,
            plain,
            method,
            url,
            expires_s,
            ..
        } = request;
        let target = Target::parse(&url)?;
        audit.update(|record| {
            record.host = Some(target.host.clone());
            record.path = Some(target.path.clone());
        });
        let method = policy_method(&method)?;
        let (secrets, policies, _) = self.open_all(&keyset, &item, &sealed).await?;
        let names: BTreeSet<FieldName> = plain.keys().cloned().collect();
        let plan = decide(
            &policies,
            &RequestHead {
                endpoint: Endpoint::Http(&target),
                method,
                header_names: &[],
                plain: &names,
                copy_source: None,
            },
        )?;
        audit.update(|record| record.rules = plan.rules.values().copied().collect());
        drop(policies);
        let presigned = crate::presign::presigned_url(
            &plan,
            &target,
            method,
            expires_s,
            &Sources {
                secrets: &secrets,
                plain: &plain,
            },
            self.clock.now(),
        )?;
        Ok(presigned)
    }

    /// Says whether a message's authentication code was made with a sealed secret, whose
    /// policy must allow it. The answer is only yes or no: the code is never computed
    /// for the caller. Every call leaves one audit record, with the answer.
    ///
    /// # Errors
    ///
    /// Returns a [`BrokerError`] with the reason, which never includes a value. A code
    /// that does not match is not an error.
    pub async fn verify(&self, request: VerifyRequest) -> Result<bool, BrokerError> {
        let VerifyRequest {
            caller,
            keyset,
            item,
            field,
            value,
            message,
            mac,
        } = request;
        let sealed = BTreeMap::from([(field.clone(), value)]);
        let progress = Arc::new(Progress::new());
        let record = self.first_record("verify", &caller, &keyset, &item, &sealed);
        let mut audit = AuditGuard::new(Arc::clone(&self.audit), record, Arc::clone(&progress));
        match self
            .verify_audited(&keyset, &item, &field, &sealed, message, &mac, &progress)
            .await
        {
            Ok(valid) => {
                audit.update(|record| record.verified = Some(valid));
                audit.finish(Outcome::Ok, None).map_err(|_| {
                    BrokerError::new(ErrorCode::Internal, "could not write the audit record")
                })?;
                Ok(valid)
            }
            Err(error) => {
                // The caller hears the refusal either way.
                let _ = audit.finish(Outcome::Refused, Some(error.code()));
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)] // The parts of one request, already taken apart.
    async fn verify_audited(
        &self,
        keyset: &KeysetId,
        item: &ItemId,
        field: &FieldName,
        sealed: &BTreeMap<FieldName, Presented>,
        message: RequestBody,
        mac: &[u8],
        progress: &Progress,
    ) -> Result<bool, BrokerError> {
        let (secrets, policies, _) = self.open_all(keyset, item, sealed).await?;
        let verify = policies.get(field).and_then(|policy| policy.verify);
        drop(policies);
        let Some(seal_format::policy::Verify::Hmac { hash }) = verify else {
            return Err(BrokerError::for_field(
                ErrorCode::PolicyDenied,
                "this value's policy does not allow verification",
                field,
            ));
        };
        // The message is held whole, so it takes a buffer's place and its deadline.
        let _permit = self.buffer_permit(self.limits.first_byte_timeout).await?;
        let message = within(
            Some(Instant::now() + self.limits.buffered_total_timeout),
            read_capped(
                message,
                self.limits.buffer_cap,
                BrokerError::new(ErrorCode::BodyTooLarge, "the message is over the cap"),
                |error| error,
            ),
        )
        .await?;
        progress.set_bytes_in(message.len() as u64);
        let secret = secrets.get(field).ok_or_else(|| {
            BrokerError::for_field(ErrorCode::Internal, "a matched secret is missing", field)
        })?;
        Ok(secret.expose(|key| crate::verify::hmac_matches(hash, key, &message, mac)))
    }

    /// Sends a request using the sealed values it presents. Every call leaves one audit
    /// record, including a refusal, and a request whose caller goes away.
    ///
    /// # Errors
    ///
    /// Returns a [`BrokerError`] with the reason, which never includes a value.
    pub async fn send(&self, request: SendRequest) -> Result<SendResponse, BrokerError> {
        let progress = Arc::new(Progress::new());
        let mut audit = AuditGuard::new(
            Arc::clone(&self.audit),
            {
                let mut record = self.first_record(
                    "send",
                    &request.caller,
                    &request.keyset,
                    &request.item,
                    &request.sealed,
                );
                request.method.as_str().clone_into(&mut record.method);
                record
            },
            Arc::clone(&progress),
        );
        let mut contacted = false;
        match self
            .send_audited(request, &mut audit, &progress, &mut contacted)
            .await
        {
            Ok(Sent::Sealed(response)) => {
                progress.set_bytes_out(response.body_len);
                audit.finish(Outcome::Ok, None).map_err(|_| {
                    BrokerError::new(ErrorCode::Internal, "could not write the audit record")
                })?;
                Ok(response.response)
            }
            Ok(Sent::Streaming(response, make_body)) => Ok(SendResponse {
                body: make_body(audit),
                ..*response
            }),
            Err(error) => {
                let error = progress.failure().unwrap_or(error);
                let outcome = if contacted {
                    Outcome::Failed
                } else {
                    Outcome::Refused
                };
                // The caller hears the refusal or failure either way.
                let _ = audit.finish(outcome, Some(error.code()));
                Err(error)
            }
        }
    }

    /// The record of a request that has only just arrived: a cancellation, until it
    /// ends some other way.
    fn first_record(
        &self,
        op: &'static str,
        caller: &str,
        keyset: &KeysetId,
        item: &ItemId,
        sealed: &BTreeMap<FieldName, Presented>,
    ) -> AuditRecord {
        let ts = self
            .clock
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        AuditRecord {
            ts,
            op,
            caller: caller.to_owned(),
            keyset: keyset.to_string(),
            item: item.to_string(),
            fields: sealed.keys().map(ToString::to_string).collect(),
            shared: sealed
                .iter()
                .filter_map(|(field, presented)| {
                    let value_item = presented.item.as_ref().unwrap_or(item);
                    let elsewhere = presented.envelope.keyset() != keyset || value_item != item;
                    elsewhere
                        .then(|| format!("{field}={}/{value_item}", presented.envelope.keyset()))
                })
                .collect(),
            rules: Vec::new(),
            method: String::new(),
            host: None,
            path: None,
            status: None,
            bytes_in: 0,
            bytes_out: 0,
            ms: 0,
            outcome: Outcome::Cancelled,
            code: None,
            pg_auth: None,
            verified: None,
            expires_s: None,
        }
    }

    async fn send_audited(
        &self,
        request: SendRequest,
        audit: &mut AuditGuard,
        progress: &Arc<Progress>,
        contacted: &mut bool,
    ) -> Result<Sent, BrokerError> {
        let SendRequest {
            keyset,
            item,
            sealed,
            plain,
            method,
            url,
            headers,
            body,
            ..
        } = request;

        let target = Target::parse(&url)?;
        audit.update(|record| {
            record.host = Some(target.host.clone());
            record.path = Some(target.path.clone());
        });
        let policy_method = policy_method(&method)?;

        // Opening needs the keys, and a key is held only for this step.
        let (secrets, policies, origins) = self.open_all(&keyset, &item, &sealed).await?;

        let names: BTreeSet<FieldName> = plain.keys().cloned().collect();
        let header_names: Vec<&str> = headers.keys().map(http::HeaderName::as_str).collect();
        let copy_source = copy_source(&headers)?;
        let plan = decide(
            &policies,
            &RequestHead {
                endpoint: Endpoint::Http(&target),
                method: policy_method,
                header_names: &header_names,
                plain: &names,
                copy_source,
            },
        )?;
        audit.update(|record| record.rules = plan.rules.values().copied().collect());
        drop(policies);

        let limits = self.limits.tightened_by(&plan.limits);
        let mut outgoing = build_head(
            &plan,
            &target,
            &headers,
            &Sources {
                secrets: &secrets,
                plain: &plain,
            },
            self.clock.now(),
        )?;
        drop(secrets);

        let mut signing = outgoing.signing;
        let mut outgoing_headers = outgoing.headers;
        // A signature covers Content-Length where present, so it must be set before
        // signing, not added by the HTTP layer afterwards.
        if signing.is_some()
            && !outgoing_headers.contains_key(header::CONTENT_LENGTH)
            && let Some(length) = http_body::Body::size_hint(&body).exact().filter(|n| *n > 0)
        {
            outgoing_headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
        }
        if let Some(Signing::Aws {
            signer,
            allowed,
            allow_unsigned,
        }) = &mut signing
        {
            signer.payload = sigv4::choose_payload(&sigv4::PayloadChoice {
                allowed,
                allow_unsigned: *allow_unsigned,
                headers: &outgoing_headers,
                buffer_cap: limits.buffer_cap,
                body_injected: outgoing.body.is_some(),
            })?;
        }
        let hashing = matches!(
            &signing,
            Some(Signing::Aws { signer, .. }) if signer.payload == sigv4::Payload::Computed
        );
        let reading = outgoing.body.is_some() || !plan.form_requirements.is_empty() || hashing;
        let buffering = reading || plan.response.is_some();
        let permit = if buffering {
            Some(self.buffer_permit(limits.first_byte_timeout).await?)
        } else {
            None
        };
        // Holding a capped buffer has a total deadline, to protect a scarce slot. What
        // streams afterwards is timed like any other stream.
        let stream_deadline = limits
            .max_stream_duration
            .map(|limit| Instant::now() + limit);
        let total_deadline = if buffering {
            Some(Instant::now() + limits.buffered_total_timeout)
        } else {
            stream_deadline
        };

        let mut out_headers = outgoing_headers;
        let (path, query) = outgoing
            .path_and_query
            .split_once('?')
            .unwrap_or((outgoing.path_and_query.as_str(), ""));
        let body = if reading {
            let read = read_capped(
                body,
                limits.buffer_cap,
                BrokerError::new(ErrorCode::BodyTooLarge, "the body is over the cap"),
                |error| error,
            );
            let original = within(total_deadline, read).await?;
            check_form_requirements(&plan.form_requirements, &out_headers, &original)?;
            let sent = match &outgoing.body {
                Some(injection) => apply_to_body(injection, &out_headers, &original)?,
                None => original,
            };
            out_headers.insert(header::CONTENT_LENGTH, HeaderValue::from(sent.len()));
            if let Some(signing) = &signing {
                signing.sign(method.as_str(), path, query, &mut out_headers, Some(&sent))?;
            }
            wiped_body(sent)
        } else {
            match &signing {
                Some(Signing::Aws { signer, .. }) => {
                    if let sigv4::Payload::Streaming { decoded_length } = signer.payload {
                        sigv4::prepare_streaming(&mut out_headers, decoded_length)?;
                        let seed =
                            signer.sign(method.as_str(), path, query, &mut out_headers, None)?;
                        sigv4::ChunkedBody::new(body, signer.chunks(seed), decoded_length)
                            .boxed_unsync()
                    } else {
                        signer.sign(method.as_str(), path, query, &mut out_headers, None)?;
                        body
                    }
                }
                Some(signing) => {
                    signing.sign(method.as_str(), path, query, &mut out_headers, None)?;
                    body
                }
                None => body,
            }
        };
        drop(signing);

        // Everything decidable locally has been decided. Next comes DNS.
        let addresses = tokio::time::timeout(
            limits.connect_timeout,
            self.client
                .permitted_addresses(&target, plan.allow_private_destination),
        )
        .await
        .map_err(|_| BrokerError::new(ErrorCode::UpstreamTimeout, "resolving timed out"))??;

        let declared_length = out_headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|text| text.parse::<u64>().ok());
        let body = TrackedRequestBody::new(
            body,
            Arc::clone(progress),
            limits.idle_timeout,
            total_deadline,
            declared_length,
        );
        let mut outgoing_request = Request::builder()
            .method(method)
            .uri(outgoing.path_and_query.as_str())
            .body(body.boxed_unsync())
            .map_err(|_| {
                BrokerError::new(ErrorCode::BadRequest, "the request could not be formed")
            })?;
        *outgoing_request.headers_mut() = out_headers;

        *contacted = true;
        let mark_connected = || progress.mark_connected();
        let identity = outgoing.client_cert.map(|material| {
            let origin = origins.get(&material.field);
            ClientIdentity {
                origin: origin
                    .map(|origin| origin.origin.clone())
                    .unwrap_or_default(),
                sealing_key: origin
                    .map(|origin| origin.sealing_key.clone())
                    .unwrap_or_default(),
                material,
            }
        });
        let sending = self.client.send(
            &target,
            &addresses,
            outgoing_request,
            ConnectLimits {
                connect_timeout: limits.connect_timeout,
            },
            &mark_connected,
            identity,
        );
        let (response, checkout) =
            wait_for_head(sending, progress, &limits, total_deadline).await?;
        let (mut parts, incoming) = response.into_parts();
        remove_hop_by_hop(&mut parts.headers);
        let injected = std::mem::take(&mut outgoing.injected);
        for secret in &injected {
            remove_headers_repeating(&mut parts.headers, secret);
        }
        let scan = ReflectionScan::new(injected);
        audit.update(|record| record.status = Some(parts.status.as_u16()));

        let Some(sealing) = plan.response else {
            drop(permit);
            let response = SendResponse {
                status: parts.status,
                headers: parts.headers,
                sealed_fields: BTreeMap::new(),
                claims: BTreeMap::new(),
                body: ResponseBody::buffered(Bytes::new()),
            };
            let progress = Arc::clone(progress);
            let idle = limits.idle_timeout;
            return Ok(Sent::Streaming(
                Box::new(response),
                Box::new(move |audit| {
                    ResponseBody::stream(ResponseStream::new(
                        incoming,
                        Finish { checkout, audit },
                        progress,
                        idle,
                        stream_deadline,
                        scan,
                    ))
                }),
            ));
        };

        // Sealed responses are read whole, and over the cap nothing is returned.
        let body = within(
            total_deadline,
            read_capped(
                incoming,
                limits.buffer_cap,
                BrokerError::new(ErrorCode::ResponseTooLarge, "the response is over the cap"),
                |error| body_error(&error),
            ),
        )
        .await?;
        checkout.finish();
        let sealed_response = self
            .seal_response(&sealing, &keyset, &item, &parts.headers, &body)
            .await?;
        // Looked for once the declared fields are sealed: a provider may return a
        // token it was sent, such as a refresh token, where the rule seals it.
        if scan.is_some_and(|scan| scan.finds(&sealed_response.body)) {
            return Err(BrokerError::new(
                ErrorCode::ResponseUnparseable,
                "the response repeats a credential",
            ));
        }
        drop(permit);

        let mut headers = parts.headers;
        let unchanged_empty = body.is_empty() && sealed_response.body.is_empty();
        if !unchanged_empty {
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from(sealed_response.body.len()),
            );
        }
        let body_len = sealed_response.body.len() as u64;
        Ok(Sent::Sealed(Box::new(SealedOutcome {
            body_len,
            response: SendResponse {
                status: parts.status,
                headers,
                sealed_fields: sealed_response.fields,
                claims: sealed_response.claims,
                body: ResponseBody::buffered(Bytes::from(sealed_response.body)),
            },
        })))
    }

    async fn open_all(
        &self,
        keyset: &KeysetId,
        item: &ItemId,
        sealed: &BTreeMap<FieldName, Presented>,
    ) -> Result<
        (
            BTreeMap<FieldName, Secret>,
            BTreeMap<FieldName, seal_format::Policy>,
            BTreeMap<FieldName, KeyOrigin>,
        ),
        BrokerError,
    > {
        let mut secrets = BTreeMap::new();
        let mut policies = BTreeMap::new();
        let mut origins = BTreeMap::new();
        for (field, presented) in sealed {
            let envelope = &presented.envelope;
            let (value_keyset, value_item) =
                (envelope.keyset(), presented.item.as_ref().unwrap_or(item));
            let key = self
                .keys
                .private_key(value_keyset, envelope.kid())
                .await
                .map_err(|error| key_error(error, field))?;
            let binding = Binding {
                keyset: value_keyset,
                item: value_item,
                field,
            };
            let opened = seal_format::open(&key, envelope, binding).map_err(|_| {
                BrokerError::for_field(ErrorCode::OpenFailed, "the value did not open", field)
            })?;
            origins.insert(
                field.clone(),
                KeyOrigin {
                    origin: crate::identity::length_prefixed([
                        value_keyset.as_str().as_bytes(),
                        value_item.as_str().as_bytes(),
                        envelope.kid().as_str().as_bytes(),
                    ]),
                    sealing_key: Arc::downgrade(&key),
                },
            );
            drop(key);
            // Only a value its sealer marked shared may serve another record, so a
            // tenant's tokens can never be presented with another tenant's request.
            let elsewhere = value_keyset != keyset || value_item != item;
            if elsewhere && !opened.policy.shared {
                return Err(BrokerError::for_field(
                    ErrorCode::PolicyDenied,
                    "a value from another record must be shared",
                    field,
                ));
            }
            secrets.insert(field.clone(), opened.secret);
            policies.insert(field.clone(), opened.policy);
        }
        Ok((secrets, policies, origins))
    }

    async fn buffer_permit(&self, wait: Duration) -> Result<OwnedSemaphorePermit, BrokerError> {
        tokio::time::timeout(wait, Arc::clone(&self.buffers).acquire_owned())
            .await
            .ok()
            .and_then(Result::ok)
            .ok_or_else(|| {
                BrokerError::new(ErrorCode::LimitExceeded, "too many requests are buffering")
            })
    }

    async fn seal_response(
        &self,
        sealing: &ResponseSealing,
        keyset: &KeysetId,
        item: &ItemId,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<SealedParts, BrokerError> {
        let (kid, public) =
            self.keys
                .current_public_key(keyset)
                .await
                .map_err(|error| match error {
                    KeyError::UnknownKeyset | KeyError::UnknownKey => {
                        BrokerError::new(ErrorCode::KeysetUnknown, "the keyset has no current key")
                    }
                    _ => {
                        BrokerError::new(ErrorCode::KeysUnavailable, "the keys could not be loaded")
                    }
                })?;
        let mut claims = BTreeMap::new();
        let sealed = seal_response_fields(&sealing.sealing, headers, body, |field, plaintext| {
            if let Some(exposed) = crate::claims::exposed(plaintext, &field.expose_claims) {
                claims.insert(field.as_field.clone(), exposed);
            }
            let policy = sealing
                .policy
                .for_response_field(&field.policy)
                .map_err(|_| BrokerError::new(ErrorCode::Internal, "a definition is missing"))?;
            let binding = Binding {
                keyset,
                item,
                field: &field.as_field,
            };
            seal_value(&public, &kid, binding, plaintext, &policy).map_err(|_| {
                BrokerError::for_field(
                    ErrorCode::Internal,
                    "could not seal a response field",
                    &field.as_field,
                )
            })
        })?;
        Ok(SealedParts {
            body: sealed.body,
            fields: sealed.fields,
            claims,
        })
    }
}

/// A response with its fields sealed, and the claims its policy exposes.
struct SealedParts {
    body: Vec<u8>,
    fields: BTreeMap<FieldName, Envelope>,
    claims: BTreeMap<FieldName, String>,
}

struct SealedOutcome {
    body_len: u64,
    response: SendResponse,
}

/// Builds the streaming body, once the audit guard can move into it.
type MakeBody = Box<dyn FnOnce(AuditGuard) -> ResponseBody + Send>;

enum Sent {
    Sealed(Box<SealedOutcome>),
    Streaming(Box<SendResponse>, MakeBody),
}

/// Where a sealed value's key came from, for a client certificate's identity.
struct KeyOrigin {
    /// The keyset, item and kid, length-prefixed.
    origin: Vec<u8>,
    /// The sealing key, which the keyring holds while it is loaded.
    sealing_key: std::sync::Weak<seal_keys::LiveKey>,
}

/// The caller's `x-amz-copy-source`, which must be one printable value.
fn copy_source(headers: &HeaderMap) -> Result<Option<&str>, BrokerError> {
    let mut values = headers.get_all("x-amz-copy-source").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(BrokerError::new(
            ErrorCode::BadRequest,
            "x-amz-copy-source is repeated",
        ));
    }
    value.to_str().map(Some).map_err(|_| {
        BrokerError::new(
            ErrorCode::BadRequest,
            "x-amz-copy-source is not printable ASCII",
        )
    })
}

/// Each required form field must appear exactly once, with one of its allowed values.
fn check_form_requirements(
    requirements: &[(String, Vec<String>)],
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), BrokerError> {
    if requirements.is_empty() {
        return Ok(());
    }
    let refused = || {
        BrokerError::new(
            ErrorCode::PolicyDenied,
            "the request's form does not meet a rule's requirements",
        )
    };
    if headers.contains_key(header::CONTENT_ENCODING)
        || !crate::inject::media_type_is(headers, crate::inject::is_form)
    {
        return Err(refused());
    }
    if crate::inject::has_semicolon_separator(body) {
        return Err(refused());
    }
    let pairs: Vec<(String, String)> = form_urlencoded::parse(body).into_owned().collect();
    for (name, allowed) in requirements {
        let mut values = pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value);
        match (values.next(), values.next()) {
            (Some(value), None) if allowed.contains(value) => {}
            _ => return Err(refused()),
        }
    }
    Ok(())
}

fn policy_method(method: &HttpMethod) -> Result<Method, BrokerError> {
    Ok(match *method {
        HttpMethod::GET => Method::Get,
        HttpMethod::HEAD => Method::Head,
        HttpMethod::POST => Method::Post,
        HttpMethod::PUT => Method::Put,
        HttpMethod::PATCH => Method::Patch,
        HttpMethod::DELETE => Method::Delete,
        HttpMethod::OPTIONS => Method::Options,
        _ => {
            return Err(BrokerError::new(
                ErrorCode::BadRequest,
                "this method is refused",
            ));
        }
    })
}

fn key_error(error: KeyError, field: &FieldName) -> BrokerError {
    match error {
        KeyError::UnknownKeyset => {
            BrokerError::for_field(ErrorCode::KeysetUnknown, "the keyset does not exist", field)
        }
        // The same answer as any other value that does not open.
        KeyError::UnknownKey => {
            BrokerError::for_field(ErrorCode::OpenFailed, "the value did not open", field)
        }
        _ => BrokerError::for_field(
            ErrorCode::KeysUnavailable,
            "the keys could not be loaded",
            field,
        ),
    }
}

async fn within<T>(
    deadline: Option<Instant>,
    future: impl Future<Output = Result<T, BrokerError>>,
) -> Result<T, BrokerError> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| BrokerError::new(ErrorCode::UpstreamTimeout, "over the total deadline"))?,
        None => future.await,
    }
}

/// Waits for the response head. Connecting has its own timeout; after that, while the
/// request is still going up, progress is what counts; once it is sent, the first-byte
/// timeout starts.
async fn wait_for_head<T>(
    sending: impl Future<Output = Result<T, BrokerError>>,
    progress: &Progress,
    limits: &Limits,
    total_deadline: Option<Instant>,
) -> Result<T, BrokerError> {
    tokio::pin!(sending);
    loop {
        let head = progress.head_deadline(limits.idle_timeout, limits.first_byte_timeout);
        let deadline = match (head, total_deadline) {
            (Some(head), Some(total)) => Some(head.min(total)),
            (head, total) => head.or(total),
        };
        let expiry = async {
            match deadline {
                Some(deadline) => sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            result = &mut sending => return result,
            () = progress.connected_signal() => {}
            () = expiry => {
                if total_deadline.is_some_and(|total| total <= Instant::now()) {
                    return Err(BrokerError::new(
                        ErrorCode::UpstreamTimeout,
                        "over the total deadline",
                    ));
                }
                let head = progress.head_deadline(limits.idle_timeout, limits.first_byte_timeout);
                if head.is_some_and(|head| head <= Instant::now()) {
                    return Err(BrokerError::new(
                        ErrorCode::UpstreamTimeout,
                        "the provider did not respond in time",
                    ));
                }
            }
        }
    }
}

/// Drops headers that apply to one connection, including any `Connection` names.
fn remove_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();
    for name in named {
        headers.remove(name.as_str());
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

/// Drops every header that repeats a secret seal put in the request head, as it was
/// written there: a redirect's `Location` is the usual one. A header is dropped whole,
/// whichever of its values has it.
fn remove_headers_repeating(headers: &mut HeaderMap, secret: &[u8]) {
    if secret.is_empty() {
        return;
    }
    let repeats = |value: &HeaderValue| {
        value
            .as_bytes()
            .windows(secret.len())
            .any(|window| window == secret)
    };
    let names: Vec<header::HeaderName> = headers
        .iter()
        .filter(|(_, value)| repeats(value))
        .map(|(name, _)| name.clone())
        .collect();
    for name in names {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_can_only_tighten_limits() {
        let limits = Limits::default();
        let tighter = limits.tightened_by(&RuleLimits {
            buffer_cap_bytes: Some(10),
            idle_timeout_s: Some(5),
            ..RuleLimits::default()
        });
        assert_eq!(tighter.buffer_cap, 10);
        assert_eq!(tighter.idle_timeout, Duration::from_secs(5));

        let looser = limits.tightened_by(&RuleLimits {
            buffer_cap_bytes: Some(u64::MAX),
            idle_timeout_s: Some(u32::MAX),
            connect_timeout_s: Some(u32::MAX),
            first_byte_timeout_s: Some(u32::MAX),
            buffered_total_timeout_s: Some(u32::MAX),
            max_stream_duration_s: None,
            pg_max_session_s: None,
        });
        assert_eq!(looser.buffer_cap, limits.buffer_cap);
        assert_eq!(looser.idle_timeout, limits.idle_timeout);
        assert_eq!(looser.connect_timeout, limits.connect_timeout);
        assert_eq!(looser.first_byte_timeout, limits.first_byte_timeout);
        assert_eq!(looser.buffered_total_timeout, limits.buffered_total_timeout);
    }

    #[test]
    fn a_rule_can_set_a_stream_deadline_but_not_lift_one() {
        let none = Limits::default();
        let rule = RuleLimits {
            max_stream_duration_s: Some(30),
            ..RuleLimits::default()
        };
        assert_eq!(
            none.tightened_by(&rule).max_stream_duration,
            Some(Duration::from_secs(30))
        );

        let global = Limits {
            max_stream_duration: Some(Duration::from_secs(10)),
            ..Limits::default()
        };
        assert_eq!(
            global.tightened_by(&rule).max_stream_duration,
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            global
                .tightened_by(&RuleLimits::default())
                .max_stream_duration,
            Some(Duration::from_secs(10))
        );
    }

    #[test]
    fn only_the_listed_methods_are_accepted() {
        for method in [HttpMethod::CONNECT, HttpMethod::TRACE] {
            assert_eq!(
                policy_method(&method).unwrap_err().code(),
                ErrorCode::BadRequest
            );
        }
        assert_eq!(policy_method(&HttpMethod::GET).unwrap(), Method::Get);
    }

    #[test]
    fn hop_by_hop_response_headers_are_removed() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("connection", "x-drop"),
            ("x-drop", "1"),
            ("transfer-encoding", "chunked"),
            ("keep-alive", "1"),
            ("x-keep", "1"),
        ] {
            headers.insert(
                http::HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        remove_hop_by_hop(&mut headers);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key("x-keep"));
    }
}
