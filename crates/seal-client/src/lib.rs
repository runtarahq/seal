//! Client for applications using seal: in-process, Unix socket or mTLS, behind one
//! interface, so an application changes mode by configuration, not code.
//!
//! The in-process mode links the opening code and is behind the `in-process` feature:
//! without it, an application cannot open sealed values at all.

#![forbid(unsafe_code)]

mod grpc;
#[cfg(feature = "in-process")]
mod in_process;

use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use seal_format::{Envelope, FieldName, ItemId, KeysetId};

pub use grpc::{ClientTls, GrpcClient, mtls, unix};
#[cfg(feature = "in-process")]
pub use in_process::{InProcessClient, in_process};

/// Where the private keys are, which decides what a compromised application gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// In this process: the application can read every credential.
    InProcess,
    /// Another process on this host, over a Unix socket.
    Unix,
    /// Another machine, over mutual TLS.
    Mtls,
}

impl Mode {
    /// The name `Info` reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InProcess => "in_process",
            Self::Unix => "unix",
            Self::Mtls => "mtls",
        }
    }
}

/// A request or response body. Errors end it.
pub type Body = UnsyncBoxBody<Bytes, SealError>;

/// What seal reported. Matches seal's error codes, plus `Transport` when seal could not
/// be reached at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum ErrorCode {
    CallerDenied,
    BadRequest,
    OpenFailed,
    KeysetUnknown,
    KeysUnavailable,
    PolicyDenied,
    DestinationRefused,
    Conflict,
    BodyTooLarge,
    ResponseTooLarge,
    ResponseUnparseable,
    UpstreamConnect,
    UpstreamTls,
    UpstreamTimeout,
    UpstreamReset,
    PgAuthFailed,
    LimitExceeded,
    Internal,
    /// seal could not be reached, or did not say why.
    Transport,
}

impl ErrorCode {
    const NAMES: &'static [(&'static str, Self)] = &[
        ("CALLER_DENIED", Self::CallerDenied),
        ("BAD_REQUEST", Self::BadRequest),
        ("OPEN_FAILED", Self::OpenFailed),
        ("KEYSET_UNKNOWN", Self::KeysetUnknown),
        ("KEYS_UNAVAILABLE", Self::KeysUnavailable),
        ("POLICY_DENIED", Self::PolicyDenied),
        ("DESTINATION_REFUSED", Self::DestinationRefused),
        ("CONFLICT", Self::Conflict),
        ("BODY_TOO_LARGE", Self::BodyTooLarge),
        ("RESPONSE_TOO_LARGE", Self::ResponseTooLarge),
        ("RESPONSE_UNPARSEABLE", Self::ResponseUnparseable),
        ("UPSTREAM_CONNECT", Self::UpstreamConnect),
        ("UPSTREAM_TLS", Self::UpstreamTls),
        ("UPSTREAM_TIMEOUT", Self::UpstreamTimeout),
        ("UPSTREAM_RESET", Self::UpstreamReset),
        ("PG_AUTH_FAILED", Self::PgAuthFailed),
        ("LIMIT_EXCEEDED", Self::LimitExceeded),
        ("INTERNAL", Self::Internal),
        ("TRANSPORT", Self::Transport),
    ];

    /// The code for a name on the wire.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::NAMES
            .iter()
            .find(|(known, _)| *known == name)
            .map(|(_, code)| *code)
    }

    /// The name on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, code)| *code == self)
            .map_or("TRANSPORT", |(name, _)| name)
    }

    /// Whether trying again may help. `POLICY_DENIED` is a bug or an attack, never this.
    #[must_use]
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::KeysUnavailable
                | Self::UpstreamConnect
                | Self::UpstreamTls
                | Self::UpstreamTimeout
                | Self::UpstreamReset
                | Self::LimitExceeded
                | Self::Transport
        )
    }
}

/// A refusal or failure. Carries identifiers and static text only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealError {
    /// What happened.
    pub code: ErrorCode,
    /// Identifiers and static text.
    pub detail: String,
}

impl SealError {
    pub(crate) fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for SealError {}

/// A sealed value presented with a request.
///
/// It opens against its envelope's keyset and, unless it names one, the request's
/// item. seal refuses a value bound to another record unless its sealer marked it
/// shared, such as a platform OAuth app's client secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedValue {
    /// The sealed value.
    pub envelope: Envelope,
    /// The record it is bound to, if not the request's.
    pub item: Option<ItemId>,
}

impl SealedValue {
    /// A value bound to another record.
    #[must_use]
    pub fn from_record(envelope: Envelope, item: ItemId) -> Self {
        Self {
            envelope,
            item: Some(item),
        }
    }
}

impl From<Envelope> for SealedValue {
    fn from(envelope: Envelope) -> Self {
        Self {
            envelope,
            item: None,
        }
    }
}

/// A request to send through seal. It holds no credentials.
pub struct SendRequest {
    /// The keyset the values are sealed to.
    pub keyset: KeysetId,
    /// The record the values belong to.
    pub item: ItemId,
    /// The sealed values, by field name.
    pub sealed: BTreeMap<FieldName, SealedValue>,
    /// Plain parts of a credential, by field name.
    pub plain: BTreeMap<FieldName, String>,
    /// The request, with an absolute URL.
    pub request: http::Request<Body>,
}

/// A message to check against a sealed secret, such as a webhook and its signature. It
/// holds no credentials.
pub struct VerifyRequest {
    /// The keyset the request is for.
    pub keyset: KeysetId,
    /// The record the request is for.
    pub item: ItemId,
    /// The field the secret is sealed as.
    pub field: FieldName,
    /// The sealed secret, whose policy must have `verify`.
    pub value: SealedValue,
    /// The message, as the provider signed it: for Slack, `v0:<timestamp>:<body>`.
    pub message: Bytes,
    /// The code that came with the message, decoded to bytes.
    pub mac: Vec<u8>,
}

/// A Postgres session to open through seal. It holds no credentials.
pub struct ConnectRequest {
    /// The keyset the values are sealed to.
    pub keyset: KeysetId,
    /// The record the values belong to.
    pub item: ItemId,
    /// The sealed values, by field name: a password, a client certificate's key, or both.
    pub sealed: BTreeMap<FieldName, SealedValue>,
    /// Plain parts of a credential, by field name.
    pub plain: BTreeMap<FieldName, String>,
    /// The server's host, as the policy names it.
    pub host: String,
    /// The server's port.
    pub port: u16,
}

/// A Postgres session through seal, as a byte stream. Use it with `tokio-postgres`'
/// `Config::connect_raw`, with no TLS and no password: the leg to seal is already
/// protected, and seal logs in. A login seal refuses comes back as a Postgres error.
pub struct PgStream {
    inner: tokio::io::DuplexStream,
}

impl PgStream {
    pub(crate) fn new(inner: tokio::io::DuplexStream) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for PgStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgStream").finish_non_exhaustive()
    }
}

impl tokio::io::AsyncRead for PgStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PgStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The buffer between an application and a session.
pub(crate) const PG_BUFFER: usize = 64 * 1024;

/// Cancels a running query through seal: the cancel request goes to the server over a
/// new session, so any seal instance can forward it. `request` presents the same values
/// as the session's.
///
/// # Errors
///
/// A refusal from seal, or [`ErrorCode::Transport`] if the cancel could not be sent.
#[cfg(feature = "postgres")]
pub async fn cancel_pg(
    client: &dyn SealClient,
    request: ConnectRequest,
    token: &tokio_postgres::CancelToken,
) -> Result<(), SealError> {
    let stream = client.connect_pg(request).await?;
    token
        .cancel_query_raw(stream, tokio_postgres::NoTls)
        .await
        .map_err(|_| SealError::new(ErrorCode::Transport, "the cancel could not be sent"))
}

/// What came back.
pub struct SendResponse {
    /// The response. A redirect is returned, never followed.
    pub response: http::Response<Body>,
    /// Values sealed from the response, by field name.
    pub sealed_fields: BTreeMap<FieldName, Envelope>,
    /// Claims of sealed values that are JWTs, in plaintext, where the policy names
    /// them in `expose_claims`: by field name, each a JSON object. seal does not check
    /// the token's signature.
    pub claims: BTreeMap<FieldName, String>,
}

/// What seal says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    /// The mode.
    pub mode: String,
    /// seal's version.
    pub version: String,
    /// The largest capped buffer.
    pub buffer_cap: u64,
}

/// A wrapped private key, made by `generate_keyset` or `rotate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    /// The keyset.
    pub keyset: String,
    /// The key's id.
    pub kid: String,
    /// The public key, in base64url.
    pub public: String,
    /// When it was made, in seconds since the Unix epoch.
    pub created: u64,
    /// The wrapping key's id.
    pub wrap_id: String,
    /// The wrapped private key, in base64url.
    pub wrapped: String,
}

/// A keyset's public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// The key's id.
    pub kid: String,
    /// The public key, in base64url.
    pub public: String,
    /// When it was made.
    pub created: u64,
}

/// seal, wherever it runs.
#[async_trait]
pub trait SealClient: Send + Sync {
    /// The mode.
    fn mode(&self) -> Mode;

    /// Sends a request using sealed values.
    async fn send(&self, request: SendRequest) -> Result<SendResponse, SealError>;

    /// Whether a message's authentication code was made with a sealed secret. seal
    /// compares the whole code and never returns one, so this can check a webhook's
    /// signature but cannot make one. A code that does not match is `Ok(false)`.
    async fn verify(&self, request: VerifyRequest) -> Result<bool, SealError>;

    /// Opens a Postgres session. seal logs in with the sealed credential; the stream
    /// then carries the session.
    async fn connect_pg(&self, request: ConnectRequest) -> Result<PgStream, SealError>;

    /// What seal says about itself.
    async fn info(&self) -> Result<Info, SealError>;

    /// Administrative: makes a keyset's first key.
    async fn generate_keyset(&self, keyset: &KeysetId) -> Result<WrappedKey, SealError>;

    /// Administrative: adds a key, which becomes current.
    async fn rotate(&self, keyset: &KeysetId) -> Result<WrappedKey, SealError>;

    /// Administrative: a keyset's public keys, oldest first.
    async fn public_keys(&self, keyset: &KeysetId) -> Result<Vec<PublicKeyInfo>, SealError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_name_that_maps_back() {
        for (name, code) in ErrorCode::NAMES {
            assert_eq!(ErrorCode::from_name(name), Some(*code));
            assert_eq!(code.as_str(), *name);
        }
        assert_eq!(ErrorCode::from_name("NOPE"), None);
    }

    #[test]
    fn a_policy_refusal_is_never_retryable() {
        assert!(!ErrorCode::PolicyDenied.is_retryable());
        assert!(!ErrorCode::OpenFailed.is_retryable());
        assert!(ErrorCode::Transport.is_retryable());
    }
}
