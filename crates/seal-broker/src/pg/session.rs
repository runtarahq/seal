//! One Postgres session through seal: the caller's preamble, the server's TLS, the
//! login, then the relay.
//!
//! The caller speaks to seal as to a server that offers no TLS and asks for no
//! password; the leg to seal is already protected. seal checks the startup against the
//! policy, logs in to the server with the sealed credential, says `AuthenticationOk`,
//! and relays everything after. A cancel request needs no session table: it goes to the
//! server over a new connection, so any seal instance can forward any cancel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use seal_format::policy::PgTls;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use crate::audit::{AuditRecord, AuditSink, Outcome};
use crate::client::HttpClient;
use crate::error::{BrokerError, ErrorCode};
use crate::identity::ClientCertMaterial;
use crate::pg::login::{self, Credentials, LoginFailed};
use crate::pg::wire::{self, Preamble, Startup};
use crate::relay::{RelayLimits, relay};

/// The most encryption requests a caller may make before its startup: libpq may ask
/// for GSSAPI and then for TLS.
const MAX_ENCRYPTION_REQUESTS: usize = 2;

/// A session that passed every check that needs no network: its values opened and
/// the policy allows the server. It holds the credential until the login, and audits
/// itself once, however it ends.
pub struct PgSession {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) databases: Vec<String>,
    pub(crate) allow_replication: bool,
    pub(crate) tls: PgTls,
    pub(crate) password: Option<Zeroizing<Vec<u8>>>,
    pub(crate) allow_md5: bool,
    pub(crate) allow_cleartext: bool,
    pub(crate) client_cert: Option<ClientCertMaterial>,
    pub(crate) allow_private: bool,
    pub(crate) connect_timeout: Duration,
    pub(crate) relay: RelayLimits,
    pub(crate) client: Arc<HttpClient>,
    pub(crate) audit: Arc<dyn AuditSink>,
    pub(crate) record: Option<AuditRecord>,
    pub(crate) started: Instant,
}

impl std::fmt::Debug for PgSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgSession")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl Drop for PgSession {
    fn drop(&mut self) {
        // A session never run still leaves its record.
        if let Some(mut record) = self.record.take() {
            record.outcome = Outcome::Cancelled;
            let _ = self.audit.record(&record);
        }
    }
}

/// An error, and what the caller is told in Postgres terms.
struct Refusal {
    error: BrokerError,
    sqlstate: String,
    message: &'static str,
}

impl Refusal {
    fn new(code: ErrorCode, sqlstate: &str, message: &'static str) -> Self {
        Self {
            error: BrokerError::new(code, message),
            sqlstate: sqlstate.to_owned(),
            message,
        }
    }
}

/// What a session did, for its record.
#[derive(Default)]
struct Progress {
    contacted: bool,
    caller_to_server: u64,
    server_to_caller: u64,
    pg_auth: Option<&'static str>,
    database: Option<String>,
    cancel: bool,
    /// Why a relay ended, if not cleanly.
    failure: Option<BrokerError>,
}

impl PgSession {
    /// Runs the session over the caller's stream until it ends.
    ///
    /// # Errors
    ///
    /// Why it was refused or ended early. The caller has been told, as a Postgres
    /// `ErrorResponse`, if it was still logging in.
    pub async fn run<C>(mut self, caller: C) -> Result<(), BrokerError>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut caller = caller;
        let mut progress = Progress::default();
        let result = self.drive(&mut caller, &mut progress).await;
        let result = match result {
            Ok(()) => Ok(()),
            Err(Some(refusal)) => {
                // Still in the login: tell the caller in its own protocol.
                let _ = caller
                    .write_all(&wire::error_response(&refusal.sqlstate, refusal.message))
                    .await;
                let _ = caller.flush().await;
                Err(refusal.error)
            }
            Err(None) => progress.failure.take().map_or(Ok(()), Err),
        };
        if let Some(mut record) = self.record.take() {
            if progress.cancel {
                record.op = "cancel";
            }
            record.path = progress.database.clone();
            record.pg_auth = progress.pg_auth;
            record.bytes_in = progress.caller_to_server;
            record.bytes_out = progress.server_to_caller;
            record.ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
            match &result {
                Ok(()) => record.outcome = Outcome::Ok,
                Err(error) => {
                    record.outcome = if progress.contacted {
                        Outcome::Failed
                    } else {
                        Outcome::Refused
                    };
                    record.code = Some(error.code().as_str());
                }
            }
            self.audit.record(&record).map_err(|_| {
                BrokerError::new(ErrorCode::Internal, "could not write the audit record")
            })?;
        }
        result
    }

    /// `Err(None)` is a relay that ended badly after the login; its error is in the
    /// progress, since the caller can no longer be told in Postgres terms.
    async fn drive<C>(
        &mut self,
        caller: &mut C,
        progress: &mut Progress,
    ) -> Result<(), Option<Refusal>>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let startup = match self.preamble(caller).await? {
            Preamble::Cancel(packet) => {
                progress.cancel = true;
                return self.cancel(&packet, progress).await.map_err(Some);
            }
            Preamble::Startup(startup) => startup,
            Preamble::SslRequest | Preamble::GssEncRequest => {
                return Err(Some(Refusal::new(
                    ErrorCode::BadRequest,
                    "08P01",
                    "too many encryption requests",
                )));
            }
        };
        let startup = self.check_startup(&startup, progress).map_err(Some)?;

        progress.contacted = true;
        let (mut server, end_point, _permit) = self.open_server().await.map_err(Some)?;
        write(&mut server, &startup.encode()).await.map_err(|()| {
            Some(Refusal::new(
                ErrorCode::UpstreamReset,
                "08006",
                "the server closed",
            ))
        })?;
        let password = self.password.take();
        let credentials = Credentials {
            user: &self.user,
            password: password.as_deref().map(Vec::as_slice),
            allow_md5: self.allow_md5,
            allow_cleartext: self.allow_cleartext,
            client_cert: self.client_cert.is_some(),
            end_point,
        };
        // The login has the deadline the connection had: a server that goes quiet
        // after the handshake would otherwise hold this session for as long as it likes.
        let outcome = tokio::time::timeout(
            self.connect_timeout,
            login::login(&mut server, &credentials),
        )
        .await
        .unwrap_or_else(|_| {
            Err(LoginFailed {
                error: BrokerError::new(
                    ErrorCode::UpstreamTimeout,
                    "the server did not finish the login in time",
                ),
                sqlstate: "08006".to_owned(),
            })
        });
        drop(password);
        self.client_cert = None;
        let (method, before_ok) = outcome.map_err(|LoginFailed { error, sqlstate }| {
            let sqlstate = if error.code() == ErrorCode::PgAuthFailed && valid_state(&sqlstate) {
                sqlstate
            } else {
                "08006".to_owned()
            };
            Some(Refusal {
                error,
                sqlstate,
                message: "authentication failed",
            })
        })?;
        progress.pg_auth = Some(method.as_str());

        let mut hello = before_ok;
        hello.extend_from_slice(&wire::authentication_ok());
        write(caller, &hello).await.map_err(|()| {
            Some(Refusal::new(
                ErrorCode::BadRequest,
                "08006",
                "the caller closed",
            ))
        })?;
        let relayed = relay(caller, server, self.relay).await;
        progress.caller_to_server = relayed.caller_to_server;
        progress.server_to_caller = relayed.server_to_caller + hello.len() as u64;
        progress.failure = relayed.result.err();
        Err(None)
    }

    async fn preamble<C: AsyncRead + AsyncWrite + Unpin>(
        &self,
        caller: &mut C,
    ) -> Result<Preamble, Option<Refusal>> {
        for _ in 0..=MAX_ENCRYPTION_REQUESTS {
            let preamble = tokio::time::timeout(self.relay.idle, wire::read_preamble(caller))
                .await
                .map_err(|_| {
                    Some(Refusal::new(
                        ErrorCode::UpstreamTimeout,
                        "08P01",
                        "the caller sent nothing",
                    ))
                })?
                .map_err(|error| {
                    Some(Refusal {
                        error,
                        sqlstate: "08P01".to_owned(),
                        message: "the first packet is not valid",
                    })
                })?;
            match preamble {
                // seal offers neither: the caller goes on without.
                Preamble::SslRequest | Preamble::GssEncRequest => {
                    write(caller, b"N").await.map_err(|()| None)?;
                }
                other => return Ok(other),
            }
        }
        Ok(Preamble::SslRequest)
    }

    /// The caller's user must be the policy's, and its database one the policy
    /// allows. Returns the startup to send to the server.
    fn check_startup(
        &self,
        startup: &Startup,
        progress: &mut Progress,
    ) -> Result<Startup, Refusal> {
        if startup.param("user") != Some(self.user.as_str()) {
            return Err(Refusal::new(
                ErrorCode::PolicyDenied,
                "28000",
                "this user is not allowed",
            ));
        }
        let database = startup.param("database").unwrap_or(&self.user).to_owned();
        progress.database = Some(database.clone());
        if !self.databases.contains(&database) {
            return Err(Refusal::new(
                ErrorCode::PolicyDenied,
                "3D000",
                "this database is not allowed",
            ));
        }
        let replication = startup.param("replication").is_some_and(|value| {
            !matches!(
                value.to_ascii_lowercase().as_str(),
                "false" | "off" | "no" | "0"
            )
        });
        if replication && !self.allow_replication {
            return Err(Refusal::new(
                ErrorCode::PolicyDenied,
                "28000",
                "replication is not allowed",
            ));
        }
        let mut params: Vec<(String, String)> = startup
            .params
            .iter()
            .filter(|(name, _)| name != "database")
            .cloned()
            .collect();
        params.push(("database".to_owned(), database));
        Ok(Startup {
            version: startup.version,
            params,
        })
    }

    async fn cancel(&self, packet: &[u8], progress: &mut Progress) -> Result<(), Refusal> {
        progress.contacted = true;
        let (mut server, _, _permit) = self.open_server().await?;
        progress.caller_to_server = packet.len() as u64;
        write(&mut server, packet)
            .await
            .map_err(|()| Refusal::new(ErrorCode::UpstreamReset, "08006", "the server closed"))?;
        // The server closes once it has the request.
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(self.connect_timeout, server.read_to_end(&mut rest)).await;
        Ok(())
    }

    /// Connects to a checked address, asks for TLS, and verifies the server. Returns
    /// the stream and the channel binding data from the server's certificate.
    #[allow(clippy::type_complexity)]
    async fn open_server(
        &self,
    ) -> Result<
        (
            TlsStream<tokio::net::TcpStream>,
            Option<Vec<u8>>,
            tokio::sync::OwnedSemaphorePermit,
        ),
        Refusal,
    > {
        let unreachable = |error: BrokerError| Refusal {
            error,
            sqlstate: "08001".to_owned(),
            message: "could not connect to the server",
        };
        let addresses = tokio::time::timeout(
            self.connect_timeout,
            self.client
                .permitted_host_addresses(&self.host, self.port, self.allow_private),
        )
        .await
        .map_err(|_| {
            unreachable(BrokerError::new(
                ErrorCode::UpstreamTimeout,
                "resolving timed out",
            ))
        })?
        .map_err(unreachable)?;
        let (mut stream, permit) = self.connect_any(&addresses).await.map_err(unreachable)?;

        // Ask for TLS, and read exactly the one byte of the answer: anything sent before
        // the handshake would not be protected by it.
        write(&mut stream, &wire::ssl_request())
            .await
            .map_err(|()| {
                unreachable(BrokerError::new(
                    ErrorCode::UpstreamConnect,
                    "the server closed",
                ))
            })?;
        let answer = tokio::time::timeout(self.connect_timeout, stream.read_u8())
            .await
            .map_err(|_| {
                unreachable(BrokerError::new(
                    ErrorCode::UpstreamTimeout,
                    "the server did not answer",
                ))
            })?
            .map_err(|_| {
                unreachable(BrokerError::new(
                    ErrorCode::UpstreamConnect,
                    "the server closed",
                ))
            })?;
        if answer != b'S' {
            return Err(unreachable(BrokerError::new(
                ErrorCode::UpstreamTls,
                "the server does not offer TLS",
            )));
        }
        let (connector, name) = self.tls_connector().map_err(unreachable)?;
        let stream = tokio::time::timeout(self.connect_timeout, connector.connect(name, stream))
            .await
            .map_err(|_| {
                unreachable(BrokerError::new(
                    ErrorCode::UpstreamTimeout,
                    "TLS timed out",
                ))
            })?
            .map_err(|_| unreachable(BrokerError::new(ErrorCode::UpstreamTls, "TLS failed")))?;
        let end_point = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .and_then(|certificate| login::tls_server_end_point(certificate.as_ref()));
        // The connection's permit lives as long as the session holds it.
        Ok((stream, end_point, permit))
    }

    async fn connect_any(
        &self,
        addresses: &[SocketAddr],
    ) -> Result<(tokio::net::TcpStream, tokio::sync::OwnedSemaphorePermit), BrokerError> {
        let mut last = BrokerError::new(ErrorCode::UpstreamConnect, "could not connect");
        for address in addresses {
            match self
                .client
                .connect_counted(*address, self.connect_timeout)
                .await
            {
                Ok(connected) => return Ok(connected),
                Err(error) if error.code() == ErrorCode::LimitExceeded => return Err(error),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    fn tls_connector(&self) -> Result<(TlsConnector, ServerName<'static>), BrokerError> {
        let failed = |detail| BrokerError::new(ErrorCode::BadRequest, detail);
        let mut roots = match &self.tls {
            PgTls::VerifyFull => (*self.client.roots()).clone(),
            PgTls::Ca(pem) => {
                let mut roots = RootCertStore::empty();
                for certificate in CertificateDer::pem_slice_iter(pem.as_bytes()) {
                    let certificate =
                        certificate.map_err(|_| failed("the rule's CA is not valid PEM"))?;
                    roots
                        .add(certificate)
                        .map_err(|_| failed("the rule's CA is not valid"))?;
                }
                roots
            }
        };
        let mut name = self
            .host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        if let Some(material) = &self.client_cert {
            for certificate in &material.ca {
                roots
                    .add(certificate.clone())
                    .map_err(|_| failed("the rule's CA is not valid"))?;
            }
            if let Some(server_name) = &material.server_name {
                name.clone_from(server_name);
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| BrokerError::new(ErrorCode::Internal, "could not configure TLS"))?
            .with_root_certificates(roots);
        let mut config = match &self.client_cert {
            Some(material) => builder
                .with_client_auth_cert(material.chain.clone(), material.key.clone_key())
                .map_err(|_| {
                    BrokerError::for_field(
                        ErrorCode::BadRequest,
                        "the client certificate and key cannot be used for TLS",
                        &material.field,
                    )
                })?,
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![b"postgresql".to_vec()];
        let name = ServerName::try_from(name)
            .map_err(|_| failed("the host is not a valid server name"))?;
        Ok((TlsConnector::from(Arc::new(config)), name))
    }
}

async fn write<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<(), ()> {
    stream.write_all(bytes).await.map_err(|_| ())?;
    stream.flush().await.map_err(|_| ())
}

fn valid_state(state: &str) -> bool {
    state.len() == 5 && state.bytes().all(|b| b.is_ascii_alphanumeric())
}
