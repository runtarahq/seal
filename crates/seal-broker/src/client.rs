//! The HTTP client toward providers: checks addresses, connects to what it checked,
//! speaks TLS with the host's name, and keeps a bounded pool.
//!
//! Pools are keyed by `(scheme, host, port, resolved address)`, and by the client
//! certificate's identity for connections that carry one. It never follows
//! redirects, because a redirect could take a credential elsewhere, and it reads no
//! proxy settings from the environment.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use bytes::Bytes;
use http::uri::{Authority, PathAndQuery, Scheme as UriScheme};
use http::{Request, Response, Uri, Version, header};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use seal_format::policy::Scheme;
use seal_keys::LiveKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;

use crate::address::NetworkPolicy;
use crate::error::{BrokerError, ErrorCode};
use crate::identity::ClientIdentity;
use crate::net::{Connect, Resolve};
use crate::target::Target;

/// A request body. Errors end the request.
pub type RequestBody = UnsyncBoxBody<Bytes, BrokerError>;

/// How long to wait for a pooled HTTP/1.1 connection to report that it is ready.
const POOLED_READY_TIMEOUT: Duration = Duration::from_millis(100);

/// The client's limits.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// The most connections toward providers, active or idle.
    pub max_upstream_connections: usize,
    /// The most idle HTTP/1.1 connections to one address.
    pub max_idle_per_host: usize,
    /// How long a connection may stay idle.
    pub idle_timeout: Duration,
    /// How much one stream may buffer, which sets protocol buffers and windows.
    pub per_stream_buffer: u32,
    /// CAs to trust as well as the public roots, in DER.
    pub extra_roots: Vec<CertificateDer<'static>>,
    /// The most client-certificate identities with a TLS configuration in memory.
    pub max_client_cert_identities: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PoolKey {
    https: bool,
    host: String,
    address: SocketAddr,
    /// The client certificate's fingerprint, for connections that carry one.
    identity: Option<[u8; 32]>,
}

/// One client-certificate identity: its TLS configuration, held until its last
/// connection ends, with a permit that counts it against the limit.
struct IdentityState {
    connector: TlsConnector,
    server_name: Option<String>,
    sealing_key: Weak<LiveKey>,
    last_used: Mutex<Instant>,
    _permit: OwnedSemaphorePermit,
}

impl IdentityState {
    fn touch(&self) {
        *self
            .last_used
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    fn last_used(&self) -> Instant {
        *self
            .last_used
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

enum Connection {
    Http1(http1::SendRequest<RequestBody>),
    Http2(http2::SendRequest<RequestBody>),
}

#[derive(Default)]
struct PoolState {
    idle: HashMap<PoolKey, Vec<(http1::SendRequest<RequestBody>, Instant)>>,
    shared: HashMap<PoolKey, (http2::SendRequest<RequestBody>, Instant)>,
}

struct Pool {
    state: Mutex<PoolState>,
    permits: Arc<Semaphore>,
    config: ClientConfig,
    identities: Mutex<HashMap<[u8; 32], Arc<IdentityState>>>,
    identity_permits: Arc<Semaphore>,
}

impl Pool {
    fn lock(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hands back a live connection, if there is one.
    async fn take(&self, key: &PoolKey) -> Option<Connection> {
        {
            let mut state = self.lock();
            if let Some((sender, used)) = state.shared.get_mut(key) {
                if !sender.is_closed() {
                    *used = Instant::now();
                    return Some(Connection::Http2(sender.clone()));
                }
                state.shared.remove(key);
            }
        }
        loop {
            let (mut sender, used) = {
                let mut state = self.lock();
                let list = state.idle.get_mut(key)?;
                let entry = list.pop();
                if list.is_empty() {
                    state.idle.remove(key);
                }
                entry?
            };
            if sender.is_closed() || used.elapsed() >= self.config.idle_timeout {
                continue;
            }
            if matches!(
                tokio::time::timeout(POOLED_READY_TIMEOUT, sender.ready()).await,
                Ok(Ok(()))
            ) {
                return Some(Connection::Http1(sender));
            }
        }
    }

    /// Keeps a connection for reuse, if it is live and there is room.
    fn put(&self, key: PoolKey, sender: http1::SendRequest<RequestBody>) {
        if sender.is_closed() {
            return;
        }
        let mut state = self.lock();
        let list = state.idle.entry(key).or_default();
        if list.len() < self.config.max_idle_per_host {
            list.push((sender, Instant::now()));
        }
    }

    /// Closes the longest idle connection, to make room for a new one.
    fn close_oldest_idle(&self) -> bool {
        let mut state = self.lock();
        let oldest = state
            .idle
            .iter()
            .filter_map(|(key, list)| list.first().map(|(_, used)| (key.clone(), *used)))
            .min_by_key(|(_, used)| *used);
        let Some((key, _)) = oldest else {
            return false;
        };
        if let Some(list) = state.idle.get_mut(&key) {
            list.remove(0);
            if list.is_empty() {
                state.idle.remove(&key);
            }
        }
        true
    }

    fn identities(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Arc<IdentityState>>> {
        self.identities
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Forgets an identity and closes its idle connections. Active ones finish, and
    /// the identity's configuration and permit go with the last of them.
    fn forget_identity(&self, fingerprint: &[u8; 32]) {
        self.identities().remove(fingerprint);
        let mut state = self.lock();
        state
            .idle
            .retain(|key, _| key.identity.as_ref() != Some(fingerprint));
        state
            .shared
            .retain(|key, _| key.identity.as_ref() != Some(fingerprint));
    }

    /// Forgets the identity used least recently, to make room for another.
    fn forget_least_recent_identity(&self) {
        let oldest = self
            .identities()
            .iter()
            .min_by_key(|(_, state)| state.last_used())
            .map(|(fingerprint, _)| *fingerprint);
        if let Some(fingerprint) = oldest {
            self.forget_identity(&fingerprint);
        }
    }

    /// Forgets identities whose sealing key the keyring has let go, by eviction or
    /// removal, and those unused for the idle timeout.
    fn reap_identities(&self) {
        let timeout = self.config.idle_timeout;
        let stale: Vec<[u8; 32]> = self
            .identities()
            .iter()
            .filter(|(_, state)| {
                !crate::identity::is_live(&state.sealing_key)
                    || state.last_used().elapsed() >= timeout
            })
            .map(|(fingerprint, _)| *fingerprint)
            .collect();
        for fingerprint in stale {
            self.forget_identity(&fingerprint);
        }
    }

    /// Drops whatever has been idle too long, or has closed.
    fn reap(&self) {
        self.reap_identities();
        let timeout = self.config.idle_timeout;
        let mut state = self.lock();
        state.idle.retain(|_, list| {
            list.retain(|(sender, used)| !sender.is_closed() && used.elapsed() < timeout);
            !list.is_empty()
        });
        state
            .shared
            .retain(|_, (sender, used)| !sender.is_closed() && used.elapsed() < timeout);
    }

    #[cfg(test)]
    fn idle_count(&self) -> usize {
        self.lock().idle.values().map(Vec::len).sum()
    }
}

/// Returns an HTTP/1.1 connection to the pool once its response has finished.
pub struct Checkout {
    pool: Arc<Pool>,
    key: PoolKey,
    sender: Option<http1::SendRequest<RequestBody>>,
}

impl Checkout {
    /// The response finished cleanly, so the connection can be reused. Dropping a
    /// checkout without calling this closes the connection, which is how a caller
    /// going away cancels the upstream request.
    pub fn finish(mut self) {
        if let Some(sender) = self.sender.take() {
            self.pool.put(self.key.clone(), sender);
        }
    }
}

/// The client.
pub struct HttpClient {
    resolve: Arc<dyn Resolve>,
    connect: Arc<dyn Connect>,
    network: NetworkPolicy,
    tls: TlsConnector,
    /// Shared by every identity that adds no CA of its own.
    roots: Arc<RootCertStore>,
    pool: Arc<Pool>,
    /// Generated at start, so fingerprints mean nothing outside this process.
    fingerprint_key: ring::hmac::Key,
}

/// Limits for one request.
#[derive(Clone, Copy, Debug)]
pub struct ConnectLimits {
    /// How long a connection may take, including TLS.
    pub connect_timeout: Duration,
}

impl HttpClient {
    /// Creates a client. Needs a Tokio runtime, for the task that drops idle
    /// connections.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Internal`] if TLS cannot be configured.
    pub fn new(
        resolve: Arc<dyn Resolve>,
        connect: Arc<dyn Connect>,
        network: NetworkPolicy,
        config: ClientConfig,
    ) -> Result<Self, BrokerError> {
        let roots = Arc::new(root_store(&config)?);
        let tls = tls_connector(Arc::clone(&roots), None)?;
        let fingerprint_key =
            ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &ring::rand::SystemRandom::new())
                .map_err(|_| BrokerError::new(ErrorCode::Internal, "could not generate a key"))?;
        let pool = Arc::new(Pool {
            state: Mutex::new(PoolState::default()),
            permits: Arc::new(Semaphore::new(config.max_upstream_connections)),
            identities: Mutex::new(HashMap::new()),
            identity_permits: Arc::new(Semaphore::new(config.max_client_cert_identities)),
            config,
        });
        spawn_reaper(Arc::downgrade(&pool));
        Ok(Self {
            resolve,
            connect,
            network,
            tls,
            roots,
            pool,
            fingerprint_key,
        })
    }

    /// Finds the addresses a request may use, refusing if there are none.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::UpstreamConnect`] if the lookup fails, and
    /// [`ErrorCode::DestinationRefused`] if no address is permitted. Refusing makes
    /// no connection.
    pub async fn permitted_addresses(
        &self,
        target: &Target,
        allow_private: bool,
    ) -> Result<Vec<SocketAddr>, BrokerError> {
        self.permitted_host_addresses(target.bare_host(), target.port, allow_private)
            .await
    }

    /// Finds the addresses a host and port may use, as for a URL.
    ///
    /// # Errors
    ///
    /// As [`HttpClient::permitted_addresses`].
    pub async fn permitted_host_addresses(
        &self,
        host: &str,
        port: u16,
        allow_private: bool,
    ) -> Result<Vec<SocketAddr>, BrokerError> {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let addresses: Vec<IpAddr> = match bare.parse::<IpAddr>() {
            Ok(address) => vec![address],
            Err(_) => self.resolve.resolve(bare).await.map_err(|_| {
                BrokerError::new(ErrorCode::UpstreamConnect, "could not resolve host")
            })?,
        };
        let permitted: Vec<SocketAddr> = addresses
            .into_iter()
            .filter(|address| self.network.permits(*address, allow_private))
            .map(|address| SocketAddr::new(address, port))
            .collect();
        if permitted.is_empty() {
            return Err(BrokerError::new(
                ErrorCode::DestinationRefused,
                "the destination's address is refused",
            ));
        }
        Ok(permitted)
    }

    /// Sends a request to the first address that works, reusing a pooled connection
    /// if there is one.
    ///
    /// A request is only retried if it was certainly never sent: `hyper` hands it
    /// back when a pooled connection turns out to be closed. `connected` is called once
    /// a connection is ready, which is when timing the provider can start.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::UpstreamConnect`], [`ErrorCode::UpstreamTls`],
    /// [`ErrorCode::UpstreamTimeout`], [`ErrorCode::UpstreamReset`] or
    /// [`ErrorCode::LimitExceeded`].
    pub async fn send(
        &self,
        target: &Target,
        addresses: &[SocketAddr],
        request: Request<RequestBody>,
        limits: ConnectLimits,
        connected: &(dyn Fn() + Sync),
        identity: Option<ClientIdentity>,
    ) -> Result<(Response<Incoming>, Checkout), BrokerError> {
        let identity = match identity {
            Some(identity) => Some(
                self.identity_state(identity, limits.connect_timeout)
                    .await?,
            ),
            None => None,
        };
        let fingerprint = identity.as_ref().map(|(fingerprint, _)| *fingerprint);
        let identity = identity.map(|(_, state)| state);
        let mut request = request;
        for address in addresses {
            let key = PoolKey {
                https: target.scheme == Scheme::Https,
                host: target.host.clone(),
                address: *address,
                identity: fingerprint,
            };
            while let Some(connection) = self.pool.take(&key).await {
                connected();
                match self.try_send(connection, target, request, &key).await {
                    Ok(sent) => return Ok(sent),
                    Err(NotSent::Unsent(unsent)) => request = *unsent,
                    Err(NotSent::Failed(error)) => return Err(error),
                }
            }
        }

        let mut last_error = BrokerError::new(ErrorCode::UpstreamConnect, "could not connect");
        for address in addresses {
            let key = PoolKey {
                https: target.scheme == Scheme::Https,
                host: target.host.clone(),
                address: *address,
                identity: fingerprint,
            };
            match self
                .open_connection(target, *address, limits, identity.as_ref(), key.clone())
                .await
            {
                Ok(connection) => {
                    connected();
                    return match self.try_send(connection, target, request, &key).await {
                        Ok(sent) => Ok(sent),
                        Err(NotSent::Unsent(_)) => Err(BrokerError::new(
                            ErrorCode::UpstreamReset,
                            "the connection closed before the request was sent",
                        )),
                        Err(NotSent::Failed(error)) => Err(error),
                    };
                }
                Err(error) if error.code() == ErrorCode::LimitExceeded => return Err(error),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    async fn try_send(
        &self,
        connection: Connection,
        target: &Target,
        request: Request<RequestBody>,
        key: &PoolKey,
    ) -> Result<(Response<Incoming>, Checkout), NotSent> {
        let failed = |_| {
            NotSent::Failed(BrokerError::new(
                ErrorCode::BadRequest,
                "the request could not be formed",
            ))
        };
        match connection {
            Connection::Http1(mut sender) => {
                let request = for_http1(request).map_err(failed)?;
                match sender.try_send_request(request).await {
                    Ok(response) => Ok((
                        response,
                        Checkout {
                            pool: Arc::clone(&self.pool),
                            key: key.clone(),
                            sender: Some(sender),
                        },
                    )),
                    Err(mut error) => match error.take_message() {
                        Some(unsent) => Err(NotSent::Unsent(Box::new(unsent))),
                        None => Err(NotSent::Failed(upstream_error(error.error()))),
                    },
                }
            }
            Connection::Http2(mut sender) => {
                let request = for_http2(request, target).map_err(failed)?;
                match sender.try_send_request(request).await {
                    Ok(response) => Ok((
                        response,
                        Checkout {
                            pool: Arc::clone(&self.pool),
                            key: key.clone(),
                            sender: None,
                        },
                    )),
                    Err(mut error) => match error.take_message() {
                        Some(unsent) => Err(NotSent::Unsent(Box::new(unsent))),
                        None => Err(NotSent::Failed(upstream_error(error.error()))),
                    },
                }
            }
        }
    }

    /// A TCP connection to a checked address, counted against the connection limit for
    /// as long as the permit is held.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::LimitExceeded`], [`ErrorCode::UpstreamTimeout`] or
    /// [`ErrorCode::UpstreamConnect`].
    pub async fn connect_counted(
        &self,
        address: SocketAddr,
        timeout: Duration,
    ) -> Result<(tokio::net::TcpStream, OwnedSemaphorePermit), BrokerError> {
        let permit = self.connection_permit(timeout).await?;
        let stream = tokio::time::timeout(timeout, self.connect.connect(address))
            .await
            .map_err(|_| BrokerError::new(ErrorCode::UpstreamTimeout, "connecting timed out"))?
            .map_err(|_| BrokerError::new(ErrorCode::UpstreamConnect, "could not connect"))?;
        Ok((stream, permit))
    }

    /// How much one stream may buffer.
    #[must_use]
    pub fn per_stream_buffer(&self) -> usize {
        self.pool.config.per_stream_buffer as usize
    }

    /// Whether this deployment lets a Postgres rule connect with no TLS.
    #[must_use]
    pub fn allows_plaintext_postgres(&self) -> bool {
        self.network.honour_plaintext_postgres_rules
    }

    /// The roots providers are verified against: the public ones and any configured.
    #[must_use]
    pub fn roots(&self) -> Arc<RootCertStore> {
        Arc::clone(&self.roots)
    }

    /// The identity for a client certificate: the one in use if it is the same
    /// credential from the same live key, otherwise a new one in its place.
    async fn identity_state(
        &self,
        identity: ClientIdentity,
        timeout: Duration,
    ) -> Result<([u8; 32], Arc<IdentityState>), BrokerError> {
        let fingerprint = crate::identity::fingerprint(&self.fingerprint_key, &identity);
        let existing = self.pool.identities().get(&fingerprint).cloned();
        if let Some(state) = existing {
            if crate::identity::same_live_key(&state.sealing_key, &identity.sealing_key) {
                state.touch();
                return Ok((fingerprint, state));
            }
            // The same credential from a reloaded key: start again.
            self.pool.forget_identity(&fingerprint);
        }
        let permit = self.identity_permit(timeout).await?;
        let material = identity.material;
        let failed = || {
            BrokerError::for_field(
                ErrorCode::BadRequest,
                "the client certificate and key cannot be used for TLS",
                &material.field,
            )
        };
        let roots = if material.ca.is_empty() {
            Arc::clone(&self.roots)
        } else {
            let mut roots = (*self.roots).clone();
            for ca in &material.ca {
                roots.add(ca.clone()).map_err(|_| failed())?;
            }
            Arc::new(roots)
        };
        let connector = tls_connector(
            roots,
            Some((material.chain.clone(), material.key.clone_key())),
        )
        .map_err(|_| failed())?;
        let state = Arc::new(IdentityState {
            connector,
            server_name: material.server_name.clone(),
            sealing_key: identity.sealing_key,
            last_used: Mutex::new(Instant::now()),
            _permit: permit,
        });
        self.pool
            .identities()
            .insert(fingerprint, Arc::clone(&state));
        Ok((fingerprint, state))
    }

    /// An identity's permit. At the limit, forgets the least recently used identity,
    /// whose permit returns once its last connection ends, and otherwise waits.
    async fn identity_permit(
        &self,
        timeout: Duration,
    ) -> Result<OwnedSemaphorePermit, BrokerError> {
        let permits = Arc::clone(&self.pool.identity_permits);
        if let Ok(permit) = Arc::clone(&permits).try_acquire_owned() {
            return Ok(permit);
        }
        self.pool.forget_least_recent_identity();
        tokio::time::timeout(timeout, permits.acquire_owned())
            .await
            .ok()
            .and_then(Result::ok)
            .ok_or_else(|| {
                BrokerError::new(
                    ErrorCode::LimitExceeded,
                    "too many client certificate identities",
                )
            })
    }

    async fn open_connection(
        &self,
        target: &Target,
        address: SocketAddr,
        limits: ConnectLimits,
        identity: Option<&Arc<IdentityState>>,
        key: PoolKey,
    ) -> Result<Connection, BrokerError> {
        let permit = self.connection_permit(limits.connect_timeout).await?;
        let timed_out = || BrokerError::new(ErrorCode::UpstreamTimeout, "connecting timed out");
        let deadline = Instant::now() + limits.connect_timeout;

        let stream = tokio::time::timeout_at(deadline, self.connect.connect(address))
            .await
            .map_err(|_| timed_out())?
            .map_err(|_| BrokerError::new(ErrorCode::UpstreamConnect, "could not connect"))?;

        // A connection holds its identity, and so its permit, until it ends.
        let held = identity.map(Arc::clone);
        match target.scheme {
            Scheme::Http => {
                self.handshake_http1(TokioIo::new(stream), permit, held)
                    .await
            }
            Scheme::Https => {
                let (connector, name) = match identity {
                    Some(state) => (
                        &state.connector,
                        state
                            .server_name
                            .clone()
                            .unwrap_or_else(|| target.bare_host().to_owned()),
                    ),
                    None => (&self.tls, target.bare_host().to_owned()),
                };
                let name = ServerName::try_from(name).map_err(|_| {
                    BrokerError::new(ErrorCode::BadRequest, "URL host is not a valid server name")
                })?;
                let stream = tokio::time::timeout_at(deadline, connector.connect(name, stream))
                    .await
                    .map_err(|_| timed_out())?
                    .map_err(|_| BrokerError::new(ErrorCode::UpstreamTls, "TLS failed"))?;
                let negotiated_http2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                let stream = TokioIo::new(stream);
                if negotiated_http2 {
                    self.handshake_http2(stream, permit, key, held).await
                } else {
                    self.handshake_http1(stream, permit, held).await
                }
            }
        }
    }

    /// A connection's permit. At the limit, closes an idle connection to make room,
    /// and otherwise waits.
    async fn connection_permit(
        &self,
        timeout: Duration,
    ) -> Result<OwnedSemaphorePermit, BrokerError> {
        let permits = Arc::clone(&self.pool.permits);
        if let Ok(permit) = Arc::clone(&permits).try_acquire_owned() {
            return Ok(permit);
        }
        self.pool.close_oldest_idle();
        tokio::time::timeout(timeout, permits.acquire_owned())
            .await
            .ok()
            .and_then(Result::ok)
            .ok_or_else(|| {
                BrokerError::new(ErrorCode::LimitExceeded, "too many upstream connections")
            })
    }

    async fn handshake_http1<S>(
        &self,
        stream: TokioIo<S>,
        permit: OwnedSemaphorePermit,
        identity: Option<Arc<IdentityState>>,
    ) -> Result<Connection, BrokerError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let buffer = (self.pool.config.per_stream_buffer as usize).max(8192);
        let (sender, connection) = http1::Builder::new()
            .max_buf_size(buffer)
            .handshake(stream)
            .await
            .map_err(|_| BrokerError::new(ErrorCode::UpstreamConnect, "HTTP handshake failed"))?;
        tokio::spawn(async move {
            let _held = (permit, identity);
            let _ = connection.await;
        });
        Ok(Connection::Http1(sender))
    }

    async fn handshake_http2<S>(
        &self,
        stream: TokioIo<S>,
        permit: OwnedSemaphorePermit,
        key: PoolKey,
        identity: Option<Arc<IdentityState>>,
    ) -> Result<Connection, BrokerError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let window = self.pool.config.per_stream_buffer.max(65_535);
        let (sender, connection) = http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .initial_stream_window_size(window)
            .initial_connection_window_size(window.saturating_mul(16))
            .max_send_buf_size(window as usize)
            .handshake(stream)
            .await
            .map_err(|_| BrokerError::new(ErrorCode::UpstreamConnect, "HTTP handshake failed"))?;
        tokio::spawn(async move {
            let _held = (permit, identity);
            let _ = connection.await;
        });
        self.pool
            .lock()
            .shared
            .insert(key, (sender.clone(), Instant::now()));
        Ok(Connection::Http2(sender))
    }

    #[cfg(test)]
    fn pool_idle_count(&self) -> usize {
        self.pool.idle_count()
    }
}

enum NotSent {
    /// Certainly never sent, so it can go on another connection.
    Unsent(Box<Request<RequestBody>>),
    Failed(BrokerError),
}

/// HTTP/1.1 uses the origin form and a `Host` header, which is already set. The
/// request may have been prepared for HTTP/2 before it came back unsent.
fn for_http1(request: Request<RequestBody>) -> Result<Request<RequestBody>, http::Error> {
    let (mut parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    parts.uri = Uri::builder().path_and_query(path).build()?;
    parts.version = Version::HTTP_11;
    Ok(Request::from_parts(parts, body))
}

/// HTTP/2 carries the scheme and authority in the URI, not in `Host`.
fn for_http2(
    request: Request<RequestBody>,
    target: &Target,
) -> Result<Request<RequestBody>, http::Error> {
    let (mut parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    let authority = Authority::try_from(target.authority())?;
    parts.uri = Uri::builder()
        .scheme(UriScheme::HTTPS)
        .authority(authority)
        .path_and_query(path)
        .build()?;
    parts.version = Version::HTTP_2;
    parts.headers.remove(header::HOST);
    Ok(Request::from_parts(parts, body))
}

/// Maps an error to a code, keeping its kind and dropping its text.
fn upstream_error(error: &hyper::Error) -> BrokerError {
    if error.is_timeout() {
        BrokerError::new(ErrorCode::UpstreamTimeout, "the provider timed out")
    } else {
        BrokerError::new(ErrorCode::UpstreamReset, "the provider's connection failed")
    }
}

/// Maps an error from a response body. A code a body wrapper recorded takes priority.
#[must_use]
pub fn body_error(error: &hyper::Error) -> BrokerError {
    upstream_error(error)
}

fn root_store(config: &ClientConfig) -> Result<RootCertStore, BrokerError> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for root in &config.extra_roots {
        roots
            .add(root.clone())
            .map_err(|_| BrokerError::new(ErrorCode::Internal, "could not configure TLS"))?;
    }
    Ok(roots)
}

/// A connector trusting these roots, presenting a client certificate if given.
fn tls_connector(
    roots: Arc<RootCertStore>,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<TlsConnector, BrokerError> {
    let failed = || BrokerError::new(ErrorCode::Internal, "could not configure TLS");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| failed())?
        .with_root_certificates(roots);
    let mut tls = match client_auth {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .map_err(|_| failed())?,
        None => builder.with_no_client_auth(),
    };
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(tls)))
}

fn spawn_reaper(pool: Weak<Pool>) {
    tokio::spawn(async move {
        let interval = pool
            .upgrade()
            .map(|pool| pool.config.idle_timeout / 2)
            .filter(|interval| !interval.is_zero())
            .unwrap_or(Duration::from_secs(1));
        loop {
            tokio::time::sleep(interval).await;
            let Some(pool) = pool.upgrade() else {
                return;
            };
            pool.reap();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_take_the_form_each_protocol_needs() {
        let target = Target::parse("https://api.example.com:8443/a/b?c=d").unwrap();
        let body = || RequestBody::default();
        let request = Request::builder()
            .uri("/a/b?c=d")
            .header(header::HOST, "api.example.com:8443")
            .body(body())
            .unwrap();

        let http2 = for_http2(request, &target).unwrap();
        assert_eq!(
            http2.uri().to_string(),
            "https://api.example.com:8443/a/b?c=d"
        );
        assert!(!http2.headers().contains_key(header::HOST));

        let http1 = for_http1(http2).unwrap();
        assert_eq!(http1.uri().to_string(), "/a/b?c=d");
        assert_eq!(http1.version(), Version::HTTP_11);
    }

    #[tokio::test]
    async fn a_client_starts_with_nothing_idle() {
        let client = HttpClient::new(
            Arc::new(crate::net::DnsResolver::from_system().unwrap()),
            Arc::new(crate::net::TcpConnector),
            NetworkPolicy::default(),
            ClientConfig {
                max_upstream_connections: 4,
                max_idle_per_host: 2,
                idle_timeout: Duration::from_secs(1),
                per_stream_buffer: 65_536,
                extra_roots: Vec::new(),
                max_client_cert_identities: 4,
            },
        )
        .unwrap();
        assert_eq!(client.pool_idle_count(), 0);
    }
}
