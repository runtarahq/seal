//! A provider to test against, over plain HTTP or TLS with a test CA.
//!
//! It records what it receives, so that a test can assert on what a provider really
//! saw, and has endpoints for the awkward cases:
//!
//! | Path | Behaviour |
//! |---|---|
//! | `/echo…` | Returns what it received, as JSON |
//! | `/quiet…` | Records what it received, and returns nothing of it |
//! | `/redirect` | 302 to `/echo` |
//! | `/zeros/<n>` | Streams `n` zero bytes |
//! | `/sink` | Reads the body, and returns its length as `{"bytes":n}` |
//! | `/hold` | Never responds |
//! | `/stall` | Sends a head and some body, then nothing |
//! | `/json-stall/<n>` | Sends a JSON head and `n` bytes, then nothing |
//! | `/trickle` | Sends a byte now and then, forever |
//! | `/reset` | Sends a head and some body, then breaks the connection |
//! | anything set with [`MockProvider::respond`] | That response |
//! | anything under a prefix set with [`MockProvider::handle`] | What the handler returns |

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body::{Body, Frame};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::{Interval, Sleep, interval, sleep};
use tokio_rustls::TlsAcceptor;

use crate::pki::TestPki;

type MockBody = BoxBody<Bytes, std::io::Error>;

/// The host name a TLS provider has a certificate for.
pub const TLS_HOST: &str = "provider.test";

/// What the provider received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    /// The method.
    pub method: String,
    /// The path and query.
    pub uri: String,
    /// The HTTP version, as debug text.
    pub version: String,
    /// The headers, with lowercase names.
    pub headers: Vec<(String, String)>,
    /// The body, up to 1 MiB.
    pub body: Vec<u8>,
}

impl Received {
    /// A header's value.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A response set with [`MockProvider::respond`].
#[derive(Clone, Debug)]
pub struct CannedResponse {
    /// The status.
    pub status: u16,
    /// The headers.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl CannedResponse {
    /// A 200 response with this content type and body.
    #[must_use]
    pub fn ok(content_type: &str, body: &[u8]) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".to_owned(), content_type.to_owned())],
            body: body.to_vec(),
        }
    }
}

/// Answers the requests under a path prefix. Set with [`MockProvider::handle`].
pub type Handler = Arc<dyn Fn(&Received) -> CannedResponse + Send + Sync>;

#[derive(Default)]
struct State {
    received: Mutex<Vec<Received>>,
    canned: Mutex<HashMap<String, CannedResponse>>,
    handlers: Mutex<Vec<(String, Handler)>>,
    connections: AtomicU64,
    /// How many connections have ended.
    closed: AtomicU64,
    /// The client certificate each TLS connection presented, in DER, in order.
    client_certificates: Mutex<Vec<Option<Vec<u8>>>>,
    /// How many handlers or response bodies were dropped before they finished.
    cancelled: AtomicU64,
}

/// A running provider. Stops when dropped.
pub struct MockProvider {
    address: SocketAddr,
    ca_der: Option<CertificateDer<'static>>,
    state: Arc<State>,
    task: JoinHandle<()>,
}

impl Drop for MockProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Which protocols a TLS provider offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alpn {
    /// HTTP/2 and HTTP/1.1, preferring HTTP/2.
    Both,
    /// HTTP/1.1 only.
    Http1,
}

impl MockProvider {
    /// Starts a provider over plain HTTP, on a loopback port.
    ///
    /// # Panics
    ///
    /// Panics if it cannot listen, which only a broken test environment causes.
    pub async fn plain() -> Self {
        Self::start(None, None).await
    }

    /// Starts a provider over TLS, with a certificate for [`TLS_HOST`] from a new CA.
    ///
    /// # Panics
    ///
    /// Panics if it cannot listen or make certificates.
    pub async fn tls(alpn: Alpn) -> Self {
        let pki = TestPki::new("seal test CA");
        Self::tls_with(&pki, alpn, &[TLS_HOST], None).await
    }

    /// Starts a provider over TLS, with a certificate from `pki` for `names`. With
    /// `client_ca`, it requires a client certificate issued by that CA.
    ///
    /// # Panics
    ///
    /// Panics if it cannot listen or make certificates.
    pub async fn tls_with(
        pki: &TestPki,
        alpn: Alpn,
        names: &[&str],
        client_ca: Option<&CertificateDer<'static>>,
    ) -> Self {
        let server = pki.server(names);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|_| unreachable!("protocol versions"));
        let builder = match client_ca {
            None => builder.with_no_client_auth(),
            Some(ca) => {
                let mut roots = rustls::RootCertStore::empty();
                roots
                    .add(ca.clone())
                    .unwrap_or_else(|_| unreachable!("a test CA"));
                let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    provider,
                )
                .build()
                .unwrap_or_else(|_| unreachable!("a client verifier"));
                builder.with_client_cert_verifier(verifier)
            }
        };
        let mut config = builder
            .with_single_cert(vec![server.cert_der.clone()], server.key_der())
            .unwrap_or_else(|_| unreachable!("a test certificate"));
        config.alpn_protocols = match alpn {
            Alpn::Both => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Alpn::Http1 => vec![b"http/1.1".to_vec()],
        };
        Self::start(
            Some(TlsAcceptor::from(Arc::new(config))),
            Some(pki.ca_der.clone()),
        )
        .await
    }

    async fn start(acceptor: Option<TlsAcceptor>, ca_der: Option<CertificateDer<'static>>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|_| unreachable!("binding a loopback port"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|_| unreachable!("a bound socket has an address"));
        let state = Arc::new(State::default());
        let task = tokio::spawn(accept_loop(listener, acceptor, Arc::clone(&state)));
        Self {
            address,
            ca_der,
            state,
            task,
        }
    }

    /// The address it listens on.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The port it listens on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.address.port()
    }

    /// The CA to trust, for a TLS provider.
    #[must_use]
    pub fn ca(&self) -> Option<CertificateDer<'static>> {
        self.ca_der.clone()
    }

    /// Sets the response for a path.
    pub fn respond(&self, path: &str, response: CannedResponse) {
        self.state
            .canned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(path.to_owned(), response);
    }

    /// Answers every path that starts with `prefix` with what `handler` returns.
    pub fn handle(&self, prefix: &str, handler: Handler) {
        self.state
            .handlers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((prefix.to_owned(), handler));
    }

    /// Everything received so far.
    #[must_use]
    pub fn received(&self) -> Vec<Received> {
        self.state
            .received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many connections have been accepted.
    #[must_use]
    pub fn connections(&self) -> u64 {
        self.state.connections.load(Ordering::SeqCst)
    }

    /// How many accepted connections are still open.
    #[must_use]
    pub fn open_connections(&self) -> u64 {
        self.connections() - self.state.closed.load(Ordering::SeqCst)
    }

    /// The client certificate each TLS connection presented, in DER, in order.
    #[must_use]
    pub fn client_certificates(&self) -> Vec<Option<Vec<u8>>> {
        self.state
            .client_certificates
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many handlers or response bodies were dropped before they finished.
    #[must_use]
    pub fn cancelled(&self) -> u64 {
        self.state.cancelled.load(Ordering::SeqCst)
    }
}

async fn accept_loop(listener: TcpListener, acceptor: Option<TlsAcceptor>, state: Arc<State>) {
    while let Ok((stream, _)) = listener.accept().await {
        state.connections.fetch_add(1, Ordering::SeqCst);
        let state = Arc::clone(&state);
        let closing = Arc::clone(&state);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(handle(request, state).await) }
            });
            let builder = auto::Builder::new(TokioExecutor::new());
            match acceptor {
                None => {
                    let _ = builder
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                }
                Some(acceptor) => {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        let presented = stream
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|chain| chain.first())
                            .map(|certificate| certificate.as_ref().to_vec());
                        closing
                            .client_certificates
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(presented);
                        let _ = builder
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    }
                }
            }
            closing.closed.fetch_add(1, Ordering::SeqCst);
        });
    }
}

/// Counts a cancellation unless it is disarmed first.
struct CancelGuard {
    state: Arc<State>,
    armed: bool,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if self.armed {
            self.state.cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

async fn handle(request: Request<Incoming>, state: Arc<State>) -> Response<MockBody> {
    let path = request.uri().path().to_owned();
    if path == "/sink" {
        return sink(request).await;
    }
    if let Some(count) = path.strip_prefix("/json-stall/") {
        let count: u64 = count.parse().unwrap_or(0);
        let mut response = with_body(
            StatusCode::OK,
            Streamed::zeros_then_stall(count, Arc::clone(&state)),
        );
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        return response;
    }
    if let Some(count) = path.strip_prefix("/zeros/") {
        let count: u64 = count.parse().unwrap_or(0);
        return with_body(StatusCode::OK, Streamed::zeros(count, Arc::clone(&state)));
    }

    let (parts, body) = request.into_parts();
    // Read in full, so that echoing shows what really arrived.
    let body = match body.collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => return empty(StatusCode::BAD_REQUEST),
    };
    let uri = parts
        .uri
        .path_and_query()
        .map_or_else(|| path.clone(), ToString::to_string);
    let received = Received {
        method: parts.method.to_string(),
        uri,
        version: format!("{:?}", parts.version),
        headers: parts
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: body.to_vec(),
    };
    state
        .received
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(received.clone());

    let canned = state
        .canned
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&path)
        .cloned();
    if let Some(canned) = canned {
        return canned_response(&canned);
    }
    let handler = state
        .handlers
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .find(|(prefix, _)| path.starts_with(prefix.as_str()))
        .map(|(_, handler)| Arc::clone(handler));
    if let Some(handler) = handler {
        return canned_response(&handler(&received));
    }

    match path.as_str() {
        "/redirect" => {
            let mut response = empty(StatusCode::FOUND);
            response
                .headers_mut()
                .insert(header::LOCATION, http::HeaderValue::from_static("/echo"));
            response
        }
        "/hold" => {
            let _guard = CancelGuard {
                state: Arc::clone(&state),
                armed: true,
            };
            std::future::pending::<()>().await;
            empty(StatusCode::OK)
        }
        "/stall" => with_body(StatusCode::OK, Streamed::stall(Arc::clone(&state))),
        "/trickle" => with_body(StatusCode::OK, Streamed::trickle(Arc::clone(&state))),
        "/reset" => with_body(StatusCode::OK, Streamed::reset(Arc::clone(&state))),
        _ if path.starts_with("/echo") => echo(&received),
        _ if path.starts_with("/quiet") => empty(StatusCode::OK),
        _ => empty(StatusCode::NOT_FOUND),
    }
}

async fn sink(request: Request<Incoming>) -> Response<MockBody> {
    let mut body = request.into_body();
    let mut bytes = 0_u64;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Some(data) = frame.data_ref() {
                    bytes += data.len() as u64;
                }
            }
            Err(_) => return empty(StatusCode::BAD_REQUEST),
        }
    }
    let mut response = with_full(
        StatusCode::OK,
        format!("{{\"bytes\":{bytes}}}").into_bytes(),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    response
}

fn echo(received: &Received) -> Response<MockBody> {
    let json = serde_json::json!({
        "method": received.method,
        "uri": received.uri,
        "version": received.version,
        "headers": received.headers,
        "body": String::from_utf8_lossy(&received.body),
    });
    let mut response = with_full(StatusCode::OK, json.to_string().into_bytes());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    response
}

fn canned_response(canned: &CannedResponse) -> Response<MockBody> {
    let status = StatusCode::from_u16(canned.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = with_full(status, canned.body.clone());
    for (name, value) in &canned.headers {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            response.headers_mut().append(name, value);
        }
    }
    response
}

fn empty(status: StatusCode) -> Response<MockBody> {
    let mut response = Response::new(
        Empty::new()
            .map_err(|never: Infallible| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response
}

fn with_full(status: StatusCode, body: Vec<u8>) -> Response<MockBody> {
    let mut response = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never: Infallible| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response
}

fn with_body(status: StatusCode, body: Streamed) -> Response<MockBody> {
    let mut response = Response::new(body.boxed());
    *response.status_mut() = status;
    response
}

enum Behaviour {
    Zeros {
        remaining: u64,
    },
    /// Some bytes, then a timer that never fires in a test's lifetime.
    Stall {
        sent: bool,
        wait: Pin<Box<Sleep>>,
    },
    /// Zeros, then a timer that never fires in a test's lifetime.
    ZerosThenStall {
        remaining: u64,
        wait: Pin<Box<Sleep>>,
    },
    Trickle {
        tick: Interval,
    },
    /// Some bytes, a pause so that they reach the client, then a broken connection.
    Reset {
        sent: bool,
        wait: Pin<Box<Sleep>>,
    },
}

/// A response body that streams without holding anything in memory, and counts a
/// cancellation if it is dropped before it finishes.
struct Streamed {
    behaviour: Behaviour,
    guard: CancelGuard,
}

const ZERO_CHUNK: usize = 64 * 1024;
static ZEROS: [u8; ZERO_CHUNK] = [0; ZERO_CHUNK];

impl Streamed {
    fn new(behaviour: Behaviour, state: Arc<State>) -> Self {
        Self {
            behaviour,
            guard: CancelGuard { state, armed: true },
        }
    }

    fn zeros(remaining: u64, state: Arc<State>) -> Self {
        Self::new(Behaviour::Zeros { remaining }, state)
    }

    fn zeros_then_stall(remaining: u64, state: Arc<State>) -> Self {
        Self::new(
            Behaviour::ZerosThenStall {
                remaining,
                wait: Box::pin(sleep(Duration::from_secs(86_400))),
            },
            state,
        )
    }

    fn stall(state: Arc<State>) -> Self {
        Self::new(
            Behaviour::Stall {
                sent: false,
                wait: Box::pin(sleep(Duration::from_secs(86_400))),
            },
            state,
        )
    }

    fn trickle(state: Arc<State>) -> Self {
        Self::new(
            Behaviour::Trickle {
                tick: interval(Duration::from_millis(20)),
            },
            state,
        )
    }

    fn reset(state: Arc<State>) -> Self {
        Self::new(
            Behaviour::Reset {
                sent: false,
                wait: Box::pin(sleep(Duration::from_millis(50))),
            },
            state,
        )
    }
}

impl Body for Streamed {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let this = self.get_mut();
        let some_bytes = || Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"partial")))));
        match &mut this.behaviour {
            Behaviour::Zeros { remaining } => {
                if *remaining == 0 {
                    this.guard.armed = false;
                    return Poll::Ready(None);
                }
                let size = (*remaining).min(ZERO_CHUNK as u64);
                *remaining -= size;
                let slice = &ZEROS[..usize::try_from(size).unwrap_or(ZERO_CHUNK)];
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(slice)))))
            }
            Behaviour::ZerosThenStall { remaining, wait } => {
                if *remaining == 0 {
                    return wait.as_mut().poll(cx).map(|()| None);
                }
                let size = (*remaining).min(ZERO_CHUNK as u64);
                *remaining -= size;
                let slice = &ZEROS[..usize::try_from(size).unwrap_or(ZERO_CHUNK)];
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(slice)))))
            }
            Behaviour::Stall { sent, wait } => {
                if *sent {
                    wait.as_mut().poll(cx).map(|()| None)
                } else {
                    *sent = true;
                    some_bytes()
                }
            }
            Behaviour::Trickle { tick } => tick
                .poll_tick(cx)
                .map(|_| Some(Ok(Frame::data(Bytes::from_static(b"x"))))),
            Behaviour::Reset { sent, wait } => {
                if !*sent {
                    *sent = true;
                    return some_bytes();
                }
                match wait.as_mut().poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(()) => {
                        this.guard.armed = false;
                        Poll::Ready(Some(Err(std::io::Error::other("reset"))))
                    }
                }
            }
        }
    }
}
