//! `/metrics`, `/healthz` and `/readyz`, on their own address. Metrics carry no keyset or
//! item labels, so they reveal nothing about tenants.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use seal_format::KeysetId;
use seal_keys::KeySource;
use tokio::net::TcpListener;
use tokio::time::Instant;

/// Installs the metrics recorder for the process. Call once.
///
/// # Errors
///
/// Returns an error if a recorder is already installed.
pub fn install_recorder() -> Result<PrometheusHandle, String> {
    PrometheusBuilder::new()
        .install_recorder()
        .map_err(|_| "a metrics recorder is already installed".to_owned())
}

/// How long an answer from the key source stands for. The listener has no
/// authentication, so without this every request to `/readyz` would be a request to
/// the key source, for anyone who can reach the address.
pub const READINESS_LASTS: Duration = Duration::from_secs(5);

/// Whether the key source answers, asked at most once in [`READINESS_LASTS`].
pub struct Readiness {
    source: Arc<dyn KeySource>,
    last: tokio::sync::Mutex<Option<(Instant, bool)>>,
}

impl Readiness {
    /// Readiness of this key source.
    #[must_use]
    pub fn new(source: Arc<dyn KeySource>) -> Self {
        Self {
            source,
            last: tokio::sync::Mutex::new(None),
        }
    }

    /// Whether the key source answered, now or within [`READINESS_LASTS`]. Concurrent
    /// probes wait for one answer.
    pub async fn is_ready(&self) -> bool {
        let mut last = self.last.lock().await;
        if let Some((at, is_ready)) = *last
            && at.elapsed() < READINESS_LASTS
        {
            return is_ready;
        }
        // A keyset nobody can create, so the probe never loads real keys.
        let probe =
            KeysetId::new("seal-readyz-probe").unwrap_or_else(|_| unreachable!("a valid id"));
        let answer =
            tokio::time::timeout(Duration::from_secs(5), self.source.wrapped_keys(&probe)).await;
        let is_ready = matches!(answer, Ok(Ok(_)));
        *last = Some((Instant::now(), is_ready));
        is_ready
    }
}

/// The shortest bearer token the listener accepts as its own.
pub const MIN_TOKEN_BYTES: usize = 16;

/// The bearer token every request must present, read from a file that only seal's
/// user can read. Surrounding whitespace is not part of it.
///
/// # Errors
///
/// Returns a message if the file cannot be read, is open to others, or holds a token
/// that is too short or not printable ASCII.
pub fn read_token(path: &std::path::Path) -> Result<Arc<str>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata =
            std::fs::metadata(path).map_err(|_| format!("cannot read {}", path.display()))?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{} is accessible to its group or others",
                path.display()
            ));
        }
    }
    let text =
        std::fs::read_to_string(path).map_err(|_| format!("cannot read {}", path.display()))?;
    let token = text.trim();
    if token.len() < MIN_TOKEN_BYTES || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(format!(
            "{} must hold at least {MIN_TOKEN_BYTES} printable characters",
            path.display()
        ));
    }
    Ok(Arc::from(token))
}

/// Whether a request presents the token, compared without stopping at the first
/// difference.
fn presents(request: &Request<Incoming>, token: &str) -> bool {
    let Some(presented) = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.as_bytes().strip_prefix(b"Bearer "))
    else {
        return false;
    };
    presented.len() == token.len()
        && presented
            .iter()
            .zip(token.as_bytes())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// Serves the endpoints. `/readyz` is ready when the key source answers. With a
/// token, every request must present it as `Authorization: Bearer`.
///
/// # Errors
///
/// Returns an error if the address cannot be bound.
pub async fn serve(
    address: SocketAddr,
    metrics: PrometheusHandle,
    source: Arc<dyn KeySource>,
    token: Option<Arc<str>>,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(address).await?;
    let local = listener.local_addr()?;
    let readiness = Arc::new(Readiness::new(source));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (metrics, readiness, token) =
                (metrics.clone(), Arc::clone(&readiness), token.clone());
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let (metrics, readiness, token) =
                        (metrics.clone(), Arc::clone(&readiness), token.clone());
                    async move {
                        if token.is_some_and(|token| !presents(&request, &token)) {
                            let mut refused = Response::new(Full::new(Bytes::new()));
                            *refused.status_mut() = StatusCode::UNAUTHORIZED;
                            return Ok(refused);
                        }
                        Ok::<_, Infallible>(
                            respond(request.uri().path(), &metrics, &readiness).await,
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok(local)
}

async fn respond(
    path: &str,
    metrics: &PrometheusHandle,
    readiness: &Readiness,
) -> Response<Full<Bytes>> {
    let (status, body) = match path {
        "/metrics" => (StatusCode::OK, metrics.render()),
        "/healthz" => (StatusCode::OK, "ok\n".to_owned()),
        "/readyz" => {
            if readiness.is_ready().await {
                (StatusCode::OK, "ready\n".to_owned())
            } else {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the key source does not answer\n".to_owned(),
                )
            }
        }
        _ => (StatusCode::NOT_FOUND, String::new()),
    };
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use seal_keys::{KeyError, WrappedKey};

    use super::*;

    #[derive(Default)]
    struct Counting {
        asked: AtomicUsize,
        down: AtomicBool,
    }

    #[async_trait]
    impl KeySource for Counting {
        async fn wrapped_keys(&self, _: &KeysetId) -> Result<Vec<WrappedKey>, KeyError> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                Err(KeyError::Unavailable)
            } else {
                Ok(Vec::new())
            }
        }

        async fn store(&self, _: &WrappedKey) -> Result<(), KeyError> {
            Err(KeyError::Unsupported)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn probes_reach_the_key_source_once_in_a_while() {
        let source = Arc::new(Counting::default());
        let readiness = Readiness::new(Arc::clone(&source) as Arc<dyn KeySource>);
        for _ in 0..100 {
            assert!(readiness.is_ready().await);
        }
        assert_eq!(source.asked.load(Ordering::SeqCst), 1);

        // An answer goes stale, and a source that stopped answering is noticed.
        source.down.store(true, Ordering::SeqCst);
        tokio::time::advance(READINESS_LASTS).await;
        for _ in 0..100 {
            assert!(!readiness.is_ready().await);
        }
        assert_eq!(source.asked.load(Ordering::SeqCst), 2);
    }

    async fn status(address: SocketAddr, path: &str, authorization: Option<&str>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let header = authorization
            .map(|value| format!("authorization: {value}\r\n"))
            .unwrap_or_default();
        let request =
            format!("GET {path} HTTP/1.1\r\nhost: seal\r\n{header}connection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response.lines().next().unwrap().to_owned()
    }

    #[tokio::test]
    async fn with_a_token_every_endpoint_needs_it() {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let source = Arc::new(Counting::default());
        let token: Arc<str> = Arc::from("a-token-of-enough-length");
        let address = serve(
            "127.0.0.1:0".parse().unwrap(),
            handle,
            Arc::clone(&source) as Arc<dyn KeySource>,
            Some(token),
        )
        .await
        .unwrap();
        for path in ["/metrics", "/healthz", "/readyz", "/other"] {
            for wrong in [
                None,
                Some("Bearer a-token-of-enough-lengtx"),
                Some("Bearer a-token-of-enough-length-and-more"),
                Some("Bearer "),
                Some("a-token-of-enough-length"),
                Some("Basic a-token-of-enough-length"),
            ] {
                assert!(
                    status(address, path, wrong).await.contains("401"),
                    "{path} {wrong:?}"
                );
            }
        }
        assert_eq!(
            source.asked.load(Ordering::SeqCst),
            0,
            "a refused probe reaches nothing"
        );
        let right = Some("Bearer a-token-of-enough-length");
        assert!(status(address, "/healthz", right).await.contains("200"));
        assert!(status(address, "/readyz", right).await.contains("200"));
        assert!(status(address, "/metrics", right).await.contains("200"));
    }

    #[tokio::test]
    async fn without_a_token_the_endpoints_are_open() {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let source = Arc::new(Counting::default()) as Arc<dyn KeySource>;
        let address = serve("127.0.0.1:0".parse().unwrap(), handle, source, None)
            .await
            .unwrap();
        assert!(status(address, "/healthz", None).await.contains("200"));
    }

    #[cfg(unix)]
    #[test]
    fn a_token_file_must_be_private_and_long_enough() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        let write = |contents: &str, mode: u32| {
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        write("a-token-of-enough-length\n", 0o600);
        assert_eq!(&*read_token(&path).unwrap(), "a-token-of-enough-length");
        write("a-token-of-enough-length\n", 0o640);
        assert!(read_token(&path).is_err());
        write("short\n", 0o600);
        assert!(read_token(&path).is_err());
        write("a token with spaces in it\n", 0o600);
        assert!(read_token(&path).is_err());
        assert!(read_token(&directory.path().join("missing")).is_err());
    }
}
