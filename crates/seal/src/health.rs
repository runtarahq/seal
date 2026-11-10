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
const READINESS_LASTS: Duration = Duration::from_secs(5);

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

/// Serves the endpoints. `/readyz` is ready when the key source answers.
///
/// # Errors
///
/// Returns an error if the address cannot be bound.
pub async fn serve(
    address: SocketAddr,
    metrics: PrometheusHandle,
    source: Arc<dyn KeySource>,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(address).await?;
    let local = listener.local_addr()?;
    let readiness = Arc::new(Readiness::new(source));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (metrics, readiness) = (metrics.clone(), Arc::clone(&readiness));
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let (metrics, readiness) = (metrics.clone(), Arc::clone(&readiness));
                    async move {
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
}
