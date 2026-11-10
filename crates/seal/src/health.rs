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
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (metrics, source) = (metrics.clone(), Arc::clone(&source));
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let (metrics, source) = (metrics.clone(), Arc::clone(&source));
                    async move {
                        Ok::<_, Infallible>(respond(request.uri().path(), &metrics, &*source).await)
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
    source: &dyn KeySource,
) -> Response<Full<Bytes>> {
    let (status, body) = match path {
        "/metrics" => (StatusCode::OK, metrics.render()),
        "/healthz" => (StatusCode::OK, "ok\n".to_owned()),
        "/readyz" => {
            // A keyset nobody can create, so the probe never loads real keys.
            let probe =
                KeysetId::new("seal-readyz-probe").unwrap_or_else(|_| unreachable!("a valid id"));
            match tokio::time::timeout(Duration::from_secs(5), source.wrapped_keys(&probe)).await {
                Ok(Ok(_)) => (StatusCode::OK, "ready\n".to_owned()),
                _ => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the key source does not answer\n".to_owned(),
                ),
            }
        }
        _ => (StatusCode::NOT_FOUND, String::new()),
    };
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response
}
