//! Assembles the service from its configuration.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use seal_broker::address::NetworkPolicy;
use seal_broker::audit::AuditSink;
use seal_broker::client::ClientConfig;
use seal_broker::{Broker, BrokerConfig, Environment, Limits};
use seal_keys::{
    DirKeySource, FileKeyWrap, HttpKeySource, HttpKeySourceConfig, KeySource, KeyWrap, Keyring,
};
use seal_proto::MAX_BODY_CHUNK;
use seal_proto::v1::seal_server::SealServer;

use crate::callers::CallerMap;
use crate::config::{AuditSinkConfig, Config, SourceConfig, WrapConfig};
use crate::limits;
use crate::listen;
use crate::service::{Service, ServiceInfo, ServiceLimits};
use crate::sinks;

/// Where the service ended up listening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Listening {
    /// A Unix socket.
    Unix(PathBuf),
    /// A TCP address.
    Tcp(SocketAddr),
}

/// A key source and wrapping key.
pub type KeyParts = (Arc<dyn KeySource>, Arc<dyn KeyWrap>);

/// Builds the key source and wrapping key.
///
/// # Errors
///
/// Returns a message naming what could not be loaded.
pub fn key_parts(config: &Config) -> Result<KeyParts, String> {
    let source: Arc<dyn KeySource> = match &config.keys.source {
        SourceConfig::Dir(path) => {
            Arc::new(DirKeySource::new(path, config.keys.max_keys_per_keyset))
        }
        SourceConfig::Http { url, ca, cert, key } => {
            let read = |path: &PathBuf| {
                std::fs::read_to_string(path).map_err(|_| format!("cannot read {}", path.display()))
            };
            Arc::new(
                HttpKeySource::new(&HttpKeySourceConfig {
                    url: url.clone(),
                    ca_pem: read(ca)?,
                    cert_pem: read(cert)?,
                    key_pem: read(key)?,
                    timeout: Duration::from_secs(10),
                    max_keys: config.keys.max_keys_per_keyset,
                })
                .map_err(|error| error.to_string())?,
            )
        }
    };
    let wrap: Arc<dyn KeyWrap> = match &config.keys.wrap {
        WrapConfig::File(path) => {
            Arc::new(FileKeyWrap::from_file(path).map_err(|error| error.to_string())?)
        }
    };
    Ok((source, wrap))
}

/// The broker's settings.
///
/// # Errors
///
/// Returns a message if a CA file cannot be read.
pub fn broker_config(config: &Config) -> Result<BrokerConfig, String> {
    let parse = |cidrs: &[String]| {
        cidrs
            .iter()
            .map(|cidr| cidr.parse().map_err(|_| format!("address range {cidr:?}")))
            .collect::<Result<Vec<_>, String>>()
    };
    let mut extra_roots = Vec::new();
    for path in &config.network.extra_ca_files {
        for certificate in CertificateDer::pem_file_iter(path)
            .map_err(|_| format!("cannot read {}", path.display()))?
        {
            extra_roots.push(certificate.map_err(|_| format!("{} is not PEM", path.display()))?);
        }
    }
    let limits = &config.limits;
    Ok(BrokerConfig {
        network: NetworkPolicy {
            deny_cidrs: parse(&config.network.deny_cidrs)?,
            allow_private_cidrs: parse(&config.network.allow_private_cidrs)?,
            honour_private_rules: config.network.honour_private_rules,
        },
        client: ClientConfig {
            max_upstream_connections: config.pools.max_upstream_connections,
            max_idle_per_host: config.pools.max_idle_per_host,
            idle_timeout: config.pools.idle_timeout.0,
            per_stream_buffer: u32::try_from(limits.per_stream_buffer.0).unwrap_or(u32::MAX),
            extra_roots,
            max_client_cert_identities: config.pools.max_client_cert_identities,
        },
        limits: Limits {
            max_concurrent_buffered: limits.max_concurrent_buffered,
            buffer_cap: limits.buffer_cap.0,
            idle_timeout: limits.idle_timeout.0,
            connect_timeout: limits.connect_timeout.0,
            first_byte_timeout: limits.first_byte_timeout.0,
            buffered_total_timeout: limits.buffered_total_timeout.0,
            max_stream_duration: limits.max_stream_duration.map(|interval| interval.0),
            pg_max_session: limits.pg_max_session.0,
        },
    })
}

fn audit_sink(config: &Config) -> Result<Arc<dyn AuditSink>, String> {
    Ok(match &config.audit.sink {
        AuditSinkConfig::Stdout => Arc::new(sinks::Policy::new(
            sinks::StdoutSink,
            config.audit.on_failure,
        )),
        AuditSinkConfig::File(path) => Arc::new(sinks::Policy::new(
            sinks::FileSink::open(path).map_err(|_| format!("cannot open {}", path.display()))?,
            config.audit.on_failure,
        )),
    })
}

/// Runs the service until `shutdown` completes. Calls `listening` once it accepts.
///
/// # Errors
///
/// Returns a message if anything cannot be set up, including a memory ceiling over
/// the budget.
pub async fn run(
    config: Config,
    listening: impl FnOnce(&Listening),
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<(), String> {
    let (ceiling, _) = limits::ceiling(&config);
    if ceiling > config.limits.memory_budget.0 {
        return Err(format!(
            "the memory ceiling, {ceiling} bytes, is over limits.memory_budget; run check-config"
        ));
    }
    let (source, wrap) = key_parts(&config)?;
    let keyring = Keyring::new(Arc::clone(&source), wrap, config.keyring())
        .map_err(|error| error.to_string())?;
    let audit = audit_sink(&config)?;
    let broker = Broker::new(
        broker_config(&config)?,
        Arc::new(keyring.clone()),
        Environment::production(Arc::clone(&audit)).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let callers = Arc::new(CallerMap::new(&config.callers));
    let limits = &config.limits;
    let mode = if config.listen.unix.is_some() {
        "unix"
    } else {
        "mtls"
    };
    let service = Service::new(
        Arc::new(broker),
        keyring,
        Arc::clone(&callers),
        audit,
        ServiceLimits {
            max_concurrent_streams: limits.max_concurrent_streams,
            rate_per_caller: limits.rate_per_caller,
            rate_per_keyset: limits.rate_per_keyset,
            max_tracked_keysets: config.keys.max_tracked_keysets,
        },
        ServiceInfo {
            mode,
            buffer_cap: limits.buffer_cap.0,
        },
    );
    let max_message = usize::try_from(limits.max_head.0)
        .unwrap_or(usize::MAX)
        .max(2 * MAX_BODY_CHUNK);
    let server = SealServer::new(service)
        .max_decoding_message_size(max_message)
        .max_encoding_message_size(2 * MAX_BODY_CHUNK);
    let window = u32::try_from(limits.per_stream_buffer.0).unwrap_or(u32::MAX);
    let builder = tonic::transport::Server::builder()
        .initial_stream_window_size(window)
        .initial_connection_window_size(window.saturating_mul(4))
        .http2_keepalive_interval(Some(Duration::from_secs(30)));

    if let Some(address) = config.metrics.listen {
        let handle = crate::health::install_recorder()?;
        let local = crate::health::serve(address, handle, Arc::clone(&source))
            .await
            .map_err(|_| format!("cannot listen for metrics on {address}"))?;
        tracing::info!(address = %local, "serving metrics and health");
    }

    match (&config.listen.unix, config.listen.tcp, &config.listen.tls) {
        (Some(path), _, _) => {
            let incoming = listen::unix(path, callers, limits.max_caller_connections)
                .map_err(|_| format!("cannot listen on {}", path.display()))?;
            listening(&Listening::Unix(path.clone()));
            tracing::info!(mode, "seal is listening");
            builder
                .clone()
                .add_service(server)
                .serve_with_incoming_shutdown(incoming, shutdown)
                .await
                .map_err(|_| "the server failed".to_owned())
        }
        (None, Some(address), Some(files)) => {
            let tls = listen::ReloadingTls::load(&files.cert, &files.key, &files.client_ca)?;
            listen::spawn_reloader(&tls, config.listen.reload_interval.0);
            let (incoming, local) = listen::tcp(
                address,
                tls,
                callers,
                limits.max_caller_connections,
                limits.connect_timeout.0,
            )
            .await
            .map_err(|_| format!("cannot listen on {address}"))?;
            listening(&Listening::Tcp(local));
            tracing::info!(mode, "seal is listening");
            builder
                .clone()
                .add_service(server)
                .serve_with_incoming_shutdown(incoming, shutdown)
                .await
                .map_err(|_| "the server failed".to_owned())
        }
        _ => Err("no listener is configured".to_owned()),
    }
}
