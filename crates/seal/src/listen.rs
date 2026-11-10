//! Listeners. A Unix socket identifies callers by uid, from the peer's credentials; TCP
//! uses TLS 1.3 with client certificates and identifies callers by subject. Either way an
//! unknown caller is refused when it connects, before any request is read.

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::Stream;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tonic::transport::server::Connected;

use crate::callers::{CallerMap, Identity, normalise_subject};

/// A caller's connection, which tells the service who is calling.
pub struct CallerStream<S> {
    inner: S,
    identity: Identity,
    _permit: OwnedSemaphorePermit,
}

impl<S> Connected for CallerStream<S> {
    type ConnectInfo = Identity;

    fn connect_info(&self) -> Identity {
        self.identity.clone()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CallerStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CallerStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Accepted connections, as a stream for tonic.
pub struct Incoming<S> {
    receiver: mpsc::Receiver<CallerStream<S>>,
}

impl<S> Stream for Incoming<S> {
    type Item = Result<CallerStream<S>, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut()
            .receiver
            .poll_recv(cx)
            .map(|item| item.map(Ok))
    }
}

/// Listens on a Unix socket, accepting only known uids.
///
/// # Errors
///
/// Returns an error if the socket cannot be bound.
pub fn unix(
    path: &Path,
    callers: Arc<CallerMap>,
    max_connections: usize,
) -> io::Result<Incoming<tokio::net::UnixStream>> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Peer credentials decide who may call, but nobody else needs to connect at all.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    }
    let (sender, receiver) = mpsc::channel(16);
    let connections = Arc::new(Semaphore::new(max_connections));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                metrics::counter!("seal_connections_refused_total", "reason" => "limit")
                    .increment(1);
                continue;
            };
            let identity = match stream.peer_cred() {
                Ok(credentials) => Identity::Uid(credentials.uid()),
                Err(_) => continue,
            };
            if callers.get(&identity).is_none() {
                metrics::counter!("seal_connections_refused_total", "reason" => "unknown")
                    .increment(1);
                tracing::warn!(
                    caller_kind = "uid",
                    "refused a connection from an unknown caller"
                );
                continue;
            }
            let caller = CallerStream {
                inner: stream,
                identity,
                _permit: permit,
            };
            if sender.send(caller).await.is_err() {
                return;
            }
        }
    });
    Ok(Incoming { receiver })
}

/// TLS settings that reload when their files change.
pub struct ReloadingTls {
    current: RwLock<Arc<rustls::ServerConfig>>,
    files: [PathBuf; 3],
    fingerprint: RwLock<Vec<u8>>,
}

impl ReloadingTls {
    /// Loads the certificate, key and client CA.
    ///
    /// # Errors
    ///
    /// Returns an error naming which file is not valid.
    pub fn load(cert: &Path, key: &Path, client_ca: &Path) -> Result<Arc<Self>, String> {
        let files = [cert.to_owned(), key.to_owned(), client_ca.to_owned()];
        let (config, fingerprint) = build_tls(&files)?;
        Ok(Arc::new(Self {
            current: RwLock::new(Arc::new(config)),
            files,
            fingerprint: RwLock::new(fingerprint),
        }))
    }

    /// The configuration for a new connection. Existing connections keep theirs.
    #[must_use]
    pub fn current(&self) -> Arc<rustls::ServerConfig> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Reloads if the files changed. A change that does not load is logged and the old
    /// configuration kept, so a half-written renewal cannot take the service down.
    pub fn reload_if_changed(&self) -> bool {
        let Ok(contents) = read_all(&self.files) else {
            return false;
        };
        if *self
            .fingerprint
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            == contents
        {
            return false;
        }
        match build_tls(&self.files) {
            Ok((config, fingerprint)) => {
                *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(config);
                *self
                    .fingerprint
                    .write()
                    .unwrap_or_else(PoisonError::into_inner) = fingerprint;
                tracing::info!("reloaded the service's certificates");
                metrics::counter!("seal_certificate_reloads_total").increment(1);
                true
            }
            Err(_) => {
                tracing::warn!("changed certificate files did not load; keeping the old ones");
                false
            }
        }
    }
}

fn read_all(files: &[PathBuf; 3]) -> io::Result<Vec<u8>> {
    let mut all = Vec::new();
    for file in files {
        all.extend_from_slice(&std::fs::read(file)?);
        all.push(0);
    }
    Ok(all)
}

fn build_tls(files: &[PathBuf; 3]) -> Result<(rustls::ServerConfig, Vec<u8>), String> {
    let contents = read_all(files).map_err(|_| "cannot read the TLS files".to_owned())?;
    let [cert, key, client_ca] = files;
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|_| format!("{} is not a PEM certificate chain", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|_| format!("{} is not a PEM private key", key.display()))?;
    let mut roots = rustls::RootCertStore::empty();
    for ca in CertificateDer::pem_file_iter(client_ca)
        .map_err(|_| format!("{} is not a PEM certificate", client_ca.display()))?
    {
        let ca = ca.map_err(|_| format!("{} is not a PEM certificate", client_ca.display()))?;
        roots
            .add(ca)
            .map_err(|_| format!("{} is not a valid CA", client_ca.display()))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .map_err(|_| "the client CA cannot verify certificates".to_owned())?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "TLS 1.3 is not available".to_owned())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|_| "the certificate and key do not match".to_owned())?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok((config, contents))
}

/// Polls the certificate files for changes.
pub fn spawn_reloader(tls: &Arc<ReloadingTls>, interval: Duration) {
    let tls = Arc::downgrade(tls);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            let Some(tls) = tls.upgrade() else { return };
            tls.reload_if_changed();
        }
    });
}

/// The subject of a verified client certificate, normalised.
fn subject_of(stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Option<String> {
    let certificate = stream.get_ref().1.peer_certificates()?.first()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref()).ok()?;
    Some(normalise_subject(&parsed.subject().to_string()))
}

/// Listens on TCP with TLS 1.3, accepting only known certificate subjects.
///
/// # Errors
///
/// Returns an error if the address cannot be bound.
pub async fn tcp(
    address: std::net::SocketAddr,
    tls: Arc<ReloadingTls>,
    callers: Arc<CallerMap>,
    max_connections: usize,
    handshake_timeout: Duration,
) -> io::Result<(
    Incoming<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
    std::net::SocketAddr,
)> {
    let listener = TcpListener::bind(address).await?;
    let local = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel(16);
    let connections = Arc::new(Semaphore::new(max_connections));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                metrics::counter!("seal_connections_refused_total", "reason" => "limit")
                    .increment(1);
                continue;
            };
            let (tls, callers, sender) = (tls.current(), Arc::clone(&callers), sender.clone());
            // Handshakes run on their own, so one slow peer cannot hold up the others.
            tokio::spawn(async move {
                let accepted =
                    tokio::time::timeout(handshake_timeout, TlsAcceptor::from(tls).accept(stream))
                        .await;
                let Ok(Ok(stream)) = accepted else {
                    metrics::counter!("seal_connections_refused_total", "reason" => "tls")
                        .increment(1);
                    return;
                };
                let identity = match subject_of(&stream) {
                    Some(subject) => Identity::Subject(subject),
                    None => return,
                };
                if callers.get(&identity).is_none() {
                    metrics::counter!("seal_connections_refused_total", "reason" => "unknown")
                        .increment(1);
                    tracing::warn!(
                        caller_kind = "certificate",
                        "refused a connection from an unknown caller"
                    );
                    return;
                }
                let _ = sender
                    .send(CallerStream {
                        inner: stream,
                        identity,
                        _permit: permit,
                    })
                    .await;
            });
        }
    });
    Ok((Incoming { receiver }, local))
}
