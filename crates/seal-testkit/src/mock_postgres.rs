//! A fake Postgres server, for testing the plumbing of a session without a database:
//! it answers an `SSLRequest`, completes TLS with a certificate for its host from a new
//! CA, records the first packet, accepts any login at once, and then echoes.

use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::pki::TestPki;

/// The `SSLRequest` packet.
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];

/// A running fake server. Stops when dropped.
pub struct MockPostgres {
    port: u16,
    /// The CA its certificate is from, in PEM.
    pub ca_pem: String,
    packets: Arc<Mutex<Vec<Vec<u8>>>>,
    task: JoinHandle<()>,
}

impl Drop for MockPostgres {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockPostgres {
    /// Starts a server with a certificate for `host`. Without `tls`, it declines TLS.
    ///
    /// # Panics
    ///
    /// Panics if it cannot listen or make certificates.
    pub async fn start(host: &str, tls: bool) -> Self {
        let pki = TestPki::new("db CA");
        let issued = pki.server(&[host]);
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|_| unreachable!("protocol versions"))
        .with_no_client_auth()
        .with_single_cert(vec![issued.cert_der.clone()], issued.key_der())
        .unwrap_or_else(|_| unreachable!("a test certificate"));
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|_| unreachable!("binding a loopback port"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|_| unreachable!("a bound socket has an address"))
            .port();
        let packets = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&packets);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, recorded) = (acceptor.clone(), Arc::clone(&recorded));
                tokio::spawn(serve(stream, acceptor, recorded, tls));
            }
        });
        Self {
            port,
            ca_pem: pki.ca_pem,
            packets,
            task,
        }
    }

    /// The port it listens on, on 127.0.0.1.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The first packet of each session, without its length: a startup or a cancel.
    #[must_use]
    pub fn packets(&self) -> Vec<Vec<u8>> {
        self.packets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// A startup parameter from the `index`th packet.
    #[must_use]
    pub fn startup_param(&self, index: usize, name: &str) -> Option<String> {
        let packets = self.packets();
        let body = packets.get(index)?;
        let mut parts = body.get(4..)?.split(|byte| *byte == 0);
        while let Some(key) = parts.next() {
            let value = parts.next()?;
            if key == name.as_bytes() {
                return String::from_utf8(value.to_vec()).ok();
            }
        }
        None
    }
}

async fn serve(
    mut stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    recorded: Arc<Mutex<Vec<Vec<u8>>>>,
    tls: bool,
) {
    let mut request = [0; 8];
    if stream.read_exact(&mut request).await.is_err() || request != SSL_REQUEST {
        return;
    }
    if !tls {
        let _ = stream.write_all(b"N").await;
        return;
    }
    if stream.write_all(b"S").await.is_err() {
        return;
    }
    let Ok(mut stream) = acceptor.accept(stream).await else {
        return;
    };
    let Ok(length) = stream.read_u32().await else {
        return;
    };
    let mut body = vec![0; usize::try_from(length).unwrap_or(0).saturating_sub(4)];
    if stream.read_exact(&mut body).await.is_err() {
        return;
    }
    let cancel = body.starts_with(&80_877_102_u32.to_be_bytes());
    recorded
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(body);
    if cancel {
        return;
    }
    // AuthenticationOk, then ReadyForQuery.
    let hello = [b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'];
    if stream.write_all(&hello).await.is_err() {
        return;
    }
    let mut buffer = [0; 8192];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                if stream.write_all(&buffer[..read]).await.is_err() {
                    return;
                }
            }
        }
    }
}
