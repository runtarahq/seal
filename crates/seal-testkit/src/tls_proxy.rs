//! TLS in front of a plain server on this machine, for a client that insists on
//! `https` and a server in a container that speaks only `http`. Bytes pass through
//! unchanged, so the `Host` a client signs is the one the server sees.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::pki::TestPki;

/// A listener on `localhost` that ends TLS and passes each connection on.
pub struct TlsProxy {
    port: u16,
    ca_pem: String,
    connections: Arc<AtomicUsize>,
}

impl TlsProxy {
    /// Starts the proxy toward `upstream` on this machine. Needs a Tokio runtime, and
    /// lasts as long as it does.
    ///
    /// # Panics
    ///
    /// Panics if no port can be listened on.
    #[allow(clippy::unwrap_used)]
    pub async fn start(upstream: u16) -> Self {
        let pki = TestPki::new("proxy CA");
        let issued = pki.server(&["localhost"]);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![issued.cert_der.clone()], issued.key_der())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&connections);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut caller) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Ok(mut server) =
                        tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await
                    else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut caller, &mut server).await;
                });
            }
        });
        Self {
            port,
            ca_pem: pki.ca_pem.clone(),
            connections,
        }
    }

    /// The port to connect to, on `localhost`.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The CA that issued the proxy's certificate, in PEM.
    #[must_use]
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// How many connections it has taken. A client that opens one for each request has
    /// made this many requests.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}
