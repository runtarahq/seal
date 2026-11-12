//! The HTTPS client the key source and the KMS wrappers share: HTTP/1.1, one request
//! per connection, no redirects, and a response no larger than the caller allows.

use std::sync::Arc;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::KeyError;

/// The most a response buffer is sized for up front. A response that may hold a key
/// must be allowed no more than this, so that its buffer never grows and leaves an
/// unwiped copy behind.
pub(crate) const PREALLOCATED_BYTES: usize = 64 * 1024;

/// What to call each part when it is refused.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Names {
    /// The URL is not a URL.
    pub url: &'static str,
    /// The URL is not plain `https`.
    pub not_https: &'static str,
    /// The URL has no host.
    pub no_host: &'static str,
    /// The CA.
    pub ca: &'static str,
}

/// Which certificates the server's is verified against.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Roots<'a> {
    /// These, in PEM, and no others.
    Pem(&'a str),
    /// Mozilla's public roots.
    Public,
}

/// A client certificate with its chain, and its key, both in PEM.
#[derive(Clone, Copy)]
pub(crate) struct ClientIdentity<'a> {
    /// The certificate and its chain.
    pub cert_pem: &'a str,
    /// The key.
    pub key_pem: &'a str,
}

/// A server reached over HTTPS.
pub(crate) struct Https {
    host: String,
    port: u16,
    base_path: String,
    tls: TlsConnector,
}

impl Https {
    /// Configures the client. Connects to nothing.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if the URL or any certificate or key is not valid.
    pub(crate) fn new(
        url: &str,
        roots: Roots<'_>,
        identity: Option<ClientIdentity<'_>>,
        names: Names,
    ) -> Result<Self, KeyError> {
        let url = url::Url::parse(url).map_err(|_| KeyError::Invalid(names.url))?;
        let has_credentials = !url.username().is_empty() || url.password().is_some();
        if url.scheme() != "https"
            || url.query().is_some()
            || url.fragment().is_some()
            || has_credentials
        {
            return Err(KeyError::Invalid(names.not_https));
        }
        let host = url
            .host_str()
            .ok_or(KeyError::Invalid(names.no_host))?
            .to_owned();
        let port = url.port_or_known_default().unwrap_or(443);

        let mut store = RootCertStore::empty();
        match roots {
            Roots::Pem(pem) => {
                for certificate in CertificateDer::pem_slice_iter(pem.as_bytes()) {
                    let certificate = certificate.map_err(|_| KeyError::Invalid(names.ca))?;
                    store
                        .add(certificate)
                        .map_err(|_| KeyError::Invalid(names.ca))?;
                }
                if store.is_empty() {
                    return Err(KeyError::Invalid(names.ca));
                }
            }
            Roots::Public => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| KeyError::Invalid("TLS"))?
            .with_root_certificates(store);
        let mut tls = match identity {
            Some(identity) => {
                let chain = CertificateDer::pem_slice_iter(identity.cert_pem.as_bytes())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| KeyError::Invalid("the client certificate"))?;
                let key = PrivateKeyDer::from_pem_slice(identity.key_pem.as_bytes())
                    .map_err(|_| KeyError::Invalid("the client key"))?;
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|_| KeyError::Invalid("the client certificate or key"))?
            }
            None => builder.with_no_client_auth(),
        };
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self {
            host,
            port,
            base_path: url.path().trim_end_matches('/').to_owned(),
            tls: TlsConnector::from(Arc::new(tls)),
        })
    }

    /// The host, as the URL has it.
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// The URL's path, without a trailing slash.
    pub(crate) fn base_path(&self) -> &str {
        &self.base_path
    }

    /// What goes in `Host`: the host, and the port unless it is the default.
    pub(crate) fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Sends a request on a new connection and reads the whole response, which may be
    /// at most `limit` bytes. The request needs a `Host` header. The response is wiped
    /// when dropped.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Unavailable`] if the server cannot be reached, its
    /// certificate is not valid, or the response is too large.
    pub(crate) async fn send(
        &self,
        request: Request<Full<Bytes>>,
        limit: usize,
    ) -> Result<(StatusCode, Zeroizing<Vec<u8>>), KeyError> {
        let stream = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|_| KeyError::Unavailable)?;
        let name =
            ServerName::try_from(self.host.clone()).map_err(|_| KeyError::Invalid("host"))?;
        let stream = self
            .tls
            .connect(name, stream)
            .await
            .map_err(|_| KeyError::Unavailable)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| KeyError::Unavailable)?;
        tokio::spawn(connection);
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| KeyError::Unavailable)?;
        let status = response.status();
        let mut received = Zeroizing::new(Vec::with_capacity(limit.min(PREALLOCATED_BYTES)));
        let mut body = response.into_body();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| KeyError::Unavailable)?;
            if let Some(data) = frame.data_ref() {
                if data.len() > limit.saturating_sub(received.len()) {
                    return Err(KeyError::Unavailable);
                }
                received.extend_from_slice(data);
            }
        }
        Ok((status, received))
    }
}
