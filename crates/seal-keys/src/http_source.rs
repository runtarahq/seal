//! Reads wrapped keys over HTTPS with a client certificate, from
//! `GET <base>/keysets/<keyset>/keys`, which returns a JSON array of wrapped keys.
//! Read-only.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode, header};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use seal_format::KeysetId;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::KeyError;
use crate::source::{KeySource, MAX_WRAPPED_KEY_BYTES, WrappedKey};

/// How to reach a key service.
#[derive(Clone, Debug)]
pub struct HttpKeySourceConfig {
    /// The base URL, `https` only.
    pub url: String,
    /// The CA that issued the key service's certificate, in PEM.
    pub ca_pem: String,
    /// seal's client certificate and its chain, in PEM.
    pub cert_pem: String,
    /// seal's client key, in PEM.
    pub key_pem: String,
    /// How long a fetch may take.
    pub timeout: Duration,
    /// The most keys accepted per keyset.
    pub max_keys: usize,
}

/// A key source over HTTPS.
pub struct HttpKeySource {
    host: String,
    port: u16,
    base_path: String,
    tls: TlsConnector,
    timeout: Duration,
    max_keys: usize,
}

impl std::fmt::Debug for HttpKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpKeySource")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl HttpKeySource {
    /// Configures the source.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if the URL or any certificate or key is not valid.
    pub fn new(config: &HttpKeySourceConfig) -> Result<Self, KeyError> {
        let url =
            url::Url::parse(&config.url).map_err(|_| KeyError::Invalid("the key source URL"))?;
        let has_credentials = !url.username().is_empty() || url.password().is_some();
        if url.scheme() != "https" || url.query().is_some() || has_credentials {
            return Err(KeyError::Invalid("the key source URL must be plain https"));
        }
        let host = url
            .host_str()
            .ok_or(KeyError::Invalid("the key source URL has no host"))?
            .to_owned();
        let port = url.port_or_known_default().unwrap_or(443);

        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(config.ca_pem.as_bytes()) {
            let certificate = certificate.map_err(|_| KeyError::Invalid("the key source CA"))?;
            roots
                .add(certificate)
                .map_err(|_| KeyError::Invalid("the key source CA"))?;
        }
        let chain = CertificateDer::pem_slice_iter(config.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| KeyError::Invalid("the client certificate"))?;
        let key = PrivateKeyDer::from_pem_slice(config.key_pem.as_bytes())
            .map_err(|_| KeyError::Invalid("the client key"))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| KeyError::Invalid("TLS"))?
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)
            .map_err(|_| KeyError::Invalid("the client certificate or key"))?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self {
            host,
            port,
            base_path: url.path().trim_end_matches('/').to_owned(),
            tls: TlsConnector::from(Arc::new(tls)),
            timeout: config.timeout,
            max_keys: config.max_keys,
        })
    }

    async fn get(&self, path: String) -> Result<(StatusCode, Bytes), KeyError> {
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
        let request = Request::get(path)
            .header(header::HOST, &self.host)
            .header(header::ACCEPT, "application/json")
            .body(Empty::<Bytes>::new())
            .map_err(|_| KeyError::Invalid("the key source path"))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| KeyError::Unavailable)?;
        let status = response.status();
        let limit = self.max_keys.saturating_add(1) * MAX_WRAPPED_KEY_BYTES;
        let body = Limited::new(response.into_body(), limit)
            .collect()
            .await
            .map_err(|_| KeyError::Unavailable)?
            .to_bytes();
        Ok((status, body))
    }
}

#[async_trait]
impl KeySource for HttpKeySource {
    async fn wrapped_keys(&self, keyset: &KeysetId) -> Result<Vec<WrappedKey>, KeyError> {
        let encoded: String = percent_encoding::utf8_percent_encode(
            keyset.as_str(),
            percent_encoding::NON_ALPHANUMERIC,
        )
        .collect();
        let path = format!("{}/keysets/{encoded}/keys", self.base_path);
        let (status, body) = tokio::time::timeout(self.timeout, self.get(path))
            .await
            .map_err(|_| KeyError::Unavailable)??;
        match status {
            StatusCode::NOT_FOUND => Ok(Vec::new()),
            StatusCode::OK => {
                let keys: Vec<WrappedKey> = serde_json::from_slice(&body)
                    .map_err(|_| KeyError::Invalid("the key source's response"))?;
                if keys.len() > self.max_keys {
                    return Err(KeyError::Unavailable);
                }
                Ok(keys)
            }
            _ => Err(KeyError::Unavailable),
        }
    }
}
