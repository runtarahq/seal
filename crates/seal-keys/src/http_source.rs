//! Reads wrapped keys over HTTPS with a client certificate, from
//! `GET <base>/keysets/<keyset>/keys`, which returns a JSON array of wrapped keys.
//! Read-only.

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, StatusCode, header};
use http_body_util::Full;
use seal_format::KeysetId;

use crate::KeyError;
use crate::https::{ClientIdentity, Https, Names, Roots};
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
    https: Https,
    timeout: Duration,
    max_keys: usize,
}

impl std::fmt::Debug for HttpKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpKeySource")
            .field("host", &self.https.host())
            .field("port", &self.https.port())
            .finish_non_exhaustive()
    }
}

const NAMES: Names = Names {
    url: "the key source URL",
    not_https: "the key source URL must be plain https",
    no_host: "the key source URL has no host",
    ca: "the key source CA",
};

impl HttpKeySource {
    /// Configures the source.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if the URL or any certificate or key is not valid.
    pub fn new(config: &HttpKeySourceConfig) -> Result<Self, KeyError> {
        let https = Https::new(
            &config.url,
            Roots::Pem(&config.ca_pem),
            Some(ClientIdentity {
                cert_pem: &config.cert_pem,
                key_pem: &config.key_pem,
            }),
            NAMES,
        )?;
        Ok(Self {
            https,
            timeout: config.timeout,
            max_keys: config.max_keys,
        })
    }

    async fn get(&self, path: String) -> Result<(StatusCode, Vec<u8>), KeyError> {
        let request = Request::get(path)
            .header(header::HOST, self.https.authority())
            .header(header::ACCEPT, "application/json")
            .body(Full::new(Bytes::new()))
            .map_err(|_| KeyError::Invalid("the key source path"))?;
        let limit = self.max_keys.saturating_add(1) * MAX_WRAPPED_KEY_BYTES;
        let (status, body) = self.https.send(request, limit).await?;
        Ok((status, body.to_vec()))
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
        let path = format!("{}/keysets/{encoded}/keys", self.https.base_path());
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
