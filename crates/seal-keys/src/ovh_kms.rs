//! Wrapping with a service key in OVHcloud KMS, so that the wrapping key never leaves
//! the KMS: seal sends each private key to be encrypted or decrypted, over HTTPS, to
//! `POST <endpoint>/api/<okms id>/v1/servicekey/<key id>/{encrypt,decrypt}`.
//!
//! The keyset and kid go as the KMS's `context`, its additional authenticated data,
//! so a wrapped key moved to another keyset or kid does not unwrap. What is stored is
//! the KMS's ciphertext, a JWE string, as it came.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderValue, Request, StatusCode, header};
use http_body_util::Full;
use seal_format::id::KeyId;
use seal_format::{KeysetId, PrivateKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::KeyError;
use crate::https::{ClientIdentity, Https, Names, PREALLOCATED_BYTES, Roots};
use crate::source::MAX_WRAPPED_KEY_BYTES;
use crate::wrap::{KeyWrap, associated_data};

/// How seal proves who it is to the KMS.
#[derive(Clone)]
pub enum OvhKmsAuth {
    /// An access certificate with its chain, and its key, both in PEM.
    Certificate {
        /// The certificate.
        cert_pem: String,
        /// The key.
        key_pem: Zeroizing<String>,
    },
    /// A personal access token, sent as a bearer token.
    Token(Zeroizing<String>),
}

impl std::fmt::Debug for OvhKmsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Certificate { .. } => "Certificate",
            Self::Token(_) => "Token",
        })
    }
}

/// How to reach a service key.
#[derive(Clone, Debug)]
pub struct OvhKmsConfig {
    /// The KMS's regional endpoint, such as `https://eu-west-rbx.okms.ovh.net`.
    pub endpoint: String,
    /// The KMS's id, a UUID.
    pub okms_id: String,
    /// The service key's id, a UUID. An AES key that may encrypt and decrypt.
    pub key_id: String,
    /// seal's credentials.
    pub auth: OvhKmsAuth,
    /// The CA that issued the endpoint's certificate, in PEM, if it is not a public one.
    pub ca_pem: Option<String>,
    /// How long one request may take.
    pub timeout: Duration,
}

/// Wraps with a service key in OVHcloud KMS.
pub struct OvhKmsWrap {
    https: Https,
    encrypt_path: String,
    decrypt_path: String,
    authorization: Option<HeaderValue>,
    id: String,
    timeout: Duration,
}

impl std::fmt::Debug for OvhKmsWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OvhKmsWrap")
            .field("id", &self.id)
            .field("host", &self.https.host())
            .finish_non_exhaustive()
    }
}

const NAMES: Names = Names {
    url: "the KMS endpoint",
    not_https: "the KMS endpoint must be plain https",
    no_host: "the KMS endpoint has no host",
    ca: "the KMS CA",
};

/// The most a private key takes in base64, with room to spare.
const PLAINTEXT_BASE64_BYTES: usize = 128;

/// Whether this is a UUID as the KMS writes them: 8-4-4-4-12 hex digits.
fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// The KMS's `context` for a key: the associated data of a file-wrapped key, in
/// base64url, since a context is text.
fn context(keyset: &KeysetId, kid: &KeyId) -> String {
    URL_SAFE_NO_PAD.encode(associated_data(keyset, kid))
}

#[derive(Serialize)]
struct DecryptRequest<'a> {
    ciphertext: &'a str,
    context: &'a str,
}

#[derive(Deserialize)]
struct EncryptResponse {
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptResponse {
    plaintext: String,
}

/// The parts of the KMS's error that say what went wrong, and hold nothing of a key.
#[derive(Default, Deserialize)]
struct ErrorResponse {
    error_code: Option<i64>,
    request_id: Option<String>,
}

impl OvhKmsWrap {
    /// Configures the wrapper. Connects to nothing.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if the endpoint, an id or a credential is not
    /// valid.
    pub fn new(config: &OvhKmsConfig) -> Result<Self, KeyError> {
        if !is_uuid(&config.okms_id) {
            return Err(KeyError::Invalid("the KMS id is not a UUID"));
        }
        if !is_uuid(&config.key_id) {
            return Err(KeyError::Invalid("the service key id is not a UUID"));
        }
        let (okms_id, key_id) = (
            config.okms_id.to_ascii_lowercase(),
            config.key_id.to_ascii_lowercase(),
        );
        let roots = config.ca_pem.as_deref().map_or(Roots::Public, Roots::Pem);
        let (identity, authorization) = match &config.auth {
            OvhKmsAuth::Certificate { cert_pem, key_pem } => (
                Some(ClientIdentity {
                    cert_pem,
                    key_pem: key_pem.as_str(),
                }),
                None,
            ),
            OvhKmsAuth::Token(token) => {
                let token = token.trim();
                if token.is_empty() {
                    return Err(KeyError::Invalid("the KMS token is empty"));
                }
                let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| KeyError::Invalid("the KMS token"))?;
                value.set_sensitive(true);
                (None, Some(value))
            }
        };
        let https = Https::new(&config.endpoint, roots, identity, NAMES)?;
        let key_path = format!("{}/api/{okms_id}/v1/servicekey/{key_id}", https.base_path());
        Ok(Self {
            https,
            encrypt_path: format!("{key_path}/encrypt"),
            decrypt_path: format!("{key_path}/decrypt"),
            authorization,
            id: format!("ovh-kms:{okms_id}/{key_id}"),
            timeout: config.timeout,
        })
    }

    /// Posts a JSON body and returns the response to a 200. Anything else is logged,
    /// by status and the KMS's error code and request id, and is `Unavailable`.
    async fn post(
        &self,
        operation: &'static str,
        path: &str,
        body: Bytes,
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let mut request = Request::post(path)
            .header(header::HOST, self.https.authority())
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .body(Full::new(body))
            .map_err(|_| KeyError::Invalid("the KMS path"))?;
        if let Some(authorization) = &self.authorization {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, authorization.clone());
        }
        let sent =
            tokio::time::timeout(self.timeout, self.https.send(request, PREALLOCATED_BYTES)).await;
        let outcome = match &sent {
            Ok(Ok((StatusCode::OK, _))) => "ok",
            Ok(Ok(_)) => "refused",
            Ok(Err(_)) => "unreachable",
            Err(_) => "timeout",
        };
        metrics::counter!(
            "seal_kms_requests_total",
            "kms" => "ovh",
            "operation" => operation,
            "outcome" => outcome,
        )
        .increment(1);
        match sent {
            Ok(Ok((StatusCode::OK, body))) => Ok(body),
            Ok(Ok((status, body))) => {
                let error: ErrorResponse = serde_json::from_slice(&body).unwrap_or_default();
                tracing::warn!(
                    kms = "ovh",
                    operation,
                    status = status.as_u16(),
                    error_code = error.error_code,
                    request_id = error.request_id.as_deref().filter(|id| is_uuid(id)),
                    "the KMS refused a request"
                );
                Err(KeyError::Unavailable)
            }
            Ok(Err(error)) => {
                tracing::warn!(kms = "ovh", operation, "the KMS could not be reached");
                Err(error)
            }
            Err(_) => {
                tracing::warn!(kms = "ovh", operation, "the KMS did not answer in time");
                Err(KeyError::Unavailable)
            }
        }
    }
}

#[async_trait]
impl KeyWrap for OvhKmsWrap {
    fn id(&self) -> &str {
        &self.id
    }

    async fn wrap(
        &self,
        keyset: &KeysetId,
        kid: &KeyId,
        key: &PrivateKey,
    ) -> Result<Vec<u8>, KeyError> {
        let context = context(keyset, kid);
        // Written by hand into a buffer of its final size, so the key is never in an
        // allocation that is not wiped. Neither value needs escaping: both are base64.
        let mut body = Zeroizing::new(Vec::with_capacity(
            PLAINTEXT_BASE64_BYTES + context.len() + 64,
        ));
        body.extend_from_slice(br#"{"plaintext":""#);
        let mut encoded = Zeroizing::new([0_u8; PLAINTEXT_BASE64_BYTES]);
        let length = key
            .expose(|bytes| STANDARD.encode_slice(bytes, encoded.as_mut_slice()))
            .map_err(|_| KeyError::Unavailable)?;
        body.extend_from_slice(encoded.get(..length).ok_or(KeyError::Unavailable)?);
        body.extend_from_slice(br#"","context":""#);
        body.extend_from_slice(context.as_bytes());
        body.extend_from_slice(br#""}"#);

        let response = self
            .post("encrypt", &self.encrypt_path, Bytes::copy_from_slice(&body))
            .await?;
        let EncryptResponse { ciphertext } =
            serde_json::from_slice(&response).map_err(|_| KeyError::Unavailable)?;
        if ciphertext.is_empty()
            || ciphertext.len() > MAX_WRAPPED_KEY_BYTES / 2
            || !ciphertext.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(KeyError::Unavailable);
        }
        Ok(ciphertext.into_bytes())
    }

    async fn unwrap(
        &self,
        keyset: &KeysetId,
        kid: &KeyId,
        wrapped: &[u8],
    ) -> Result<PrivateKey, KeyError> {
        let ciphertext = std::str::from_utf8(wrapped).map_err(|_| KeyError::Unavailable)?;
        if !ciphertext.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(KeyError::Unavailable);
        }
        let body = serde_json::to_vec(&DecryptRequest {
            ciphertext,
            context: &context(keyset, kid),
        })
        .map_err(|_| KeyError::Unavailable)?;
        let response = self
            .post("decrypt", &self.decrypt_path, Bytes::from(body))
            .await?;
        let plaintext = serde_json::from_slice::<DecryptResponse>(&response)
            .map(|response| Zeroizing::new(response.plaintext))
            .map_err(|_| KeyError::Unavailable)?;
        let mut decoded = Zeroizing::new([0_u8; PLAINTEXT_BASE64_BYTES]);
        let length = STANDARD
            .decode_slice(plaintext.as_bytes(), decoded.as_mut_slice())
            .map_err(|_| KeyError::Unavailable)?;
        PrivateKey::from_bytes(decoded.get(..length).ok_or(KeyError::Unavailable)?)
            .map_err(|_| KeyError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OKMS: &str = "11111111-2222-3333-4444-555555555555";
    const KEY: &str = "AAAAAAAA-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn config() -> OvhKmsConfig {
        OvhKmsConfig {
            endpoint: "https://eu-west-rbx.okms.ovh.net".to_owned(),
            okms_id: OKMS.to_owned(),
            key_id: KEY.to_owned(),
            auth: OvhKmsAuth::Token(Zeroizing::new("a-token\n".to_owned())),
            ca_pem: None,
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn the_id_names_the_kms_and_the_key_and_the_paths_follow() {
        let wrap = OvhKmsWrap::new(&config()).unwrap();
        assert_eq!(
            wrap.id(),
            "ovh-kms:11111111-2222-3333-4444-555555555555/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        );
        assert_eq!(
            wrap.encrypt_path,
            "/api/11111111-2222-3333-4444-555555555555/v1/servicekey/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/encrypt"
        );
        assert!(wrap.decrypt_path.ends_with("/decrypt"));
    }

    #[test]
    fn a_token_is_trimmed_marked_sensitive_and_never_printed() {
        let wrap = OvhKmsWrap::new(&config()).unwrap();
        let authorization = wrap.authorization.as_ref().unwrap();
        assert_eq!(authorization.as_bytes(), b"Bearer a-token");
        assert!(authorization.is_sensitive());
        assert!(!format!("{wrap:?} {:?}", config()).contains("a-token"));
    }

    #[test]
    fn ids_that_are_not_uuids_and_bad_endpoints_and_tokens_are_refused() {
        for id in [
            "",
            "../../v1",
            "11111111-2222-3333-4444-55555555555g",
            "1111",
        ] {
            let mut bad = config();
            bad.okms_id = id.to_owned();
            assert!(OvhKmsWrap::new(&bad).is_err(), "okms id {id:?}");
            let mut bad = config();
            bad.key_id = id.to_owned();
            assert!(OvhKmsWrap::new(&bad).is_err(), "key id {id:?}");
        }
        for endpoint in [
            "http://eu-west-rbx.okms.ovh.net",
            "https://user:pass@eu-west-rbx.okms.ovh.net",
            "https://eu-west-rbx.okms.ovh.net/?a=b",
            "not a url",
        ] {
            let mut bad = config();
            bad.endpoint = endpoint.to_owned();
            assert!(OvhKmsWrap::new(&bad).is_err(), "endpoint {endpoint:?}");
        }
        for token in ["", "  \n", "two\nlines"] {
            let mut bad = config();
            bad.auth = OvhKmsAuth::Token(Zeroizing::new(token.to_owned()));
            assert!(OvhKmsWrap::new(&bad).is_err(), "token {token:?}");
        }
        let mut bad = config();
        bad.ca_pem = Some("not a certificate".to_owned());
        assert!(OvhKmsWrap::new(&bad).is_err());
    }

    #[test]
    fn the_context_differs_by_keyset_and_kid() {
        let (a, b) = (KeysetId::new("a").unwrap(), KeysetId::new("ab").unwrap());
        let (k, bk) = (KeyId::new("bk").unwrap(), KeyId::new("k").unwrap());
        assert_ne!(context(&a, &k), context(&b, &bk));
        assert!(
            context(&a, &k)
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
    }
}
