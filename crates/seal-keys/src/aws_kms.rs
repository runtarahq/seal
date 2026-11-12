//! Wrapping with a key in AWS KMS, so that the wrapping key never leaves the KMS: seal
//! sends each private key to `Encrypt` or `Decrypt`, signed with Signature Version 4.
//!
//! The keyset and kid go as the encryption context, `seal:keyset` and `seal:kid`, so a
//! wrapped key moved to another keyset or kid does not unwrap, and each use shows in
//! CloudTrail under its keyset. What is stored is the KMS's `CiphertextBlob`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{HeaderValue, Request, header};
use http_body_util::Full;
use ring::{digest, hmac};
use seal_format::id::KeyId;
use seal_format::{KeysetId, PrivateKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::KeyError;
use crate::aws_credentials::{AwsCredentialSource, CredentialProvider, Credentials};
use crate::https::{Https, Names, Roots};
use crate::kms::{KEY_BASE64_BYTES, Refusal, exchange, key_from_base64, push_key_base64};
use crate::source::MAX_WRAPPED_KEY_BYTES;
use crate::wrap::KeyWrap;

/// How to reach a KMS key.
#[derive(Clone, Debug)]
pub struct AwsKmsConfig {
    /// The key's ARN, `arn:aws:kms:<region>:<account>:key/<id>`. A symmetric key that
    /// may encrypt and decrypt. Not an alias, which can be pointed at another key.
    pub key_arn: String,
    /// Where seal's credentials come from: a file, or the role its host gives it.
    pub credentials: AwsCredentialSource,
    /// The endpoint, if it is not the region's public one: a VPC or FIPS endpoint.
    pub endpoint: Option<String>,
    /// The CA that issued the endpoint's certificate, in PEM, if it is not a public one.
    pub ca_pem: Option<String>,
    /// How long one request may take.
    pub timeout: Duration,
}

/// Wraps with a key in AWS KMS.
pub struct AwsKmsWrap {
    https: Https,
    key_arn: String,
    region: String,
    credentials: CredentialProvider,
    id: String,
    timeout: Duration,
}

impl std::fmt::Debug for AwsKmsWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsWrap")
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

const CONTENT_TYPE: &str = "application/x-amz-json-1.1";

/// The region of a key ARN, if it is the ARN of a key.
fn region_of(arn: &str) -> Option<(&str, &str)> {
    let mut parts = arn.splitn(6, ':');
    let ("arn", partition, "kms", region, account, resource) = (
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
    ) else {
        return None;
    };
    let plain = |value: &str| {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    let key = resource.strip_prefix("key/")?;
    let valid = plain(partition)
        && plain(region)
        && account.len() == 12
        && account.bytes().all(|byte| byte.is_ascii_digit())
        && plain(key);
    valid.then_some((partition, region))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// `20150830` and `20150830T123600Z`, for a time since the epoch.
fn amz_dates(now: SystemTime) -> (String, String) {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let of_day = seconds % 86_400;
    // Howard Hinnant's days-to-civil algorithm.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let date = format!("{year:04}{month:02}{day:02}");
    let time = format!(
        "{date}T{:02}{:02}{:02}Z",
        of_day / 3600,
        of_day / 60 % 60,
        of_day % 60
    );
    (date, time)
}

/// The headers of a signed request, besides `Host` and `Content-Type`.
struct Signed {
    amz_date: String,
    authorization: HeaderValue,
}

/// Signs a `POST /` with no query, the only request seal makes of AWS KMS. The signed
/// headers are `content-type`, `host`, `x-amz-date`, `x-amz-target`, and the session
/// token if there is one.
fn sign(
    credentials: &Credentials,
    region: &str,
    authority: &str,
    target: &str,
    body: &[u8],
    now: SystemTime,
) -> Result<Signed, KeyError> {
    let (date, amz_date) = amz_dates(now);
    let mut headers =
        format!("content-type:{CONTENT_TYPE}\nhost:{authority}\nx-amz-date:{amz_date}\n");
    let mut signed_headers = "content-type;host;x-amz-date".to_owned();
    if let Some(token) = &credentials.session_token {
        headers.push_str("x-amz-security-token:");
        headers.push_str(token);
        headers.push('\n');
        signed_headers.push_str(";x-amz-security-token");
    }
    headers.push_str("x-amz-target:");
    headers.push_str(target);
    headers.push('\n');
    signed_headers.push_str(";x-amz-target");

    let payload = hex(digest::digest(&digest::SHA256, body).as_ref());
    let canonical = format!("POST\n/\n\n{headers}\n{signed_headers}\n{payload}");
    let scope = format!("{date}/{region}/kms/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(digest::digest(&digest::SHA256, canonical.as_bytes()).as_ref())
    );

    let mut secret = Zeroizing::new(Vec::with_capacity(4 + credentials.secret_access_key.len()));
    secret.extend_from_slice(b"AWS4");
    secret.extend_from_slice(credentials.secret_access_key.as_bytes());
    let mut key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &secret), date.as_bytes());
    for part in [region, "kms", "aws4_request"] {
        key = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, key.as_ref()),
            part.as_bytes(),
        );
    }
    let signature = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, key.as_ref()),
        to_sign.as_bytes(),
    );
    let authorization = HeaderValue::from_str(&format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={}",
        credentials.access_key_id,
        hex(signature.as_ref())
    ))
    .map_err(|_| KeyError::Invalid("the AWS access key id"))?;
    Ok(Signed {
        amz_date,
        authorization,
    })
}

#[derive(Serialize)]
struct Context<'a> {
    #[serde(rename = "seal:keyset")]
    keyset: &'a str,
    #[serde(rename = "seal:kid")]
    kid: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DecryptRequest<'a> {
    ciphertext_blob: String,
    key_id: &'a str,
    encryption_context: Context<'a>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EncryptResponse {
    ciphertext_blob: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DecryptResponse {
    plaintext: String,
}

/// The part of the KMS's error that names it, such as `AccessDeniedException`.
#[derive(Default, Deserialize)]
struct ErrorResponse {
    #[serde(rename = "__type")]
    kind: Option<String>,
}

impl AwsKmsWrap {
    /// Configures the wrapper. Connects to nothing, and does not read or fetch the
    /// credentials.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if the ARN, the endpoint or the source of the
    /// credentials is not valid.
    pub fn new(config: &AwsKmsConfig) -> Result<Self, KeyError> {
        let (partition, region) = region_of(&config.key_arn)
            .ok_or(KeyError::Invalid("the KMS key must be a key's ARN"))?;
        let endpoint = config.endpoint.clone().unwrap_or_else(|| {
            let suffix = if partition == "aws-cn" {
                "amazonaws.com.cn"
            } else {
                "amazonaws.com"
            };
            format!("https://kms.{region}.{suffix}")
        });
        let roots = config.ca_pem.as_deref().map_or(Roots::Public, Roots::Pem);
        let https = Https::new(&endpoint, roots, None, NAMES)?;
        if !https.base_path().is_empty() {
            return Err(KeyError::Invalid("the KMS endpoint must have no path"));
        }
        Ok(Self {
            https,
            id: format!("aws-kms:{}", config.key_arn),
            key_arn: config.key_arn.clone(),
            region: region.to_owned(),
            credentials: CredentialProvider::new(&config.credentials, config.timeout)?,
            timeout: config.timeout,
        })
    }

    /// Signs and posts a JSON body, and returns the response to a 200. Anything else
    /// is logged, by status and the name of the KMS's error, and is `Unavailable`.
    async fn call(
        &self,
        operation: &'static str,
        target: &'static str,
        body: Bytes,
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let credentials = self.credentials.credentials().await?;
        let authority = self.https.authority();
        let signed = sign(
            &credentials,
            &self.region,
            &authority,
            target,
            &body,
            SystemTime::now(),
        )?;
        let mut request = Request::post("/")
            .header(header::HOST, authority)
            .header(header::CONTENT_TYPE, CONTENT_TYPE)
            .header("x-amz-date", signed.amz_date)
            .header("x-amz-target", target)
            .header(header::AUTHORIZATION, signed.authorization)
            .body(Full::new(body))
            .map_err(|_| KeyError::Invalid("the KMS request"))?;
        if let Some(token) = &credentials.session_token {
            let mut value = HeaderValue::from_str(token)
                .map_err(|_| KeyError::Invalid("the AWS session token"))?;
            value.set_sensitive(true);
            request.headers_mut().insert("x-amz-security-token", value);
        }
        match exchange(&self.https, request, self.timeout, "aws", operation).await? {
            Ok(body) => Ok(body),
            Err(Refusal { status, body }) => {
                let error: ErrorResponse = serde_json::from_slice(&body).unwrap_or_default();
                let kind = error.kind.as_deref().filter(|kind| {
                    kind.len() <= 96
                        && kind
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"#._".contains(&byte))
                });
                tracing::warn!(
                    kms = "aws",
                    operation,
                    status = status.as_u16(),
                    error = kind,
                    "the KMS refused a request"
                );
                Err(KeyError::Unavailable)
            }
        }
    }
}

#[async_trait]
impl KeyWrap for AwsKmsWrap {
    fn id(&self) -> &str {
        &self.id
    }

    async fn wrap(
        &self,
        keyset: &KeysetId,
        kid: &KeyId,
        key: &PrivateKey,
    ) -> Result<Vec<u8>, KeyError> {
        let context = serde_json::to_string(&Context {
            keyset: keyset.as_str(),
            kid: kid.as_str(),
        })
        .map_err(|_| KeyError::Unavailable)?;
        // Written by hand into a buffer of its final size, so the key is never in an
        // allocation that is not wiped. The ARN needs no escaping, and base64 has none.
        let mut body = Zeroizing::new(Vec::with_capacity(
            KEY_BASE64_BYTES + self.key_arn.len() + context.len() + 64,
        ));
        body.extend_from_slice(br#"{"KeyId":""#);
        body.extend_from_slice(self.key_arn.as_bytes());
        body.extend_from_slice(br#"","EncryptionContext":"#);
        body.extend_from_slice(context.as_bytes());
        body.extend_from_slice(br#","Plaintext":""#);
        push_key_base64(key, &mut body)?;
        body.extend_from_slice(br#""}"#);

        let response = self
            .call(
                "encrypt",
                "TrentService.Encrypt",
                Bytes::copy_from_slice(&body),
            )
            .await?;
        let EncryptResponse { ciphertext_blob } =
            serde_json::from_slice(&response).map_err(|_| KeyError::Unavailable)?;
        let wrapped = STANDARD
            .decode(ciphertext_blob)
            .map_err(|_| KeyError::Unavailable)?;
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_KEY_BYTES / 2 {
            return Err(KeyError::Unavailable);
        }
        Ok(wrapped)
    }

    async fn unwrap(
        &self,
        keyset: &KeysetId,
        kid: &KeyId,
        wrapped: &[u8],
    ) -> Result<PrivateKey, KeyError> {
        let body = serde_json::to_vec(&DecryptRequest {
            ciphertext_blob: STANDARD.encode(wrapped),
            // Named, so that the KMS refuses a ciphertext from any other key.
            key_id: &self.key_arn,
            encryption_context: Context {
                keyset: keyset.as_str(),
                kid: kid.as_str(),
            },
        })
        .map_err(|_| KeyError::Unavailable)?;
        let response = self
            .call("decrypt", "TrentService.Decrypt", Bytes::from(body))
            .await?;
        let plaintext = serde_json::from_slice::<DecryptResponse>(&response)
            .map(|response| Zeroizing::new(response.plaintext))
            .map_err(|_| KeyError::Unavailable)?;
        key_from_base64(&plaintext)
    }
}

#[cfg(test)]
mod tests {
    use aws_credential_types::Credentials as SdkCredentials;
    use aws_sigv4::http_request::{
        SignableBody, SignableRequest, SigningSettings, sign as sdk_sign,
    };
    use aws_sigv4::sign::v4;

    use super::*;

    const ARN: &str =
        "arn:aws:kms:eu-central-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    fn config() -> AwsKmsConfig {
        AwsKmsConfig {
            key_arn: ARN.to_owned(),
            credentials: AwsCredentialSource::File {
                path: "/nowhere".into(),
                profile: None,
            },
            endpoint: None,
            ca_pem: None,
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn the_region_endpoint_and_id_come_from_the_arn() {
        let wrap = AwsKmsWrap::new(&config()).unwrap();
        assert_eq!(wrap.id(), format!("aws-kms:{ARN}"));
        assert_eq!(wrap.region, "eu-central-1");
        assert_eq!(wrap.https.host(), "kms.eu-central-1.amazonaws.com");

        let mut china = config();
        china.key_arn = ARN
            .replace("arn:aws:", "arn:aws-cn:")
            .replace("eu-central-1", "cn-north-1");
        assert_eq!(
            AwsKmsWrap::new(&china).unwrap().https.host(),
            "kms.cn-north-1.amazonaws.com.cn"
        );

        let mut multi_region = config();
        multi_region.key_arn =
            "arn:aws:kms:us-east-1:123456789012:key/mrk-1234abcd12ab34cd56ef1234567890ab"
                .to_owned();
        assert!(AwsKmsWrap::new(&multi_region).is_ok());

        let mut elsewhere = config();
        elsewhere.endpoint = Some("https://vpce-1.kms.eu-central-1.vpce.amazonaws.com".to_owned());
        assert_eq!(
            AwsKmsWrap::new(&elsewhere).unwrap().https.host(),
            "vpce-1.kms.eu-central-1.vpce.amazonaws.com"
        );
    }

    #[test]
    fn only_a_keys_arn_and_a_plain_endpoint_are_accepted() {
        for key in [
            "",
            "1234abcd-12ab-34cd-56ef-1234567890ab",
            "alias/seal",
            "arn:aws:kms:eu-central-1:123456789012:alias/seal",
            "arn:aws:s3:eu-central-1:123456789012:key/1234abcd",
            "arn:aws:kms::123456789012:key/1234abcd",
            "arn:aws:kms:eu-central-1:12345:key/1234abcd",
            "arn:aws:kms:eu-central-1:123456789012:key/",
            "arn:aws:kms:eu-central-1:123456789012:key/a\"b",
            "arn:aws:kms:eu-central-1.evil.example:123456789012:key/1234abcd",
        ] {
            let mut bad = config();
            bad.key_arn = key.to_owned();
            assert!(AwsKmsWrap::new(&bad).is_err(), "key {key:?}");
        }
        for endpoint in [
            "http://kms.eu-central-1.amazonaws.com",
            "https://kms.eu-central-1.amazonaws.com/path",
            "https://kms.eu-central-1.amazonaws.com/?a=b",
        ] {
            let mut bad = config();
            bad.endpoint = Some(endpoint.to_owned());
            assert!(AwsKmsWrap::new(&bad).is_err(), "endpoint {endpoint:?}");
        }
        let mut bad = config();
        bad.credentials = AwsCredentialSource::File {
            path: "/nowhere".into(),
            profile: Some(String::new()),
        };
        assert!(AwsKmsWrap::new(&bad).is_err());
    }

    #[test]
    fn dates_are_as_sigv4_writes_them() {
        let at = |seconds| amz_dates(UNIX_EPOCH + Duration::from_secs(seconds));
        assert_eq!(
            at(0),
            ("19700101".to_owned(), "19700101T000000Z".to_owned())
        );
        assert_eq!(at(1_440_938_160).1, "20150830T123600Z");
        assert_eq!(at(1_709_251_199).1, "20240229T235959Z");
        assert_eq!(at(4_102_444_800).1, "21000101T000000Z");
    }

    /// seal's signature is the AWS SDK's, with and without a session token.
    #[test]
    fn the_signature_is_what_the_aws_sdk_makes() {
        let host = "kms.eu-central-1.amazonaws.com";
        for (index, token) in [None, Some("a/session+token==")].into_iter().enumerate() {
            let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000 + index as u64 * 86_399);
            let body = format!(r#"{{"KeyId":"{ARN}","n":{index}}}"#);
            let target = "TrentService.Decrypt";
            let credentials = Credentials {
                access_key_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
                secret_access_key: Zeroizing::new(
                    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
                ),
                session_token: token.map(|token| Zeroizing::new(token.to_owned())),
            };
            let ours = sign(
                &credentials,
                "eu-central-1",
                host,
                target,
                body.as_bytes(),
                now,
            )
            .unwrap();

            let identity = SdkCredentials::new(
                credentials.access_key_id.clone(),
                credentials.secret_access_key.as_str(),
                token.map(str::to_owned),
                None,
                "test",
            )
            .into();
            let params = v4::SigningParams::builder()
                .identity(&identity)
                .region("eu-central-1")
                .name("kms")
                .time(now)
                .settings(SigningSettings::default())
                .build()
                .unwrap()
                .into();
            let url = format!("https://{host}/");
            let headers = [
                ("host", host),
                ("content-type", CONTENT_TYPE),
                ("x-amz-target", target),
            ];
            let signable = SignableRequest::new(
                "POST",
                &url,
                headers.into_iter(),
                SignableBody::Bytes(body.as_bytes()),
            )
            .unwrap();
            let (instructions, _) = sdk_sign(signable, &params).unwrap().into_parts();
            let theirs: std::collections::BTreeMap<_, _> = instructions
                .headers()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect();
            assert_eq!(theirs["x-amz-date"], ours.amz_date);
            assert_eq!(
                theirs["authorization"],
                ours.authorization.to_str().unwrap()
            );
        }
    }
}
