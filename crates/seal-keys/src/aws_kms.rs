//! Wrapping with a key in AWS KMS, so that the wrapping key never leaves the KMS: seal
//! sends each private key to `Encrypt` or `Decrypt`, with the AWS SDK.
//!
//! The keyset and kid go as the encryption context, `seal:keyset` and `seal:kid`, so a
//! wrapped key moved to another keyset or kid does not unwrap, and each use shows in
//! CloudTrail under its keyset. What is stored is the KMS's `CiphertextBlob`.
//!
//! seal's credentials are a file it reads for every request, or whatever the SDK's
//! default chain finds: the environment, the shared files, a web identity token, the
//! container credentials endpoint or the instance metadata service.
//!
//! Only in a build with the `aws-kms` feature.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use aws_config::default_provider::credentials::DefaultCredentialsChain;
use aws_config::provider_config::ProviderConfig;
use aws_credential_types::provider::error::CredentialsError;
use aws_credential_types::provider::future::ProvideCredentials as ProvidingCredentials;
use aws_sdk_kms::Client;
use aws_sdk_kms::config::http::HttpResponse;
use aws_sdk_kms::config::retry::RetryConfig;
use aws_sdk_kms::config::timeout::TimeoutConfig;
use aws_sdk_kms::config::{
    BehaviorVersion, IdentityCache, ProvideCredentials, Region, SharedHttpClient,
};
use aws_sdk_kms::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_kms::primitives::Blob;
use aws_smithy_http_client::tls::rustls_provider::CryptoMode;
use aws_smithy_http_client::tls::{Provider, TlsContext, TrustStore};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use seal_format::id::KeyId;
use seal_format::{KeysetId, PrivateKey};
use tokio::sync::OnceCell;
use zeroize::Zeroizing;

use crate::KeyError;
use crate::https::{Https, Names, Roots};
use crate::kms::count;
use crate::source::MAX_WRAPPED_KEY_BYTES;
use crate::wrap::{KeyWrap, check_private};

/// Where seal's AWS credentials come from.
#[derive(Clone, Debug)]
pub enum AwsCredentials {
    /// A file in the AWS shared credentials format, readable only by seal's user. It is
    /// read for every request, so new credentials need no restart.
    File {
        /// The file.
        path: PathBuf,
        /// The profile in it. `default` if not given.
        profile: Option<String>,
    },
    /// What the AWS SDK finds, in its usual order: the environment, the shared
    /// credentials and configuration files, a web identity token, the container
    /// credentials endpoint, and the instance metadata service.
    Found {
        /// The profile in the shared files. `AWS_PROFILE` or `default` if not given.
        profile: Option<String>,
    },
}

/// How to reach a KMS key.
#[derive(Clone, Debug)]
pub struct AwsKmsConfig {
    /// The key's ARN, `arn:aws:kms:<region>:<account>:key/<id>`. A symmetric key that
    /// may encrypt and decrypt. Not an alias, which can be pointed at another key.
    pub key_arn: String,
    /// Where seal's credentials come from.
    pub credentials: AwsCredentials,
    /// The endpoint, if it is not the region's public one: a VPC or FIPS endpoint.
    pub endpoint: Option<String>,
    /// The CA that issued the endpoint's certificate, in PEM, if it is not a public one.
    pub ca_pem: Option<String>,
    /// How long one request may take, with its retries.
    pub timeout: Duration,
}

/// Wraps with a key in AWS KMS.
pub struct AwsKmsWrap {
    key_arn: String,
    region: String,
    id: String,
    credentials: AwsCredentials,
    endpoint: Option<String>,
    timeout: Duration,
    /// Reaches the KMS: verified against the configured CA, or the public roots.
    kms_http: SharedHttpClient,
    /// Reaches whatever gives credentials: verified against the public roots.
    credentials_http: SharedHttpClient,
    /// Made on first use, since finding the credentials' sources is asynchronous.
    client: OnceCell<Client>,
}

impl std::fmt::Debug for AwsKmsWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKmsWrap")
            .field("id", &self.id)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

const NAMES: Names = Names {
    url: "the KMS endpoint",
    not_https: "the KMS endpoint must be plain https",
    no_host: "the KMS endpoint has no host",
    ca: "the KMS CA",
};

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

/// Credentials from a file.
struct Credentials {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

/// Reads one profile of a shared credentials file: `[name]`, then `key = value` lines.
fn parse_credentials(text: &str, profile: &str) -> Option<Credentials> {
    let (mut inside, mut id, mut secret, mut token) = (false, None, None, None);
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            inside = section.trim() == profile;
            continue;
        }
        if !inside {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match name.trim() {
            "aws_access_key_id" => id = Some(value.to_owned()),
            "aws_secret_access_key" => secret = Some(Zeroizing::new(value.to_owned())),
            "aws_session_token" => token = Some(Zeroizing::new(value.to_owned())),
            _ => {}
        }
    }
    let visible = |value: &str| !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic());
    let (access_key_id, secret_access_key) = (id?, secret?);
    let valid = visible(&access_key_id)
        && visible(&secret_access_key)
        && token.as_ref().is_none_or(|token| visible(token));
    valid.then_some(Credentials {
        access_key_id,
        secret_access_key,
        session_token: token,
    })
}

fn read_credentials(path: &Path, profile: &str) -> Result<Credentials, KeyError> {
    if !path.exists() {
        return Err(KeyError::Invalid("the AWS credentials file does not exist"));
    }
    check_private(path)?;
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|_| KeyError::Invalid("the AWS credentials file cannot be read"))?,
    );
    parse_credentials(&text, profile).ok_or(KeyError::Invalid(
        "the AWS credentials file has no such profile with a key id and a secret key",
    ))
}

/// Gives the credentials in a file, read anew each time it is asked.
#[derive(Debug)]
struct CredentialsFile {
    path: PathBuf,
    profile: String,
}

impl ProvideCredentials for CredentialsFile {
    fn provide_credentials<'a>(&'a self) -> ProvidingCredentials<'a>
    where
        Self: 'a,
    {
        ProvidingCredentials::ready(
            read_credentials(&self.path, &self.profile)
                .map(|credentials| {
                    aws_sdk_kms::config::Credentials::new(
                        credentials.access_key_id,
                        credentials.secret_access_key.as_str(),
                        credentials
                            .session_token
                            .map(|token| token.as_str().to_owned()),
                        None,
                        "seal's credentials file",
                    )
                })
                .map_err(|error| CredentialsError::not_loaded(error.to_string())),
        )
    }
}

/// The public roots, as the PEM the SDK's HTTP client takes.
fn public_roots() -> String {
    let mut pem = String::new();
    for certificate in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        let encoded = STANDARD.encode(certificate.as_ref());
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(line));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
    }
    pem
}

/// An HTTP client for the SDK that trusts these certificates and no others: not the
/// platform's, which a minimal container image does not have.
fn http_client(roots_pem: &str) -> Result<SharedHttpClient, KeyError> {
    // Checked here, since the client panics on a certificate it cannot read.
    let certificates = CertificateDer::pem_slice_iter(roots_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| KeyError::Invalid(NAMES.ca))?;
    let mut store = rustls::RootCertStore::empty();
    for certificate in certificates {
        store
            .add(certificate)
            .map_err(|_| KeyError::Invalid(NAMES.ca))?;
    }
    if store.is_empty() {
        return Err(KeyError::Invalid(NAMES.ca));
    }
    let context = TlsContext::builder()
        .with_trust_store(TrustStore::empty().with_pem_certificate(roots_pem.as_bytes()))
        .build()
        .map_err(|_| KeyError::Invalid(NAMES.ca))?;
    Ok(aws_smithy_http_client::Builder::new()
        .tls_provider(Provider::Rustls(CryptoMode::Ring))
        .tls_context(context)
        .build_https())
}

impl AwsKmsWrap {
    /// Configures the wrapper. Connects to nothing, and does not look for the
    /// credentials.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if the ARN, the endpoint, the CA or a profile is
    /// not valid.
    pub fn new(config: &AwsKmsConfig) -> Result<Self, KeyError> {
        let (_, region) = region_of(&config.key_arn)
            .ok_or(KeyError::Invalid("the KMS key must be a key's ARN"))?;
        if let Some(endpoint) = &config.endpoint {
            // Held to what seal asks of any HTTPS endpoint it is configured with.
            let https = Https::new(endpoint, Roots::Public, None, NAMES)?;
            if !https.base_path().is_empty() {
                return Err(KeyError::Invalid("the KMS endpoint must have no path"));
            }
        }
        let (AwsCredentials::File { profile, .. } | AwsCredentials::Found { profile }) =
            &config.credentials;
        if profile.as_ref().is_some_and(String::is_empty) {
            return Err(KeyError::Invalid("the AWS profile is empty"));
        }
        let public = public_roots();
        let credentials_http = http_client(&public)?;
        let kms_http = match &config.ca_pem {
            Some(ca) => http_client(ca)?,
            None => credentials_http.clone(),
        };
        Ok(Self {
            id: format!("aws-kms:{}", config.key_arn),
            key_arn: config.key_arn.clone(),
            region: region.to_owned(),
            credentials: config.credentials.clone(),
            endpoint: config.endpoint.clone(),
            timeout: config.timeout,
            kms_http,
            credentials_http,
            client: OnceCell::new(),
        })
    }

    /// The SDK's client. The region, endpoint and CA are the configured ones, whatever
    /// the environment or the shared files say; only credentials are looked for there.
    async fn client(&self) -> &Client {
        self.client
            .get_or_init(|| async {
                let region = Region::new(self.region.clone());
                let mut config = aws_sdk_kms::Config::builder()
                    .behavior_version(BehaviorVersion::latest())
                    .region(region.clone())
                    .http_client(self.kms_http.clone())
                    .retry_config(RetryConfig::standard())
                    .timeout_config(
                        TimeoutConfig::builder()
                            .operation_timeout(self.timeout)
                            .build(),
                    );
                if let Some(endpoint) = &self.endpoint {
                    config = config.endpoint_url(endpoint);
                }
                config = match &self.credentials {
                    AwsCredentials::File { path, profile } => config
                        .credentials_provider(CredentialsFile {
                            path: path.clone(),
                            profile: profile.clone().unwrap_or_else(|| "default".to_owned()),
                        })
                        // The file is read for every request.
                        .identity_cache(IdentityCache::no_cache()),
                    AwsCredentials::Found { profile } => {
                        let mut chain = DefaultCredentialsChain::builder()
                            .configure(
                                ProviderConfig::without_region()
                                    .with_region(Some(region.clone()))
                                    .with_http_client(self.credentials_http.clone()),
                            )
                            .region(region);
                        if let Some(profile) = profile {
                            chain = chain.profile_name(profile);
                        }
                        config.credentials_provider(chain.build().await)
                    }
                };
                Client::from_conf(config.build())
            })
            .await
    }
}

/// What went wrong, as each error in the chain describes itself. Not their debug form,
/// which holds whole responses, and so may hold a token or a credential.
fn described(error: &(dyn std::error::Error + 'static)) -> String {
    const LONGEST: usize = 400;
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    if text.len() > LONGEST {
        let mut end = LONGEST;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// Counts and logs a request that the KMS did not do, and makes it `Unavailable`.
fn failed<E>(operation: &'static str, error: &SdkError<E, HttpResponse>) -> KeyError
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
{
    match error {
        SdkError::ServiceError(refusal) => {
            count("aws", operation, "refused");
            let kind = refusal.err().code().filter(|kind| {
                kind.len() <= 96
                    && kind
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"#._".contains(&byte))
            });
            tracing::warn!(
                kms = "aws",
                operation,
                status = refusal.raw().status().as_u16(),
                error = kind,
                "the KMS refused a request"
            );
        }
        SdkError::TimeoutError(_) => {
            count("aws", operation, "timeout");
            tracing::warn!(kms = "aws", operation, "the KMS did not answer in time");
        }
        other => {
            count("aws", operation, "unreachable");
            tracing::warn!(
                kms = "aws",
                operation,
                error = described(other),
                "the KMS could not be asked"
            );
        }
    }
    KeyError::Unavailable
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
        let answer = self
            .client()
            .await
            .encrypt()
            .key_id(&self.key_arn)
            .encryption_context("seal:keyset", keyset.as_str())
            .encryption_context("seal:kid", kid.as_str())
            .plaintext(key.expose(|bytes| Blob::new(bytes)))
            .send()
            .await
            .map_err(|error| failed("encrypt", &error))?;
        count("aws", "encrypt", "ok");
        let wrapped = answer
            .ciphertext_blob
            .map(Blob::into_inner)
            .ok_or(KeyError::Unavailable)?;
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
        let answer = self
            .client()
            .await
            .decrypt()
            // Named, so that the KMS refuses a ciphertext from any other key.
            .key_id(&self.key_arn)
            .encryption_context("seal:keyset", keyset.as_str())
            .encryption_context("seal:kid", kid.as_str())
            .ciphertext_blob(Blob::new(wrapped))
            .send()
            .await
            .map_err(|error| failed("decrypt", &error))?;
        count("aws", "decrypt", "ok");
        let plaintext = Zeroizing::new(
            answer
                .plaintext
                .map(Blob::into_inner)
                .ok_or(KeyError::Unavailable)?,
        );
        PrivateKey::from_bytes(&plaintext).map_err(|_| KeyError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARN: &str =
        "arn:aws:kms:eu-central-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    fn config() -> AwsKmsConfig {
        AwsKmsConfig {
            key_arn: ARN.to_owned(),
            credentials: AwsCredentials::Found { profile: None },
            endpoint: None,
            ca_pem: None,
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn the_region_and_id_come_from_the_arn() {
        let wrap = AwsKmsWrap::new(&config()).unwrap();
        assert_eq!(wrap.id(), format!("aws-kms:{ARN}"));
        assert_eq!(wrap.region, "eu-central-1");

        let mut china = config();
        china.key_arn = ARN
            .replace("arn:aws:", "arn:aws-cn:")
            .replace("eu-central-1", "cn-north-1");
        assert_eq!(AwsKmsWrap::new(&china).unwrap().region, "cn-north-1");

        let mut multi_region = config();
        multi_region.key_arn =
            "arn:aws:kms:us-east-1:123456789012:key/mrk-1234abcd12ab34cd56ef1234567890ab"
                .to_owned();
        assert!(AwsKmsWrap::new(&multi_region).is_ok());

        let mut elsewhere = config();
        elsewhere.endpoint = Some("https://vpce-1.kms.eu-central-1.vpce.amazonaws.com".to_owned());
        assert!(AwsKmsWrap::new(&elsewhere).is_ok());
    }

    #[test]
    fn only_a_keys_arn_a_plain_endpoint_and_a_readable_ca_are_accepted() {
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
        for ca in [
            "",
            "not a certificate",
            "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n",
        ] {
            let mut bad = config();
            bad.ca_pem = Some(ca.to_owned());
            assert!(AwsKmsWrap::new(&bad).is_err(), "CA {ca:?}");
        }
        for credentials in [
            AwsCredentials::Found {
                profile: Some(String::new()),
            },
            AwsCredentials::File {
                path: "/nowhere".into(),
                profile: Some(String::new()),
            },
        ] {
            let mut bad = config();
            bad.credentials = credentials;
            assert!(AwsKmsWrap::new(&bad).is_err());
        }
    }

    #[test]
    fn the_public_roots_are_certificates_the_client_takes() {
        let pem = public_roots();
        let read = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(read.len(), webpki_root_certs::TLS_SERVER_ROOT_CERTS.len());
        assert!(read.len() > 50);
        assert!(http_client(&pem).is_ok());
    }

    #[test]
    fn a_profile_is_read_from_a_shared_credentials_file() {
        let text = "# a comment\n[other]\naws_access_key_id = AKIAOTHER\naws_secret_access_key = no\n\n\
                    [default]\naws_access_key_id=AKIAEXAMPLE\n  aws_secret_access_key =  secret/with+signs==  \n\
                    region = eu-central-1\n; another comment\n[ temporary ]\naws_access_key_id = ASIAEXAMPLE\n\
                    aws_secret_access_key = temporary\naws_session_token = a-token\n";
        let default = parse_credentials(text, "default").unwrap();
        assert_eq!(default.access_key_id, "AKIAEXAMPLE");
        assert_eq!(default.secret_access_key.as_str(), "secret/with+signs==");
        assert!(default.session_token.is_none());
        let temporary = parse_credentials(text, "temporary").unwrap();
        assert_eq!(temporary.access_key_id, "ASIAEXAMPLE");
        assert_eq!(temporary.session_token.unwrap().as_str(), "a-token");

        assert!(parse_credentials(text, "missing").is_none());
        assert!(parse_credentials("[default]\naws_access_key_id = A\n", "default").is_none());
        assert!(
            parse_credentials(
                "aws_access_key_id = A\naws_secret_access_key = b\n",
                "default"
            )
            .is_none()
        );
        for bad in ["a b", "", "tab\there"] {
            let text = format!("[default]\naws_access_key_id = A\naws_secret_access_key = {bad}\n");
            assert!(parse_credentials(&text, "default").is_none(), "{bad:?}");
        }
    }
}
