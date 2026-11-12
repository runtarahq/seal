//! Where seal's AWS credentials come from: a shared credentials file, or the role the
//! host gives its workloads, from the container credentials endpoint (ECS, Fargate,
//! EKS Pod Identity) or the instance metadata service (EC2, IMDSv2 only).
//!
//! A file is read for every request. A role's credentials are kept until five minutes
//! before they expire, and then fetched again; if that fails, the ones in hand are used
//! for as long as they are valid.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode, header};
use http_body_util::Full;
use serde::Deserialize;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::KeyError;
use crate::https::send_plain;
use crate::wrap::check_private;

/// Where the container credentials endpoint is when only its path is given.
const CONTAINER_ADDRESS: Ipv4Addr = Ipv4Addr::new(169, 254, 170, 2);
/// The other addresses a container credentials endpoint may have: EKS Pod Identity's.
const POD_IDENTITY_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 170, 23);
const POD_IDENTITY_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x23);
/// The instance metadata service.
const METADATA_ADDRESS: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// The most a credential endpoint may answer with.
const RESPONSE_LIMIT: usize = 16 * 1024;
/// The longest one fetch of credentials may take, whatever a KMS request is allowed.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Credentials are fetched again this long before they expire.
const REFRESH_BEFORE_EXPIRY: Duration = Duration::from_secs(5 * 60);
/// After a fetch fails while valid credentials are in hand, the next is this much later.
const RETRY_AFTER: Duration = Duration::from_secs(30);
/// Credentials that do not say when they expire are fetched again after this long.
const UNDATED_LIFETIME: Duration = Duration::from_secs(5 * 60);
/// How long an instance metadata session lasts. Each fetch starts a new one.
const METADATA_SESSION_SECONDS: &str = "60";

/// What a container credentials endpoint is shown, if it asks for anything.
#[derive(Clone)]
pub enum ContainerToken {
    /// A file holding the token, read for every fetch, since the platform renews it.
    File(PathBuf),
    /// The token.
    Value(Zeroizing<String>),
}

impl std::fmt::Debug for ContainerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
            Self::Value(_) => f.write_str("Value(..)"),
        }
    }
}

/// Where seal's AWS credentials come from.
#[derive(Clone, Debug)]
pub enum AwsCredentialSource {
    /// A file in the AWS shared credentials format, readable only by seal's user. It is
    /// read for every request, so new credentials need no restart.
    File {
        /// The file.
        path: PathBuf,
        /// The profile in it. `default` if not given.
        profile: Option<String>,
    },
    /// The container credentials endpoint, over plain HTTP: the task role on ECS and
    /// Fargate, and the pod's role with EKS Pod Identity.
    Container {
        /// The endpoint's address.
        address: SocketAddr,
        /// The path, and query if any, that names seal's credentials.
        path: String,
        /// What to send as `Authorization`, if the endpoint asks for it.
        token: Option<ContainerToken>,
    },
    /// The instance metadata service, version 2, over plain HTTP: the role of the
    /// instance profile on EC2.
    InstanceMetadata {
        /// The service's address.
        address: SocketAddr,
    },
}

impl AwsCredentialSource {
    /// The role the host gives seal, as the AWS SDKs find it in the environment: the
    /// container credentials endpoint if `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or
    /// `AWS_CONTAINER_CREDENTIALS_FULL_URI` is set, and otherwise the instance metadata
    /// service. `variable` reads an environment variable.
    ///
    /// A full URI must be plain `http` to a loopback address or one of the addresses
    /// ECS and EKS use, so that the credentials' token is sent nowhere else.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if a variable is set to something seal will not
    /// use, or `AWS_EC2_METADATA_DISABLED` rules out the only source left.
    pub fn from_environment(variable: impl Fn(&str) -> Option<String>) -> Result<Self, KeyError> {
        let set = |name: &str| variable(name).filter(|value| !value.is_empty());
        let token = || {
            set("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
                .map(|path| ContainerToken::File(path.into()))
                .or_else(|| {
                    set("AWS_CONTAINER_AUTHORIZATION_TOKEN")
                        .map(|token| ContainerToken::Value(Zeroizing::new(token)))
                })
        };
        if let Some(path) = set("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
            if !path.starts_with('/') || !path.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Err(KeyError::Invalid(
                    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is not a path",
                ));
            }
            return Ok(Self::Container {
                address: SocketAddr::new(CONTAINER_ADDRESS.into(), 80),
                path,
                token: token(),
            });
        }
        if let Some(full) = set("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
            const REFUSED: KeyError = KeyError::Invalid(
                "AWS_CONTAINER_CREDENTIALS_FULL_URI must be plain http to a loopback, ECS or EKS address",
            );
            let url = url::Url::parse(&full).map_err(|_| REFUSED)?;
            let ip = match url.host() {
                Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
                Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
                _ => return Err(REFUSED),
            };
            let allowed = ip.is_loopback()
                || ip == IpAddr::V4(CONTAINER_ADDRESS)
                || ip == IpAddr::V4(POD_IDENTITY_V4)
                || ip == IpAddr::V6(POD_IDENTITY_V6);
            if url.scheme() != "http"
                || !allowed
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(REFUSED);
            }
            let mut path = url.path().to_owned();
            if let Some(query) = url.query() {
                path.push('?');
                path.push_str(query);
            }
            return Ok(Self::Container {
                address: SocketAddr::new(ip, url.port().unwrap_or(80)),
                path,
                token: token(),
            });
        }
        if set("AWS_EC2_METADATA_DISABLED").is_some_and(|value| value.eq_ignore_ascii_case("true"))
        {
            return Err(KeyError::Invalid(
                "no AWS credentials: no credentials file or container endpoint, and AWS_EC2_METADATA_DISABLED is set",
            ));
        }
        Ok(Self::InstanceMetadata {
            address: SocketAddr::new(METADATA_ADDRESS.into(), 80),
        })
    }

    /// What the source is called in a log.
    fn name(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Container { .. } => "container endpoint",
            Self::InstanceMetadata { .. } => "instance metadata",
        }
    }
}

/// seal's AWS credentials.
pub(crate) struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

fn visible(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Reads one profile of a shared credentials file: `[name]`, then `key = value` lines.
fn parse_file(text: &str, profile: &str) -> Option<Credentials> {
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

fn read_file(path: &Path, profile: &str) -> Result<Credentials, KeyError> {
    check_private(path)?;
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|_| KeyError::Invalid("the AWS credentials file cannot be read"))?,
    );
    parse_file(&text, profile).ok_or(KeyError::Invalid(
        "the AWS credentials file has no such profile with a key id and a secret key",
    ))
}

/// Days since the epoch of a date. Howard Hinnant's days-from-civil algorithm.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The time `2026-11-12T16:39:16Z` says, with or without a fraction of a second.
fn parse_expiration(text: &str) -> Option<SystemTime> {
    let text = text.strip_suffix('Z')?;
    let (text, _fraction) = text.split_once('.').unwrap_or((text, ""));
    let bytes = text.as_bytes();
    let punctuated = bytes.len() == 19
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            _ => byte.is_ascii_digit(),
        });
    if !punctuated {
        return None;
    }
    let number = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    let valid = (1970..=9999).contains(&year)
        && (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour < 24
        && minute < 60
        && second < 61;
    if !valid {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).ok()?))
}

/// What both endpoints answer with.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Answer {
    access_key_id: String,
    secret_access_key: String,
    token: Option<String>,
    expiration: Option<String>,
}

/// Why a fetch did not give credentials. Never holds what the endpoint said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    /// The token file could not be read, or holds no token.
    TokenFile,
    /// Nothing answered.
    Unreachable,
    /// The endpoint answered with this status.
    Status(u16),
    /// The answer is not credentials.
    NotCredentials,
    /// The instance has no role.
    NoRole,
    /// It took too long.
    Timeout,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenFile => f.write_str("the token file cannot be read or is empty"),
            Self::Unreachable => f.write_str("the endpoint cannot be reached"),
            Self::Status(status) => write!(f, "the endpoint answered {status}"),
            Self::NotCredentials => f.write_str("the answer is not credentials"),
            Self::NoRole => f.write_str("the instance has no role"),
            Self::Timeout => f.write_str("the endpoint did not answer in time"),
        }
    }
}

/// Credentials that were fetched, and for how long they are good.
struct Fetched {
    credentials: Arc<Credentials>,
    /// When to fetch again.
    refresh_at: SystemTime,
    /// When they stop working.
    expires: SystemTime,
}

fn parse_answer(body: &[u8], now: SystemTime) -> Result<Fetched, Failure> {
    let answer: Answer = serde_json::from_slice(body).map_err(|_| Failure::NotCredentials)?;
    let credentials = Credentials {
        access_key_id: answer.access_key_id,
        secret_access_key: Zeroizing::new(answer.secret_access_key),
        session_token: answer.token.map(Zeroizing::new),
    };
    let valid = visible(&credentials.access_key_id)
        && visible(&credentials.secret_access_key)
        && credentials
            .session_token
            .as_ref()
            .is_none_or(|token| visible(token));
    if !valid {
        return Err(Failure::NotCredentials);
    }
    let (refresh_at, expires) = match answer.expiration {
        Some(expiration) => {
            let expires = parse_expiration(&expiration).ok_or(Failure::NotCredentials)?;
            if expires <= now {
                return Err(Failure::NotCredentials);
            }
            let refresh_at = expires.checked_sub(REFRESH_BEFORE_EXPIRY).unwrap_or(now);
            (refresh_at, expires)
        }
        None => (now + UNDATED_LIFETIME, now + UNDATED_LIFETIME),
    };
    Ok(Fetched {
        credentials: Arc::new(credentials),
        refresh_at,
        expires,
    })
}

/// What goes in `Host` for an address.
fn authority(address: SocketAddr) -> String {
    match (address.ip(), address.port()) {
        (IpAddr::V4(ip), 80) => ip.to_string(),
        (IpAddr::V6(ip), 80) => format!("[{ip}]"),
        _ => address.to_string(),
    }
}

/// One request to a credential endpoint, and the body of a 200.
async fn ask(
    address: SocketAddr,
    method: Method,
    path: &str,
    headers: &[(&'static str, HeaderValue)],
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, authority(address))
        .body(Full::new(Bytes::new()))
        .map_err(|_| Failure::NotCredentials)?;
    for (name, value) in headers {
        request.headers_mut().insert(*name, value.clone());
    }
    match send_plain(address, request, RESPONSE_LIMIT).await {
        Ok((StatusCode::OK, body)) => Ok(body),
        Ok((status, _)) => Err(Failure::Status(status.as_u16())),
        Err(_) => Err(Failure::Unreachable),
    }
}

fn sensitive(value: &str) -> Option<HeaderValue> {
    let mut value = HeaderValue::from_str(value.trim()).ok()?;
    value.set_sensitive(true);
    Some(value)
}

async fn fetch_container(
    address: SocketAddr,
    path: &str,
    token: Option<&ContainerToken>,
) -> Result<Fetched, Failure> {
    let token = match token {
        None => None,
        Some(ContainerToken::Value(token)) => Some(token.clone()),
        Some(ContainerToken::File(file)) => Some(Zeroizing::new(
            tokio::fs::read_to_string(file)
                .await
                .map_err(|_| Failure::TokenFile)?,
        )),
    };
    let mut headers = Vec::new();
    if let Some(token) = token {
        let value = sensitive(&token)
            .filter(|value| !value.is_empty())
            .ok_or(Failure::TokenFile)?;
        headers.push(("authorization", value));
    }
    let body = ask(address, Method::GET, path, &headers).await?;
    parse_answer(&body, SystemTime::now())
}

async fn fetch_instance_metadata(address: SocketAddr) -> Result<Fetched, Failure> {
    const ROLES: &str = "/latest/meta-data/iam/security-credentials/";
    let session = ask(
        address,
        Method::PUT,
        "/latest/api/token",
        &[(
            "x-aws-ec2-metadata-token-ttl-seconds",
            HeaderValue::from_static(METADATA_SESSION_SECONDS),
        )],
    )
    .await?;
    let session = std::str::from_utf8(&session)
        .ok()
        .and_then(sensitive)
        .filter(|value| !value.is_empty())
        .ok_or(Failure::NotCredentials)?;
    let session = [("x-aws-ec2-metadata-token", session)];

    let roles = match ask(address, Method::GET, ROLES, &session).await {
        Err(Failure::Status(404)) => return Err(Failure::NoRole),
        other => other?,
    };
    let role = std::str::from_utf8(&roles)
        .ok()
        .and_then(|roles| roles.lines().next())
        .map(str::trim)
        .ok_or(Failure::NoRole)?;
    // A role name, as IAM allows it, and so nothing that changes the path.
    let named = !role.is_empty()
        && role.len() <= 64
        && role
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+=,.@_-".contains(&byte));
    if !named {
        return Err(Failure::NoRole);
    }
    let body = ask(address, Method::GET, &format!("{ROLES}{role}"), &session).await?;
    parse_answer(&body, SystemTime::now())
}

/// Gives the credentials to sign a request with.
pub(crate) struct CredentialProvider {
    source: AwsCredentialSource,
    profile: String,
    timeout: Duration,
    fetched: Mutex<Option<Fetched>>,
}

impl CredentialProvider {
    /// Reads and fetches nothing. `timeout` is how long a KMS request may take; a
    /// fetch of credentials is allowed no more than that, and no more than five seconds.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Invalid`] if a profile or a container path is not one.
    pub(crate) fn new(source: &AwsCredentialSource, timeout: Duration) -> Result<Self, KeyError> {
        let mut profile = "default".to_owned();
        match source {
            AwsCredentialSource::File {
                profile: Some(named),
                ..
            } => {
                if named.is_empty() {
                    return Err(KeyError::Invalid("the AWS profile is empty"));
                }
                profile.clone_from(named);
            }
            AwsCredentialSource::Container { path, .. }
                if !path.starts_with('/') || !path.bytes().all(|byte| byte.is_ascii_graphic()) =>
            {
                return Err(KeyError::Invalid(
                    "the container credentials path is not a path",
                ));
            }
            _ => {}
        }
        Ok(Self {
            source: source.clone(),
            profile,
            timeout: timeout.min(FETCH_TIMEOUT),
            fetched: Mutex::new(None),
        })
    }

    /// The credentials. A failure is logged, with why, and is `Unavailable`.
    pub(crate) async fn credentials(&self) -> Result<Arc<Credentials>, KeyError> {
        let source = self.source.name();
        if let AwsCredentialSource::File { path, .. } = &self.source {
            return match read_file(path, &self.profile) {
                Ok(credentials) => Ok(Arc::new(credentials)),
                Err(error) => {
                    tracing::warn!(kms = "aws", source, %error, "no AWS credentials");
                    Err(KeyError::Unavailable)
                }
            };
        }

        // Held across the fetch, so that requests arriving together fetch once.
        let mut fetched = self.fetched.lock().await;
        let now = SystemTime::now();
        if let Some(held) = fetched.as_ref()
            && now < held.refresh_at
        {
            return Ok(Arc::clone(&held.credentials));
        }
        let fetch = async {
            match &self.source {
                AwsCredentialSource::Container {
                    address,
                    path,
                    token,
                } => fetch_container(*address, path, token.as_ref()).await,
                AwsCredentialSource::InstanceMetadata { address } => {
                    fetch_instance_metadata(*address).await
                }
                AwsCredentialSource::File { .. } => Err(Failure::NotCredentials),
            }
        };
        let failure = match tokio::time::timeout(self.timeout, fetch).await {
            Ok(Ok(fresh)) => {
                let credentials = Arc::clone(&fresh.credentials);
                *fetched = Some(fresh);
                return Ok(credentials);
            }
            Ok(Err(failure)) => failure,
            Err(_) => Failure::Timeout,
        };
        match fetched.as_mut() {
            Some(held) if now < held.expires => {
                tracing::warn!(
                    kms = "aws",
                    source,
                    error = %failure,
                    "AWS credentials could not be renewed; using the ones in hand"
                );
                held.refresh_at = now + RETRY_AFTER;
                Ok(Arc::clone(&held.credentials))
            }
            _ => {
                *fetched = None;
                tracing::warn!(kms = "aws", source, error = %failure, "no AWS credentials");
                Err(KeyError::Unavailable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(pairs: &[(&str, &str)]) -> Result<AwsCredentialSource, KeyError> {
        AwsCredentialSource::from_environment(|name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn a_profile_is_read_from_a_shared_credentials_file() {
        let text = "# a comment\n[other]\naws_access_key_id = AKIAOTHER\naws_secret_access_key = no\n\n\
                    [default]\naws_access_key_id=AKIAEXAMPLE\n  aws_secret_access_key =  secret/with+signs==  \n\
                    region = eu-central-1\n; another comment\n[ temporary ]\naws_access_key_id = ASIAEXAMPLE\n\
                    aws_secret_access_key = temporary\naws_session_token = a-token\n";
        let default = parse_file(text, "default").unwrap();
        assert_eq!(default.access_key_id, "AKIAEXAMPLE");
        assert_eq!(default.secret_access_key.as_str(), "secret/with+signs==");
        assert!(default.session_token.is_none());
        let temporary = parse_file(text, "temporary").unwrap();
        assert_eq!(temporary.access_key_id, "ASIAEXAMPLE");
        assert_eq!(temporary.session_token.unwrap().as_str(), "a-token");

        assert!(parse_file(text, "missing").is_none());
        assert!(parse_file("[default]\naws_access_key_id = A\n", "default").is_none());
        assert!(
            parse_file(
                "aws_access_key_id = A\naws_secret_access_key = b\n",
                "default"
            )
            .is_none()
        );
        for bad in ["a b", "", "tab\there"] {
            let text = format!("[default]\naws_access_key_id = A\naws_secret_access_key = {bad}\n");
            assert!(parse_file(&text, "default").is_none(), "{bad:?}");
        }
    }

    #[test]
    fn an_expiration_is_read_as_the_time_it_says() {
        let at = |seconds| Some(UNIX_EPOCH + Duration::from_secs(seconds));
        assert_eq!(parse_expiration("1970-01-01T00:00:00Z"), at(0));
        assert_eq!(parse_expiration("2015-08-30T12:36:00Z"), at(1_440_938_160));
        assert_eq!(parse_expiration("2024-02-29T23:59:59Z"), at(1_709_251_199));
        assert_eq!(
            parse_expiration("2024-02-29T23:59:59.123456Z"),
            at(1_709_251_199)
        );
        assert_eq!(parse_expiration("2100-01-01T00:00:00Z"), at(4_102_444_800));
        for bad in [
            "",
            "2024-02-29T23:59:59",
            "2024-02-29T23:59:59+00:00",
            "2024-02-29 23:59:59Z",
            "2024-13-01T00:00:00Z",
            "2024-02-29T24:00:00Z",
            "1969-12-31T23:59:59Z",
            "24-02-29T23:59:59Z",
            "2024-02-29T23:59:5Z",
        ] {
            assert_eq!(parse_expiration(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn an_answer_gives_credentials_to_renew_before_they_expire() {
        let now = UNIX_EPOCH + Duration::from_secs(1_709_251_199 - 3600);
        let body = br#"{"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"ASIAEXAMPLE",
            "SecretAccessKey":"a/secret","Token":"a+token==","Expiration":"2024-02-29T23:59:59Z"}"#;
        let fetched = parse_answer(body, now).unwrap();
        assert_eq!(fetched.credentials.access_key_id, "ASIAEXAMPLE");
        assert_eq!(fetched.credentials.secret_access_key.as_str(), "a/secret");
        assert_eq!(
            fetched.credentials.session_token.as_ref().unwrap().as_str(),
            "a+token=="
        );
        assert_eq!(fetched.expires, now + Duration::from_secs(3600));
        assert_eq!(fetched.refresh_at, now + Duration::from_secs(3300));

        let undated = br#"{"AccessKeyId":"AKIAEXAMPLE","SecretAccessKey":"a/secret"}"#;
        let fetched = parse_answer(undated, now).unwrap();
        assert!(fetched.credentials.session_token.is_none());
        assert_eq!(fetched.refresh_at, now + UNDATED_LIFETIME);

        let later = now + Duration::from_secs(3600);
        for (bad, at) in [
            (&body[..], later),
            (&br#"{"AccessKeyId":"A"}"#[..], now),
            (&br#"{"AccessKeyId":"","SecretAccessKey":"s"}"#[..], now),
            (&br#"{"AccessKeyId":"A","SecretAccessKey":"a b"}"#[..], now),
            (
                &br#"{"AccessKeyId":"A","SecretAccessKey":"s","Expiration":"soon"}"#[..],
                now,
            ),
            (&br#"{"Code":"AssumeRoleUnauthorizedAccess"}"#[..], now),
            (&b"<html>"[..], now),
        ] {
            assert_eq!(
                parse_answer(bad, at).err(),
                Some(Failure::NotCredentials),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn the_environment_says_where_the_role_is() {
        let Ok(AwsCredentialSource::InstanceMetadata { address }) = environment(&[]) else {
            panic!("not instance metadata");
        };
        assert_eq!(address.to_string(), "169.254.169.254:80");
        assert!(environment(&[("AWS_EC2_METADATA_DISABLED", "TRUE")]).is_err());
        assert!(environment(&[("AWS_EC2_METADATA_DISABLED", "false")]).is_ok());

        let Ok(AwsCredentialSource::Container {
            address,
            path,
            token: None,
        }) = environment(&[
            (
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                "/v2/credentials/1",
            ),
            ("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://127.0.0.1/no"),
            ("AWS_EC2_METADATA_DISABLED", "true"),
        ])
        else {
            panic!("not the container endpoint");
        };
        assert_eq!(address.to_string(), "169.254.170.2:80");
        assert_eq!(path, "/v2/credentials/1");

        let Ok(AwsCredentialSource::Container {
            address,
            path,
            token: Some(ContainerToken::File(file)),
        }) = environment(&[
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "http://169.254.170.23/v1/credentials?a=b",
            ),
            ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/var/run/token"),
            ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "not this"),
        ])
        else {
            panic!("not the container endpoint");
        };
        assert_eq!(address.to_string(), "169.254.170.23:80");
        assert_eq!(path, "/v1/credentials?a=b");
        assert_eq!(file, PathBuf::from("/var/run/token"));

        let Ok(AwsCredentialSource::Container {
            address,
            token: Some(token @ ContainerToken::Value(_)),
            ..
        }) = environment(&[
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "http://[fd00:ec2::23]:8080/v1/credentials",
            ),
            ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "a-secret-token"),
        ])
        else {
            panic!("not the container endpoint");
        };
        assert_eq!(address.to_string(), "[fd00:ec2::23]:8080");
        assert!(!format!("{token:?}").contains("a-secret-token"));

        for full in [
            "https://169.254.170.2/v1/credentials",
            "http://169.254.169.254/latest",
            "http://10.0.0.1/v1/credentials",
            "http://localhost/v1/credentials",
            "http://example.com/v1/credentials",
            "http://user@127.0.0.1/v1/credentials",
            "not a url",
        ] {
            assert!(
                environment(&[("AWS_CONTAINER_CREDENTIALS_FULL_URI", full)]).is_err(),
                "{full:?}"
            );
        }
        for relative in ["v2/credentials", "/v2/cred entials"] {
            assert!(
                environment(&[("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", relative)]).is_err(),
                "{relative:?}"
            );
        }
    }

    #[test]
    fn host_is_the_address_without_the_default_port() {
        let host = |address: &str| authority(address.parse().unwrap());
        assert_eq!(host("169.254.169.254:80"), "169.254.169.254");
        assert_eq!(host("127.0.0.1:8080"), "127.0.0.1:8080");
        assert_eq!(host("[fd00:ec2::23]:80"), "[fd00:ec2::23]");
        assert_eq!(host("[::1]:8080"), "[::1]:8080");
    }
}
