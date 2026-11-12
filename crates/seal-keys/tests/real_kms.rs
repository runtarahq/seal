//! The KMS wrappers against the real services, with credentials from the environment.
//! Ignored by default; each test skips if its settings are not there.
//!
//! OVHcloud KMS:
//!
//! - `SEAL_TEST_OVH_KMS_ENDPOINT`: such as `https://eu-central-waw.okms.ovh.net`.
//! - `SEAL_TEST_OVH_KMS_OKMS_ID` and `SEAL_TEST_OVH_KMS_KEY_ID`: the KMS, and an AES
//!   service key in it that may encrypt and decrypt.
//! - `SEAL_TEST_OVH_KMS_TOKEN_FILE`, a file holding a personal access token; or
//!   `SEAL_TEST_OVH_KMS_CERT` and `SEAL_TEST_OVH_KMS_KEY`, an access certificate and its
//!   key, in PEM.
//!
//! AWS KMS:
//!
//! - `SEAL_TEST_AWS_KMS_KEY_ARN`: a symmetric key that may encrypt and decrypt.
//! - `SEAL_TEST_AWS_KMS_CREDENTIALS_FILE`: a shared credentials file that only its
//!   owner can read, such as `~/.aws/credentials`, and optionally
//!   `SEAL_TEST_AWS_KMS_PROFILE`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

use std::time::{Duration, Instant};

use seal_format::id::KeyId;
use seal_format::{KeysetId, PrivateKey};
use seal_keys::{AwsKmsConfig, AwsKmsWrap, KeyWrap, OvhKmsAuth, OvhKmsConfig, OvhKmsWrap};
use seal_testkit::log_capture::LogCapture;
use tracing::dispatcher::DefaultGuard;
use zeroize::Zeroizing;

/// Prints what was logged when the test ends, pass or fail: a wrapper says only
/// `Unavailable`, and the log says why.
struct Logs {
    capture: LogCapture,
    _guard: DefaultGuard,
}

impl Logs {
    fn print_at_the_end() -> Self {
        let capture = LogCapture::new();
        let guard = capture.install();
        Self {
            capture,
            _guard: guard,
        }
    }
}

impl Drop for Logs {
    fn drop(&mut self) {
        let logged = self.capture.contents();
        if !logged.is_empty() {
            println!("logged:\n{logged}");
        }
    }
}

fn setting(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn file(name: &str) -> Option<String> {
    let path = setting(name)?;
    Some(std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("cannot read {path}")))
}

fn ovh() -> Option<OvhKmsConfig> {
    let auth = match (
        file("SEAL_TEST_OVH_KMS_TOKEN_FILE"),
        file("SEAL_TEST_OVH_KMS_CERT"),
        file("SEAL_TEST_OVH_KMS_KEY"),
    ) {
        (Some(token), _, _) => OvhKmsAuth::Token(Zeroizing::new(token)),
        (None, Some(cert_pem), Some(key_pem)) => OvhKmsAuth::Certificate {
            cert_pem,
            key_pem: Zeroizing::new(key_pem),
        },
        _ => return None,
    };
    Some(OvhKmsConfig {
        endpoint: setting("SEAL_TEST_OVH_KMS_ENDPOINT")?,
        okms_id: setting("SEAL_TEST_OVH_KMS_OKMS_ID")?,
        key_id: setting("SEAL_TEST_OVH_KMS_KEY_ID")?,
        auth,
        ca_pem: None,
        timeout: Duration::from_secs(10),
    })
}

#[tokio::test]
#[ignore = "needs an OVHcloud KMS service key"]
async fn ovh_kms_wraps_and_unwraps_a_key() {
    let Some(config) = ovh() else {
        println!("skipped: the SEAL_TEST_OVH_KMS_* settings are not all set");
        return;
    };
    let _logs = Logs::print_at_the_end();
    println!("authenticating with {:?}", config.auth);
    round_trip(&OvhKmsWrap::new(&config).unwrap(), true).await;
}

#[tokio::test]
#[ignore = "needs a key in AWS KMS"]
async fn aws_kms_wraps_and_unwraps_a_key() {
    let (Some(key_arn), Some(credentials_file)) = (
        setting("SEAL_TEST_AWS_KMS_KEY_ARN"),
        setting("SEAL_TEST_AWS_KMS_CREDENTIALS_FILE"),
    ) else {
        println!("skipped: the SEAL_TEST_AWS_KMS_* settings are not all set");
        return;
    };
    let _logs = Logs::print_at_the_end();
    let wrap = AwsKmsWrap::new(&AwsKmsConfig {
        key_arn,
        credentials_file: credentials_file.into(),
        profile: setting("SEAL_TEST_AWS_KMS_PROFILE"),
        endpoint: None,
        ca_pem: None,
        timeout: Duration::from_secs(10),
    })
    .unwrap();
    round_trip(&wrap, false).await;
}

/// Wraps a new key, unwraps it, and checks that nothing else unwraps. `text` says the
/// wrapped key is text, of which a character is changed rather than a bit.
async fn round_trip(wrap: &dyn KeyWrap, text: bool) {
    let keyset = KeysetId::new("seal-real-kms-test").unwrap();
    let kid = KeyId::new("k1").unwrap();
    let (key, public) = PrivateKey::generate();

    let started = Instant::now();
    let wrapped = wrap
        .wrap(&keyset, &kid, &key)
        .await
        .expect("the KMS encrypts");
    println!(
        "wrapped in {:?}: {} bytes, wrap id {}",
        started.elapsed(),
        wrapped.len(),
        wrap.id()
    );
    assert!(!key.expose(|bytes| wrapped.windows(bytes.len()).any(|window| window == bytes)));

    let started = Instant::now();
    let unwrapped = wrap
        .unwrap(&keyset, &kid, &wrapped)
        .await
        .expect("the KMS decrypts");
    println!("unwrapped in {:?}", started.elapsed());
    assert_eq!(unwrapped.public_key().unwrap(), public);

    // The context binds the wrapped key to its keyset and kid.
    let other_keyset = KeysetId::new("seal-real-kms-other").unwrap();
    let other_kid = KeyId::new("k2").unwrap();
    assert!(wrap.unwrap(&other_keyset, &kid, &wrapped).await.is_err());
    assert!(wrap.unwrap(&keyset, &other_kid, &wrapped).await.is_err());

    // A changed ciphertext does not decrypt.
    let mut changed = wrapped.clone();
    let last = changed.len() - 2;
    changed[last] = match (text, changed[last]) {
        (true, b'A') => b'B',
        (true, _) => b'A',
        (false, byte) => byte ^ 1,
    };
    assert!(wrap.unwrap(&keyset, &kid, &changed).await.is_err());
}
