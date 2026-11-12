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

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

use std::time::{Duration, Instant};

use seal_format::id::KeyId;
use seal_format::{KeysetId, PrivateKey};
use seal_keys::{KeyWrap, OvhKmsAuth, OvhKmsConfig, OvhKmsWrap};
use zeroize::Zeroizing;

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
    println!("authenticating with {:?}", config.auth);
    let wrap = OvhKmsWrap::new(&config).unwrap();
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
    changed[last] = if changed[last] == b'A' { b'B' } else { b'A' };
    assert!(wrap.unwrap(&keyset, &kid, &changed).await.is_err());
}
