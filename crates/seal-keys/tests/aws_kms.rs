//! The AWS KMS wrapper against a stand-in for the KMS.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use seal_format::id::KeyId;
use seal_format::{KeysetId, PrivateKey};
use seal_keys::{AwsKmsConfig, AwsKmsWrap, KeyError, KeyWrap};
use seal_testkit::mock_kms::serve_aws;
use seal_testkit::mock_provider::{Alpn, CannedResponse, MockProvider};
use seal_testkit::pki::TestPki;

const ARN: &str = "arn:aws:kms:eu-central-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab";
const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

struct Kms {
    provider: MockProvider,
    pki: TestPki,
    dir: tempfile::TempDir,
}

async fn kms() -> Kms {
    let pki = TestPki::new("KMS CA");
    let provider = MockProvider::tls_with(&pki, Alpn::Http1, &["localhost"], None).await;
    serve_aws(&provider, ARN, ACCESS_KEY);
    Kms {
        provider,
        pki,
        dir: tempfile::tempdir().unwrap(),
    }
}

fn write_private(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn credentials(kms: &Kms, text: &str) -> PathBuf {
    let path = kms.dir.path().join("credentials");
    write_private(&path, text);
    path
}

fn static_credentials(kms: &Kms) -> PathBuf {
    credentials(
        kms,
        &format!(
            "[default]\naws_access_key_id = {ACCESS_KEY}\naws_secret_access_key = {SECRET_KEY}\n"
        ),
    )
}

fn wrapper(kms: &Kms, credentials_file: PathBuf) -> AwsKmsWrap {
    AwsKmsWrap::new(&AwsKmsConfig {
        key_arn: ARN.to_owned(),
        credentials_file,
        profile: None,
        endpoint: Some(format!("https://localhost:{}", kms.provider.port())),
        ca_pem: Some(kms.pki.ca_pem.clone()),
        timeout: Duration::from_secs(5),
    })
    .unwrap()
}

fn keyset() -> KeysetId {
    KeysetId::new("acme").unwrap()
}

fn kid() -> KeyId {
    KeyId::new("k1").unwrap()
}

#[tokio::test]
async fn a_key_wrapped_by_the_kms_unwraps_to_the_same_key() {
    let kms = kms().await;
    let wrap = wrapper(&kms, static_credentials(&kms));
    let (key, public) = PrivateKey::generate();

    let wrapped = wrap.wrap(&keyset(), &kid(), &key).await.unwrap();
    assert!(!key.expose(|bytes| wrapped.windows(bytes.len()).any(|window| window == bytes)));
    let unwrapped = wrap.unwrap(&keyset(), &kid(), &wrapped).await.unwrap();
    assert_eq!(unwrapped.public_key().unwrap(), public);

    let received = kms.provider.received();
    let targets: Vec<_> = received
        .iter()
        .map(|request| request.header("x-amz-target").unwrap().to_owned())
        .collect();
    assert_eq!(
        targets,
        ["TrustedService.Encrypt", "TrustedService.Decrypt"]
    );
    let host = format!("localhost:{}", kms.provider.port());
    for request in &received {
        assert_eq!(
            (request.method.as_str(), request.uri.as_str()),
            ("POST", "/")
        );
        assert_eq!(request.header("host"), Some(host.as_str()));
        assert_eq!(request.header("x-amz-security-token"), None);
        let authorization = request.header("authorization").unwrap();
        assert!(authorization.contains(
            "/eu-central-1/kms/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature="
        ));
        assert!(!authorization.contains(SECRET_KEY));
    }
}

#[tokio::test]
async fn the_requests_are_what_the_kms_documents() {
    let kms = kms().await;
    let wrap = wrapper(&kms, static_credentials(&kms));
    let (key, _) = PrivateKey::generate();
    let wrapped = wrap.wrap(&keyset(), &kid(), &key).await.unwrap();
    wrap.unwrap(&keyset(), &kid(), &wrapped).await.unwrap();

    use base64::Engine;
    let base64 = base64::engine::general_purpose::STANDARD;
    let received = kms.provider.received();
    let encrypt: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
    let decrypt: serde_json::Value = serde_json::from_slice(&received[1].body).unwrap();
    let context = serde_json::json!({ "seal:keyset": "acme", "seal:kid": "k1" });
    assert_eq!(
        encrypt,
        serde_json::json!({
            "KeyId": ARN,
            "EncryptionContext": context,
            "Plaintext": key.expose(|bytes| base64.encode(bytes)),
        })
    );
    assert_eq!(
        decrypt,
        serde_json::json!({
            "KeyId": ARN,
            "EncryptionContext": context,
            "CiphertextBlob": base64.encode(&wrapped),
        })
    );
}

#[tokio::test]
async fn a_wrapped_key_does_not_unwrap_under_another_keyset_or_kid() {
    let kms = kms().await;
    let wrap = wrapper(&kms, static_credentials(&kms));
    let (key, _) = PrivateKey::generate();
    let wrapped = wrap.wrap(&keyset(), &kid(), &key).await.unwrap();

    let other_keyset = KeysetId::new("other").unwrap();
    let other_kid = KeyId::new("k2").unwrap();
    for (keyset, kid) in [(&other_keyset, &kid()), (&keyset(), &other_kid)] {
        assert_eq!(
            wrap.unwrap(keyset, kid, &wrapped).await.err(),
            Some(KeyError::Unavailable)
        );
    }
    assert!(wrap.unwrap(&keyset(), &kid(), &wrapped).await.is_ok());
}

#[tokio::test]
async fn temporary_credentials_send_their_session_token_signed() {
    let kms = kms().await;
    let file = credentials(
        &kms,
        &format!(
            "[default]\naws_access_key_id = {ACCESS_KEY}\naws_secret_access_key = {SECRET_KEY}\n\
             aws_session_token = a/session+token==\n"
        ),
    );
    let wrap = wrapper(&kms, file);
    let (key, _) = PrivateKey::generate();
    wrap.wrap(&keyset(), &kid(), &key).await.unwrap();
    let request = &kms.provider.received()[0];
    assert_eq!(
        request.header("x-amz-security-token"),
        Some("a/session+token==")
    );
    assert!(
        request.header("authorization").unwrap().contains(
            "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target,"
        )
    );
}

#[tokio::test]
async fn credentials_are_read_for_each_request_so_new_ones_need_no_restart() {
    let kms = kms().await;
    let file = credentials(
        &kms,
        "[default]\naws_access_key_id = AKIAREVOKED\naws_secret_access_key = old\n",
    );
    let wrap = wrapper(&kms, file.clone());
    let (key, _) = PrivateKey::generate();
    assert_eq!(
        wrap.wrap(&keyset(), &kid(), &key).await.err(),
        Some(KeyError::Unavailable)
    );
    static_credentials(&kms);
    assert!(wrap.wrap(&keyset(), &kid(), &key).await.is_ok());

    // Without credentials nothing is sent.
    let sent = kms.provider.received().len();
    std::fs::remove_file(&file).unwrap();
    assert_eq!(
        wrap.wrap(&keyset(), &kid(), &key).await.err(),
        Some(KeyError::Unavailable)
    );
    write_private(
        &file,
        "[other]\naws_access_key_id = A\naws_secret_access_key = b\n",
    );
    assert_eq!(
        wrap.wrap(&keyset(), &kid(), &key).await.err(),
        Some(KeyError::Unavailable)
    );
    assert_eq!(kms.provider.received().len(), sent);
}

#[cfg(unix)]
#[tokio::test]
async fn credentials_others_can_read_are_not_used() {
    use std::os::unix::fs::PermissionsExt;
    let kms = kms().await;
    let file = static_credentials(&kms);
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let wrap = wrapper(&kms, file);
    let (key, _) = PrivateKey::generate();
    assert_eq!(
        wrap.wrap(&keyset(), &kid(), &key).await.err(),
        Some(KeyError::Unavailable)
    );
    assert!(kms.provider.received().is_empty());
}

#[tokio::test]
async fn answers_that_are_not_what_the_kms_documents_are_refused() {
    let kms = kms().await;
    let wrap = wrapper(&kms, static_credentials(&kms));
    let (key, _) = PrivateKey::generate();
    let huge = format!(r#"{{"CiphertextBlob":"{}"}}"#, "QUFB".repeat(4000));
    let long = format!(r#"{{"Plaintext":"{}"}}"#, "QUFB".repeat(64));
    // A canned response for `/` answers both operations.
    for body in [
        "not json",
        "{}",
        r#"{"CiphertextBlob":""}"#,
        r#"{"CiphertextBlob":"not base64!"}"#,
        r#"{"CiphertextBlob":7}"#,
        huge.as_str(),
    ] {
        kms.provider
            .respond("/", CannedResponse::ok("application/json", body.as_bytes()));
        assert_eq!(
            wrap.wrap(&keyset(), &kid(), &key).await.err(),
            Some(KeyError::Unavailable),
            "{body:.40}"
        );
    }
    for body in [
        "not json",
        "{}",
        r#"{"Plaintext":"not base64!"}"#,
        r#"{"Plaintext":"c2hvcnQ="}"#,
        long.as_str(),
    ] {
        kms.provider
            .respond("/", CannedResponse::ok("application/json", body.as_bytes()));
        assert_eq!(
            wrap.unwrap(&keyset(), &kid(), b"anything").await.err(),
            Some(KeyError::Unavailable),
            "{body:.40}"
        );
    }
}

#[tokio::test]
async fn a_kms_with_a_certificate_from_another_ca_is_not_trusted() {
    let kms = kms().await;
    let wrap = AwsKmsWrap::new(&AwsKmsConfig {
        key_arn: ARN.to_owned(),
        credentials_file: static_credentials(&kms),
        profile: None,
        endpoint: Some(format!("https://localhost:{}", kms.provider.port())),
        ca_pem: Some(TestPki::new("someone else").ca_pem),
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    let (key, _) = PrivateKey::generate();
    assert_eq!(
        wrap.wrap(&keyset(), &kid(), &key).await.err(),
        Some(KeyError::Unavailable)
    );
    assert!(kms.provider.received().is_empty());
}
