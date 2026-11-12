//! The AWS KMS wrapper against a stand-in for the KMS.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use seal_format::id::KeyId;
use seal_format::{KeysetId, PrivateKey};
use seal_keys::{AwsCredentialSource, AwsKmsConfig, AwsKmsWrap, ContainerToken, KeyError, KeyWrap};
use seal_testkit::mock_kms::{
    AWS_METADATA_SESSION, AwsRoleCredentials, aws_role_credentials, serve_aws,
    serve_aws_container_credentials, serve_aws_instance_metadata,
};
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
    wrapper_with(
        kms,
        AwsCredentialSource::File {
            path: credentials_file,
            profile: None,
        },
    )
}

fn wrapper_with(kms: &Kms, credentials: AwsCredentialSource) -> AwsKmsWrap {
    AwsKmsWrap::new(&AwsKmsConfig {
        key_arn: ARN.to_owned(),
        credentials,
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
    assert_eq!(targets, ["TrentService.Encrypt", "TrentService.Decrypt"]);
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
        credentials: AwsCredentialSource::File {
            path: static_credentials(&kms),
            profile: None,
        },
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

const HOUR: Duration = Duration::from_secs(3600);

fn role(access_key_id: &str, lifetime: Duration) -> AwsRoleCredentials {
    std::sync::Arc::new(std::sync::Mutex::new(aws_role_credentials(
        access_key_id,
        lifetime,
    )))
}

fn paths(provider: &MockProvider) -> Vec<String> {
    provider
        .received()
        .iter()
        .map(|request| format!("{} {}", request.method, request.uri))
        .collect()
}

#[tokio::test]
async fn an_instance_profile_gives_the_credentials_and_they_are_kept() {
    let kms = kms().await;
    let metadata = MockProvider::plain().await;
    let credentials = role(ACCESS_KEY, HOUR);
    serve_aws_instance_metadata(&metadata, Some("seal-role"), &credentials);
    let wrap = wrapper_with(
        &kms,
        AwsCredentialSource::InstanceMetadata {
            address: metadata.address(),
        },
    );
    let (key, public) = PrivateKey::generate();

    let wrapped = wrap.wrap(&keyset(), &kid(), &key).await.unwrap();
    let unwrapped = wrap.unwrap(&keyset(), &kid(), &wrapped).await.unwrap();
    assert_eq!(unwrapped.public_key().unwrap(), public);

    // Version 2: a session first, then the role's name, then its credentials. Once.
    assert_eq!(
        paths(&metadata),
        [
            "PUT /latest/api/token",
            "GET /latest/meta-data/iam/security-credentials/",
            "GET /latest/meta-data/iam/security-credentials/seal-role",
        ]
    );
    let asked = metadata.received();
    let host = metadata.address().to_string();
    for request in &asked {
        assert_eq!(request.header("host"), Some(host.as_str()));
    }
    assert!(asked[0].header("x-aws-ec2-metadata-token").is_none());
    assert_eq!(
        asked[2].header("x-aws-ec2-metadata-token"),
        Some(AWS_METADATA_SESSION)
    );

    let token = format!("session-of-{ACCESS_KEY}");
    for request in kms.provider.received() {
        assert_eq!(request.header("x-amz-security-token"), Some(token.as_str()));
        assert!(
            request
                .header("authorization")
                .unwrap()
                .contains(";x-amz-security-token;")
        );
    }
}

#[tokio::test]
async fn credentials_about_to_expire_are_fetched_again_and_kept_if_that_fails() {
    let kms = kms().await;
    let metadata = MockProvider::plain().await;
    // Inside the five minutes before expiry, so every request asks for newer ones.
    let credentials = role("ASIAOLD", Duration::from_secs(120));
    serve_aws_instance_metadata(&metadata, Some("seal-role"), &credentials);
    let wrap = wrapper_with(
        &kms,
        AwsCredentialSource::InstanceMetadata {
            address: metadata.address(),
        },
    );
    let (key, _) = PrivateKey::generate();

    // The KMS knows another key id, so it refuses, having been asked with the old one.
    assert!(wrap.wrap(&keyset(), &kid(), &key).await.is_err());
    assert_eq!(metadata.received().len(), 3);
    assert!(
        kms.provider.received()[0]
            .header("authorization")
            .unwrap()
            .contains("Credential=ASIAOLD/")
    );

    // The role's credentials have been rotated: the next request uses the new ones.
    *credentials.lock().unwrap() = aws_role_credentials(ACCESS_KEY, Duration::from_secs(120));
    assert!(wrap.wrap(&keyset(), &kid(), &key).await.is_ok());
    assert_eq!(metadata.received().len(), 6);

    // The endpoint fails: the ones in hand are still valid, and are used, and the
    // endpoint is not asked again at once.
    *credentials.lock().unwrap() = serde_json::Value::Null;
    assert!(wrap.wrap(&keyset(), &kid(), &key).await.is_ok());
    assert_eq!(metadata.received().len(), 9);
    assert!(wrap.wrap(&keyset(), &kid(), &key).await.is_ok());
    assert_eq!(metadata.received().len(), 9);
}

#[tokio::test]
async fn without_a_role_or_an_endpoint_nothing_is_sent_to_the_kms() {
    let kms = kms().await;
    let (key, _) = PrivateKey::generate();

    // An instance with no role.
    let no_role = MockProvider::plain().await;
    serve_aws_instance_metadata(&no_role, None, &role(ACCESS_KEY, HOUR));
    // An endpoint that answers, but not with credentials.
    let failing = MockProvider::plain().await;
    serve_aws_instance_metadata(
        &failing,
        Some("seal-role"),
        &std::sync::Arc::new(std::sync::Mutex::new(serde_json::Value::Null)),
    );
    // Credentials that have already expired.
    let expired = MockProvider::plain().await;
    let stale = role(ACCESS_KEY, HOUR);
    stale.lock().unwrap()["Expiration"] = "2020-01-01T00:00:00Z".into();
    serve_aws_instance_metadata(&expired, Some("seal-role"), &stale);
    // Version 1 only: no session is given.
    let version_one = MockProvider::plain().await;
    version_one.respond(
        "/latest/meta-data/iam/security-credentials/",
        CannedResponse::ok("text/plain", b"seal-role"),
    );
    // Nothing listening.
    let gone = MockProvider::plain().await;
    let gone_address = gone.address();
    drop(gone);

    for address in [
        no_role.address(),
        failing.address(),
        expired.address(),
        version_one.address(),
        gone_address,
    ] {
        let wrap = wrapper_with(&kms, AwsCredentialSource::InstanceMetadata { address });
        assert_eq!(
            wrap.wrap(&keyset(), &kid(), &key).await.err(),
            Some(KeyError::Unavailable)
        );
    }
    assert!(kms.provider.received().is_empty());
}

#[tokio::test]
async fn a_container_endpoint_gives_the_credentials_for_its_token() {
    let kms = kms().await;
    let endpoint = MockProvider::plain().await;
    let credentials = role(ACCESS_KEY, Duration::from_secs(120));
    serve_aws_container_credentials(
        &endpoint,
        "/v1/credentials?id=7",
        Some("first-token"),
        &credentials,
    );
    let token_file = kms.dir.path().join("token");
    std::fs::write(&token_file, "first-token\n").unwrap();
    let source = |token| AwsCredentialSource::Container {
        address: endpoint.address(),
        path: "/v1/credentials?id=7".to_owned(),
        token,
    };
    let wrap = wrapper_with(&kms, source(Some(ContainerToken::File(token_file.clone()))));
    let (key, _) = PrivateKey::generate();

    assert!(wrap.wrap(&keyset(), &kid(), &key).await.is_ok());
    assert_eq!(paths(&endpoint), ["GET /v1/credentials?id=7"]);
    assert_eq!(
        endpoint.received()[0].header("authorization"),
        Some("first-token")
    );
    let token = format!("session-of-{ACCESS_KEY}");
    assert_eq!(
        kms.provider.received()[0].header("x-amz-security-token"),
        Some(token.as_str())
    );

    // The platform renews the token in the file: it is read for each fetch.
    std::fs::write(&token_file, "second-token").unwrap();
    assert!(wrap.wrap(&keyset(), &kid(), &key).await.is_ok());
    assert_eq!(
        endpoint.received()[1].header("authorization"),
        Some("second-token")
    );

    // A token given as a value, and none at all, which this endpoint refuses.
    let sent = kms.provider.received().len();
    let value = ContainerToken::Value(zeroize::Zeroizing::new("first-token".to_owned()));
    let wrap = wrapper_with(&kms, source(Some(value)));
    assert!(wrap.wrap(&keyset(), &kid(), &key).await.is_ok());
    for refused in [
        source(None),
        source(Some(ContainerToken::File(kms.dir.path().join("missing")))),
    ] {
        let wrap = wrapper_with(&kms, refused);
        assert_eq!(
            wrap.wrap(&keyset(), &kid(), &key).await.err(),
            Some(KeyError::Unavailable)
        );
    }
    assert_eq!(kms.provider.received().len(), sent + 1);
}
