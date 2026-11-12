//! The OVHcloud KMS wrapper against a stand-in for the KMS.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use seal_format::id::KeyId;
use seal_format::{KeysetId, PrivateKey};
use seal_keys::{KeyError, KeyWrap, OvhKmsAuth, OvhKmsConfig, OvhKmsWrap};
use seal_testkit::mock_kms::serve_ovh;
use seal_testkit::mock_provider::{Alpn, CannedResponse, MockProvider};
use seal_testkit::pki::TestPki;
use zeroize::Zeroizing;

const OKMS: &str = "11111111-2222-3333-4444-555555555555";
const KEY: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const TOKEN: &str = "a-personal-access-token";

struct Kms {
    provider: MockProvider,
    pki: TestPki,
    clients: TestPki,
}

/// A KMS that asks for a client certificate.
async fn kms_with_certificates() -> Kms {
    let (pki, clients) = (TestPki::new("KMS CA"), TestPki::new("access certificates"));
    let provider =
        MockProvider::tls_with(&pki, Alpn::Http1, &["localhost"], Some(&clients.ca_der)).await;
    serve_ovh(&provider, OKMS, KEY, None);
    Kms {
        provider,
        pki,
        clients,
    }
}

/// A KMS that asks for a bearer token.
async fn kms_with_tokens() -> Kms {
    let (pki, clients) = (TestPki::new("KMS CA"), TestPki::new("unused"));
    let provider = MockProvider::tls_with(&pki, Alpn::Http1, &["localhost"], None).await;
    serve_ovh(&provider, OKMS, KEY, Some(TOKEN));
    Kms {
        provider,
        pki,
        clients,
    }
}

fn config(kms: &Kms, auth: OvhKmsAuth) -> OvhKmsConfig {
    OvhKmsConfig {
        endpoint: format!("https://localhost:{}", kms.provider.port()),
        okms_id: OKMS.to_owned(),
        key_id: KEY.to_owned(),
        auth,
        ca_pem: Some(kms.pki.ca_pem.clone()),
        timeout: Duration::from_secs(5),
    }
}

fn certificate(pki: &TestPki) -> OvhKmsAuth {
    let identity = pki.client("seal");
    OvhKmsAuth::Certificate {
        cert_pem: identity.cert_pem,
        key_pem: Zeroizing::new(identity.key_pem),
    }
}

fn token(value: &str) -> OvhKmsAuth {
    OvhKmsAuth::Token(Zeroizing::new(value.to_owned()))
}

fn keyset() -> KeysetId {
    KeysetId::new("acme").unwrap()
}

fn kid() -> KeyId {
    KeyId::new("k1").unwrap()
}

#[tokio::test]
async fn a_key_wrapped_by_the_kms_unwraps_to_the_same_key() {
    let kms = kms_with_certificates().await;
    let wrap = OvhKmsWrap::new(&config(&kms, certificate(&kms.clients))).unwrap();
    let (key, public) = PrivateKey::generate();

    let wrapped = wrap.wrap(&keyset(), &kid(), &key).await.unwrap();
    assert!(!key.expose(|bytes| wrapped.windows(bytes.len()).any(|window| window == bytes)));
    let unwrapped = wrap.unwrap(&keyset(), &kid(), &wrapped).await.unwrap();
    assert_eq!(unwrapped.public_key().unwrap(), public);

    let received = kms.provider.received();
    let paths: Vec<_> = received.iter().map(|request| request.uri.clone()).collect();
    assert_eq!(
        paths,
        [
            format!("/api/{OKMS}/v1/servicekey/{KEY}/encrypt"),
            format!("/api/{OKMS}/v1/servicekey/{KEY}/decrypt"),
        ]
    );
    for request in &received {
        assert_eq!(request.method, "POST");
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.header("authorization"), None);
    }
    assert!(
        kms.provider
            .client_certificates()
            .iter()
            .all(Option::is_some)
    );
}

#[tokio::test]
async fn the_requests_are_what_the_kms_documents() {
    let kms = kms_with_tokens().await;
    let wrap = OvhKmsWrap::new(&config(&kms, token(TOKEN))).unwrap();
    let (key, _) = PrivateKey::generate();
    let wrapped = wrap.wrap(&keyset(), &kid(), &key).await.unwrap();
    wrap.unwrap(&keyset(), &kid(), &wrapped).await.unwrap();

    let received = kms.provider.received();
    let encrypt: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
    let decrypt: serde_json::Value = serde_json::from_slice(&received[1].body).unwrap();
    // The plaintext is standard base64 of the key, as the KMS's own SDK sends it.
    use base64::Engine;
    let sent = base64::engine::general_purpose::STANDARD
        .decode(encrypt["plaintext"].as_str().unwrap())
        .unwrap();
    assert!(key.expose(|bytes| bytes == sent));
    assert_eq!(encrypt.as_object().unwrap().len(), 2);
    assert_eq!(decrypt.as_object().unwrap().len(), 2);
    assert_eq!(encrypt["context"], decrypt["context"]);
    assert_eq!(
        decrypt["ciphertext"].as_str().unwrap().as_bytes(),
        wrapped.as_slice()
    );
    for request in &received {
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
    }
}

#[tokio::test]
async fn a_wrapped_key_does_not_unwrap_under_another_keyset_or_kid() {
    let kms = kms_with_tokens().await;
    let wrap = OvhKmsWrap::new(&config(&kms, token(TOKEN))).unwrap();
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
async fn credentials_the_kms_does_not_accept_are_unavailable() {
    let kms = kms_with_tokens().await;
    let wrap = OvhKmsWrap::new(&config(&kms, token("another-token"))).unwrap();
    let (key, _) = PrivateKey::generate();
    assert_eq!(
        wrap.wrap(&keyset(), &kid(), &key).await.err(),
        Some(KeyError::Unavailable)
    );

    let kms = kms_with_certificates().await;
    let stranger = TestPki::new("someone else");
    let wrap = OvhKmsWrap::new(&config(&kms, certificate(&stranger))).unwrap();
    assert_eq!(
        wrap.wrap(&keyset(), &kid(), &key).await.err(),
        Some(KeyError::Unavailable)
    );
    assert!(kms.provider.received().is_empty());
}

#[tokio::test]
async fn a_kms_with_a_certificate_from_another_ca_is_not_trusted() {
    let kms = kms_with_tokens().await;
    let mut config = config(&kms, token(TOKEN));
    config.ca_pem = Some(TestPki::new("someone else").ca_pem);
    let wrap = OvhKmsWrap::new(&config).unwrap();
    let (key, _) = PrivateKey::generate();
    assert_eq!(
        wrap.wrap(&keyset(), &kid(), &key).await.err(),
        Some(KeyError::Unavailable)
    );
    assert!(kms.provider.received().is_empty());
}

#[tokio::test]
async fn answers_that_are_not_what_the_kms_documents_are_refused() {
    let kms = kms_with_tokens().await;
    let wrap = OvhKmsWrap::new(&config(&kms, token(TOKEN))).unwrap();
    let (key, _) = PrivateKey::generate();
    let encrypt = format!("/api/{OKMS}/v1/servicekey/{KEY}/encrypt");
    let decrypt = format!("/api/{OKMS}/v1/servicekey/{KEY}/decrypt");

    let huge = format!(r#"{{"ciphertext":"{}"}}"#, "a".repeat(9000));
    for body in [
        "not json",
        "{}",
        r#"{"ciphertext":""}"#,
        r#"{"ciphertext":"two words"}"#,
        r#"{"ciphertext":7}"#,
        huge.as_str(),
    ] {
        kms.provider.respond(
            &encrypt,
            CannedResponse::ok("application/json", body.as_bytes()),
        );
        assert_eq!(
            wrap.wrap(&keyset(), &kid(), &key).await.err(),
            Some(KeyError::Unavailable),
            "{body:.40}"
        );
    }

    let long = format!(r#"{{"plaintext":"{}"}}"#, "QUFB".repeat(64));
    for body in [
        "not json",
        "{}",
        r#"{"plaintext":"not base64!"}"#,
        r#"{"plaintext":"c2hvcnQ="}"#,
        long.as_str(),
    ] {
        kms.provider.respond(
            &decrypt,
            CannedResponse::ok("application/json", body.as_bytes()),
        );
        assert_eq!(
            wrap.unwrap(&keyset(), &kid(), b"fake.a.b").await.err(),
            Some(KeyError::Unavailable),
            "{body:.40}"
        );
    }

    // A response larger than a key could ever need is not read to its end.
    kms.provider.respond(
        &decrypt,
        CannedResponse::ok("application/json", &vec![b' '; 200_000]),
    );
    assert_eq!(
        wrap.unwrap(&keyset(), &kid(), b"fake.a.b").await.err(),
        Some(KeyError::Unavailable)
    );
    // What was stored is sent as it is, so it must be text that needs no escaping.
    for wrapped in [&b"\xff\xfe"[..], b"with space", b"quote\""] {
        assert_eq!(
            wrap.unwrap(&keyset(), &kid(), wrapped).await.err(),
            Some(KeyError::Unavailable)
        );
    }
}

#[tokio::test]
async fn a_kms_that_does_not_answer_is_given_up_on() {
    // Accepts connections and says nothing, so the TLS handshake never finishes.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let silent = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let wrap = OvhKmsWrap::new(&OvhKmsConfig {
        endpoint: format!("https://localhost:{port}"),
        okms_id: OKMS.to_owned(),
        key_id: KEY.to_owned(),
        auth: token(TOKEN),
        ca_pem: Some(TestPki::new("KMS CA").ca_pem),
        timeout: Duration::from_millis(200),
    })
    .unwrap();
    let (key, _) = PrivateKey::generate();
    let started = std::time::Instant::now();
    assert_eq!(
        wrap.wrap(&keyset(), &kid(), &key).await.err(),
        Some(KeyError::Unavailable)
    );
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(200) && waited < Duration::from_secs(4));
    silent.abort();
}
