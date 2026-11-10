//! The HTTP key source against a key service that requires a client certificate.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use seal_format::KeysetId;
use seal_format::id::KeyId;
use seal_keys::{HttpKeySource, HttpKeySourceConfig, KeyError, KeySource, WrappedKey};
use seal_testkit::mock_provider::{Alpn, CannedResponse, MockProvider};
use seal_testkit::pki::TestPki;

fn key(kid: &str) -> WrappedKey {
    WrappedKey {
        keyset: KeysetId::new("acme").unwrap(),
        kid: KeyId::new(kid).unwrap(),
        public: "p".to_owned(),
        created: 1,
        wrap_id: "file:00".to_owned(),
        wrapped: "w".to_owned(),
    }
}

struct Service {
    provider: MockProvider,
    pki: TestPki,
    clients: TestPki,
}

async fn service() -> Service {
    let (pki, clients) = (TestPki::new("key service CA"), TestPki::new("client CA"));
    let provider =
        MockProvider::tls_with(&pki, Alpn::Http1, &["localhost"], Some(&clients.ca_der)).await;
    Service {
        provider,
        pki,
        clients,
    }
}

fn source(service: &Service, client: &TestPki, max_keys: usize) -> HttpKeySource {
    let identity = client.client("seal");
    HttpKeySource::new(&HttpKeySourceConfig {
        url: format!("https://localhost:{}/v1", service.provider.port()),
        ca_pem: service.pki.ca_pem.clone(),
        cert_pem: identity.cert_pem,
        key_pem: identity.key_pem,
        timeout: Duration::from_secs(5),
        max_keys,
    })
    .unwrap()
}

#[tokio::test]
async fn reads_a_keysets_keys_with_a_client_certificate() {
    let service = service().await;
    let body = serde_json::to_vec(&[key("k1"), key("k2")]).unwrap();
    service.provider.respond(
        "/v1/keysets/acme/keys",
        CannedResponse::ok("application/json", &body),
    );
    let keys = source(&service, &service.clients, 16)
        .wrapped_keys(&KeysetId::new("acme").unwrap())
        .await
        .unwrap();
    assert_eq!(keys, [key("k1"), key("k2")]);
}

#[tokio::test]
async fn an_unknown_keyset_has_no_keys() {
    let service = service().await;
    let keys = source(&service, &service.clients, 16)
        .wrapped_keys(&KeysetId::new("nobody").unwrap())
        .await
        .unwrap();
    assert!(keys.is_empty());
}

#[tokio::test]
async fn identifiers_are_encoded_as_path_segments() {
    let service = service().await;
    let source = source(&service, &service.clients, 16);
    let _ = source.wrapped_keys(&KeysetId::new("a:b.c").unwrap()).await;
    assert_eq!(
        service.provider.received()[0].uri,
        "/v1/keysets/a%3Ab%2Ec/keys"
    );
}

#[tokio::test]
async fn a_client_certificate_from_another_ca_is_refused_by_the_service() {
    let service = service().await;
    let stranger = TestPki::new("someone else");
    let result = source(&service, &stranger, 16)
        .wrapped_keys(&KeysetId::new("acme").unwrap())
        .await;
    assert_eq!(result, Err(KeyError::Unavailable));
    assert!(service.provider.received().is_empty());
}

#[tokio::test]
async fn too_many_keys_or_a_bad_response_is_refused() {
    let service = service().await;
    let body = serde_json::to_vec(&[key("k1"), key("k2"), key("k3")]).unwrap();
    service.provider.respond(
        "/v1/keysets/acme/keys",
        CannedResponse::ok("application/json", &body),
    );
    let acme = KeysetId::new("acme").unwrap();
    assert_eq!(
        source(&service, &service.clients, 2)
            .wrapped_keys(&acme)
            .await,
        Err(KeyError::Unavailable)
    );

    service.provider.respond(
        "/v1/keysets/acme/keys",
        CannedResponse::ok("application/json", b"not json"),
    );
    assert!(matches!(
        source(&service, &service.clients, 16)
            .wrapped_keys(&acme)
            .await,
        Err(KeyError::Invalid(_))
    ));

    service.provider.respond(
        "/v1/keysets/acme/keys",
        CannedResponse {
            status: 500,
            headers: vec![],
            body: vec![],
        },
    );
    assert_eq!(
        source(&service, &service.clients, 16)
            .wrapped_keys(&acme)
            .await,
        Err(KeyError::Unavailable)
    );
}

#[test]
fn only_plain_https_urls_are_accepted() {
    let pki = TestPki::new("x");
    let identity = pki.client("seal");
    for url in [
        "http://localhost/",
        "https://user@localhost/",
        "https://localhost/?a=1",
        "nonsense",
    ] {
        let config = HttpKeySourceConfig {
            url: url.to_owned(),
            ca_pem: pki.ca_pem.clone(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            timeout: Duration::from_secs(1),
            max_keys: 1,
        };
        assert!(HttpKeySource::new(&config).is_err(), "{url}");
    }
}
