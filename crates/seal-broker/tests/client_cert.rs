//! Client certificates toward providers: what the provider sees, the rule's CA and
//! server name, and pooling per identity, so that a replaced or evicted credential
//! never reuses an old connection.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::time::Duration;

use seal_broker::ErrorCode;
use seal_format::Envelope;
use seal_format::policy::Policy;
use seal_testkit::pki::{Issued, TestPki};
use serde_json::{Value, json};
use support::{Alpn, Harness, MockProvider, Options, TLS_HOST, read_body, request, rule_policy};

fn rule(provider: &MockProvider, inject: Value) -> Value {
    json!({
        "destination": { "scheme": "https", "host": TLS_HOST, "port": provider.port() },
        "inject": { "client_cert": inject },
        "plain": ["cert"],
    })
}

fn url(provider: &MockProvider) -> String {
    format!("https://{TLS_HOST}:{}/echo", provider.port())
}

/// A provider requiring certificates from `clients`, and a broker trusting it.
async fn setup(clients: &TestPki, alpn: Alpn) -> (MockProvider, Harness) {
    let server = TestPki::new("provider CA");
    let provider = MockProvider::tls_with(&server, alpn, &[TLS_HOST], Some(&clients.ca_der)).await;
    let mut options = Options::default();
    options.client.extra_roots = vec![provider.ca().unwrap()];
    (provider, Harness::with(options))
}

/// Sends with the private key sealed and the certificate as a plain field.
async fn send(
    harness: &Harness,
    provider: &MockProvider,
    key: &Envelope,
    issued: &Issued,
) -> Result<(), seal_broker::BrokerError> {
    let mut send = request(&url(provider), &[("client_key", key)]);
    send.plain
        .insert(support::field("cert"), issued.cert_pem.clone());
    let response = harness.broker.send(send).await?;
    read_body(response).await.map(|_| ())
}

fn seal_key(harness: &Harness, issued: &Issued, policy: &Policy) -> Envelope {
    harness.seal("client_key", issued.key_pem.as_bytes(), policy)
}

#[tokio::test]
async fn the_provider_sees_the_sealed_keys_certificate() {
    for alpn in [Alpn::Http1, Alpn::Both] {
        let clients = TestPki::new("client CA");
        let (provider, harness) = setup(&clients, alpn).await;
        let issued = clients.client("tenant-a");
        let policy = rule_policy(&rule(&provider, json!({ "cert": { "field": "cert" } })));
        let key = seal_key(&harness, &issued, &policy);
        send(&harness, &provider, &key, &issued).await.unwrap();
        assert_eq!(
            provider.client_certificates(),
            [Some(issued.cert_der.as_ref().to_vec())]
        );
        assert_eq!(provider.received().len(), 1);
    }
}

#[tokio::test]
async fn without_a_client_certificate_the_provider_refuses() {
    let clients = TestPki::new("client CA");
    let (provider, harness) = setup(&clients, Alpn::Http1).await;
    let policy = support::rule_policy(&json!({
        "destination": { "scheme": "https", "host": TLS_HOST, "port": provider.port() },
        "inject": { "header": { "name": "x-api-key", "format": "{}" } },
    }));
    let token = harness.seal("token", b"t", &policy);
    let error = harness
        .get(&url(&provider), &[("token", &token)])
        .await
        .err()
        .unwrap();
    assert!(
        matches!(
            error.code(),
            ErrorCode::UpstreamTls | ErrorCode::UpstreamReset
        ),
        "{:?}",
        error.code()
    );
    assert!(provider.received().is_empty());
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_refused_by_the_provider() {
    let clients = TestPki::new("client CA");
    let (provider, harness) = setup(&clients, Alpn::Http1).await;
    let stranger = TestPki::new("someone else").client("tenant-a");
    let policy = rule_policy(&rule(&provider, json!({ "cert": { "field": "cert" } })));
    let key = seal_key(&harness, &stranger, &policy);
    assert!(send(&harness, &provider, &key, &stranger).await.is_err());
    assert!(provider.received().is_empty());
}

#[tokio::test]
async fn the_rules_ca_and_server_name_verify_the_provider() {
    let clients = TestPki::new("client CA");
    let server = TestPki::new("private provider CA");
    // The provider's certificate names another host, from a CA only the rule trusts.
    let provider = MockProvider::tls_with(
        &server,
        Alpn::Http1,
        &["internal.test"],
        Some(&clients.ca_der),
    )
    .await;
    let harness = Harness::new();
    let issued = clients.client("tenant-a");
    let with = |ca: bool, name: bool| {
        let mut inject = json!({ "cert": { "field": "cert" } });
        if ca {
            inject["ca"] = json!(server.ca_pem);
        }
        if name {
            inject["server_name"] = json!("internal.test");
        }
        rule_policy(&rule(&provider, inject))
    };

    let key = seal_key(&harness, &issued, &with(true, true));
    send(&harness, &provider, &key, &issued).await.unwrap();

    for (ca, name) in [(false, true), (true, false)] {
        let key = seal_key(&harness, &issued, &with(ca, name));
        let error = send(&harness, &provider, &key, &issued)
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), ErrorCode::UpstreamTls, "ca {ca}, name {name}");
    }
    assert_eq!(provider.received().len(), 1);
}

#[tokio::test]
async fn an_identity_reuses_its_connection_and_another_never_does() {
    let clients = TestPki::new("client CA");
    let (provider, harness) = setup(&clients, Alpn::Http1).await;
    let policy = rule_policy(&rule(&provider, json!({ "cert": { "field": "cert" } })));
    let first = clients.client("tenant-a");
    let key = seal_key(&harness, &first, &policy);
    send(&harness, &provider, &key, &first).await.unwrap();
    send(&harness, &provider, &key, &first).await.unwrap();
    assert_eq!(
        provider.connections(),
        1,
        "the same identity reuses its connection"
    );

    // A replaced certificate and key, sealed under the same kid, is a new identity.
    let replaced = clients.client("tenant-a");
    let new_key = seal_key(&harness, &replaced, &policy);
    assert_eq!(new_key.kid(), key.kid());
    send(&harness, &provider, &new_key, &replaced)
        .await
        .unwrap();
    assert_eq!(provider.connections(), 2);
    // A certificate that does not match the key is refused before connecting.
    let other = clients.client("tenant-b");
    let mut mismatched = request(&url(&provider), &[("client_key", &key)]);
    mismatched
        .plain
        .insert(support::field("cert"), other.cert_pem.clone());
    let error = harness.broker.send(mismatched).await.err().unwrap();
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert_eq!(provider.connections(), 2);

    let presented = provider.client_certificates();
    assert_eq!(presented[0], Some(first.cert_der.as_ref().to_vec()));
    assert_eq!(presented[1], Some(replaced.cert_der.as_ref().to_vec()));

    // A connection without a client certificate is never one of these.
    let plain = support::rule_policy(&json!({
        "destination": { "scheme": "https", "host": TLS_HOST, "port": provider.port() },
        "inject": { "header": { "name": "x-api-key", "format": "{}" } },
    }));
    let token = harness.seal("token", b"t", &plain);
    assert!(
        harness
            .get(&url(&provider), &[("token", &token)])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn evicting_the_sealing_key_closes_the_identitys_connections() {
    let clients = TestPki::new("client CA");
    let server = TestPki::new("provider CA");
    let provider =
        MockProvider::tls_with(&server, Alpn::Http1, &[TLS_HOST], Some(&clients.ca_der)).await;
    let mut options = Options::default();
    options.client.extra_roots = vec![provider.ca().unwrap()];
    // The reaper runs at half the idle timeout.
    options.client.idle_timeout = Duration::from_secs(4);
    let harness = Harness::with(options);
    let issued = clients.client("tenant-a");
    let policy = rule_policy(&rule(&provider, json!({ "cert": { "field": "cert" } })));
    let key = seal_key(&harness, &issued, &policy);
    send(&harness, &provider, &key, &issued).await.unwrap();
    assert_eq!(provider.open_connections(), 1);

    harness.keys.evict();
    let closed = async {
        while provider.open_connections() > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(3), closed)
        .await
        .expect("the idle connection closes once the key is gone");

    // The reloaded key makes a new identity, on a new connection.
    send(&harness, &provider, &key, &issued).await.unwrap();
    assert_eq!(provider.connections(), 2);
}

#[tokio::test]
async fn a_reloaded_key_never_reuses_the_old_connection() {
    let clients = TestPki::new("client CA");
    let (provider, harness) = setup(&clients, Alpn::Http1).await;
    let issued = clients.client("tenant-a");
    let policy = rule_policy(&rule(&provider, json!({ "cert": { "field": "cert" } })));
    let key = seal_key(&harness, &issued, &policy);
    send(&harness, &provider, &key, &issued).await.unwrap();
    harness.keys.evict();
    // Before any reaper runs, the next request already gets a new connection.
    send(&harness, &provider, &key, &issued).await.unwrap();
    assert_eq!(provider.connections(), 2);
}

#[tokio::test]
async fn identities_are_limited_and_the_least_recent_makes_room() {
    let clients = TestPki::new("client CA");
    let server = TestPki::new("provider CA");
    let provider =
        MockProvider::tls_with(&server, Alpn::Http1, &[TLS_HOST], Some(&clients.ca_der)).await;
    let mut options = Options::default();
    options.client.extra_roots = vec![provider.ca().unwrap()];
    options.client.max_client_cert_identities = 2;
    let harness = Harness::with(options);
    let policy = rule_policy(&rule(&provider, json!({ "cert": { "field": "cert" } })));
    let tenants: Vec<(Issued, Envelope)> = (0..3)
        .map(|index| {
            let issued = clients.client(&format!("tenant-{index}"));
            let key = seal_key(&harness, &issued, &policy);
            (issued, key)
        })
        .collect();
    for (issued, key) in &tenants {
        send(&harness, &provider, key, issued).await.unwrap();
    }
    assert_eq!(provider.connections(), 3);
    // The first identity made room for the third, so it connects again.
    let (issued, key) = &tenants[0];
    send(&harness, &provider, key, issued).await.unwrap();
    assert_eq!(provider.connections(), 4);
    // The third is still pooled.
    let (issued, key) = &tenants[2];
    send(&harness, &provider, key, issued).await.unwrap();
    assert_eq!(provider.connections(), 4);
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/jwt/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[tokio::test]
async fn keys_in_pkcs8_pkcs1_and_sec1_all_work() {
    let clients = TestPki::new("client CA");
    let (provider, harness) = setup(&clients, Alpn::Http1).await;
    let policy = rule_policy(&rule(&provider, json!({ "cert": { "field": "cert" } })));
    for (pkcs8, forms) in [
        ("rsa-pkcs8.pem", &["rsa-pkcs8.pem", "rsa-pkcs1.pem"][..]),
        ("ec-pkcs8.pem", &["ec-pkcs8.pem", "ec-sec1.pem"]),
        ("ed25519-pkcs8.pem", &["ed25519-pkcs8.pem"]),
    ] {
        let issued = clients.client_for_key("tenant-a", &fixture(pkcs8)).unwrap();
        for form in forms {
            let mut variant = issued.clone();
            variant.key_pem = fixture(form);
            let key = seal_key(&harness, &variant, &policy);
            send(&harness, &provider, &key, &variant)
                .await
                .unwrap_or_else(|error| panic!("{form}: {error:?}"));
        }
    }
    assert_eq!(provider.received().len(), 5);
}
