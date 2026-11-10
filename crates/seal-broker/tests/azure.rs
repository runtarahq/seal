//! Azure Shared Key in the broker: what the provider receives, and refused headers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http::{HeaderValue, Method, header};
use seal_broker::ErrorCode;
use seal_testkit::mock_provider::Received;
use serde_json::{Value, json};
use support::{
    Harness, MockProvider, plain_rule, read_body, request, request_body, rule_policy, url,
};

/// Azurite's well-known development key.
const KEY: &[u8] =
    b"Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

fn rule(provider: &MockProvider, service: &str) -> Value {
    plain_rule(
        provider,
        &json!({ "azure_shared_key": { "account": { "literal": "acct" }, "service": service } }),
    )
}

/// The signature over a string to sign written out by the test.
fn expected(to_sign: &str) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &STANDARD.decode(KEY).unwrap());
    format!(
        "SharedKey acct:{}",
        STANDARD.encode(ring::hmac::sign(&key, to_sign.as_bytes()))
    )
}

fn date(received: &Received) -> String {
    received.header("x-ms-date").unwrap().to_owned()
}

#[tokio::test]
async fn a_blob_put_is_signed_over_its_final_headers() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let key = harness.seal("account_key", KEY, &rule_policy(&rule(&provider, "blob")));
    let mut send = request(
        &url(
            &provider,
            "/container/a%20b.txt?timeout=30&comp=block&blockid=QUJD",
        ),
        &[("account_key", &key)],
    );
    send.method = Method::PUT;
    send.body = request_body(b"hello");
    for (name, value) in [
        ("content-length", "5"),
        ("content-type", "text/plain; charset=UTF-8"),
        ("x-ms-blob-type", "BlockBlob"),
        ("x-ms-meta-owner", "  a   b "),
    ] {
        send.headers.insert(name, HeaderValue::from_static(value));
    }
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();

    let received = &provider.received()[0];
    assert_eq!(received.body, b"hello");
    assert_eq!(received.header("x-ms-version"), Some("2021-12-02"));
    let to_sign = format!(
        "PUT\n\n\n5\n\ntext/plain; charset=UTF-8\n\n\n\n\n\n\nx-ms-blob-type:BlockBlob\nx-ms-date:{}\nx-ms-meta-owner:a b\nx-ms-version:2021-12-02\n/acct/container/a%20b.txt\nblockid:QUJD\ncomp:block\ntimeout:30",
        date(received)
    );
    assert_eq!(
        received.header("authorization"),
        Some(expected(&to_sign).as_str())
    );
    assert!(!format!("{:?}", received.headers).contains("Eby8"));
}

#[tokio::test]
async fn a_table_request_is_signed_with_the_date_and_comp() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let key = harness.seal("account_key", KEY, &rule_policy(&rule(&provider, "table")));
    let mut send = request(
        &url(&provider, "/Tables?comp=list&$top=5"),
        &[("account_key", &key)],
    );
    send.headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/json;odata=nometadata"),
    );
    send.headers
        .insert("x-ms-version", HeaderValue::from_static("2019-02-02"));
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();

    let received = &provider.received()[0];
    assert_eq!(received.header("date"), Some(date(received).as_str()));
    assert_eq!(
        received.header("x-ms-version"),
        Some("2019-02-02"),
        "the caller's version stays"
    );
    let to_sign = format!("GET\n\n\n{}\n/acct/Tables?comp=list", date(received));
    assert_eq!(
        received.header("authorization"),
        Some(expected(&to_sign).as_str())
    );
}

#[tokio::test]
async fn the_date_and_authorization_are_seals_alone() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let key = harness.seal("account_key", KEY, &rule_policy(&rule(&provider, "queue")));
    for name in ["x-ms-date", "date", "authorization"] {
        let mut send = request(&url(&provider, "/queue/messages"), &[("account_key", &key)]);
        send.headers.insert(
            name,
            HeaderValue::from_static("Sun, 30 Aug 2015 12:36:00 GMT"),
        );
        let error = harness.broker.send(send).await.err().unwrap();
        assert_eq!(error.code(), ErrorCode::Conflict, "{name}");
    }

    // A repeated header could be read two ways, so Shared Key refuses it.
    let mut send = request(&url(&provider, "/queue/messages"), &[("account_key", &key)]);
    send.headers
        .append("x-ms-meta-a", HeaderValue::from_static("1"));
    send.headers
        .append("x-ms-meta-a", HeaderValue::from_static("2"));
    let error = harness.broker.send(send).await.err().unwrap();
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert_eq!((harness.lookups(), harness.connects()), (0, 0));
}

#[tokio::test]
async fn a_key_that_is_not_base64_is_refused() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let key = harness.seal(
        "account_key",
        b"not base64!",
        &rule_policy(&rule(&provider, "blob")),
    );
    let error = harness
        .get(&url(&provider, "/c"), &[("account_key", &key)])
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert_eq!(harness.connects(), 0);
}

#[tokio::test]
async fn a_known_body_length_is_set_before_signing() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let key = harness.seal("account_key", KEY, &rule_policy(&rule(&provider, "blob")));
    let mut send = request(&url(&provider, "/c/b"), &[("account_key", &key)]);
    send.method = Method::PUT;
    send.body = request_body(b"hello");
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();
    let received = &provider.received()[0];
    assert_eq!(received.header("content-length"), Some("5"));
    let to_sign = format!(
        "PUT\n\n\n5\n\n\n\n\n\n\n\n\nx-ms-date:{}\nx-ms-version:2021-12-02\n/acct/c/b",
        date(received)
    );
    assert_eq!(
        received.header("authorization"),
        Some(expected(&to_sign).as_str())
    );
}
