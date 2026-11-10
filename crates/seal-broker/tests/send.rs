//! The broker end to end, in library mode, against a mock provider.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use http::{HeaderValue, Method, header};
use http_body::Body;
use http_body_util::BodyExt;
use seal_broker::address::NetworkPolicy;
use seal_broker::{ErrorCode, Limits};
use seal_format::policy::builder;
use seal_format::{Envelope, Policy};
use seal_testkit::canary::{Canary, CanaryRegistry};
use seal_testkit::log_capture::LogCapture;
use serde_json::{Value, json};
use support::{
    Alpn, CannedResponse, HOST, Harness, MockProvider, Options, TLS_HOST, bearer, field,
    plain_policy, plain_rule, read_body, read_text, request, request_body, rule_policy, url,
};

fn options_with_limits(change: impl FnOnce(&mut Limits)) -> Options {
    let mut options = Options::default();
    change(&mut options.limits);
    options
}

async fn echo_json(harness: &Harness, url: &str, sealed: &[(&str, &Envelope)]) -> Value {
    let response = harness.get(url, sealed).await.unwrap();
    serde_json::from_str(&read_text(response).await).unwrap()
}

// Injection reaches the provider.

#[tokio::test]
async fn a_bearer_token_reaches_the_provider_and_the_caller_gets_the_response() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"s3cret", &plain_policy(&provider, &bearer()));

    let response = harness
        .get(&url(&provider, "/echo?a=1"), &[("token", &token)])
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert!(response.sealed_fields.is_empty());
    read_body(response).await.unwrap();

    let received = provider.received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].header("authorization"), Some("Bearer s3cret"));
    assert_eq!(received[0].uri, "/echo?a=1");
    assert_eq!(
        received[0].header("host").unwrap(),
        format!("{HOST}:{}", provider.port())
    );
}

#[tokio::test]
async fn each_injection_kind_reaches_the_provider_as_the_rule_says() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();

    let basic = plain_policy(
        &provider,
        &json!({ "basic": { "username": { "literal": "user" } } }),
    );
    let value = harness.seal("password", b"hunter2", &basic);
    read_body(
        harness
            .get(&url(&provider, "/echo"), &[("password", &value)])
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        provider.received()[0].header("authorization"),
        Some("Basic dXNlcjpodW50ZXIy")
    );

    let query = plain_policy(&provider, &json!({ "query": { "name": "api_key" } }));
    let value = harness.seal("key", b"a b", &query);
    read_body(
        harness
            .get(&url(&provider, "/echo?x=1"), &[("key", &value)])
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(provider.received()[1].uri, "/echo?x=1&api_key=a%20b");

    let form = plain_policy(&provider, &json!({ "form_field": { "name": "password" } }));
    let value = harness.seal("password", b"a&b", &form);
    let mut send = request(&url(&provider, "/echo"), &[("password", &value)]);
    send.method = Method::POST;
    send.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    send.body = request_body(b"user=me");
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();
    let received = &provider.received()[2];
    assert_eq!(received.body, b"user=me&password=a%26b");
    assert_eq!(received.header("content-length"), Some("22"));

    let body_json = plain_policy(
        &provider,
        &json!({ "json_field": { "pointer": "/auth/token" } }),
    );
    let value = harness.seal("token", b"s3cret", &body_json);
    let mut send = request(&url(&provider, "/echo"), &[("token", &value)]);
    send.method = Method::POST;
    send.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    send.body = request_body(br#"{"a":1}"#);
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();
    let received: Value = serde_json::from_slice(&provider.received()[3].body).unwrap();
    assert_eq!(received, json!({ "a": 1, "auth": { "token": "s3cret" } }));
}

/// A provider that repeats the credential in a response header does not hand it to
/// the caller, wherever in the request head seal put it.
#[tokio::test]
async fn a_secret_a_response_header_repeats_is_not_passed_on() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let reflecting = |values: &[&str]| CannedResponse {
        status: 200,
        headers: values
            .iter()
            .enumerate()
            .map(|(index, value)| (format!("x-echo-{index}"), (*value).to_owned()))
            .chain([("x-kept".to_owned(), "yes".to_owned())])
            .collect(),
        body: Vec::new(),
    };
    let cases = [
        (
            bearer(),
            &b"HEADER-canary_value"[..],
            vec!["Bearer HEADER-canary_value", "HEADER-canary_value"],
        ),
        (
            json!({ "basic": { "username": { "literal": "user" } } }),
            b"BASIC-canary",
            vec!["Basic dXNlcjpCQVNJQy1jYW5hcnk=", "user:BASIC-canary"],
        ),
        (
            json!({ "query": { "name": "api_key" } }),
            b"QUERY canary",
            vec!["/reflect?api_key=QUERY%20canary", "QUERY canary"],
        ),
    ];
    for (inject, secret, echoes) in cases {
        let value = harness.seal("token", secret, &plain_policy(&provider, &inject));
        provider.respond("/reflect", reflecting(&echoes));
        let response = harness
            .get(&url(&provider, "/reflect"), &[("token", &value)])
            .await
            .unwrap();
        assert_eq!(response.headers["x-kept"], "yes");
        for (index, echo) in echoes.iter().enumerate() {
            assert!(
                !response.headers.contains_key(format!("x-echo-{index}")),
                "{echo}"
            );
        }
        read_body(response).await.unwrap();
    }

    // A secret too short to search for takes no header with it.
    let value = harness.seal("token", b"yes", &plain_policy(&provider, &bearer()));
    provider.respond("/reflect", reflecting(&[]));
    let response = harness
        .get(&url(&provider, "/reflect"), &[("token", &value)])
        .await
        .unwrap();
    assert_eq!(response.headers["x-kept"], "yes");
    read_body(response).await.unwrap();
}

/// The secret goes in the path, as Telegram's bot API has it. The audit record has the
/// path the caller named, and a header that repeats the secret is not passed on.
#[tokio::test]
async fn a_secret_in_the_path_reaches_the_provider_and_is_not_recorded_or_reflected() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let policy = plain_policy(&provider, &json!({ "path": { "prefix": "/bot{}" } }));
    let token = harness.seal("token", b"123456:PATH-canary_value", &policy);
    provider.respond(
        "/bot123456:PATH-canary_value/redirect",
        CannedResponse {
            status: 301,
            headers: vec![
                (
                    "location".to_owned(),
                    "/bot123456:PATH-canary_value/redirect/".to_owned(),
                ),
                ("x-kept".to_owned(), "yes".to_owned()),
            ],
            body: Vec::new(),
        },
    );

    let response = harness
        .get(&url(&provider, "/redirect?a=1"), &[("token", &token)])
        .await
        .unwrap();
    assert_eq!(response.status, 301);
    assert!(!response.headers.contains_key(header::LOCATION));
    assert_eq!(response.headers["x-kept"], "yes");
    read_body(response).await.unwrap();

    assert_eq!(
        provider.received()[0].uri,
        "/bot123456:PATH-canary_value/redirect?a=1"
    );
    let record = harness.audit.last();
    assert_eq!(record.path.as_deref(), Some("/redirect"));
    assert_eq!(record.status, Some(301));

    // Presented with it, another value would be carried outside its own path prefix.
    let bearer = harness.seal("other", b"x", &plain_policy(&provider, &bearer()));
    let error = harness
        .get(
            &url(&provider, "/echo"),
            &[("token", &token), ("other", &bearer)],
        )
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::Conflict);
    assert_eq!(provider.received().len(), 1);
}

#[tokio::test]
async fn caller_headers_pass_through_and_hop_by_hop_ones_do_not() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let mut send = request(&url(&provider, "/echo"), &[("token", &token)]);
    send.headers
        .insert("x-request-id", HeaderValue::from_static("abc"));
    send.headers
        .insert(header::CONNECTION, HeaderValue::from_static("x-drop"));
    send.headers.insert("x-drop", HeaderValue::from_static("1"));
    send.headers
        .insert(header::UPGRADE, HeaderValue::from_static("h2c"));
    send.headers
        .insert(header::HOST, HeaderValue::from_static("evil.example"));
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();
    let received = &provider.received()[0];
    assert_eq!(received.header("x-request-id"), Some("abc"));
    assert_eq!(received.header("x-drop"), None);
    assert_eq!(received.header("upgrade"), None);
    assert_ne!(received.header("host"), Some("evil.example"));
}

// TLS.

async fn tls_harness(provider: &MockProvider) -> Harness {
    let mut options = Options::default();
    options.client.extra_roots = vec![provider.ca().unwrap()];
    Harness::with(options)
}

fn tls_policy(provider: &MockProvider) -> Policy {
    builder::bearer(&format!("https://{TLS_HOST}:{}/", provider.port())).unwrap()
}

fn tls_url(provider: &MockProvider, path: &str) -> String {
    format!("https://{TLS_HOST}:{}{path}", provider.port())
}

#[tokio::test]
async fn tls_with_http2_works_and_carries_the_host_as_the_authority() {
    let provider = MockProvider::tls(Alpn::Both).await;
    let harness = tls_harness(&provider).await;
    let token = harness.seal("token", b"s3cret", &tls_policy(&provider));
    let response = harness
        .get(&tls_url(&provider, "/echo?a=1"), &[("token", &token)])
        .await
        .unwrap();
    read_body(response).await.unwrap();
    let received = &provider.received()[0];
    assert_eq!(received.version, "HTTP/2.0");
    assert_eq!(received.header("authorization"), Some("Bearer s3cret"));
    assert!(received.uri.ends_with("/echo?a=1"));
}

#[tokio::test]
async fn tls_with_http1_works() {
    let provider = MockProvider::tls(Alpn::Http1).await;
    let harness = tls_harness(&provider).await;
    let token = harness.seal("token", b"s3cret", &tls_policy(&provider));
    let response = harness
        .get(&tls_url(&provider, "/echo"), &[("token", &token)])
        .await
        .unwrap();
    read_body(response).await.unwrap();
    assert_eq!(provider.received()[0].version, "HTTP/1.1");
}

#[tokio::test]
async fn an_untrusted_certificate_is_refused_and_nothing_is_sent() {
    let provider = MockProvider::tls(Alpn::Both).await;
    let harness = Harness::new();
    let token = harness.seal("token", b"s3cret", &tls_policy(&provider));
    let error = harness
        .get(&tls_url(&provider, "/echo"), &[("token", &token)])
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::UpstreamTls);
    assert!(provider.received().is_empty());
}

#[tokio::test]
async fn a_certificate_for_another_name_is_refused_and_nothing_is_sent() {
    let provider = MockProvider::tls(Alpn::Both).await;
    let harness = tls_harness(&provider).await;
    let other = "other.test";
    let policy = builder::bearer(&format!("https://{other}:{}/", provider.port())).unwrap();
    let token = harness.seal("token", b"s3cret", &policy);
    let url = format!("https://{other}:{}/echo", provider.port());
    let error = harness.get(&url, &[("token", &token)]).await.err().unwrap();
    assert_eq!(error.code(), ErrorCode::UpstreamTls);
    assert!(provider.received().is_empty());
}

// Redirects.

#[tokio::test]
async fn acceptance_redirects_are_returned_not_followed() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let response = harness
        .get(&url(&provider, "/redirect"), &[("token", &token)])
        .await
        .unwrap();
    assert_eq!(response.status, 302);
    assert_eq!(response.headers[header::LOCATION], "/echo");
    read_body(response).await.unwrap();
    assert_eq!(
        provider.received().len(),
        1,
        "only the first request was made"
    );
}

// Traffic on refusal, one test per row of the table in CONTRIBUTING.md, "Deny by default".

fn assert_traffic(harness: &Harness, keys: usize, lookups: usize, connects: usize) {
    assert_eq!(harness.key_fetches(), keys, "key fetches");
    assert_eq!(harness.lookups(), lookups, "DNS lookups");
    assert_eq!(harness.connects(), connects, "connections");
}

#[tokio::test]
async fn acceptance_a_malformed_request_causes_no_traffic_at_all() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    for bad_url in [
        "not a url",
        "http://provider.test/a/../b",
        "http://user:pass@provider.test/",
        "ftp://provider.test/",
    ] {
        let error = harness
            .get(bad_url, &[("token", &token)])
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), ErrorCode::BadRequest, "{bad_url}");
    }
    let mut trace = request(&url(&provider, "/"), &[("token", &token)]);
    trace.method = Method::TRACE;
    let error = harness.broker.send(trace).await.err().unwrap();
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert_traffic(&harness, 0, 0, 0);
    assert!(provider.received().is_empty());
}

#[tokio::test]
async fn acceptance_a_disallowed_destination_method_or_path_causes_no_dns_or_connection() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let mut limited = plain_rule(&provider, &bearer());
    limited["methods"] = json!(["GET"]);
    limited["destination"]["path_prefix"] = json!("/allowed/");
    let token = harness.seal("token", b"x", &rule_policy(&limited));
    let port = provider.port();

    for (method, target) in [
        (Method::GET, format!("http://evil.test:{port}/allowed/x")),
        (Method::GET, format!("http://{HOST}:1/allowed/x")),
        (Method::GET, format!("http://{HOST}:{port}/other/x")),
        (Method::POST, format!("http://{HOST}:{port}/allowed/x")),
    ] {
        let mut send = request(&target, &[("token", &token)]);
        send.method = method;
        let error = harness.broker.send(send).await.err().unwrap();
        assert_eq!(error.code(), ErrorCode::PolicyDenied, "{target}");
    }
    assert_eq!(harness.lookups(), 0);
    assert_eq!(harness.connects(), 0);
    assert_eq!(
        harness.key_fetches(),
        4,
        "opening needs the key, which is allowed"
    );
    assert_eq!(provider.connections(), 0);
}

#[tokio::test]
async fn a_conflict_or_a_failed_open_causes_no_dns_or_connection() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));

    let mut send = request(&url(&provider, "/"), &[("token", &token)]);
    send.headers
        .insert(header::AUTHORIZATION, HeaderValue::from_static("mine"));
    assert_eq!(
        harness.broker.send(send).await.err().unwrap().code(),
        ErrorCode::Conflict
    );

    // The value, presented for another field.
    let error = harness
        .get(&url(&provider, "/"), &[("other", &token)])
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::OpenFailed);
    assert!(error.detail().contains("other"));

    assert_eq!(harness.lookups(), 0);
    assert_eq!(harness.connects(), 0);
}

#[tokio::test]
async fn a_body_over_the_cap_for_injection_causes_no_dns_or_connection() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(options_with_limits(|limits| limits.buffer_cap = 8));
    let value = harness.seal(
        "password",
        b"x",
        &plain_policy(&provider, &json!({ "form_field": { "name": "p" } })),
    );
    let mut send = request(&url(&provider, "/echo"), &[("password", &value)]);
    send.method = Method::POST;
    send.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    send.body = request_body(b"this is more than eight bytes");
    let error = harness.broker.send(send).await.err().unwrap();
    assert_eq!(error.code(), ErrorCode::BodyTooLarge);
    assert_eq!(harness.lookups(), 0);
    assert_eq!(harness.connects(), 0);
}

#[tokio::test]
async fn acceptance_a_private_address_is_refused_after_dns_with_no_connection() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(Options {
        network: NetworkPolicy::default(),
        ..Options::default()
    });
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let error = harness
        .get(&url(&provider, "/"), &[("token", &token)])
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::DestinationRefused);
    assert_eq!(harness.lookups(), 1);
    assert_eq!(harness.connects(), 0);
    assert_eq!(provider.connections(), 0);
}

#[tokio::test]
async fn a_private_address_in_an_ip_literal_is_refused_with_no_dns() {
    let harness = Harness::with(Options {
        network: NetworkPolicy::default(),
        ..Options::default()
    });
    let mut rule = json!({
        "destination": { "scheme": "http", "host": "169.254.169.254" },
        "allow_plain_http": true,
        "inject": bearer(),
    });
    rule["allow_private_destination"] = json!(true);
    let token = harness.seal("token", b"x", &rule_policy(&rule));
    let error = harness
        .get(
            "http://169.254.169.254/latest/meta-data/",
            &[("token", &token)],
        )
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::DestinationRefused);
    assert_eq!(harness.lookups(), 0);
    assert_eq!(harness.connects(), 0);
}

#[tokio::test]
async fn a_rule_can_allow_a_private_address_only_where_configuration_honours_it() {
    let provider = MockProvider::plain().await;
    let send = |honour: bool| {
        let provider = &provider;
        async move {
            let harness = Harness::with(Options {
                network: NetworkPolicy {
                    honour_private_rules: honour,
                    ..NetworkPolicy::default()
                },
                ..Options::default()
            });
            let mut rule = plain_rule(provider, &bearer());
            rule["allow_private_destination"] = json!(true);
            let token = harness.seal("token", b"x", &rule_policy(&rule));
            let result = harness
                .get(&url(provider, "/echo"), &[("token", &token)])
                .await;
            result.map(|_| ()).map_err(|error| error.code())
        }
    };
    assert_eq!(send(false).await, Err(ErrorCode::DestinationRefused));
    assert_eq!(send(true).await, Ok(()));
}

#[tokio::test]
async fn only_permitted_addresses_are_tried_when_a_name_has_several() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(Options {
        addresses: vec![
            "169.254.169.254".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        ],
        ..Options::default()
    });
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    read_body(
        harness
            .get(&url(&provider, "/echo"), &[("token", &token)])
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let targets = harness.connect.targets.lock().unwrap().clone();
    assert_eq!(
        targets,
        [provider.address()],
        "connected to the address that was checked"
    );
}

#[tokio::test]
async fn a_lookup_that_fails_is_reported_as_a_connection_failure() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(Options {
        addresses: vec![],
        ..Options::default()
    });
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let error = harness
        .get(&url(&provider, "/"), &[("token", &token)])
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::UpstreamConnect);
    assert_eq!(harness.connects(), 0);
}

#[tokio::test]
async fn a_connection_that_fails_is_reported() {
    let closed_port = {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        listener.local_addr().unwrap().port()
    };
    let harness = Harness::new();
    let rule = json!({
        "destination": { "scheme": "http", "host": HOST, "port": closed_port },
        "allow_plain_http": true,
        "inject": bearer(),
    });
    let token = harness.seal("token", b"x", &rule_policy(&rule));
    let error = harness
        .get(
            &format!("http://{HOST}:{closed_port}/"),
            &[("token", &token)],
        )
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::UpstreamConnect);
}

#[tokio::test]
async fn keys_are_not_fetched_for_a_value_of_an_unknown_keyset_twice_over() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let policy = plain_policy(&provider, &bearer());
    let token = harness.seal_at("other", "c_1", "token", b"x", &policy);
    let mut send = request(&url(&provider, "/"), &[("token", &token)]);
    send.keyset = seal_format::KeysetId::new("other").unwrap();
    let error = harness.broker.send(send).await.err().unwrap();
    assert_eq!(error.code(), ErrorCode::KeysetUnknown);
    assert_eq!(harness.connects(), 0);
}

// Response sealing.

fn sealing_rule(
    provider: &MockProvider,
    path: &str,
    format: &str,
    ats: &[(&str, &str, &str)],
) -> Value {
    let fields: Vec<Value> = ats
        .iter()
        .map(|(at, name, policy)| json!({ "at": at, "as": name, "policy": policy }))
        .collect();
    let mut rule = plain_rule(
        provider,
        &json!({ "form_field": { "name": "client_secret" } }),
    );
    rule["destination"]["path_prefix"] = json!(path);
    rule["seal_response"] = json!({ "format": format, "fields": fields });
    rule
}

fn oauth_like_policy(provider: &MockProvider) -> Policy {
    let token = sealing_rule(
        provider,
        "/token",
        "json",
        &[
            ("/access_token", "access_token", "api"),
            ("/refresh_token", "refresh_token", "refresh"),
        ],
    );
    let mut refresh = token.clone();
    refresh["inject"] = json!({ "form_field": { "name": "refresh_token" } });
    let value = json!({
        "rules": [token],
        "definitions": {
            "api": { "rules": [plain_rule(provider, &bearer())] },
            "refresh": { "rules": [refresh] },
        }
    });
    Policy::from_json(value.to_string().as_bytes()).unwrap()
}

fn post_form(url: String, sealed: &[(&str, &Envelope)]) -> seal_broker::SendRequest {
    let mut send = request(&url, sealed);
    send.method = Method::POST;
    send.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    send.body = request_body(b"grant_type=x");
    send
}

/// A JWT whose payload is
/// `{"authentication_event_id":"evt-1","exp":1700000000,"sub":"user"}`.
const JWT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJhdXRoZW50aWNhdGlvbl9ldmVudF9pZCI6ImV2dC0xIiwiZXhwIjoxNzAwMDAwMDAwLCJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl";

/// Xero names the tenant a token was issued for in a claim of the access token, which
/// the application needs and could not otherwise read.
#[tokio::test]
async fn named_claims_of_a_sealed_jwt_are_returned_and_nothing_else_of_it() {
    let provider = MockProvider::plain().await;
    let tokens = json!({ "access_token": JWT, "refresh_token": "rt-opaque-plaintext" });
    provider.respond(
        "/token",
        CannedResponse::ok("application/json", tokens.to_string().as_bytes()),
    );
    let mut rule = sealing_rule(
        &provider,
        "/token",
        "json",
        &[
            ("/access_token", "access_token", "api"),
            ("/refresh_token", "refresh_token", "api"),
        ],
    );
    for field in rule["seal_response"]["fields"].as_array_mut().unwrap() {
        field["expose_claims"] = json!(["authentication_event_id", "exp", "absent"]);
    }
    let policy = Policy::from_json(
        json!({
            "rules": [rule],
            "definitions": { "api": { "rules": [plain_rule(&provider, &bearer())] } }
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    let harness = Harness::new();
    harness
        .canaries
        .lock()
        .unwrap()
        .register(&Canary::from_value(JWT));
    let secret = harness.seal("client_secret", b"cs", &policy);

    let response = harness
        .broker
        .send(post_form(
            url(&provider, "/token"),
            &[("client_secret", &secret)],
        ))
        .await
        .unwrap();
    let claims = response.claims.clone();
    let sealed = response.sealed_fields.clone();
    let body = read_text(response).await;

    assert_eq!(
        claims.keys().collect::<Vec<_>>(),
        [&field("access_token")],
        "an opaque token exposes nothing"
    );
    let exposed: Value = serde_json::from_str(&claims[&field("access_token")]).unwrap();
    assert_eq!(
        exposed,
        json!({ "authentication_event_id": "evt-1", "exp": 1_700_000_000 })
    );
    assert!(
        !body.contains(JWT) && !body.contains("rt-opaque-plaintext"),
        "{body}"
    );
    assert!(!format!("{claims:?}").contains("c2lnbmF0dXJl"));
    assert_eq!(
        harness.open("access_token", &sealed[&field("access_token")]),
        JWT.as_bytes()
    );
}

const TOKEN_RESPONSE: &[u8] =
    br#"{"access_token":"at-plaintext","refresh_token":"rt-plaintext","expires_in":3600}"#;

#[tokio::test]
async fn acceptance_named_response_fields_never_reach_the_caller_in_plaintext() {
    let provider = MockProvider::plain().await;
    provider.respond(
        "/token",
        CannedResponse::ok("application/json", TOKEN_RESPONSE),
    );
    let harness = Harness::new();
    let secret = harness.seal("client_secret", b"cs", &oauth_like_policy(&provider));

    let response = harness
        .broker
        .send(post_form(
            url(&provider, "/token"),
            &[("client_secret", &secret)],
        ))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let sealed = response.sealed_fields.clone();
    let length = response.headers[header::CONTENT_LENGTH].clone();
    let body = read_text(response).await;

    assert!(
        !body.contains("at-plaintext") && !body.contains("rt-plaintext"),
        "{body}"
    );
    assert_eq!(length.to_str().unwrap(), body.len().to_string());
    let value: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["expires_in"], 3600);
    assert!(value["access_token"].is_object());
    assert_eq!(
        harness.open("access_token", &sealed[&field("access_token")]),
        b"at-plaintext"
    );
    assert_eq!(
        harness.open("refresh_token", &sealed[&field("refresh_token")]),
        b"rt-plaintext"
    );
    assert_eq!(
        provider.received()[0].header("accept-encoding"),
        Some("identity")
    );
}

#[tokio::test]
async fn sealed_tokens_can_only_be_used_where_their_definition_says() {
    let provider = MockProvider::plain().await;
    provider.respond(
        "/token",
        CannedResponse::ok("application/json", TOKEN_RESPONSE),
    );
    let harness = Harness::new();
    let secret = harness.seal("client_secret", b"cs", &oauth_like_policy(&provider));
    let response = harness
        .broker
        .send(post_form(
            url(&provider, "/token"),
            &[("client_secret", &secret)],
        ))
        .await
        .unwrap();
    let sealed = response.sealed_fields.clone();
    read_body(response).await.unwrap();

    let access = &sealed[&field("access_token")];
    let response = harness
        .get(&url(&provider, "/echo"), &[("access_token", access)])
        .await
        .unwrap();
    read_body(response).await.unwrap();
    assert_eq!(
        provider.received().last().unwrap().header("authorization"),
        Some("Bearer at-plaintext")
    );

    let elsewhere = harness
        .get(
            &format!("http://evil.test:{}/", provider.port()),
            &[("access_token", access)],
        )
        .await;
    assert_eq!(elsewhere.err().unwrap().code(), ErrorCode::PolicyDenied);
}

#[tokio::test]
async fn acceptance_several_rotations_keep_working_with_the_same_policy() {
    let provider = MockProvider::plain().await;
    provider.respond(
        "/token",
        CannedResponse::ok("application/json", TOKEN_RESPONSE),
    );
    let harness = Harness::new();
    let secret = harness.seal("client_secret", b"cs", &oauth_like_policy(&provider));
    let response = harness
        .broker
        .send(post_form(
            url(&provider, "/token"),
            &[("client_secret", &secret)],
        ))
        .await
        .unwrap();
    let mut refresh = response.sealed_fields[&field("refresh_token")].clone();
    read_body(response).await.unwrap();
    let first_policy = harness
        .open_policy("refresh_token", &refresh)
        .canonical_json()
        .unwrap();

    for rotation in 0..6 {
        let response = harness
            .broker
            .send(post_form(
                url(&provider, "/token"),
                &[("refresh_token", &refresh)],
            ))
            .await
            .unwrap_or_else(|error| panic!("rotation {rotation}: {error}"));
        refresh = response.sealed_fields[&field("refresh_token")].clone();
        read_body(response).await.unwrap();
        assert_eq!(
            harness
                .open_policy("refresh_token", &refresh)
                .canonical_json()
                .unwrap(),
            first_policy
        );
    }
    assert_eq!(provider.received().len(), 7);
}

#[tokio::test]
async fn a_form_response_is_sealed() {
    let provider = MockProvider::plain().await;
    provider.respond(
        "/token",
        CannedResponse::ok(
            "application/x-www-form-urlencoded",
            b"access_token=gh-plaintext&scope=repo",
        ),
    );
    let harness = Harness::new();
    let rule = sealing_rule(
        &provider,
        "/token",
        "form",
        &[("access_token", "access_token", "api")],
    );
    let policy = Policy::from_json(json!({ "rules": [rule], "definitions": { "api": { "rules": [plain_rule(&provider, &bearer())] } } }).to_string().as_bytes()).unwrap();
    let secret = harness.seal("client_secret", b"cs", &policy);
    let response = harness
        .broker
        .send(post_form(
            url(&provider, "/token"),
            &[("client_secret", &secret)],
        ))
        .await
        .unwrap();
    let sealed = response.sealed_fields.clone();
    let body = read_text(response).await;
    assert!(!body.contains("gh-plaintext"));
    assert_eq!(
        harness.open("access_token", &sealed[&field("access_token")]),
        b"gh-plaintext"
    );
}

async fn sealed_send_error(canned: CannedResponse, cap: u64) -> (ErrorCode, Harness, MockProvider) {
    let provider = MockProvider::plain().await;
    provider.respond("/token", canned);
    let harness = Harness::with(options_with_limits(|limits| limits.buffer_cap = cap));
    let secret = harness.seal("client_secret", b"cs", &oauth_like_policy(&provider));
    let error = harness
        .broker
        .send(post_form(
            url(&provider, "/token"),
            &[("client_secret", &secret)],
        ))
        .await
        .err()
        .unwrap();
    (error.code(), harness, provider)
}

#[tokio::test]
async fn acceptance_an_over_cap_sealed_response_is_refused_and_nothing_reaches_the_caller() {
    let big = format!(
        r#"{{"access_token":"at-plaintext","pad":"{}"}}"#,
        "x".repeat(4096)
    );
    let (code, harness, provider) =
        sealed_send_error(CannedResponse::ok("application/json", big.as_bytes()), 2048).await;
    assert_eq!(code, ErrorCode::ResponseTooLarge);
    assert_eq!(provider.received().len(), 1, "the provider was contacted");
    let audit = harness.audit.last();
    assert_eq!(audit.code, Some("RESPONSE_TOO_LARGE"));
    assert_eq!(audit.bytes_out, 0);
}

#[tokio::test]
async fn a_response_that_cannot_be_sealed_is_refused_rather_than_passed_through() {
    for canned in [
        CannedResponse::ok("text/html", TOKEN_RESPONSE),
        CannedResponse::ok("application/json", b"not json at-plaintext"),
        CannedResponse {
            status: 200,
            headers: vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                ("content-encoding".to_owned(), "gzip".to_owned()),
            ],
            body: TOKEN_RESPONSE.to_vec(),
        },
        CannedResponse::ok("application/json", br#"{"access_token":123}"#),
    ] {
        let (code, _, _) = sealed_send_error(canned, 1024 * 1024).await;
        assert_eq!(code, ErrorCode::ResponseUnparseable);
    }
}

#[tokio::test]
async fn an_error_response_without_tokens_passes_through_sealing() {
    let provider = MockProvider::plain().await;
    provider.respond(
        "/token",
        CannedResponse {
            status: 400,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: br#"{"error":"invalid_grant"}"#.to_vec(),
        },
    );
    let harness = Harness::new();
    let secret = harness.seal("client_secret", b"cs", &oauth_like_policy(&provider));
    let response = harness
        .broker
        .send(post_form(
            url(&provider, "/token"),
            &[("client_secret", &secret)],
        ))
        .await
        .unwrap();
    assert_eq!(response.status, 400);
    assert!(response.sealed_fields.is_empty());
    assert!(read_text(response).await.contains("invalid_grant"));
}

// Values made by whoever holds the public key.

#[tokio::test]
async fn acceptance_a_value_made_by_an_attacker_cannot_strip_response_sealing() {
    let provider = MockProvider::plain().await;
    provider.respond(
        "/token",
        CannedResponse::ok("application/json", TOKEN_RESPONSE),
    );
    let harness = Harness::new();
    let genuine = harness.seal("client_secret", b"cs", &oauth_like_policy(&provider));

    // Anyone with the public key can seal this, for the same destination.
    let mut no_sealing = plain_rule(&provider, &json!({ "form_field": { "name": "x" } }));
    no_sealing["destination"]["path_prefix"] = json!("/token");
    let attacker = harness.seal("attacker", b"known", &rule_policy(&no_sealing));

    let result = harness
        .broker
        .send(post_form(
            url(&provider, "/token"),
            &[("attacker", &attacker), ("client_secret", &genuine)],
        ))
        .await;
    assert_eq!(result.err().unwrap().code(), ErrorCode::Conflict);
    assert_eq!(harness.connects(), 0);
    assert!(provider.received().is_empty());
}

// Streaming and pools.

#[tokio::test]
async fn a_download_streams_in_full() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let size = 3 * 1024 * 1024_u64;
    let response = harness
        .get(
            &url(&provider, &format!("/zeros/{size}")),
            &[("token", &token)],
        )
        .await
        .unwrap();
    let body = read_body(response).await.unwrap();
    assert_eq!(body.len() as u64, size);
    let audit = harness.audit.last();
    assert_eq!(audit.bytes_out, size);
    assert_eq!(audit.status, Some(200));
}

#[tokio::test]
async fn an_upload_streams_in_full() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let mut send = request(&url(&provider, "/sink"), &[("token", &token)]);
    send.method = Method::PUT;
    send.body = seal_broker::body::full_body(vec![7_u8; 2 * 1024 * 1024]);
    let response = harness.broker.send(send).await.unwrap();
    assert_eq!(read_text(response).await, r#"{"bytes":2097152}"#);
    assert_eq!(harness.audit.last().bytes_in, 2 * 1024 * 1024);
}

#[tokio::test]
async fn a_connection_is_reused_once_the_response_has_finished() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    for _ in 0..4 {
        read_body(
            harness
                .get(&url(&provider, "/echo"), &[("token", &token)])
                .await
                .unwrap(),
        )
        .await
        .unwrap();
    }
    assert_eq!(provider.connections(), 1);
    assert_eq!(harness.connects(), 1);
    assert_eq!(harness.lookups(), 4, "the address is checked on every send");
}

#[tokio::test]
async fn http2_shares_one_connection_between_concurrent_requests() {
    let provider = MockProvider::tls(Alpn::Both).await;
    let harness = tls_harness(&provider).await;
    let token = harness.seal("token", b"x", &tls_policy(&provider));
    read_body(
        harness
            .get(&tls_url(&provider, "/echo"), &[("token", &token)])
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let url = tls_url(&provider, "/echo");
    let sealed = [("token", &token)];
    let sends = (0..8).map(|_| harness.get(&url, &sealed));
    for response in futures_join(sends).await {
        read_body(response.unwrap()).await.unwrap();
    }
    assert_eq!(provider.connections(), 1);
}

async fn futures_join<F: std::future::Future>(futures: impl Iterator<Item = F>) -> Vec<F::Output> {
    let mut pinned: Vec<_> = futures.map(Box::pin).collect();
    let mut outputs = Vec::new();
    // Polled together, so that the requests really overlap.
    std::future::poll_fn(|cx| {
        let mut index = 0;
        while index < pinned.len() {
            if let std::task::Poll::Ready(output) = pinned[index].as_mut().poll(cx) {
                outputs.push(output);
                drop(pinned.swap_remove(index));
            } else {
                index += 1;
            }
        }
        if pinned.is_empty() {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
    outputs
}

#[tokio::test]
async fn a_connection_the_provider_closed_is_replaced_without_failing_the_request() {
    let provider = MockProvider::plain().await;
    provider.respond(
        "/closes",
        CannedResponse {
            status: 200,
            headers: vec![("connection".to_owned(), "close".to_owned())],
            body: b"bye".to_vec(),
        },
    );
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    for _ in 0..3 {
        let response = harness
            .get(&url(&provider, "/closes"), &[("token", &token)])
            .await
            .unwrap();
        assert_eq!(read_text(response).await, "bye");
    }
    assert_eq!(provider.connections(), 3);
}

#[tokio::test]
async fn at_the_connection_limit_an_idle_connection_is_closed_to_make_room() {
    let provider = MockProvider::plain().await;
    let other = MockProvider::plain().await;
    let mut options = Options::default();
    options.client.max_upstream_connections = 1;
    let harness = Harness::with(options);
    for target in [&provider, &other, &provider] {
        let token = harness.seal("token", b"x", &plain_policy(target, &bearer()));
        read_body(
            harness
                .get(&url(target, "/echo"), &[("token", &token)])
                .await
                .unwrap(),
        )
        .await
        .unwrap();
    }
    assert_eq!(provider.connections(), 2);
    assert_eq!(other.connections(), 1);
}

#[tokio::test]
async fn at_the_connection_limit_with_nothing_idle_a_request_fails_with_limit_exceeded() {
    let provider = MockProvider::plain().await;
    let mut options =
        options_with_limits(|limits| limits.connect_timeout = Duration::from_millis(100));
    options.client.max_upstream_connections = 1;
    let harness = Harness::with(options);
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let holding = harness
        .get(&url(&provider, "/stall"), &[("token", &token)])
        .await
        .unwrap();
    let error = harness
        .get(&url(&provider, "/echo"), &[("token", &token)])
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::LimitExceeded);
    drop(holding);
}

#[tokio::test]
async fn buffering_is_limited_and_a_request_gets_limit_exceeded_when_it_cannot_wait() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(options_with_limits(|limits| {
        limits.max_concurrent_buffered = 1;
        limits.first_byte_timeout = Duration::from_secs(5);
        limits.buffered_total_timeout = Duration::from_secs(5);
    }));
    let policy_with = |first_byte: Option<u32>| {
        let mut rule = sealing_rule(&provider, "/hold", "json", &[("/a", "a", "api")]);
        if let Some(seconds) = first_byte {
            rule["limits"] = json!({ "first_byte_timeout_s": seconds });
        }
        Policy::from_json(
            json!({ "rules": [rule], "definitions": { "api": { "rules": [plain_rule(&provider, &bearer())] } } })
                .to_string()
                .as_bytes(),
        )
        .unwrap()
    };
    let holder = harness.seal("client_secret", b"cs", &policy_with(None));
    let waiter = harness.seal("client_secret", b"cs", &policy_with(Some(1)));

    let first = harness.broker.send(post_form(
        url(&provider, "/hold"),
        &[("client_secret", &holder)],
    ));
    let second = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        harness
            .broker
            .send(post_form(
                url(&provider, "/hold"),
                &[("client_secret", &waiter)],
            ))
            .await
    };
    // The first holds the only slot until after the second has given up waiting.
    tokio::select! {
        _ = first => panic!("the first request should still be waiting"),
        second = second => assert_eq!(second.err().unwrap().code(), ErrorCode::LimitExceeded),
    }
    assert_eq!(
        provider.received().len(),
        1,
        "the second never reached the provider"
    );
}

// Timeouts.

#[tokio::test]
async fn a_provider_that_never_responds_hits_the_first_byte_timeout() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(options_with_limits(|limits| {
        limits.first_byte_timeout = Duration::from_millis(100)
    }));
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let error = harness
        .get(&url(&provider, "/hold"), &[("token", &token)])
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::UpstreamTimeout);
    assert_eq!(harness.audit.last().code, Some("UPSTREAM_TIMEOUT"));
}

#[tokio::test]
async fn a_download_that_stalls_hits_the_idle_timeout() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(options_with_limits(|limits| {
        limits.idle_timeout = Duration::from_millis(100)
    }));
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let response = harness
        .get(&url(&provider, "/stall"), &[("token", &token)])
        .await
        .unwrap();
    let error = read_body(response).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::UpstreamTimeout);
    let audit = harness.audit.last();
    assert_eq!(audit.code, Some("UPSTREAM_TIMEOUT"));
    assert_eq!(audit.bytes_out, 7, "what got through is counted");
}

#[tokio::test]
async fn a_slow_transfer_that_keeps_moving_is_not_cut_off_without_a_deadline() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(options_with_limits(|limits| {
        limits.idle_timeout = Duration::from_millis(200)
    }));
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let mut response = harness
        .get(&url(&provider, "/trickle"), &[("token", &token)])
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    while started.elapsed() < Duration::from_millis(600) {
        response.body.frame().await.unwrap().unwrap();
    }
    assert!(
        started.elapsed() > harness_idle(),
        "ran past the idle timeout"
    );
}

fn harness_idle() -> Duration {
    Duration::from_millis(200)
}

#[tokio::test]
async fn max_stream_duration_cuts_off_a_transfer_when_set() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(options_with_limits(|limits| {
        limits.idle_timeout = Duration::from_secs(5);
        limits.max_stream_duration = Some(Duration::from_millis(150));
    }));
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let response = harness
        .get(&url(&provider, "/trickle"), &[("token", &token)])
        .await
        .unwrap();
    assert_eq!(
        read_body(response).await.unwrap_err().code(),
        ErrorCode::UpstreamTimeout
    );
}

#[tokio::test]
async fn a_trickling_response_cannot_hold_a_buffer_past_its_total_deadline() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(options_with_limits(|limits| {
        limits.idle_timeout = Duration::from_secs(5);
        limits.buffered_total_timeout = Duration::from_millis(150);
    }));
    let mut rule = sealing_rule(&provider, "/", "json", &[("/a", "a", "api")]);
    rule["destination"]
        .as_object_mut()
        .unwrap()
        .remove("path_prefix");
    let policy = Policy::from_json(json!({ "rules": [rule], "definitions": { "api": { "rules": [plain_rule(&provider, &bearer())] } } }).to_string().as_bytes()).unwrap();
    let secret = harness.seal("client_secret", b"cs", &policy);
    let error = harness
        .broker
        .send(post_form(
            url(&provider, "/trickle"),
            &[("client_secret", &secret)],
        ))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::UpstreamTimeout);
}

/// The total deadline protects a scarce buffer slot. Once the slot is released, a
/// streamed response is timed on progress like any other.
#[tokio::test]
async fn a_streamed_response_is_not_held_to_the_deadline_of_a_buffered_request() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(options_with_limits(|limits| {
        limits.idle_timeout = Duration::from_secs(5);
        limits.buffered_total_timeout = Duration::from_millis(150);
    }));
    let policy = plain_policy(&provider, &json!({ "form_field": { "name": "password" } }));
    let value = harness.seal("password", b"x", &policy);
    let mut response = harness
        .broker
        .send(post_form(
            url(&provider, "/trickle"),
            &[("password", &value)],
        ))
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    while started.elapsed() < Duration::from_millis(500) {
        response.body.frame().await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn a_lookup_that_hangs_hits_the_connect_timeout() {
    let provider = MockProvider::plain().await;
    let harness = Harness::with(options_with_limits(|limits| {
        limits.connect_timeout = Duration::from_millis(100);
    }));
    harness.resolve.hang.store(true, Ordering::SeqCst);
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        harness.get(&url(&provider, "/echo"), &[("token", &token)]),
    )
    .await
    .expect("the broker gives up by itself")
    .err()
    .unwrap();
    assert_eq!(error.code(), ErrorCode::UpstreamTimeout);
    assert_eq!(harness.connects(), 0);
}

#[tokio::test]
async fn a_rule_can_tighten_the_timeout() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let mut rule = plain_rule(&provider, &bearer());
    rule["limits"] = json!({ "first_byte_timeout_s": 1 });
    let token = harness.seal("token", b"x", &rule_policy(&rule));
    let started = tokio::time::Instant::now();
    let error = harness
        .get(&url(&provider, "/hold"), &[("token", &token)])
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::UpstreamTimeout);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the rule's limit applied, not the global 10 s"
    );
}

// Failures and cancellation.

#[tokio::test]
async fn a_provider_reset_ends_the_stream_with_a_code() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let response = harness
        .get(&url(&provider, "/reset"), &[("token", &token)])
        .await
        .unwrap();
    let error = read_body(response).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::UpstreamReset);
    let audit = harness.audit.last();
    assert_eq!(audit.outcome, seal_broker::audit::Outcome::Failed);
    assert_eq!(audit.code, Some("UPSTREAM_RESET"));
}

#[tokio::test]
async fn a_caller_that_goes_away_mid_stream_cancels_the_provider() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let mut response = harness
        .get(&url(&provider, "/stall"), &[("token", &token)])
        .await
        .unwrap();
    response.body.frame().await.unwrap().unwrap();
    drop(response);

    wait_until(|| provider.cancelled() == 1).await;
    assert_eq!(
        harness.audit.last().outcome,
        seal_broker::audit::Outcome::Cancelled
    );
}

#[tokio::test]
async fn a_caller_that_goes_away_before_the_response_cancels_the_provider() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let (target, sealed) = (url(&provider, "/hold"), [("token", &token)]);
    let sending = harness.get(&target, &sealed);
    let timed_out = tokio::time::timeout(Duration::from_millis(150), sending).await;
    assert!(timed_out.is_err(), "still waiting");

    wait_until(|| provider.cancelled() == 1).await;
    assert_eq!(
        harness.audit.last().outcome,
        seal_broker::audit::Outcome::Cancelled
    );
}

async fn wait_until(condition: impl Fn() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the condition did not become true");
}

#[tokio::test]
async fn a_connection_abandoned_mid_stream_is_not_reused() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    drop(
        harness
            .get(&url(&provider, "/stall"), &[("token", &token)])
            .await
            .unwrap(),
    );
    read_body(
        harness
            .get(&url(&provider, "/echo"), &[("token", &token)])
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(provider.connections(), 2);
}

// Audit.

#[tokio::test]
async fn every_request_leaves_one_record_of_identifiers_and_counts() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let path = format!("/echo?secret_query={}", "SECRETQUERY");
    read_body(
        harness
            .get(&url(&provider, &path), &[("token", &token)])
            .await
            .unwrap(),
    )
    .await
    .unwrap();

    let records = harness.audit.all();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.op, "send");
    assert_eq!(record.caller, "test-app");
    assert_eq!(record.keyset, "acme");
    assert_eq!(record.item, "connection-1");
    assert_eq!(record.fields, ["token"]);
    assert_eq!(record.rules, [0]);
    assert_eq!(record.method, "GET");
    assert_eq!(record.host.as_deref(), Some(HOST));
    assert_eq!(record.path.as_deref(), Some("/echo"), "no query string");
    assert_eq!(record.status, Some(200));
    assert_eq!(record.outcome, seal_broker::audit::Outcome::Ok);
    assert_eq!(record.code, None);
    assert!(record.ts > 1_700_000_000);
    assert!(
        !serde_json::to_string(record)
            .unwrap()
            .contains("SECRETQUERY")
    );
}

#[tokio::test]
async fn a_refusal_is_recorded_as_a_refusal() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let _ = harness
        .get(
            &format!("http://evil.test:{}/", provider.port()),
            &[("token", &token)],
        )
        .await;
    let record = harness.audit.last();
    assert_eq!(record.outcome, seal_broker::audit::Outcome::Refused);
    assert_eq!(record.code, Some("POLICY_DENIED"));
    assert_eq!(record.rules, Vec::<usize>::new());
    assert_eq!(record.status, None);
}

#[tokio::test]
async fn an_audit_failure_fails_the_request_rather_than_leaving_it_unaudited() {
    let provider = MockProvider::plain().await;
    provider.respond(
        "/token",
        CannedResponse::ok("application/json", TOKEN_RESPONSE),
    );
    let harness = Harness::new();
    *harness.audit.fail.lock().unwrap() = true;

    let token = harness.seal("token", b"x", &plain_policy(&provider, &bearer()));
    let response = harness
        .get(&url(&provider, "/echo"), &[("token", &token)])
        .await
        .unwrap();
    assert_eq!(
        read_body(response).await.unwrap_err().code(),
        ErrorCode::Internal
    );

    let secret = harness.seal("client_secret", b"cs", &oauth_like_policy(&provider));
    let error = harness
        .broker
        .send(post_form(
            url(&provider, "/token"),
            &[("client_secret", &secret)],
        ))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::Internal);
}

// Canaries.

#[tokio::test]
async fn acceptance_a_canary_never_appears_in_logs_audit_errors_or_sealed_responses() {
    let provider = MockProvider::plain().await;
    let secret = Canary::generate().unwrap();
    let (access, refresh) = (Canary::generate().unwrap(), Canary::generate().unwrap());
    let token_body =
        json!({ "access_token": access.value(), "refresh_token": refresh.value() }).to_string();
    provider.respond(
        "/token",
        CannedResponse::ok("application/json", token_body.as_bytes()),
    );

    let mut registry = CanaryRegistry::new();
    for canary in [&secret, &access, &refresh] {
        registry.register(canary);
    }
    registry.register_basic_auth("user", &secret);

    let capture = LogCapture::new();
    let harness = Harness::new();
    let mut seen = Vec::new();
    {
        let _guard = capture.install();
        // A flat, single-threaded walk through success and each kind of failure.
        let header = harness.seal(
            "secret",
            secret.value().as_bytes(),
            &plain_policy(
                &provider,
                &json!({ "header": { "name": "X-Key", "format": "{}" } }),
            ),
        );
        let basic = harness.seal(
            "secret",
            secret.value().as_bytes(),
            &plain_policy(
                &provider,
                &json!({ "basic": { "username": { "literal": "user" } } }),
            ),
        );
        let form = harness.seal(
            "client_secret",
            secret.value().as_bytes(),
            &oauth_like_policy(&provider),
        );

        let response = harness
            .get(&url(&provider, "/hold-not"), &[("secret", &header)])
            .await
            .unwrap();
        seen.push(format!("{:?}", response.headers));
        seen.push(String::from_utf8_lossy(&read_body(response).await.unwrap()).into_owned());

        for attempt in [
            harness
                .get(&url(&provider, "/hold-not"), &[("secret", &basic)])
                .await,
            harness
                .get(
                    &format!("http://evil.test:{}/", provider.port()),
                    &[("secret", &header)],
                )
                .await,
            harness
                .get(&url(&provider, "/"), &[("wrong_field", &header)])
                .await,
        ] {
            match attempt {
                Ok(response) => seen.push(
                    String::from_utf8_lossy(&read_body(response).await.unwrap()).into_owned(),
                ),
                Err(error) => seen.push(format!("{error} {error:?}")),
            }
        }

        let response = harness
            .broker
            .send(post_form(
                url(&provider, "/token"),
                &[("client_secret", &form)],
            ))
            .await
            .unwrap();
        seen.push(format!("{:?}", response.headers));
        seen.push(format!("{:?}", response.sealed_fields));
        seen.push(String::from_utf8_lossy(&read_body(response).await.unwrap()).into_owned());

        // A secret that cannot go in a header: the error must not repeat it.
        let bad = harness.seal(
            "secret",
            format!("{}\nX: y", secret.value()).as_bytes(),
            &plain_policy(&provider, &bearer()),
        );
        seen.push(format!(
            "{}",
            harness
                .get(&url(&provider, "/"), &[("secret", &bad)])
                .await
                .err()
                .unwrap()
        ));
    }

    for text in &seen {
        let hits = registry.scan("caller", text);
        assert!(hits.is_empty(), "{hits:?}");
    }
    let hits = registry.scan("logs", &capture.contents());
    assert!(hits.is_empty(), "{hits:?}");
    let audit: String = harness
        .audit
        .all()
        .iter()
        .map(|record| serde_json::to_string(record).unwrap())
        .collect();
    assert!(harness.audit.all().len() >= 5);
    let hits = registry.scan("audit", &audit);
    assert!(hits.is_empty(), "{hits:?}");

    // And the scan can see: the provider did receive the real secret.
    assert!(
        provider
            .received()
            .iter()
            .any(|received| received.header("x-key") == Some(secret.value()))
    );
}

/// A boundary the threat model states: a provider that echoes a credential gives it to the
/// caller, and seal does not inspect responses for this.
#[tokio::test]
async fn a_providers_own_echo_is_outside_the_guarantee() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal(
        "token",
        b"s3cret-echoed",
        &plain_policy(&provider, &bearer()),
    );
    let value = echo_json(&harness, &url(&provider, "/echo"), &[("token", &token)]).await;
    assert!(value.to_string().contains("s3cret-echoed"));
}

#[tokio::test]
async fn is_end_stream_and_size_hints_are_sensible_for_a_buffered_response() {
    let provider = MockProvider::plain().await;
    provider.respond(
        "/token",
        CannedResponse::ok("application/json", br#"{"access_token":"a"}"#),
    );
    let harness = Harness::new();
    let secret = harness.seal("client_secret", b"cs", &oauth_like_policy(&provider));
    let response = harness
        .broker
        .send(post_form(
            url(&provider, "/token"),
            &[("client_secret", &secret)],
        ))
        .await
        .unwrap();
    assert!(!response.body.is_end_stream());
    assert!(response.body.size_hint().exact().is_some());
    let key_fetches = harness.keys.fetches.load(Ordering::SeqCst);
    assert_eq!(key_fetches, 1);
}

/// The fakes stand in for DNS and TCP everywhere else, so this is the real path.
#[tokio::test]
async fn the_production_network_path_resolves_checks_and_connects() {
    use std::sync::Arc;

    use seal_broker::{Broker, BrokerConfig, Environment};
    use seal_format::id::KeyId;
    use seal_keys::{Keys, StaticKeys};

    let provider = MockProvider::plain().await;
    let (private, _) = seal_format::PrivateKey::generate();
    let public = private.public_key().unwrap();
    let mut keys = StaticKeys::new();
    keys.add(support::keyset(), KeyId::new("k1").unwrap(), private)
        .unwrap();
    let audit = Arc::new(support::MemoryAudit::default());
    let broker = Broker::new(
        BrokerConfig {
            network: NetworkPolicy {
                allow_private_cidrs: vec![
                    "127.0.0.0/8".parse().unwrap(),
                    "::1/128".parse().unwrap(),
                ],
                ..NetworkPolicy::default()
            },
            ..BrokerConfig::default()
        },
        Arc::new(keys) as Arc<dyn Keys>,
        Environment::production(audit.clone()).unwrap(),
    )
    .unwrap();

    let host = "localhost";
    let rule = json!({
        "destination": { "scheme": "http", "host": host, "port": provider.port() },
        "allow_plain_http": true,
        "inject": bearer(),
    });
    let (keyset, item, name) = (support::keyset(), support::item(), field("token"));
    let token = seal_format::seal(
        &public,
        &KeyId::new("k1").unwrap(),
        seal_format::Binding {
            keyset: &keyset,
            item: &item,
            field: &name,
        },
        b"s3cret",
        &rule_policy(&rule),
    )
    .unwrap();
    let target = format!("http://{host}:{}/echo", provider.port());
    let response = broker
        .send(request(&target, &[("token", &token)]))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    read_body(response).await.unwrap();
    assert_eq!(
        provider.received()[0].header("authorization"),
        Some("Bearer s3cret")
    );
    assert_eq!(audit.last().outcome, seal_broker::audit::Outcome::Ok);
}

// Shared values: a platform credential used with a tenant's request.

fn shared_policy(provider: &MockProvider) -> Policy {
    let mut value = serde_json::to_value(oauth_like_policy(provider)).unwrap();
    value["shared"] = json!(true);
    value["rules"][0]["require_form"] =
        json!({ "grant_type": ["authorization_code", "refresh_token"] });
    Policy::from_json(value.to_string().as_bytes()).unwrap()
}

fn platform_secret(harness: &Harness, provider: &MockProvider) -> seal_broker::Presented {
    seal_broker::Presented {
        envelope: harness.seal_at(
            "platform",
            "oauth-app",
            "client_secret",
            b"platform-cs",
            &shared_policy(provider),
        ),
        item: Some(seal_format::ItemId::new("oauth-app").unwrap()),
    }
}

fn form_with(url: String, body: &'static [u8]) -> seal_broker::SendRequest {
    let mut send = post_form(url, &[]);
    send.body = request_body(body);
    send
}

#[tokio::test]
async fn a_shared_value_serves_a_tenant_and_new_tokens_belong_to_the_tenant() {
    let provider = MockProvider::plain().await;
    provider.respond(
        "/token",
        CannedResponse::ok("application/json", TOKEN_RESPONSE),
    );
    let harness = Harness::new();
    let mut send = form_with(
        url(&provider, "/token"),
        b"grant_type=refresh_token&client_id=c",
    );
    send.sealed
        .insert(field("client_secret"), platform_secret(&harness, &provider));

    let response = harness.broker.send(send).await.unwrap();
    assert_eq!(response.status, 200);
    let sealed = response.sealed_fields.clone();
    read_body(response).await.unwrap();

    assert_eq!(
        provider.received()[0].body,
        b"grant_type=refresh_token&client_id=c&client_secret=platform-cs"
    );
    // The tokens are bound to the tenant's record, not the platform's.
    assert_eq!(
        harness.open("access_token", &sealed[&field("access_token")]),
        b"at-plaintext"
    );
    assert!(
        !harness
            .open_policy("refresh_token", &sealed[&field("refresh_token")])
            .shared
    );
    assert_eq!(
        harness.audit.last().shared,
        ["client_secret=platform/oauth-app"]
    );
}

#[tokio::test]
async fn a_value_from_another_record_is_refused_unless_shared() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let policy = oauth_like_policy(&provider);
    for (keyset, item) in [("acme", "c_other"), ("platform", "c_1")] {
        let mut send = form_with(url(&provider, "/token"), b"grant_type=refresh_token");
        send.sealed.insert(
            field("client_secret"),
            seal_broker::Presented {
                envelope: harness.seal_at(keyset, item, "client_secret", b"cs", &policy),
                item: Some(seal_format::ItemId::new(item).unwrap()),
            },
        );
        let error = harness.broker.send(send).await.err().unwrap();
        assert_eq!(error.code(), ErrorCode::PolicyDenied, "{keyset}/{item}");
        assert!(error.detail().contains("client_secret"));
    }

    // A value presented as the request's own when it was sealed elsewhere does not open.
    let other = harness.seal_at("acme", "c_other", "client_secret", b"cs", &policy);
    let mut send = form_with(url(&provider, "/token"), b"grant_type=refresh_token");
    send.sealed.insert(field("client_secret"), other.into());
    assert_eq!(
        harness.broker.send(send).await.err().unwrap().code(),
        ErrorCode::OpenFailed
    );
    assert_eq!((harness.lookups(), harness.connects()), (0, 0));
}

#[tokio::test]
async fn a_shared_value_is_refused_for_a_grant_its_rule_does_not_allow() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let bodies: [&'static [u8]; 5] = [
        b"grant_type=client_credentials",
        b"client_id=c",
        b"grant_type=refresh_token&grant_type=client_credentials",
        b"grant_type=refresh_token&grant_type=refresh_token",
        b"grant_type=Refresh_token",
    ];
    for body in bodies {
        let mut send = form_with(url(&provider, "/token"), body);
        send.sealed
            .insert(field("client_secret"), platform_secret(&harness, &provider));
        let error = harness.broker.send(send).await.err().unwrap();
        assert_eq!(error.code(), ErrorCode::PolicyDenied, "{body:?}");
    }

    // The body must be a plain form for seal to read it.
    for (name, value) in [
        (header::CONTENT_TYPE, "application/json"),
        (header::CONTENT_ENCODING, "gzip"),
    ] {
        let mut send = form_with(url(&provider, "/token"), b"grant_type=refresh_token");
        send.headers.insert(name, HeaderValue::from_static(value));
        send.sealed
            .insert(field("client_secret"), platform_secret(&harness, &provider));
        assert_eq!(
            harness.broker.send(send).await.err().unwrap().code(),
            ErrorCode::PolicyDenied
        );
    }
    assert_eq!((harness.lookups(), harness.connects()), (0, 0));
    assert!(provider.received().is_empty());
}

#[tokio::test]
async fn a_required_form_field_is_checked_without_changing_the_body() {
    let provider = MockProvider::plain().await;
    let mut rule = plain_rule(&provider, &bearer());
    rule["methods"] = json!(["POST"]);
    rule["require_form"] = json!({ "action": ["read"] });
    let harness = Harness::new();
    let token = harness.seal("token", b"t", &rule_policy(&rule));

    let mut send = form_with(url(&provider, "/echo"), b"action=read&x=%20y");
    send.sealed.insert(field("token"), token.clone().into());
    read_body(harness.broker.send(send).await.unwrap())
        .await
        .unwrap();
    assert_eq!(provider.received()[0].body, b"action=read&x=%20y");

    let mut send = form_with(url(&provider, "/echo"), b"action=write");
    send.sealed.insert(field("token"), token.into());
    assert_eq!(
        harness.broker.send(send).await.err().unwrap().code(),
        ErrorCode::PolicyDenied
    );
}
