//! The same tests in all three modes, through `seal-client`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::time::Duration;

use http::{HeaderValue, Method, header};
use http_body::Body as _;
use http_body_util::BodyExt;
use seal_client::{ErrorCode, Mode};
use seal_format::Policy;
use seal_testkit::canary::{Canary, CanaryRegistry};
use serde_json::{Value, json};
use support::*;

async fn simple(mode: Mode) -> (Instance, MockProvider) {
    let provider = MockProvider::plain().await;
    let instance = start(mode, Options::default(), &[&provider]).await;
    (instance, provider)
}

fn oauth_like(provider: &MockProvider) -> Policy {
    let sealing = json!({
        "format": "json",
        "fields": [
            { "at": "/access_token", "as": "access_token", "policy": "api" },
            { "at": "/refresh_token", "as": "refresh_token", "policy": "refresh" }
        ]
    });
    let mut token = plain_rule(
        provider,
        &json!({ "form_field": { "name": "client_secret" } }),
    );
    token["destination"]["path_prefix"] = json!("/token");
    token["seal_response"] = sealing;
    let mut refresh = token.clone();
    refresh["inject"] = json!({ "form_field": { "name": "refresh_token" } });
    policy(&json!({
        "rules": [token],
        "definitions": {
            "api": { "rules": [plain_rule(provider, &bearer())] },
            "refresh": { "rules": [refresh] },
        }
    }))
}

fn post_form(url: &str, sealed: &[(&str, &seal_format::Envelope)]) -> seal_client::SendRequest {
    let mut request = request(Method::POST, url, sealed, body("grant_type=x"));
    request.request.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    request
}

const TOKENS: &[u8] =
    br#"{"access_token":"at-plaintext","refresh_token":"rt-plaintext","expires_in":3600}"#;

mode_matrix! {
    info_reports_the_mode => |mode: Mode| async move {
        let (instance, _provider) = simple(mode).await;
        let info = instance.client.info().await.unwrap();
        assert_eq!(info.mode, mode.as_str());
        assert_eq!(info.buffer_cap, 1 << 20);
    };

    a_bearer_token_reaches_the_provider => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        let token = instance.setup.seal("token", b"SEALCANARY-s3cret", &policy(&json!({ "rules": [plain_rule(&provider, &bearer())] }))).await;
        let mut send = get(&url(&provider, "/echo?a=1"), &[("token", &token)]);
        send.request.headers_mut().insert("x-request-id", HeaderValue::from_static("abc"));
        let response = instance.client.send(send).await.unwrap();
        assert_eq!(response.response.status(), 200);
        assert!(response.sealed_fields.is_empty());
        text(response).await;
        let received = &provider.received()[0];
        assert_eq!(received.header("authorization"), Some("Bearer SEALCANARY-s3cret"));
        assert_eq!(received.header("x-request-id"), Some("abc"));
        assert_eq!(received.uri, "/echo?a=1");
    };

    acceptance_a_disallowed_destination_is_refused_and_nothing_is_sent => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        let token = instance.setup.seal("token", b"SEALCANARY-token", &policy(&json!({ "rules": [plain_rule(&provider, &bearer())] }))).await;
        let other = format!("http://127.0.0.1:{}/echo", provider.port());
        let error = instance.client.send(get(&other, &[("token", &token)])).await.err().unwrap();
        assert_eq!(error.code, ErrorCode::PolicyDenied);
        assert!(!error.code.is_retryable());
        assert_eq!(provider.connections(), 0);
    };

    a_value_presented_for_another_field_does_not_open => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        let token = instance.setup.seal("token", b"SEALCANARY-token", &policy(&json!({ "rules": [plain_rule(&provider, &bearer())] }))).await;
        let error = instance.client.send(get(&url(&provider, "/"), &[("other", &token)])).await.err().unwrap();
        assert_eq!(error.code, ErrorCode::OpenFailed);
    };

    acceptance_redirects_are_returned_not_followed => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        let token = instance.setup.seal("token", b"SEALCANARY-token", &policy(&json!({ "rules": [plain_rule(&provider, &bearer())] }))).await;
        let response = instance.client.send(get(&url(&provider, "/redirect"), &[("token", &token)])).await.unwrap();
        assert_eq!(response.response.status(), 302);
        assert_eq!(response.response.headers()[header::LOCATION], "/echo");
        text(response).await;
        assert_eq!(provider.received().len(), 1);
    };

    the_caller_cannot_set_an_injected_header => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        let token = instance.setup.seal("token", b"SEALCANARY-token", &policy(&json!({ "rules": [plain_rule(&provider, &bearer())] }))).await;
        let mut send = get(&url(&provider, "/echo"), &[("token", &token)]);
        send.request.headers_mut().insert(header::AUTHORIZATION, HeaderValue::from_static("mine"));
        assert_eq!(instance.client.send(send).await.err().unwrap().code, ErrorCode::Conflict);
    };

    acceptance_named_response_fields_are_sealed_and_usable_where_they_belong => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        provider.respond("/token", CannedResponse::ok("application/json", TOKENS));
        let secret = instance.setup.seal("client_secret", b"SEALCANARY-client-secret", &oauth_like(&provider)).await;
        let response = instance.client.send(post_form(&url(&provider, "/token"), &[("client_secret", &secret)])).await.unwrap();
        let sealed = response.sealed_fields.clone();
        let body = text(response).await;
        assert!(!body.contains("at-plaintext") && !body.contains("rt-plaintext"), "{body}");
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["expires_in"], 3600);

        let access = &sealed[&field("access_token")];
        let response = instance.client.send(get(&url(&provider, "/echo"), &[("access_token", access)])).await.unwrap();
        text(response).await;
        assert_eq!(provider.received().last().unwrap().header("authorization"), Some("Bearer at-plaintext"));
    };

    acceptance_rotating_refresh_tokens_keep_working => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        provider.respond("/token", CannedResponse::ok("application/json", TOKENS));
        let secret = instance.setup.seal("client_secret", b"SEALCANARY-client-secret", &oauth_like(&provider)).await;
        let response = instance.client.send(post_form(&url(&provider, "/token"), &[("client_secret", &secret)])).await.unwrap();
        let mut refresh = response.sealed_fields[&field("refresh_token")].clone();
        text(response).await;
        for rotation in 0..5 {
            let response = instance
                .client
                .send(post_form(&url(&provider, "/token"), &[("refresh_token", &refresh)]))
                .await
                .unwrap_or_else(|error| panic!("rotation {rotation}: {error}"));
            refresh = response.sealed_fields[&field("refresh_token")].clone();
            text(response).await;
        }
        assert_eq!(provider.received().len(), 6);
    };

    acceptance_an_over_cap_sealed_response_is_refused => |mode: Mode| async move {
        let provider = MockProvider::plain().await;
        let options = Options { limits: "buffer_cap = \"2KiB\"\n".to_owned(), ..Options::default() };
        let instance = start(mode, options, &[&provider]).await;
        let big = format!(r#"{{"access_token":"at-plaintext","pad":"{}"}}"#, "x".repeat(4096));
        provider.respond("/token", CannedResponse::ok("application/json", big.as_bytes()));
        let secret = instance.setup.seal("client_secret", b"SEALCANARY-client-secret", &oauth_like(&provider)).await;
        let error = instance.client.send(post_form(&url(&provider, "/token"), &[("client_secret", &secret)])).await.err().unwrap();
        assert_eq!(error.code, ErrorCode::ResponseTooLarge);
    };

    a_value_made_by_an_attacker_cannot_strip_response_sealing => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        provider.respond("/token", CannedResponse::ok("application/json", TOKENS));
        let genuine = instance.setup.seal("client_secret", b"SEALCANARY-client-secret", &oauth_like(&provider)).await;
        let mut plain = plain_rule(&provider, &json!({ "form_field": { "name": "x" } }));
        plain["destination"]["path_prefix"] = json!("/token");
        let attacker = instance.setup.seal("attacker", b"SEALCANARY-attacker-known", &policy(&json!({ "rules": [plain] }))).await;
        let error = instance
            .client
            .send(post_form(&url(&provider, "/token"), &[("attacker", &attacker), ("client_secret", &genuine)]))
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(provider.received().is_empty());
    };

    an_upload_and_a_download_stream_through => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        let token = instance.setup.seal("token", b"SEALCANARY-token", &policy(&json!({ "rules": [plain_rule(&provider, &bearer())] }))).await;
        let upload = vec![7_u8; 3 * 1024 * 1024 + 5];
        let response = instance.client.send(request(Method::PUT, &url(&provider, "/sink"), &[("token", &token)], body(upload))).await.unwrap();
        assert_eq!(text(response).await, format!("{{\"bytes\":{}}}", 3 * 1024 * 1024 + 5));

        let size = 3 * 1024 * 1024 + 7;
        let response = instance.client.send(get(&url(&provider, &format!("/zeros/{size}")), &[("token", &token)])).await.unwrap();
        assert_eq!(read(response).await.unwrap().len(), size);
    };

    a_stalled_download_ends_with_a_timeout_code => |mode: Mode| async move {
        let provider = MockProvider::plain().await;
        let options = Options { limits: "idle_timeout = \"200ms\"\n".to_owned(), ..Options::default() };
        let instance = start(mode, options, &[&provider]).await;
        let token = instance.setup.seal("token", b"SEALCANARY-token", &policy(&json!({ "rules": [plain_rule(&provider, &bearer())] }))).await;
        let response = instance.client.send(get(&url(&provider, "/stall"), &[("token", &token)])).await.unwrap();
        assert_eq!(read(response).await.unwrap_err().code, ErrorCode::UpstreamTimeout);
    };

    a_caller_that_goes_away_cancels_the_provider => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        let token = instance.setup.seal("token", b"SEALCANARY-token", &policy(&json!({ "rules": [plain_rule(&provider, &bearer())] }))).await;
        let response = instance.client.send(get(&url(&provider, "/stall"), &[("token", &token)])).await.unwrap();
        let mut body = response.response.into_body();
        body.frame().await.unwrap().unwrap();
        drop(body);
        for _ in 0..300 {
            if provider.cancelled() == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the provider's request was not cancelled");
    };

    the_admin_calls_make_rotate_and_list_keys => |mode: Mode| async move {
        let (instance, _provider) = simple(mode).await;
        let fresh = seal_format::KeysetId::new("fresh").unwrap();
        let created = match mode {
            // In-process mode has no callers, so no keyset limits.
            Mode::InProcess => instance.client.generate_keyset(&fresh).await.unwrap(),
            _ => {
                // The test caller may administer, but only use `acme`.
                instance.client.generate_keyset(&fresh).await.unwrap()
            }
        };
        assert_eq!(created.keyset, "fresh");
        assert_eq!(instance.client.generate_keyset(&fresh).await.err().unwrap().code, ErrorCode::Conflict);
        let rotated = instance.client.rotate(&fresh).await.unwrap();
        let keys = instance.client.public_keys(&fresh).await.unwrap();
        let kids: Vec<&str> = keys.iter().map(|key| key.kid.as_str()).collect();
        assert_eq!(kids, [created.kid.as_str(), rotated.kid.as_str()]);
        let unknown = seal_format::KeysetId::new("nobody").unwrap();
        assert_eq!(instance.client.public_keys(&unknown).await.err().unwrap().code, ErrorCode::KeysetUnknown);
    };

    every_send_leaves_an_audit_record => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        let token = instance.setup.seal("token", b"SEALCANARY-token", &policy(&json!({ "rules": [plain_rule(&provider, &bearer())] }))).await;
        let response = instance.client.send(get(&url(&provider, "/echo?q=SECRETQUERY"), &[("token", &token)])).await.unwrap();
        text(response).await;
        let _ = instance.client.send(get(&format!("http://127.0.0.1:{}/", provider.port()), &[("token", &token)])).await;
        let records = instance.setup.audit_records();
        let sends: Vec<&Value> = records.iter().filter(|record| record["op"] == "send").collect();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0]["outcome"], "ok");
        assert_eq!(sends[0]["path"], "/echo");
        assert_eq!(sends[1]["outcome"], "refused");
        assert_eq!(sends[1]["code"], "POLICY_DENIED");
        let expected_caller = if mode == Mode::InProcess { "in-process" } else { "test-app" };
        assert_eq!(sends[0]["caller"], expected_caller);
        assert!(!std::fs::read_to_string(&instance.setup.audit).unwrap().contains("SECRETQUERY"));
    };

    acceptance_a_canary_never_appears_in_logs_audit_or_errors => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        let canary = Canary::generate().unwrap();
        let mut registry = CanaryRegistry::new();
        registry.register(&canary);
        let value = instance.setup.seal("token", canary.value().as_bytes(), &policy(&json!({ "rules": [plain_rule(&provider, &json!({ "header": { "name": "X-Key", "format": "{}" } }))] }))).await;

        provider.respond("/canned", CannedResponse::ok("text/plain", b"fine"));
        let mut seen = Vec::new();
        let response = instance.client.send(get(&url(&provider, "/canned"), &[("token", &value)])).await.unwrap();
        seen.push(format!("{:?}", response.response.headers()));
        seen.push(text(response).await);
        for attempt in [
            instance.client.send(get(&format!("http://127.0.0.1:{}/", provider.port()), &[("token", &value)])).await,
            instance.client.send(get(&url(&provider, "/"), &[("wrong", &value)])).await,
        ] {
            match attempt {
                Ok(response) => seen.push(text(response).await),
                Err(error) => seen.push(format!("{error} {error:?}")),
            }
        }
        for text in &seen {
            assert!(registry.scan("caller", text).is_empty(), "{text}");
        }
        let audit = std::fs::read_to_string(&instance.setup.audit).unwrap();
        assert!(registry.scan("audit", &audit).is_empty());
        assert!(registry.scan("logs", &instance.logs()).is_empty());
        assert!(provider.received().iter().any(|received| received.header("x-key") == Some(canary.value())));
    };
}

#[tokio::test]
async fn a_streamed_body_reports_no_exact_size_before_it_ends() {
    let (instance, provider) = simple(Mode::Unix).await;
    let token = instance
        .setup
        .seal(
            "token",
            b"x",
            &policy(&json!({ "rules": [plain_rule(&provider, &bearer())] })),
        )
        .await;
    let response = instance
        .client
        .send(get(&url(&provider, "/zeros/10"), &[("token", &token)]))
        .await
        .unwrap();
    assert!(response.response.body().size_hint().exact().is_none());
    text(response).await;
}

const ASSUME_ROLE: &[u8] = br#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASIAEXAMPLE</AccessKeyId><SecretAccessKey>sk-plaintext</SecretAccessKey><SessionToken>st-plaintext</SessionToken></Credentials></AssumeRoleResult></AssumeRoleResponse>"#;

mode_matrix! {
    named_xml_response_fields_are_sealed => |mode: Mode| async move {
        let (instance, provider) = simple(mode).await;
        provider.respond("/sts", CannedResponse::ok("text/xml", ASSUME_ROLE));
        let credentials = "AssumeRoleResponse/AssumeRoleResult/Credentials";
        let mut rule = plain_rule(&provider, &json!({ "form_field": { "name": "client_secret" } }));
        rule["seal_response"] = json!({
            "format": "xml",
            "fields": [
                { "at": format!("{credentials}/SecretAccessKey"), "as": "secret_key", "policy": "api" },
                { "at": format!("{credentials}/SessionToken"), "as": "session_token", "policy": "api" },
            ]
        });
        let policy = policy(&json!({ "rules": [rule], "definitions": { "api": { "rules": [plain_rule(&provider, &bearer())] } } }));
        let secret = instance.setup.seal("client_secret", b"SEALCANARY-client-secret", &policy).await;
        let response = instance.client.send(post_form(&url(&provider, "/sts"), &[("client_secret", &secret)])).await.unwrap();
        let sealed = response.sealed_fields.clone();
        let body = text(response).await;
        assert!(!body.contains("sk-plaintext") && !body.contains("st-plaintext"), "{body}");
        assert!(body.contains("<AccessKeyId>ASIAEXAMPLE</AccessKeyId>"));
        let (plaintext, _) = instance.setup.open("secret_key", &sealed[&field("secret_key")]).await;
        assert_eq!(plaintext, b"sk-plaintext");
    };

    a_client_certificate_reaches_the_provider => |mode: Mode| async move {
        let clients = seal_testkit::pki::TestPki::new("client CA");
        let server = seal_testkit::pki::TestPki::new("provider CA");
        let provider = MockProvider::tls_with(&server, seal_testkit::mock_provider::Alpn::Both, &[HOST], Some(&clients.ca_der)).await;
        let instance = start_trusting(mode, Options::default(), &[provider.ca().unwrap()]).await;
        let issued = clients.client("tenant-a");
        let policy = policy(&json!({ "rules": [{
            "destination": { "scheme": "https", "host": HOST, "port": provider.port() },
            "inject": { "client_cert": { "cert": { "literal": issued.cert_pem } } },
        }] }));
        let key = instance.setup.seal("client_key", issued.key_pem.as_bytes(), &policy).await;
        let target = format!("https://{HOST}:{}/echo", provider.port());
        for _ in 0..2 {
            let response = instance.client.send(get(&target, &[("client_key", &key)])).await.unwrap();
            assert_eq!(response.response.status(), 200);
            text(response).await;
        }
        assert_eq!(provider.client_certificates(), [Some(issued.cert_der.as_ref().to_vec())], "one connection, reused");

        let mut registry = CanaryRegistry::new();
        registry.register(&Canary::from_value(issued.key_pem.trim()));
        assert!(registry.scan("logs", &instance.logs()).is_empty());
    };
}

fn pg_policy(server: &seal_testkit::mock_postgres::MockPostgres) -> Policy {
    policy(&json!({ "rules": [{
        "destination": {
            "scheme": "postgres", "host": HOST, "port": server.port(),
            "databases": ["app"], "user": { "literal": "app_user" },
            "tls": { "ca": server.ca_pem },
        },
        "inject": { "pg_password": {} },
    }] }))
}

fn pg_request(
    server: &seal_testkit::mock_postgres::MockPostgres,
    password: &seal_format::Envelope,
) -> seal_client::ConnectRequest {
    seal_client::ConnectRequest {
        keyset: keyset(),
        item: item(),
        sealed: std::collections::BTreeMap::from([(field("password"), password.clone().into())]),
        plain: std::collections::BTreeMap::new(),
        host: HOST.to_owned(),
        port: server.port(),
    }
}

fn pg_startup() -> Vec<u8> {
    let mut body = (3_u32 << 16).to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0app_user\0database\0app\0\0");
    let mut packet = u32::try_from(body.len() + 4)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    packet.extend_from_slice(&body);
    packet
}

mode_matrix! {
    a_postgres_session_logs_in_and_relays => |mode: Mode| async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let server = seal_testkit::mock_postgres::MockPostgres::start(HOST, true).await;
        let instance = start(mode, Options::default(), &[]).await;
        let password = instance.setup.seal("password", b"SEALCANARY-password", &pg_policy(&server)).await;
        let mut stream = instance.client.connect_pg(pg_request(&server, &password)).await.unwrap();
        stream.write_all(&pg_startup()).await.unwrap();
        let mut hello = [0; 15];
        stream.read_exact(&mut hello).await.unwrap();
        assert_eq!((hello[0], hello[9]), (b'R', b'Z'));
        let large = vec![7_u8; 300_000];
        stream.write_all(&large).await.unwrap();
        let mut echo = vec![0; large.len()];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, large);
        drop(stream);
        assert_eq!(server.startup_param(0, "user").as_deref(), Some("app_user"));
    };

    a_postgres_session_the_policy_refuses_fails_to_open => |mode: Mode| async move {
        let server = seal_testkit::mock_postgres::MockPostgres::start(HOST, true).await;
        let instance = start(mode, Options::default(), &[]).await;
        let password = instance.setup.seal("password", b"SEALCANARY-password", &pg_policy(&server)).await;
        let mut request = pg_request(&server, &password);
        request.port += 1;
        let error = instance.client.connect_pg(request).await.err().unwrap();
        assert_eq!(error.code, ErrorCode::PolicyDenied);
        assert!(server.packets().is_empty());
    };

    a_postgres_cancel_goes_through_a_session_of_its_own => |mode: Mode| async move {
        use tokio::io::AsyncWriteExt;
        let server = seal_testkit::mock_postgres::MockPostgres::start(HOST, true).await;
        let instance = start(mode, Options::default(), &[]).await;
        let password = instance.setup.seal("password", b"SEALCANARY-password", &pg_policy(&server)).await;
        let mut stream = instance.client.connect_pg(pg_request(&server, &password)).await.unwrap();
        let mut cancel = 16_u32.to_be_bytes().to_vec();
        cancel.extend_from_slice(&80_877_102_u32.to_be_bytes());
        cancel.extend_from_slice(&[0, 0, 0, 42, 1, 2, 3, 4]);
        stream.write_all(&cancel).await.unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while server.packets().is_empty() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(server.packets()[0], cancel[4..]);
    };
}

/// The harness's scan finds a sealed secret wherever seal wrote it: here, planted in
/// the audit file.
#[tokio::test]
#[should_panic(expected = "a sealed secret appeared")]
async fn the_harness_finds_a_leaked_secret() {
    let provider = MockProvider::plain().await;
    let instance = start(Mode::InProcess, Options::default(), &[&provider]).await;
    let policy = policy(&json!({ "rules": [plain_rule(&provider, &bearer())] }));
    instance
        .setup
        .seal("token", b"SEALCANARY-planted", &policy)
        .await;
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        "SEALCANARY-planted",
    );
    std::fs::write(
        &instance.setup.audit,
        format!("{{\"leak\":\"{encoded}\"}}\n"),
    )
    .unwrap();
}
