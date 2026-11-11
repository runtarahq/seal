//! Postgres sessions in the broker, against a fake server: what is checked before any
//! connection, TLS toward the server, what the server receives, cancels, and the relay.
//! Logins against real servers are in `crates/seal/tests/postgres.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;

use seal_broker::pg::wire::{self, PROTOCOL_3_0, Startup};
use seal_broker::{ConnectRequest, ErrorCode};
use seal_format::{Envelope, Policy};
use seal_testkit::mock_postgres::MockPostgres;
use serde_json::{Value, json};
use support::{Harness, Options, field, item, keyset, rule_policy};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const HOST: &str = "db.test";

fn destination(server: &MockPostgres, ca: Option<&str>) -> Value {
    let mut destination = json!({
        "scheme": "postgres", "host": HOST, "port": server.port(),
        "databases": ["app", "reports"], "user": { "literal": "app_user" },
    });
    if let Some(ca) = ca {
        destination["tls"] = json!({ "ca": ca });
    }
    destination
}

fn password_policy(server: &MockPostgres) -> Policy {
    rule_policy(&json!({
        "destination": destination(server, Some(&server.ca_pem)),
        "allow_private_destination": true,
        "inject": { "pg_password": {} },
    }))
}

fn connect_request(server: &MockPostgres, password: &Envelope) -> ConnectRequest {
    ConnectRequest {
        caller: "test-app".to_owned(),
        keyset: keyset(),
        item: item(),
        sealed: BTreeMap::from([(field("password"), password.clone().into())]),
        plain: BTreeMap::new(),
        host: HOST.to_owned(),
        port: server.port(),
    }
}

fn harness() -> Harness {
    let mut options = Options::default();
    options.network.honour_private_rules = true;
    Harness::with(options)
}

fn startup(params: &[(&str, &str)]) -> Vec<u8> {
    Startup {
        version: PROTOCOL_3_0,
        params: params
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
    }
    .encode()
}

/// Runs a session with `first` as the caller's opening bytes, and returns the caller's
/// end and the session's result.
async fn session(
    harness: &Harness,
    request: ConnectRequest,
    first: &[u8],
) -> (
    DuplexStream,
    tokio::task::JoinHandle<Result<(), seal_broker::BrokerError>>,
) {
    let session = harness.broker.open_session(request).await.unwrap();
    let (mut caller, seal_end) = tokio::io::duplex(1 << 16);
    caller.write_all(first).await.unwrap();
    (caller, tokio::spawn(session.run(seal_end)))
}

async fn read_message(caller: &mut DuplexStream) -> wire::Message {
    let closed = seal_broker::BrokerError::new(ErrorCode::UpstreamReset, "closed");
    wire::read_message(caller, 1 << 16, closed).await.unwrap()
}

#[tokio::test]
async fn a_session_logs_in_and_relays() {
    let server = MockPostgres::start_scram(HOST, b"pw").await;
    let harness = harness();
    let password = harness.seal("password", b"pw", &password_policy(&server));
    // libpq may ask for TLS first; seal declines.
    let mut first = wire::ssl_request();
    first.extend(startup(&[
        ("user", "app_user"),
        ("database", "reports"),
        ("application_name", "x"),
    ]));
    let (mut caller, task) = session(&harness, connect_request(&server, &password), &first).await;

    let mut declined = [0; 1];
    caller.read_exact(&mut declined).await.unwrap();
    assert_eq!(&declined, b"N");
    assert_eq!(read_message(&mut caller).await.tag, b'R');
    assert_eq!(read_message(&mut caller).await.tag, b'Z');
    caller.write_all(b"hello server").await.unwrap();
    let mut echo = [0; 12];
    caller.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"hello server");
    drop(caller);
    task.await.unwrap().unwrap();

    assert_eq!(server.startup_param(0, "user").as_deref(), Some("app_user"));
    assert_eq!(
        server.startup_param(0, "database").as_deref(),
        Some("reports")
    );
    assert_eq!(
        server.startup_param(0, "application_name").as_deref(),
        Some("x")
    );
    let record = harness.audit.last();
    assert_eq!(
        (record.op, record.pg_auth, record.path.as_deref()),
        ("connect", Some("scram-sha-256"), Some("reports"))
    );
    assert_eq!(record.bytes_in, 12);
}

#[tokio::test]
async fn a_startup_the_policy_does_not_allow_is_refused_before_connecting() {
    let server = MockPostgres::start_scram(HOST, b"pw").await;
    let harness = harness();
    let password = harness.seal("password", b"pw", &password_policy(&server));
    for (params, sqlstate) in [
        (&[("user", "postgres"), ("database", "app")][..], "28000"),
        (&[("database", "app")][..], "28000"),
        (&[("user", "app_user"), ("database", "other")][..], "3D000"),
        (&[("user", "app_user")][..], "3D000"),
        (
            &[
                ("user", "app_user"),
                ("database", "app"),
                ("replication", "database"),
            ][..],
            "28000",
        ),
    ] {
        let (mut caller, task) = session(
            &harness,
            connect_request(&server, &password),
            &startup(params),
        )
        .await;
        let error = read_message(&mut caller).await;
        assert_eq!(error.tag, b'E');
        assert_eq!(
            wire::error_sqlstate(&error.body).as_deref(),
            Some(sqlstate),
            "{params:?}"
        );
        assert_eq!(
            task.await.unwrap().unwrap_err().code(),
            ErrorCode::PolicyDenied
        );
    }
    assert_eq!(harness.lookups(), 0);
    assert!(server.packets().is_empty());
    assert_eq!(
        harness.audit.last().outcome,
        seal_broker::audit::Outcome::Refused
    );
}

#[tokio::test]
async fn the_policy_is_checked_when_the_session_opens() {
    let server = MockPostgres::start_scram(HOST, b"pw").await;
    let harness = harness();
    let password = harness.seal("password", b"pw", &password_policy(&server));
    let mut other_port = connect_request(&server, &password);
    other_port.port += 1;
    assert_eq!(
        harness
            .broker
            .open_session(other_port)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PolicyDenied
    );
    let mut other_host = connect_request(&server, &password);
    other_host.host = "elsewhere.test".to_owned();
    assert_eq!(
        harness
            .broker
            .open_session(other_host)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PolicyDenied
    );
    let bearer = harness.seal(
        "password",
        b"pw",
        &support::plain_policy(&support::MockProvider::plain().await, &support::bearer()),
    );
    assert_eq!(
        harness
            .broker
            .open_session(connect_request(&server, &bearer))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PolicyDenied
    );
    assert_eq!(harness.audit.last().code, Some("POLICY_DENIED"));
}

#[tokio::test]
async fn the_server_must_offer_tls_and_prove_its_name() {
    let harness = harness();
    // No TLS.
    let plain = MockPostgres::start(HOST, false).await;
    let password = harness.seal("password", b"pw", &password_policy(&plain));
    let (mut caller, task) = session(
        &harness,
        connect_request(&plain, &password),
        &startup(&[("user", "app_user"), ("database", "app")]),
    )
    .await;
    assert_eq!(
        wire::error_sqlstate(&read_message(&mut caller).await.body).as_deref(),
        Some("08001")
    );
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        ErrorCode::UpstreamTls
    );

    // A CA the policy does not name: verify-full trusts only the configured roots.
    let server = MockPostgres::start_scram(HOST, b"pw").await;
    let policy = rule_policy(&json!({
        "destination": destination(&server, None),
        "allow_private_destination": true,
        "inject": { "pg_password": {} },
    }));
    let password = harness.seal("password", b"pw", &policy);
    let (mut caller, task) = session(
        &harness,
        connect_request(&server, &password),
        &startup(&[("user", "app_user"), ("database", "app")]),
    )
    .await;
    assert_eq!(read_message(&mut caller).await.tag, b'E');
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        ErrorCode::UpstreamTls
    );
    assert!(
        server.packets().is_empty(),
        "nothing was sent before TLS was verified"
    );
}

/// A policy for `server` with this `tls` and these `pg_password` options.
fn weakened_policy(server: &MockPostgres, tls: &str, password: Value) -> Policy {
    let mut destination = destination(server, None);
    destination["tls"] = json!(tls);
    rule_policy(&json!({
        "destination": destination,
        "allow_private_destination": true,
        "inject": { "pg_password": password },
    }))
}

/// Logs in as `app_user` to `app`, and returns the first message the caller gets
/// and how the session ended.
async fn log_in(
    harness: &Harness,
    server: &MockPostgres,
    policy: &Policy,
) -> (wire::Message, Result<(), seal_broker::BrokerError>) {
    let password = harness.seal("password", b"pw", policy);
    let (mut caller, task) = session(
        harness,
        connect_request(server, &password),
        &startup(&[("user", "app_user"), ("database", "app")]),
    )
    .await;
    let first = read_message(&mut caller).await;
    drop(caller);
    (first, task.await.unwrap())
}

#[tokio::test]
async fn a_rule_may_allow_a_server_whose_certificate_cannot_be_verified() {
    // Its certificate is from a CA nothing trusts.
    let server = MockPostgres::start_scram(HOST, b"pw").await;
    let harness = harness();

    let (first, ended) = log_in(
        &harness,
        &server,
        &weakened_policy(&server, "allow_unverified", json!({})),
    )
    .await;
    assert_eq!(first.tag, b'R');
    ended.unwrap();
    let record = harness.audit.last();
    // Encrypted, to a server that did not have to prove who it is; the record says so.
    assert_eq!(record.pg_tls, Some("unverified"));
    assert_eq!(record.pg_auth, Some("scram-sha-256"));

    // Unverified still means TLS: a server without it is refused.
    let plain = MockPostgres::start_scram_without_tls(HOST, b"pw").await;
    let (first, ended) = log_in(
        &harness,
        &plain,
        &weakened_policy(&plain, "allow_unverified", json!({})),
    )
    .await;
    assert_eq!(wire::error_sqlstate(&first.body).as_deref(), Some("08001"));
    assert_eq!(ended.unwrap_err().code(), ErrorCode::UpstreamTls);

    // A rule that verifies records that it did.
    let verified = MockPostgres::start_scram(HOST, b"pw").await;
    let (_, ended) = log_in(&harness, &verified, &password_policy(&verified)).await;
    ended.unwrap();
    assert_eq!(harness.audit.last().pg_tls, Some("verified"));
}

#[tokio::test]
async fn a_rule_may_allow_a_server_with_no_tls() {
    let server = MockPostgres::start_scram_without_tls(HOST, b"pw").await;
    let harness = harness();
    let password = harness.seal(
        "password",
        b"pw",
        &weakened_policy(&server, "allow_plain", json!({})),
    );
    let (mut caller, task) = session(
        &harness,
        connect_request(&server, &password),
        &startup(&[("user", "app_user"), ("database", "app")]),
    )
    .await;
    assert_eq!(read_message(&mut caller).await.tag, b'R');
    assert_eq!(read_message(&mut caller).await.tag, b'Z');
    // The session is relayed as any other.
    caller.write_all(b"hello server").await.unwrap();
    let mut echo = [0; 12];
    caller.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"hello server");
    drop(caller);
    task.await.unwrap().unwrap();
    let record = harness.audit.last();
    assert_eq!(record.pg_tls, Some("none"));
    // The password is not sent in the clear: SCRAM proves it without disclosing it.
    assert_eq!(record.pg_auth, Some("scram-sha-256"));

    // Where the server does offer TLS, the session uses it.
    let with_tls = MockPostgres::start_scram(HOST, b"pw").await;
    let (first, ended) = log_in(
        &harness,
        &with_tls,
        &weakened_policy(&with_tls, "allow_plain", json!({})),
    )
    .await;
    assert_eq!(first.tag, b'R');
    ended.unwrap();
    assert_eq!(harness.audit.last().pg_tls, Some("unverified"));
}

#[tokio::test]
async fn a_password_is_not_sent_as_md5_over_a_session_in_the_clear() {
    // The rule allows MD5, but the server has no TLS: the hash would cross the
    // network readable.
    let server = MockPostgres::start_md5_without_tls(HOST).await;
    let harness = harness();
    let policy = weakened_policy(&server, "allow_plain", json!({ "allow_md5": true }));
    let (first, ended) = log_in(&harness, &server, &policy).await;
    assert_eq!(first.tag, b'E');
    assert_eq!(wire::error_sqlstate(&first.body).as_deref(), Some("28000"));
    assert_eq!(ended.unwrap_err().code(), ErrorCode::PgAuthFailed);
    let record = harness.audit.last();
    assert_eq!((record.pg_tls, record.pg_auth), (Some("none"), None));
    // Only the startup reached the server: no password message followed it.
    assert_eq!(server.packets().len(), 1);
}

#[tokio::test]
async fn a_server_that_asks_for_no_password_is_not_logged_in_to() {
    // It passes TLS, and accepts the login without proving it knows the password.
    let server = MockPostgres::start(HOST, true).await;
    let harness = harness();
    let password = harness.seal("password", b"pw", &password_policy(&server));
    let (mut caller, task) = session(
        &harness,
        connect_request(&server, &password),
        &startup(&[("user", "app_user"), ("database", "app")]),
    )
    .await;
    let refusal = read_message(&mut caller).await;
    assert_eq!(refusal.tag, b'E');
    assert_eq!(
        wire::error_sqlstate(&refusal.body).as_deref(),
        Some("28000")
    );
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        ErrorCode::PgAuthFailed
    );
    assert_eq!(harness.audit.last().pg_auth, None);
}

#[tokio::test]
async fn a_server_that_goes_quiet_during_the_login_is_given_up_on() {
    let server = MockPostgres::start_silent(HOST).await;
    let mut options = Options::default();
    options.network.honour_private_rules = true;
    options.limits.connect_timeout = std::time::Duration::from_millis(300);
    let harness = Harness::with(options);
    let password = harness.seal("password", b"pw", &password_policy(&server));
    let (mut caller, task) = session(
        &harness,
        connect_request(&server, &password),
        &startup(&[("user", "app_user"), ("database", "app")]),
    )
    .await;
    let refusal = read_message(&mut caller).await;
    assert_eq!(refusal.tag, b'E');
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        ErrorCode::UpstreamTimeout
    );
    assert_eq!(server.packets().len(), 1, "the startup was sent");
}

#[tokio::test]
async fn a_rule_that_requires_channel_binding_refuses_a_server_without_it() {
    // The server knows the password, but offers SCRAM without binding only.
    let server = MockPostgres::start_scram(HOST, b"pw").await;
    let harness = harness();
    let policy = rule_policy(&json!({
        "destination": destination(&server, Some(&server.ca_pem)),
        "allow_private_destination": true,
        "inject": { "pg_password": { "require_channel_binding": true } },
    }));
    let password = harness.seal("password", b"pw", &policy);
    let (mut caller, task) = session(
        &harness,
        connect_request(&server, &password),
        &startup(&[("user", "app_user"), ("database", "app")]),
    )
    .await;
    assert_eq!(read_message(&mut caller).await.tag, b'E');
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        ErrorCode::PgAuthFailed
    );
}

#[tokio::test]
async fn a_cancel_is_forwarded_as_sent() {
    let server = MockPostgres::start_scram(HOST, b"pw").await;
    let harness = harness();
    let password = harness.seal("password", b"pw", &password_policy(&server));
    for key in [4_usize, 32] {
        let mut cancel = u32::try_from(12 + key).unwrap().to_be_bytes().to_vec();
        cancel.extend_from_slice(&wire::CANCEL_REQUEST.to_be_bytes());
        cancel.extend_from_slice(&4242_u32.to_be_bytes());
        cancel.extend(std::iter::repeat_n(9, key));
        let (_caller, task) = session(&harness, connect_request(&server, &password), &cancel).await;
        task.await.unwrap().unwrap();
        assert_eq!(server.packets().last().unwrap(), &cancel[4..]);
        assert_eq!(harness.audit.last().op, "cancel");
    }
}

#[tokio::test]
async fn a_session_never_run_is_still_audited() {
    let server = MockPostgres::start_scram(HOST, b"pw").await;
    let harness = harness();
    let password = harness.seal("password", b"pw", &password_policy(&server));
    let session = harness
        .broker
        .open_session(connect_request(&server, &password))
        .await
        .unwrap();
    drop(session);
    assert_eq!(
        harness.audit.last().outcome,
        seal_broker::audit::Outcome::Cancelled
    );
}

#[tokio::test]
async fn the_user_can_be_a_plain_field_the_rule_lists() {
    let server = MockPostgres::start_scram(HOST, b"pw").await;
    let harness = harness();
    let mut destination = destination(&server, Some(&server.ca_pem));
    destination["user"] = json!({ "field": "user" });
    let policy = rule_policy(&json!({
        "destination": destination,
        "allow_private_destination": true,
        "inject": { "pg_password": {} },
        "plain": ["user"],
    }));
    let password = harness.seal("password", b"pw", &policy);
    let mut request = connect_request(&server, &password);
    request.plain.insert(field("user"), "tenant_42".to_owned());
    let (mut caller, task) = session(
        &harness,
        request,
        &startup(&[("user", "tenant_42"), ("database", "app")]),
    )
    .await;
    assert_eq!(read_message(&mut caller).await.tag, b'R');
    drop(caller);
    task.await.unwrap().unwrap();
    assert_eq!(
        server.startup_param(0, "user").as_deref(),
        Some("tenant_42")
    );

    // Without the plain field, the user is missing.
    let error = harness
        .broker
        .open_session(connect_request(&server, &password))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);
}
