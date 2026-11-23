//! Admitting an intake envelope: secrets sealed where they were entered become stored
//! values, under the policies the envelope names and no others.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::Method;
use seal_broker::audit::Outcome;
use seal_broker::body::full_body;
use seal_broker::{
    AdmitOutput, AdmitRequest, BrokerError, ConnectRequest, ErrorCode, Limits, PresignRequest,
    VerifyRequest,
};
use seal_format::intake::{Value, object};
use seal_format::policy::{HmacHash, builder};
use seal_format::{Envelope, FieldName, ItemId, Policy};
use support::{
    CannedResponse, Harness, MockProvider, Options, bearer, field, item, keyset, plain_policy,
    read_text, url,
};

const API_KEY: &str = "API-KEY-canary-secret";
const SIGNING: &str = "SIGNING-canary-secret";
const EXTRA: &str = "EXTRA-canary-secret";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn webhook() -> Policy {
    builder::webhook_hmac(HmacHash::Sha256).unwrap()
}

fn intake(outputs: &[(&str, &Policy)], not_after: u64) -> Policy {
    let outputs: BTreeMap<FieldName, Policy> = outputs
        .iter()
        .map(|(name, policy)| (field(name), (*policy).clone()))
        .collect();
    Policy::for_intake(&outputs, not_after).unwrap()
}

/// Seals an intake envelope holding these text fields, as a sealer would.
fn seal_intake(harness: &Harness, members: &[(&str, &str)], policy: &Policy) -> Envelope {
    for (_, secret) in members {
        harness.register(secret.as_bytes());
    }
    let members: BTreeMap<FieldName, Value<'_>> = members
        .iter()
        .map(|(name, secret)| (field(name), Value::Text(secret)))
        .collect();
    harness.seal("intake", &object(&members), policy)
}

fn admit(envelope: &Envelope, outputs: &[(&str, &Policy, bool)]) -> AdmitRequest {
    AdmitRequest {
        caller: "test-app".to_owned(),
        keyset: keyset(),
        item: item(),
        envelope: envelope.clone(),
        outputs: outputs
            .iter()
            .map(|(name, policy, optional)| {
                (
                    field(name),
                    AdmitOutput {
                        policy: (*policy).clone(),
                        optional: *optional,
                    },
                )
            })
            .collect(),
    }
}

fn assert_no_traffic(harness: &Harness) {
    assert_eq!((harness.lookups(), harness.connects()), (0, 0));
}

fn assert_refused(harness: &Harness, error: &BrokerError, code: ErrorCode) {
    assert_eq!(error.code(), code, "{error}");
    let record = harness.audit.last();
    assert_eq!(record.op, "admit");
    assert_eq!(record.outcome, Outcome::Refused);
    assert_eq!(record.code, Some(code.as_str()));
    for secret in [API_KEY, SIGNING, EXTRA] {
        assert!(!error.to_string().contains(secret));
    }
}

#[tokio::test]
async fn acceptance_an_intake_envelope_becomes_values_under_the_policies_it_names() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let api = plain_policy(&provider, &bearer());
    let envelope = seal_intake(
        &harness,
        &[("api_key", API_KEY), ("signing", SIGNING)],
        &intake(&[("api_key", &api), ("signing", &webhook())], now() + 60),
    );

    let sealed = harness
        .broker
        .admit(admit(
            &envelope,
            &[("api_key", &api, false), ("signing", &webhook(), false)],
        ))
        .await
        .unwrap();

    assert_eq!(
        sealed.keys().map(FieldName::as_str).collect::<Vec<_>>(),
        ["api_key", "signing"]
    );
    assert_eq!(
        harness.open("api_key", &sealed[&field("api_key")]),
        API_KEY.as_bytes()
    );
    assert_eq!(
        harness.open_policy("api_key", &sealed[&field("api_key")]),
        api
    );
    assert_eq!(
        harness.open("signing", &sealed[&field("signing")]),
        SIGNING.as_bytes()
    );
    assert_eq!(
        harness.open_policy("signing", &sealed[&field("signing")]),
        webhook()
    );

    let record = harness.audit.last();
    assert_eq!(record.op, "admit");
    assert_eq!(record.caller, "test-app");
    assert_eq!(record.outcome, Outcome::Ok);
    assert_eq!(record.fields, ["api_key", "signing"]);
    assert_eq!(
        record.policies,
        [
            format!("api_key={}", api.digest().unwrap()),
            format!("signing={}", webhook().digest().unwrap()),
        ]
    );
    assert_no_traffic(&harness);

    // What comes out is a stored value like any other.
    provider.respond("/orders", CannedResponse::ok("text/plain", b"ok"));
    let response = harness
        .get(
            &url(&provider, "/orders"),
            &[("api_key", &sealed[&field("api_key")])],
        )
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    read_text(response).await;
    assert_eq!(
        provider.received()[0].header("authorization"),
        Some(format!("Bearer {API_KEY}").as_str())
    );
}

#[tokio::test]
async fn bytes_that_are_not_text_are_admitted_as_they_were() {
    let harness = Harness::new();
    let der: Vec<u8> = (0..=255).rev().collect();
    let policy = intake(&[("key", &webhook())], now() + 60);
    let members = BTreeMap::from([(field("key"), Value::Bytes(&der))]);
    let envelope = harness.seal("intake", &object(&members), &policy);

    let sealed = harness
        .broker
        .admit(admit(&envelope, &[("key", &webhook(), false)]))
        .await
        .unwrap();
    assert_eq!(harness.open("key", &sealed[&field("key")]), der);
}

/// What keeps "the application cannot change a policy" true.
#[tokio::test]
async fn acceptance_only_an_intake_envelope_is_admitted() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let api = plain_policy(&provider, &bearer());
    // A stored value, even one whose secret is an object and whose field is `intake`.
    let object = format!("{{\"api_key\":\"{API_KEY}\"}}");
    harness.register(API_KEY.as_bytes());
    let stored = harness.seal("intake", object.as_bytes(), &api);

    let error = harness
        .broker
        .admit(admit(&stored, &[("api_key", &webhook(), false)]))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::PolicyDenied);

    // Nor one bound to the field it is stored as.
    let stored = harness.seal("api_key", API_KEY.as_bytes(), &api);
    let error = harness
        .broker
        .admit(admit(&stored, &[("api_key", &webhook(), false)]))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::OpenFailed);
}

#[tokio::test]
async fn acceptance_an_intake_envelope_serves_no_request() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let api = plain_policy(&provider, &bearer());
    let envelope = seal_intake(
        &harness,
        &[("api_key", API_KEY)],
        &intake(&[("api_key", &api)], now() + 60),
    );

    let sent = harness
        .get(&url(&provider, "/orders"), &[("intake", &envelope)])
        .await
        .err()
        .unwrap();
    assert_eq!(sent.code(), ErrorCode::PolicyDenied);
    assert_eq!(
        sent.detail(),
        "an intake envelope can only be admitted: intake"
    );

    let presigned = harness
        .broker
        .presign(PresignRequest {
            caller: "test-app".to_owned(),
            keyset: keyset(),
            item: item(),
            sealed: BTreeMap::from([(field("intake"), envelope.clone().into())]),
            plain: BTreeMap::new(),
            method: Method::GET,
            url: url(&provider, "/object"),
            expires_s: 60,
        })
        .await
        .unwrap_err();
    assert_eq!(presigned.code(), ErrorCode::PolicyDenied);

    let verified = harness
        .broker
        .verify(VerifyRequest {
            caller: "test-app".to_owned(),
            keyset: keyset(),
            item: item(),
            field: field("intake"),
            value: envelope.clone().into(),
            message: full_body(&b"message"[..]),
            mac: vec![0; 32],
        })
        .await
        .unwrap_err();
    assert_eq!(verified.code(), ErrorCode::PolicyDenied);

    let connected = harness
        .broker
        .open_session(ConnectRequest {
            caller: "test-app".to_owned(),
            keyset: keyset(),
            item: item(),
            sealed: BTreeMap::from([(field("intake"), envelope.into())]),
            plain: BTreeMap::new(),
            host: "db.example.com".to_owned(),
            port: 5432,
        })
        .await
        .err()
        .unwrap();
    assert_eq!(connected.code(), ErrorCode::PolicyDenied);

    for record in harness.audit.all() {
        assert_eq!(record.outcome, Outcome::Refused);
        assert_eq!(record.code, Some("POLICY_DENIED"));
    }
    assert_eq!(harness.audit.all().len(), 4);
    assert_no_traffic(&harness);
    assert!(provider.received().is_empty());
}

#[tokio::test]
async fn acceptance_only_a_policy_the_envelope_names_comes_out() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let api = plain_policy(&provider, &bearer());
    let envelope = seal_intake(
        &harness,
        &[("api_key", API_KEY), ("signing", SIGNING), ("other", EXTRA)],
        &intake(&[("api_key", &api), ("signing", &webhook())], now() + 60),
    );

    // Another destination for the same field: what a caller compromised after the
    // secret was sealed would ask for.
    let elsewhere = builder::bearer("https://attacker.example.com").unwrap();
    let error = harness
        .broker
        .admit(admit(&envelope, &[("api_key", &elsewhere, false)]))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::IntakeStale);
    assert_eq!(
        harness.audit.last().policies,
        [format!("api_key={}", elsewhere.digest().unwrap())],
        "the record says what was asked for"
    );

    // A policy the envelope names, for another of its fields.
    let error = harness
        .broker
        .admit(admit(&envelope, &[("api_key", &webhook(), false)]))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::IntakeStale);

    // The same rules, but shared.
    let mut shared = api.clone();
    shared.shared = true;
    let error = harness
        .broker
        .admit(admit(&envelope, &[("api_key", &shared, false)]))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::IntakeStale);

    // A field that is in the object but that the envelope does not name.
    let error = harness
        .broker
        .admit(admit(&envelope, &[("other", &api, false)]))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::PolicyDenied);

    // One bad output refuses the good ones with it.
    let error = harness
        .broker
        .admit(admit(
            &envelope,
            &[("api_key", &api, false), ("signing", &elsewhere, false)],
        ))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::IntakeStale);
}

#[tokio::test]
async fn a_shared_value_is_admitted_where_the_envelope_names_it_shared() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let mut shared = plain_policy(&provider, &bearer());
    shared.shared = true;
    let envelope = seal_intake(
        &harness,
        &[("client_secret", API_KEY)],
        &intake(&[("client_secret", &shared)], now() + 60),
    );

    let sealed = harness
        .broker
        .admit(admit(&envelope, &[("client_secret", &shared, false)]))
        .await
        .unwrap();
    assert!(
        harness
            .open_policy("client_secret", &sealed[&field("client_secret")])
            .shared
    );
}

#[tokio::test]
async fn acceptance_a_field_is_never_sealed_as_an_intake() {
    let harness = Harness::new();
    let inner = intake(&[("api_key", &webhook())], now() + 60);
    // An envelope cannot name an intake as an output's policy, so the digest here is
    // written by hand, as a sealer of its own making could.
    let mut outer = intake(&[("api_key", &webhook())], now() + 60);
    outer
        .intake
        .as_mut()
        .unwrap()
        .outputs
        .insert(field("api_key"), inner.digest().unwrap());
    let envelope = seal_intake(&harness, &[("api_key", API_KEY)], &outer);

    let error = harness
        .broker
        .admit(admit(&envelope, &[("api_key", &inner, false)]))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::PolicyDenied);
    assert_eq!(
        harness.key_fetches(),
        0,
        "refused before anything is opened"
    );
}

#[tokio::test]
async fn acceptance_an_envelope_past_its_time_or_too_far_ahead_is_refused() {
    let limits = Limits {
        max_intake_lifetime: Duration::from_secs(300),
        ..Options::default().limits
    };
    let harness = Harness::with(Options {
        limits,
        ..Options::default()
    });
    let outputs = [("api_key", &webhook(), false)];

    let past = seal_intake(
        &harness,
        &[("api_key", API_KEY)],
        &intake(&[("api_key", &webhook())], now() - 1),
    );
    let error = harness
        .broker
        .admit(admit(&past, &outputs))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::IntakeStale);

    // The sealer writes the time, so one that would never pass is held to the limit.
    for not_after in [now() + 400, u64::MAX] {
        let far = seal_intake(
            &harness,
            &[("api_key", API_KEY)],
            &intake(&[("api_key", &webhook())], not_after),
        );
        let error = harness
            .broker
            .admit(admit(&far, &outputs))
            .await
            .unwrap_err();
        assert_refused(&harness, &error, ErrorCode::PolicyDenied);
    }

    let within = seal_intake(
        &harness,
        &[("api_key", API_KEY)],
        &intake(&[("api_key", &webhook())], now() + 200),
    );
    harness
        .broker
        .admit(admit(&within, &outputs))
        .await
        .unwrap();
}

#[tokio::test]
async fn acceptance_an_absent_field_refuses_everything_unless_it_is_optional() {
    let harness = Harness::new();
    let policy = intake(
        &[("api_key", &webhook()), ("signing", &webhook())],
        now() + 60,
    );
    let envelope = seal_intake(&harness, &[("api_key", API_KEY), ("other", EXTRA)], &policy);

    let error = harness
        .broker
        .admit(admit(
            &envelope,
            &[
                ("api_key", &webhook(), false),
                ("signing", &webhook(), false),
            ],
        ))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::IntakeInvalid);
    assert_eq!(error.detail(), "the envelope has no such field: signing");

    let sealed = harness
        .broker
        .admit(admit(
            &envelope,
            &[
                ("api_key", &webhook(), false),
                ("signing", &webhook(), true),
            ],
        ))
        .await
        .unwrap();
    // The member no output names is dropped, and nothing says it was there.
    assert_eq!(
        sealed.keys().map(FieldName::as_str).collect::<Vec<_>>(),
        ["api_key"]
    );
    let record = serde_json::to_string(&harness.audit.last()).unwrap();
    assert!(!record.contains("other"));
}

#[tokio::test]
async fn acceptance_admitted_values_stay_on_the_envelopes_keyset_and_item() {
    let harness = Harness::new();
    let policy = intake(&[("api_key", &webhook())], now() + 60);
    let outputs = [("api_key", &webhook(), false)];
    let object = format!("{{\"api_key\":\"{API_KEY}\"}}");
    harness.register(API_KEY.as_bytes());

    // An envelope sealed for another record is not admitted into this one.
    let other_item = harness.seal_at("acme", "connection-2", "intake", object.as_bytes(), &policy);
    let error = harness
        .broker
        .admit(admit(&other_item, &outputs))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::OpenFailed);

    // Nor one sealed to another keyset, whichever keyset the call names.
    let other_keyset = harness.seal_at(
        "platform",
        "connection-1",
        "intake",
        object.as_bytes(),
        &policy,
    );
    let error = harness
        .broker
        .admit(admit(&other_keyset, &outputs))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::OpenFailed);

    // Admitted where it was sealed for, the value opens there and nowhere else.
    let mut request = admit(&other_item, &outputs);
    request.item = ItemId::new("connection-2").unwrap();
    let sealed = harness.broker.admit(request).await.unwrap();
    let value = &sealed[&field("api_key")];
    assert_eq!(value.keyset(), &keyset());
    let key = harness.keys.current();
    let opens_at = |item: &str| {
        let (keyset, item, field) = (keyset(), ItemId::new(item).unwrap(), field("api_key"));
        seal_format::open(
            &key,
            value,
            seal_format::Binding {
                keyset: &keyset,
                item: &item,
                field: &field,
            },
        )
        .is_ok()
    };
    assert!(opens_at("connection-2"));
    assert!(!opens_at("connection-1"));
}

#[tokio::test]
async fn acceptance_if_one_field_cannot_be_sealed_none_is_returned() {
    let harness = Harness::new();
    // A policy large enough that a long secret does not fit beside it, though the
    // secret fits in the intake envelope beside a digest.
    let rules: Vec<serde_json::Value> = (0..16)
        .map(|index| {
            serde_json::json!({
                "destination": {
                    "scheme": "https",
                    "host": "api.example.com",
                    "path_prefix": format!("/{index}/{}/", "p".repeat(600)),
                },
                "inject": bearer(),
            })
        })
        .collect();
    let large =
        Policy::from_json(serde_json::json!({ "rules": rules }).to_string().as_bytes()).unwrap();
    let long = "L".repeat(42 * 1024);
    let envelope = seal_intake(
        &harness,
        &[("api_key", API_KEY), ("blob", &long)],
        &intake(&[("api_key", &webhook()), ("blob", &large)], now() + 60),
    );

    let error = harness
        .broker
        .admit(admit(
            &envelope,
            &[("api_key", &webhook(), false), ("blob", &large, false)],
        ))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::IntakeInvalid);
    assert_eq!(
        error.detail(),
        "the field does not fit in a value beside its policy: blob"
    );

    // The other field alone is still admitted.
    harness
        .broker
        .admit(admit(&envelope, &[("api_key", &webhook(), false)]))
        .await
        .unwrap();
}

#[tokio::test]
async fn acceptance_a_secret_that_is_not_an_object_of_fields_is_refused_whole() {
    let harness = Harness::new();
    let policy = intake(&[("api_key", &webhook())], now() + 60);
    harness.register(API_KEY.as_bytes());
    for object in [
        API_KEY.to_owned(),
        format!("\"{API_KEY}\""),
        format!("[\"{API_KEY}\"]"),
        format!("{{\"api_key\":\"{API_KEY}\",\"api_key\":\"{API_KEY}\"}}"),
        format!("{{\"api_key\":\"{API_KEY}\",\"nested\":{{\"a\":\"b\"}}}}"),
        format!("{{\"api_key\":\"{API_KEY}\",\"number\":1}}"),
        format!("{{\"api_key\":\"{API_KEY}\",\"not a field\":\"x\"}}"),
        format!("{{\"api_key\":\"{API_KEY}\"}} trailing"),
    ] {
        let envelope = harness.seal("intake", object.as_bytes(), &policy);
        let error = harness
            .broker
            .admit(admit(&envelope, &[("api_key", &webhook(), false)]))
            .await
            .unwrap_err();
        assert_refused(&harness, &error, ErrorCode::IntakeInvalid);
        assert_eq!(
            error.detail(),
            "the envelope's secret is not an object of fields",
            "nothing says which part was wrong"
        );
    }
}

/// seal keeps no record of what it admitted. What comes of admitting again is the same
/// fields under the same policies, and nothing else.
#[tokio::test]
async fn an_envelope_admitted_twice_gives_the_same_fields_under_the_same_policies() {
    let harness = Harness::new();
    let envelope = seal_intake(
        &harness,
        &[("api_key", API_KEY)],
        &intake(&[("api_key", &webhook())], now() + 60),
    );
    let outputs = [("api_key", &webhook(), false)];

    let first = harness
        .broker
        .admit(admit(&envelope, &outputs))
        .await
        .unwrap();
    let second = harness
        .broker
        .admit(admit(&envelope, &outputs))
        .await
        .unwrap();
    for sealed in [&first, &second] {
        let value = &sealed[&field("api_key")];
        assert_eq!(harness.open("api_key", value), API_KEY.as_bytes());
        assert_eq!(harness.open_policy("api_key", value), webhook());
    }
    assert_ne!(first, second, "each is sealed anew");
}

#[tokio::test]
async fn an_admission_names_some_fields_and_not_too_many() {
    let harness = Harness::new();
    let envelope = seal_intake(
        &harness,
        &[("api_key", API_KEY)],
        &intake(&[("api_key", &webhook())], now() + 60),
    );

    let error = harness
        .broker
        .admit(admit(&envelope, &[]))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::BadRequest);

    let names: Vec<String> = (0..17).map(|index| format!("f{index}")).collect();
    let policy = webhook();
    let many: Vec<(&str, &Policy, bool)> = names
        .iter()
        .map(|name| (name.as_str(), &policy, true))
        .collect();
    let error = harness
        .broker
        .admit(admit(&envelope, &many))
        .await
        .unwrap_err();
    assert_refused(&harness, &error, ErrorCode::BadRequest);
    assert_eq!(harness.key_fetches(), 0);
}

#[tokio::test]
async fn nothing_is_admitted_while_the_audit_log_cannot_be_written() {
    let harness = Harness::new();
    let envelope = seal_intake(
        &harness,
        &[("api_key", API_KEY)],
        &intake(&[("api_key", &webhook())], now() + 60),
    );
    let outputs = [("api_key", &webhook(), false)];

    *harness.audit.not_ready.lock().unwrap() = true;
    let error = harness
        .broker
        .admit(admit(&envelope, &outputs))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Internal);
    assert_eq!(harness.key_fetches(), 0);
    *harness.audit.not_ready.lock().unwrap() = false;

    // A record that cannot be written fails the call, and no value is handed over.
    *harness.audit.fail.lock().unwrap() = true;
    let error = harness
        .broker
        .admit(admit(&envelope, &outputs))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Internal);
}
