//! Checking a webhook's signature against a sealed signing secret.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use ring::hmac;
use seal_broker::audit::Outcome;
use seal_broker::body::full_body;
use seal_broker::{ErrorCode, Limits, Presented, VerifyRequest};
use seal_format::Policy;
use seal_format::policy::HmacHash;
use seal_format::policy::builder;
use support::{Harness, MockProvider, Options, bearer, field, item, keyset, plain_policy, url};

const SECRET: &[u8] = b"SIGNING-canary-secret";
/// What Slack signs: a version, the timestamp and the body.
const MESSAGE: &[u8] = b"v0:1700000000:{\"type\":\"event_callback\"}";

fn mac_of(message: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, SECRET);
    hmac::sign(&key, message).as_ref().to_vec()
}

fn webhook() -> Policy {
    builder::webhook_hmac(HmacHash::Sha256).unwrap()
}

fn request(value: impl Into<Presented>, message: &'static [u8], mac: Vec<u8>) -> VerifyRequest {
    VerifyRequest {
        caller: "test-app".to_owned(),
        keyset: keyset(),
        item: item(),
        field: field("signing_secret"),
        value: value.into(),
        message: full_body(message),
        mac,
    }
}

fn assert_no_traffic(harness: &Harness) {
    assert_eq!((harness.lookups(), harness.connects()), (0, 0));
}

#[tokio::test]
async fn a_message_with_its_code_verifies_and_the_answer_is_recorded() {
    let harness = Harness::new();
    let secret = harness.seal("signing_secret", SECRET, &webhook());

    let valid = harness
        .broker
        .verify(request(secret, MESSAGE, mac_of(MESSAGE)))
        .await
        .unwrap();
    assert!(valid);

    let record = harness.audit.last();
    assert_eq!(record.op, "verify");
    assert_eq!(record.caller, "test-app");
    assert_eq!(record.fields, ["signing_secret"]);
    assert_eq!(record.verified, Some(true));
    assert_eq!(record.outcome, Outcome::Ok);
    assert_eq!(record.bytes_in, MESSAGE.len() as u64);
    assert_eq!(
        (record.host, record.path, record.status),
        (None, None, None)
    );
    assert_eq!(harness.audit.all().len(), 1);
    assert_no_traffic(&harness);
}

#[tokio::test]
async fn a_wrong_code_or_message_is_answered_no_without_an_error() {
    let harness = Harness::new();
    let secret = harness.seal("signing_secret", SECRET, &webhook());
    let mut flipped = mac_of(MESSAGE);
    flipped[31] ^= 1;
    let truncated = mac_of(MESSAGE)[..16].to_vec();
    let other_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, b"another"), MESSAGE)
        .as_ref()
        .to_vec();

    for (message, mac) in [
        (MESSAGE, flipped),
        (MESSAGE, truncated),
        (MESSAGE, Vec::new()),
        (MESSAGE, other_key),
        (&b"v0:1700000000:{\"type\":\"forged\"}"[..], mac_of(MESSAGE)),
    ] {
        let valid = harness
            .broker
            .verify(request(secret.clone(), message, mac))
            .await
            .unwrap();
        assert!(!valid);
        let record = harness.audit.last();
        assert_eq!(record.verified, Some(false));
        assert_eq!(record.outcome, Outcome::Ok);
    }
}

/// A token sealed for sending is not a key anyone agreed to check messages with.
#[tokio::test]
async fn a_value_whose_policy_has_no_verification_is_refused() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let token = harness.seal(
        "signing_secret",
        SECRET,
        &plain_policy(&provider, &bearer()),
    );

    let error = harness
        .broker
        .verify(request(token, MESSAGE, mac_of(MESSAGE)))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);
    assert!(!error.to_string().contains("canary"));
    let record = harness.audit.last();
    assert_eq!(record.outcome, Outcome::Refused);
    assert_eq!(record.code, Some("POLICY_DENIED"));
    assert_eq!(record.verified, None);
}

/// And a signing secret can be sent nowhere.
#[tokio::test]
async fn a_value_that_only_verifies_cannot_be_sent() {
    let provider = MockProvider::plain().await;
    let harness = Harness::new();
    let secret = harness.seal("signing_secret", SECRET, &webhook());
    let error = harness
        .get(&url(&provider, "/echo"), &[("signing_secret", &secret)])
        .await
        .err()
        .unwrap();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);
    assert!(provider.received().is_empty());
    assert_no_traffic(&harness);
}

#[tokio::test]
async fn a_value_for_another_field_or_record_does_not_verify() {
    let harness = Harness::new();
    let secret = harness.seal("other_field", SECRET, &webhook());
    let error = harness
        .broker
        .verify(request(secret, MESSAGE, mac_of(MESSAGE)))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::OpenFailed);

    // Bound to another record, it must have been sealed as shared.
    let elsewhere = |policy: &Policy| Presented {
        envelope: harness.seal_at("platform", "slack-app", "signing_secret", SECRET, policy),
        item: Some(seal_format::ItemId::new("slack-app").unwrap()),
    };
    let error = harness
        .broker
        .verify(request(elsewhere(&webhook()), MESSAGE, mac_of(MESSAGE)))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);

    let mut shared = webhook();
    shared.shared = true;
    let valid = harness
        .broker
        .verify(request(elsewhere(&shared), MESSAGE, mac_of(MESSAGE)))
        .await
        .unwrap();
    assert!(valid);
    assert_eq!(
        harness.audit.last().shared,
        ["signing_secret=platform/slack-app"]
    );
}

#[tokio::test]
async fn a_message_over_the_buffer_cap_is_refused() {
    let mut options = Options::default();
    options.limits = Limits {
        buffer_cap: 16,
        ..options.limits
    };
    let harness = Harness::with(options);
    let secret = harness.seal("signing_secret", SECRET, &webhook());
    let error = harness
        .broker
        .verify(request(secret, MESSAGE, mac_of(MESSAGE)))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::BodyTooLarge);
    assert_eq!(harness.audit.last().outcome, Outcome::Refused);
}

#[tokio::test]
async fn each_hash_verifies_only_its_own_codes() {
    let harness = Harness::new();
    for (hash, algorithm) in [
        (HmacHash::Sha1, hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
        (HmacHash::Sha256, hmac::HMAC_SHA256),
        (HmacHash::Sha512, hmac::HMAC_SHA512),
    ] {
        let policy = builder::webhook_hmac(hash).unwrap();
        let secret = harness.seal("signing_secret", SECRET, &policy);
        let mac = hmac::sign(&hmac::Key::new(algorithm, SECRET), MESSAGE)
            .as_ref()
            .to_vec();
        let verify = |mac: Vec<u8>| harness.broker.verify(request(secret.clone(), MESSAGE, mac));
        assert!(verify(mac).await.unwrap(), "{hash:?}");
        assert_eq!(
            verify(mac_of(MESSAGE)).await.unwrap(),
            hash == HmacHash::Sha256,
            "{hash:?}"
        );
    }
}

/// What Telegram sends back in `X-Telegram-Bot-Api-Secret-Token`.
const TOKEN: &[u8] = b"TOKEN-canary-secret_token";

fn token_policy() -> Policy {
    Policy::from_json(br#"{"verify":"equals"}"#).unwrap()
}

#[tokio::test]
async fn a_token_matches_only_itself_and_the_answer_is_recorded() {
    let harness = Harness::new();
    let secret = harness.seal("signing_secret", TOKEN, &token_policy());
    let verify = |presented: &[u8]| {
        harness
            .broker
            .verify(request(secret.clone(), b"", presented.to_vec()))
    };

    assert!(verify(TOKEN).await.unwrap());
    let record = harness.audit.last();
    assert_eq!((record.op, record.verified), ("verify", Some(true)));
    assert_eq!(record.outcome, Outcome::Ok);

    for presented in [
        &b""[..],
        &TOKEN[..TOKEN.len() - 1],
        b"TOKEN-canary-secret_tokeN",
        b"TOKEN-canary-secret_token ",
    ] {
        assert!(!verify(presented).await.unwrap());
        assert_eq!(harness.audit.last().verified, Some(false));
    }
    // Nor does the HMAC a signing secret would have made.
    let key = hmac::Key::new(hmac::HMAC_SHA256, TOKEN);
    assert!(!verify(hmac::sign(&key, b"").as_ref()).await.unwrap());
    assert_no_traffic(&harness);
}

/// A token says nothing about a message, so one is not accepted alongside it.
#[tokio::test]
async fn a_token_is_not_checked_with_a_message() {
    let harness = Harness::new();
    let secret = harness.seal("signing_secret", TOKEN, &token_policy());
    let error = harness
        .broker
        .verify(request(secret, MESSAGE, TOKEN.to_vec()))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::BadRequest);
    assert!(!format!("{error:?} {error}").contains("canary"));
    assert_eq!(harness.audit.last().outcome, Outcome::Refused);
}

#[tokio::test]
async fn a_value_sealed_empty_matches_no_token() {
    let harness = Harness::new();
    let secret = harness.seal("signing_secret", b"", &token_policy());
    let valid = harness
        .broker
        .verify(request(secret, b"", Vec::new()))
        .await
        .unwrap();
    assert!(!valid);
}

/// A signing secret is not a token: presenting it does not verify.
#[tokio::test]
async fn an_hmac_secret_is_not_compared_as_a_token() {
    let harness = Harness::new();
    let secret = harness.seal("signing_secret", SECRET, &webhook());
    let valid = harness
        .broker
        .verify(request(secret, b"", SECRET.to_vec()))
        .await
        .unwrap();
    assert!(!valid);
}
