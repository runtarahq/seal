//! Presigned URLs: issued only where a rule allows it, within its lifetime, for a
//! request the rule would allow, and never with any traffic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;

use http::Method;
use seal_broker::audit::Outcome;
use seal_broker::{ErrorCode, PresignRequest};
use seal_format::{Envelope, Policy};
use serde_json::{Value, json};
use support::{Harness, field, item, keyset, rule_policy};

const S3_SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const OBJECT: &str = "https://s3.eu-west-1.amazonaws.com/tenant-a/reports/q3.csv";
/// base64 of "0123456789abcdef0123456789abcdef".
const ACCOUNT_KEY: &[u8] = b"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
const BLOB: &str = "https://account.blob.core.windows.net/exports/q3.csv";

fn s3_rule(change: impl FnOnce(&mut Value)) -> Policy {
    let mut rule = json!({
        "destination": {
            "scheme": "https", "host": "s3.eu-west-1.amazonaws.com", "path_prefix": "/tenant-a/"
        },
        "methods": ["GET", "PUT"],
        "inject": { "aws_sigv4": {
            "region": "eu-west-1", "service": "s3",
            "access_key_id": { "literal": "AKIAIOSFODNN7EXAMPLE" },
            "payload": ["computed"],
            "allow_presign": { "max_expiry_s": 900 }
        } }
    });
    change(&mut rule);
    rule_policy(&rule)
}

fn blob_rule(methods: &[&str]) -> Policy {
    rule_policy(&json!({
        "destination": {
            "scheme": "https", "host": "account.blob.core.windows.net", "path_prefix": "/exports/"
        },
        "methods": methods,
        "inject": { "azure_shared_key": {
            "account": { "literal": "account" }, "service": "blob",
            "allow_presign": { "max_expiry_s": 900 }
        } }
    }))
}

fn presign(
    sealed: &[(&str, &Envelope)],
    method: Method,
    url: &str,
    expires_s: u32,
) -> PresignRequest {
    PresignRequest {
        caller: "test-app".to_owned(),
        keyset: keyset(),
        item: item(),
        sealed: sealed
            .iter()
            .map(|(name, envelope)| (field(name), (*envelope).clone().into()))
            .collect(),
        plain: BTreeMap::new(),
        method,
        url: url.to_owned(),
        expires_s,
    }
}

fn query_of(url: &str) -> BTreeMap<String, String> {
    let (_, query) = url.split_once('?').unwrap();
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn assert_no_traffic(harness: &Harness) {
    assert_eq!((harness.lookups(), harness.connects()), (0, 0));
}

#[tokio::test]
async fn a_rule_that_allows_it_gives_a_presigned_url_and_a_record_of_it() {
    let harness = Harness::new();
    let key = harness.seal("secret_key", S3_SECRET, &s3_rule(|_| {}));

    let url = harness
        .broker
        .presign(presign(&[("secret_key", &key)], Method::GET, OBJECT, 600))
        .await
        .unwrap();

    assert!(url.starts_with(&format!("{OBJECT}?X-Amz-Algorithm=AWS4-HMAC-SHA256&")));
    let query = query_of(&url);
    assert_eq!(query["X-Amz-Expires"], "600");
    assert_eq!(query["X-Amz-SignedHeaders"], "host");
    assert!(query["X-Amz-Credential"].starts_with("AKIAIOSFODNN7EXAMPLE/"));
    assert!(query["X-Amz-Credential"].ends_with("/eu-west-1/s3/aws4_request"));
    assert_eq!(query["X-Amz-Signature"].len(), 64);
    assert!(
        !url.contains("wJalrXUtnFEMI"),
        "the key itself never leaves"
    );

    let record = harness.audit.last();
    assert_eq!(record.op, "presign");
    assert_eq!(record.method, "GET");
    assert_eq!(record.host.as_deref(), Some("s3.eu-west-1.amazonaws.com"));
    assert_eq!(record.path.as_deref(), Some("/tenant-a/reports/q3.csv"));
    assert_eq!(record.expires_s, Some(600));
    assert_eq!(record.rules, [0]);
    assert_eq!(record.outcome, Outcome::Ok);
    assert!(
        !serde_json::to_string(&record)
            .unwrap()
            .contains(&query["X-Amz-Signature"])
    );
    assert_no_traffic(&harness);
}

/// The default: a key sealed to be used through seal gives nothing a caller can keep.
#[tokio::test]
async fn acceptance_a_rule_without_allow_presign_gives_no_url() {
    let harness = Harness::new();
    let unsigned = s3_rule(|rule| {
        let inject = rule["inject"]["aws_sigv4"].as_object_mut().unwrap();
        inject.remove("allow_presign");
    });
    let key = harness.seal("secret_key", S3_SECRET, &unsigned);
    let error = harness
        .broker
        .presign(presign(&[("secret_key", &key)], Method::GET, OBJECT, 60))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);
    let record = harness.audit.last();
    assert_eq!(record.outcome, Outcome::Refused);
    assert_eq!(record.code, Some("POLICY_DENIED"));

    // Nor does a credential of another kind.
    let bearer = rule_policy(&json!({
        "destination": { "scheme": "https", "host": "s3.eu-west-1.amazonaws.com" },
        "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } }
    }));
    let token = harness.seal("token", b"bearer-canary-token", &bearer);
    let error = harness
        .broker
        .presign(presign(&[("token", &token)], Method::GET, OBJECT, 60))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);
    assert_no_traffic(&harness);
}

#[tokio::test]
async fn a_url_is_presigned_only_within_the_rules_lifetime_methods_and_paths() {
    let harness = Harness::new();
    let key = harness.seal("secret_key", S3_SECRET, &s3_rule(|_| {}));
    let sealed = [("secret_key", &key)];
    let refused = |method: Method, url: &'static str, expires_s: u32| {
        let request = presign(&sealed, method, url, expires_s);
        async { harness.broker.presign(request).await.unwrap_err().code() }
    };

    harness
        .broker
        .presign(presign(&sealed, Method::PUT, OBJECT, 900))
        .await
        .unwrap();
    assert_eq!(
        refused(Method::GET, OBJECT, 901).await,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        refused(Method::GET, OBJECT, u32::MAX).await,
        ErrorCode::PolicyDenied
    );
    assert_eq!(refused(Method::GET, OBJECT, 0).await, ErrorCode::BadRequest);
    // The rule lists GET and PUT.
    assert_eq!(
        refused(Method::DELETE, OBJECT, 60).await,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        refused(Method::POST, OBJECT, 60).await,
        ErrorCode::PolicyDenied
    );
    // Another tenant's objects, another bucket host, and a path a parser would rewrite.
    for url in [
        "https://s3.eu-west-1.amazonaws.com/tenant-b/reports/q3.csv",
        "https://s3.eu-west-1.amazonaws.com/tenant-a%2f..%2ftenant-b/q3.csv",
        "https://s3.us-east-1.amazonaws.com/tenant-a/reports/q3.csv",
        "http://s3.eu-west-1.amazonaws.com/tenant-a/reports/q3.csv",
    ] {
        assert_eq!(
            refused(Method::GET, url, 60).await,
            ErrorCode::PolicyDenied,
            "{url}"
        );
    }
    assert_eq!(
        refused(
            Method::GET,
            "https://s3.eu-west-1.amazonaws.com/tenant-a/../tenant-b/q3.csv",
            60
        )
        .await,
        ErrorCode::BadRequest
    );
    // What a caller may not ask of the object, or set for the signature.
    for url in [
        "https://s3.eu-west-1.amazonaws.com/tenant-a/reports/q3.csv?acl",
        "https://s3.eu-west-1.amazonaws.com/tenant-a/reports/q3.csv?X-Amz-Expires=604800",
    ] {
        assert_eq!(
            refused(Method::GET, url, 60).await,
            ErrorCode::BadRequest,
            "{url}"
        );
    }
    assert_no_traffic(&harness);
}

/// A rule that seals responses, or checks the request's form, is for requests seal
/// sends: a presigned URL would step around it.
#[tokio::test]
async fn a_rule_that_needs_seal_to_send_the_request_gives_no_url() {
    let harness = Harness::new();
    let checked = s3_rule(|rule| rule["require_form"] = json!({ "kind": ["report"] }));
    let key = harness.seal("secret_key", S3_SECRET, &checked);
    let error = harness
        .broker
        .presign(presign(&[("secret_key", &key)], Method::GET, OBJECT, 60))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);
}

#[tokio::test]
async fn temporary_credentials_put_their_session_token_in_the_url() {
    let harness = Harness::new();
    let key_policy = s3_rule(|rule| {
        rule["inject"]["aws_sigv4"]["session_token"] = json!({ "field": "session_token" });
    });
    let companion = rule_policy(&json!({
        "destination": { "scheme": "https", "host": "s3.eu-west-1.amazonaws.com" },
        "inject": { "companion": {} }
    }));
    let key = harness.seal("secret_key", S3_SECRET, &key_policy);
    let token = harness.seal("session_token", b"SESSION/token+value=", &companion);
    let url = harness
        .broker
        .presign(presign(
            &[("secret_key", &key), ("session_token", &token)],
            Method::GET,
            OBJECT,
            60,
        ))
        .await
        .unwrap();
    assert_eq!(
        query_of(&url)["X-Amz-Security-Token"],
        "SESSION/token+value="
    );
}

#[tokio::test]
async fn a_blob_rule_gives_a_shared_access_signature_for_the_method() {
    let harness = Harness::new();
    let key = harness.seal(
        "account_key",
        ACCOUNT_KEY,
        &blob_rule(&["GET", "PUT", "DELETE"]),
    );
    let sealed = [("account_key", &key)];
    for (method, permissions) in [
        (Method::GET, "r"),
        (Method::HEAD, "r"),
        (Method::PUT, "cw"),
        (Method::DELETE, "d"),
    ] {
        let allowed = method != Method::HEAD;
        let result = harness
            .broker
            .presign(presign(&sealed, method.clone(), BLOB, 300))
            .await;
        if !allowed {
            // The rule does not list HEAD.
            assert_eq!(result.unwrap_err().code(), ErrorCode::PolicyDenied);
            continue;
        }
        let url = result.unwrap();
        assert!(url.starts_with(&format!("{BLOB}?se=")), "{}", *url);
        let query = query_of(&url);
        assert_eq!(query["sp"], permissions, "{method}");
        assert_eq!(
            (query["sr"].as_str(), query["spr"].as_str()),
            ("b", "https")
        );
        assert_eq!(query["sig"].len(), 44);
        assert!(!query.contains_key("st"));
    }
    assert_eq!(harness.audit.last().expires_s, Some(300));

    // A download's content type is the caller's to choose, and is signed.
    let typed = format!("{BLOB}?rsct=text/csv");
    let url = harness
        .broker
        .presign(presign(&sealed, Method::GET, &typed, 300))
        .await
        .unwrap();
    assert_eq!(query_of(&url)["rsct"], "text/csv");

    for (url, code) in [
        (
            "https://account.blob.core.windows.net/exports/q3.csv?comp=metadata",
            ErrorCode::BadRequest,
        ),
        (
            "https://account.blob.core.windows.net/exports/",
            ErrorCode::BadRequest,
        ),
        (
            "https://account.blob.core.windows.net/private/q3.csv",
            ErrorCode::PolicyDenied,
        ),
    ] {
        let error = harness
            .broker
            .presign(presign(&sealed, Method::GET, url, 300))
            .await
            .unwrap_err();
        assert_eq!(error.code(), code, "{url}");
    }
    assert_no_traffic(&harness);
}

/// The lifetime is the caller's choice within the rule's, and a signature made for
/// one lifetime is not one for another.
#[tokio::test]
async fn the_expiry_is_part_of_what_is_signed() {
    let harness = Harness::new();
    let key = harness.seal("secret_key", S3_SECRET, &s3_rule(|_| {}));
    let sign = |expires_s: u32| {
        let request = presign(&[("secret_key", &key)], Method::GET, OBJECT, expires_s);
        async { query_of(&harness.broker.presign(request).await.unwrap()) }
    };
    let (short, long) = (sign(60).await, sign(900).await);
    assert_eq!(short["X-Amz-Date"].len(), 16);
    assert_ne!(short["X-Amz-Signature"], long["X-Amz-Signature"]);
}
