//! `jwt_assertion` through the matcher and injection: the documented JWT shapes of
//! major providers, and the refusals.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use seal_broker::ErrorCode;
use seal_broker::inject::{Sources, apply_to_body, build_head};
use seal_broker::matcher::{Endpoint, RequestHead, decide};
use seal_broker::target::Target;
use seal_format::policy::Method;
use seal_format::{FieldName, Policy, Secret};
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000;

fn key(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/jwt/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn jwt_rule(destination: &Value, jwt: Value) -> Policy {
    let value =
        json!({ "rules": [{ "destination": destination, "inject": { "jwt_assertion": jwt } }] });
    Policy::from_json(value.to_string().as_bytes()).unwrap()
}

/// What the provider would receive: the form body, after injection.
fn sent_form(
    policy: &Policy,
    url: &str,
    key_pem: &[u8],
    body: &[u8],
) -> Result<BTreeMap<String, String>, ErrorCode> {
    let target = Target::parse(url).unwrap();
    let field = FieldName::new("signing_key").unwrap();
    let plain = BTreeSet::new();
    let plan = decide(
        &BTreeMap::from([(field.clone(), policy.clone())]),
        &RequestHead {
            endpoint: Endpoint::Http(&target),
            method: Method::Post,
            header_names: &["content-type"],
            plain: &plain,
            copy_source: None,
        },
    )
    .map_err(|error| error.code())?;
    let secrets = BTreeMap::from([(field, Secret::new(key_pem))]);
    let plain = BTreeMap::new();
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    let outgoing = build_head(
        &plan,
        &target,
        &headers,
        &Sources {
            secrets: &secrets,
            plain: &plain,
        },
        UNIX_EPOCH + Duration::from_secs(NOW),
    )
    .map_err(|error| error.code())?;
    let sent = apply_to_body(outgoing.body.as_ref().unwrap(), &outgoing.headers, body)
        .map_err(|error| error.code())?;
    Ok(form_urlencoded::parse(&sent).into_owned().collect())
}

fn decode(jwt: &str) -> (Value, Value) {
    let pieces: Vec<&str> = jwt.split('.').collect();
    let json = |piece: &str| {
        serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(piece).unwrap()).unwrap()
    };
    (json(pieces[0]), json(pieces[1]))
}

/// Everything but the random `jti`, which is checked separately.
fn without_jti(mut claims: Value) -> Value {
    let jti = claims.as_object_mut().unwrap().remove("jti").unwrap();
    assert_eq!(jti.as_str().unwrap().len(), 32);
    claims
}

fn times(lifetime: u64) -> Value {
    json!({ "iat": NOW, "nbf": NOW, "exp": NOW + lifetime })
}

fn merge(mut base: Value, extra: Value) -> Value {
    for (key, value) in extra.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

// The documented shapes. Each fixes the audience, algorithm, header and claims a
// provider expects; see docs/oauth.md for the sources.

#[test]
fn google_service_account_jwt_bearer_grant() {
    let policy = jwt_rule(
        &json!({ "scheme": "https", "host": "oauth2.googleapis.com", "path_prefix": "/token" }),
        json!({
            "alg": "RS256", "aud": "token_endpoint",
            "claims": { "iss": "robot@project.iam.gserviceaccount.com", "scope": "https://www.googleapis.com/auth/cloud-platform" },
            "header": { "kid": "0123456789abcdef" },
            "form_field": "assertion", "max_lifetime_s": 300
        }),
    );
    let form = sent_form(
        &policy,
        "https://oauth2.googleapis.com/token",
        &key("rsa-pkcs8.pem"),
        b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
    )
    .unwrap();
    assert_eq!(
        form["grant_type"],
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    assert!(
        !form.contains_key("client_assertion_type"),
        "a grant, not client authentication"
    );
    let (header, claims) = decode(&form["assertion"]);
    assert_eq!(
        header,
        json!({ "alg": "RS256", "typ": "JWT", "kid": "0123456789abcdef" })
    );
    assert_eq!(
        without_jti(claims),
        merge(
            times(300),
            json!({
                "iss": "robot@project.iam.gserviceaccount.com",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "aud": "https://oauth2.googleapis.com/token",
            })
        )
    );
}

#[test]
fn okta_private_key_jwt_names_the_endpoint_called() {
    let policy = jwt_rule(
        &json!({ "scheme": "https", "host": "dev-1.okta.com", "path_prefix": "/oauth2/default/v1/token" }),
        json!({
            "alg": "RS256", "aud": "token_endpoint",
            "claims": { "iss": "0oa1client", "sub": "0oa1client" },
            "form_field": "client_assertion", "max_lifetime_s": 300
        }),
    );
    let form = sent_form(
        &policy,
        "https://dev-1.okta.com/oauth2/default/v1/token",
        &key("rsa-pkcs1.pem"),
        b"grant_type=client_credentials&scope=x",
    )
    .unwrap();
    assert_eq!(
        form["client_assertion_type"],
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
    assert_eq!(form["grant_type"], "client_credentials");
    let (_, claims) = decode(&form["client_assertion"]);
    assert_eq!(
        without_jti(claims),
        merge(
            times(300),
            json!({ "iss": "0oa1client", "sub": "0oa1client", "aud": "https://dev-1.okta.com/oauth2/default/v1/token" })
        )
    );
}

#[test]
fn microsoft_entra_uses_ps256_and_the_certificate_thumbprint() {
    let policy = jwt_rule(
        &json!({ "scheme": "https", "host": "login.microsoftonline.com", "path_prefix": "/contoso.onmicrosoft.com/oauth2/v2.0/token" }),
        json!({
            "alg": "PS256", "aud": "token_endpoint",
            "claims": { "iss": "aaaabbbb-0000-cccc-1111-dddd2222eeee", "sub": "aaaabbbb-0000-cccc-1111-dddd2222eeee" },
            "header": { "x5t#S256": "A1bC2dE3fH4iJ5kL6mN7oP8qR9sT0u" },
            "form_field": "client_assertion", "max_lifetime_s": 300
        }),
    );
    let form = sent_form(
        &policy,
        "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
        &key("rsa-pkcs8.pem"),
        b"grant_type=client_credentials",
    )
    .unwrap();
    let (header, claims) = decode(&form["client_assertion"]);
    assert_eq!(
        header,
        json!({ "alg": "PS256", "typ": "JWT", "x5t#S256": "A1bC2dE3fH4iJ5kL6mN7oP8qR9sT0u" })
    );
    assert_eq!(
        claims["aud"],
        "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"
    );
}

#[test]
fn auth0_names_the_tenant_url_with_its_trailing_slash() {
    let policy = jwt_rule(
        &json!({ "scheme": "https", "host": "tenant.eu.auth0.com", "path_prefix": "/oauth/token" }),
        json!({
            "alg": "ES256", "aud": { "value": "https://tenant.eu.auth0.com/" },
            "claims": { "iss": "client", "sub": "client" },
            "form_field": "client_assertion", "max_lifetime_s": 60
        }),
    );
    let form = sent_form(
        &policy,
        "https://tenant.eu.auth0.com/oauth/token",
        &key("ec-sec1.pem"),
        b"grant_type=client_credentials",
    )
    .unwrap();
    let (header, claims) = decode(&form["client_assertion"]);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(
        without_jti(claims),
        merge(
            times(60),
            json!({ "iss": "client", "sub": "client", "aud": "https://tenant.eu.auth0.com/" })
        )
    );
}

#[test]
fn salesforce_names_the_login_url_not_the_token_path() {
    let policy = jwt_rule(
        &json!({ "scheme": "https", "host": "login.salesforce.com", "path_prefix": "/services/oauth2/token" }),
        json!({
            "alg": "RS256", "aud": { "value": "https://login.salesforce.com" },
            "claims": { "iss": "3MVG9consumerkey", "sub": "integration@example.com" },
            "form_field": "assertion", "max_lifetime_s": 180
        }),
    );
    let form = sent_form(
        &policy,
        "https://login.salesforce.com/services/oauth2/token",
        &key("rsa-pkcs8.pem"),
        b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
    )
    .unwrap();
    let (_, claims) = decode(&form["assertion"]);
    assert_eq!(
        without_jti(claims),
        merge(
            times(180),
            json!({ "iss": "3MVG9consumerkey", "sub": "integration@example.com", "aud": "https://login.salesforce.com" })
        )
    );
}

#[test]
fn the_token_endpoint_audience_keeps_a_non_default_port() {
    let policy = jwt_rule(
        &json!({ "scheme": "https", "host": "auth.example.com", "port": 8443, "path_prefix": "/token" }),
        json!({ "alg": "RS256", "aud": "token_endpoint", "claims": { "iss": "c" }, "form_field": "assertion", "max_lifetime_s": 30 }),
    );
    let form = sent_form(
        &policy,
        "https://auth.example.com:8443/token",
        &key("rsa-pkcs8.pem"),
        b"",
    )
    .unwrap();
    assert_eq!(
        decode(&form["assertion"]).1["aud"],
        "https://auth.example.com:8443/token"
    );
}

// Refusals.

fn simple() -> Policy {
    jwt_rule(
        &json!({ "scheme": "https", "host": "auth.example.com", "path_prefix": "/oauth/token" }),
        json!({ "alg": "RS256", "aud": "token_endpoint", "claims": { "iss": "c" }, "form_field": "assertion", "max_lifetime_s": 300 }),
    )
}

#[test]
fn a_longer_path_below_the_token_endpoint_is_refused() {
    for url in [
        "https://auth.example.com/oauth/token/other",
        "https://auth.example.com/oauth/token/",
        "https://auth.example.com/oauth/tokens",
        "https://auth.example.com/oauth",
    ] {
        assert_eq!(
            sent_form(&simple(), url, &key("rsa-pkcs8.pem"), b"a=1").unwrap_err(),
            ErrorCode::PolicyDenied,
            "{url}"
        );
    }
}

#[test]
fn the_caller_cannot_supply_the_assertion_fields_itself() {
    for body in [&b"assertion=mine"[..], b"client_assertion_type=x"] {
        let policy = if body.starts_with(b"assertion") {
            simple()
        } else {
            jwt_rule(
                &json!({ "scheme": "https", "host": "auth.example.com", "path_prefix": "/oauth/token" }),
                json!({ "alg": "RS256", "aud": "token_endpoint", "claims": { "iss": "c" }, "form_field": "client_assertion", "max_lifetime_s": 300 }),
            )
        };
        assert_eq!(
            sent_form(
                &policy,
                "https://auth.example.com/oauth/token",
                &key("rsa-pkcs8.pem"),
                body
            )
            .unwrap_err(),
            ErrorCode::Conflict
        );
    }
}

#[test]
fn a_rule_without_an_audience_or_exact_path_cannot_even_be_sealed() {
    let no_aud = json!({ "rules": [{
        "destination": { "scheme": "https", "host": "auth.example.com", "path_prefix": "/oauth/token" },
        "inject": { "jwt_assertion": { "alg": "RS256", "claims": { "iss": "c" }, "form_field": "assertion", "max_lifetime_s": 300 } }
    }] });
    assert!(Policy::from_json(no_aud.to_string().as_bytes()).is_err());
    let no_path = json!({ "rules": [{
        "destination": { "scheme": "https", "host": "auth.example.com" },
        "inject": { "jwt_assertion": { "alg": "RS256", "aud": "token_endpoint", "claims": { "iss": "c" }, "form_field": "assertion", "max_lifetime_s": 300 } }
    }] });
    assert!(Policy::from_json(no_path.to_string().as_bytes()).is_err());
}

#[test]
fn a_key_that_does_not_suit_the_rule_fails_cleanly() {
    let error = sent_form(
        &simple(),
        "https://auth.example.com/oauth/token",
        &key("ec-pkcs8.pem"),
        b"a=1",
    )
    .unwrap_err();
    assert_eq!(error, ErrorCode::BadRequest);
}

#[test]
fn the_clock_sets_the_times() {
    let form = sent_form(
        &simple(),
        "https://auth.example.com/oauth/token",
        &key("rsa-pkcs8.pem"),
        b"",
    )
    .unwrap();
    let (_, claims) = decode(&form["assertion"]);
    assert_eq!(claims["iat"], NOW);
    assert_eq!(claims["exp"], NOW + 300);
}
