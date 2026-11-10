//! Generates the files in `vectors/`, for the generator and the test to share.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use seal_format::id::KeyId;
use seal_format::policy::builder::{self, JwtOptions, OAuthClientAuth, OAuthConfig, PartSource};
use seal_format::policy::{
    AzureService, JwtAlg, JwtAudience, JwtClaims, JwtHeader, PayloadMode, ResponseFormat,
};
use seal_format::seal::{associated_data, seal_with_ephemeral_ikm};
use seal_format::{Binding, FieldName, ItemId, KeysetId, Policy, PrivateKey};
use serde_json::{Value, json};

/// A private key for vectors only. Never use it for anything else.
const PRIVATE_KEY: [u8; 32] = [
    0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f,
    0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f,
];
const OTHER_PRIVATE_KEY: [u8; 32] = [0x48; 32];

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").unwrap();
        text
    })
}

fn pretty(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).unwrap();
    text.push('\n');
    text
}

fn oauth_policy() -> Policy {
    builder::oauth_client(&OAuthConfig {
        token_url: "https://auth.example.com/oauth/token".to_owned(),
        revoke_url: Some("https://auth.example.com/oauth/revoke".to_owned()),
        api_base: "https://api.example.com/v2/".to_owned(),
        auth: OAuthClientAuth::ClientSecretPost,
        response_format: ResponseFormat::Json,
        shared: false,
        access_token_claims: Vec::new(),
    })
    .unwrap()
    .client
}

fn jwt_policy(aud: JwtAudience) -> Policy {
    builder::oauth_client(&OAuthConfig {
        token_url: "https://auth.example.com/oauth/token".to_owned(),
        revoke_url: None,
        api_base: "https://api.example.com/".to_owned(),
        auth: OAuthClientAuth::PrivateKeyJwt(JwtOptions {
            alg: JwtAlg::PS256,
            aud,
            claims: JwtClaims {
                iss: "client".to_owned(),
                sub: Some("client".to_owned()),
                scope: None,
                extra: BTreeMap::new(),
            },
            header: JwtHeader {
                typ: None,
                kid: Some("k1".to_owned()),
                x5t_s256: None,
            },
            max_lifetime_s: 300,
        }),
        response_format: ResponseFormat::Json,
        shared: false,
        access_token_claims: Vec::new(),
    })
    .unwrap()
    .client
}

/// Policies that exercise each part of the schema, by name.
fn valid_policies() -> Vec<(&'static str, Policy)> {
    let field = |name: &str| FieldName::new(name).unwrap();
    vec![
        (
            "bearer",
            builder::bearer("https://api.example.com/v2/").unwrap(),
        ),
        (
            "api key header",
            builder::api_key_header("https://api.example.com:8443", "X-Api-Key").unwrap(),
        ),
        (
            "basic auth with a plain username",
            builder::basic(
                "https://api.example.com/",
                PartSource::Plain(field("username")),
            )
            .unwrap()
            .secret,
        ),
        ("OAuth client with a rotating refresh token", oauth_policy()),
        (
            "private key JWT, audience is the token endpoint",
            jwt_policy(JwtAudience::TokenEndpoint),
        ),
        (
            "private key JWT, exact audience with a trailing slash",
            jwt_policy(JwtAudience::Value("https://tenant.example.com/".to_owned())),
        ),
        (
            "AWS with a sealed session token",
            builder::aws(
                "eu-west-1",
                "s3",
                "https://s3.eu-west-1.amazonaws.com",
                PartSource::Plain(field("access_key_id")),
                Some(PartSource::Sealed(field("session_token"))),
                vec![PayloadMode::Computed, PayloadMode::CallerHash],
            )
            .unwrap()
            .secret,
        ),
        (
            "Azure Table",
            builder::azure(
                PartSource::Literal("account".to_owned()),
                AzureService::Table,
                "https://account.table.core.windows.net",
            )
            .unwrap()
            .secret,
        ),
        (
            "client certificate",
            builder::client_cert(
                "https://api.example.com/",
                PartSource::Plain(field("cert")),
                None,
            )
            .unwrap()
            .secret,
        ),
        (
            "Postgres",
            builder::postgres("db.example.com", 5432, vec!["app".to_owned()], "app_user").unwrap(),
        ),
    ]
}

/// One rule's worth of JSON that a validator must refuse, by reason.
fn invalid_policies() -> Vec<(&'static str, Value)> {
    let rule = |destination: Value, inject: Value| json!({ "rules": [{ "destination": destination, "inject": inject }] });
    let https = json!({ "scheme": "https", "host": "api.example.com" });
    let bearer = json!({ "header": { "name": "Authorization", "format": "Bearer {}" } });
    let token = json!({ "scheme": "https", "host": "auth.example.com", "path_prefix": "/token" });
    let jwt = |aud: Value| {
        json!({ "jwt_assertion": {
        "alg": "RS256", "aud": aud, "claims": { "iss": "c" }, "form_field": "assertion", "max_lifetime_s": 300
    } })
    };
    vec![
        ("no rules", json!({ "rules": [] })),
        (
            "unknown field",
            json!({ "rules": [{ "destination": https, "inject": bearer, "extra": 1 }] }),
        ),
        (
            "wildcard host",
            rule(
                json!({ "scheme": "https", "host": "*.example.com" }),
                bearer.clone(),
            ),
        ),
        (
            "uppercase host",
            rule(
                json!({ "scheme": "https", "host": "API.example.com" }),
                bearer.clone(),
            ),
        ),
        (
            "dot segment in path prefix",
            rule(
                json!({ "scheme": "https", "host": "api.example.com", "path_prefix": "/v2/../admin" }),
                bearer.clone(),
            ),
        ),
        (
            "encoded separator in path prefix",
            rule(
                json!({ "scheme": "https", "host": "api.example.com", "path_prefix": "/v2%2fadmin" }),
                bearer.clone(),
            ),
        ),
        (
            "plain http without the flag",
            rule(
                json!({ "scheme": "http", "host": "api.example.com" }),
                bearer.clone(),
            ),
        ),
        (
            "template without a placeholder",
            rule(
                https.clone(),
                json!({ "header": { "name": "A", "format": "x" } }),
            ),
        ),
        (
            "header a rule may not inject into",
            rule(
                https.clone(),
                json!({ "header": { "name": "Host", "format": "{}" } }),
            ),
        ),
        ("JWT with no audience", {
            let mut policy = rule(token.clone(), jwt(json!("token_endpoint")));
            policy["rules"][0]["inject"]["jwt_assertion"]
                .as_object_mut()
                .unwrap()
                .remove("aud");
            policy
        }),
        (
            "JWT audience as an array",
            rule(token.clone(), jwt(json!({ "value": ["a", "b"] }))),
        ),
        (
            "JWT without an exact token path",
            rule(https.clone(), jwt(json!("token_endpoint"))),
        ),
        ("response field naming an unknown definition", {
            let mut policy = rule(https.clone(), bearer.clone());
            policy["rules"][0]["seal_response"] = json!({
                "format": "json", "fields": [{ "at": "/a", "as": "a", "policy": "missing" }]
            });
            policy
        }),
        ("nested response policy", {
            let mut policy = rule(https, bearer);
            policy["rules"][0]["seal_response"] = json!({
                "format": "json", "fields": [{ "at": "/a", "as": "a", "policy": { "rules": [] } }]
            });
            policy
        }),
    ]
}

struct Case {
    name: &'static str,
    keyset: &'static str,
    kid: &'static str,
    item: &'static str,
    field: &'static str,
    secret: Vec<u8>,
    policy: Policy,
    ephemeral_ikm: [u8; 32],
}

fn cases() -> Vec<Case> {
    let bearer = builder::bearer("https://api.example.com/v2/").unwrap();
    vec![
        Case {
            name: "UTF-8 secret",
            keyset: "acme",
            kid: "k3",
            item: "c_123",
            field: "api_key",
            secret: "sk-live-example".as_bytes().to_vec(),
            policy: bearer.clone(),
            ephemeral_ikm: [0x11; 32],
        },
        Case {
            name: "binary secret covering every base64url character class",
            keyset: "acme",
            kid: "k3",
            item: "c_123",
            field: "api_key",
            secret: vec![0x00, 0xfb, 0xff, 0xfe, 0x3e, 0x3f, 0x80],
            policy: bearer.clone(),
            ephemeral_ikm: [0x22; 32],
        },
        Case {
            name: "empty secret",
            keyset: "acme",
            kid: "k3",
            item: "c_123",
            field: "api_key",
            secret: Vec::new(),
            policy: bearer,
            ephemeral_ikm: [0x33; 32],
        },
        Case {
            name: "identifiers using the full alphabet, with a rotating OAuth policy",
            keyset: "Tenant_1.a:b-c",
            kid: "2026-11:k.1",
            item: "connection:0190e1a2-7f3c",
            field: "client_secret.v1",
            secret: b"client-secret-example".to_vec(),
            policy: oauth_policy(),
            ephemeral_ikm: [0x44; 32],
        },
    ]
}

fn plaintext_of(policy: &Policy, secret: &[u8]) -> String {
    use base64::Engine;
    let canonical = String::from_utf8(policy.canonical_json().unwrap()).unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
    format!("{{\"policy\":{canonical},\"secret\":{{\"b64\":\"{encoded}\"}}}}")
}

fn envelope_vectors() -> Value {
    let private = PrivateKey::from_bytes(&PRIVATE_KEY).unwrap();
    let public = private.public_key().unwrap();

    let cases: Vec<Value> = cases()
        .iter()
        .map(|case| {
            let keyset = KeysetId::new(case.keyset).unwrap();
            let kid = KeyId::new(case.kid).unwrap();
            let item = ItemId::new(case.item).unwrap();
            let field = FieldName::new(case.field).unwrap();
            let binding = Binding {
                keyset: &keyset,
                item: &item,
                field: &field,
            };
            let envelope = seal_with_ephemeral_ikm(
                &public,
                &kid,
                binding,
                &case.secret,
                &case.policy,
                &case.ephemeral_ikm,
            )
            .unwrap();
            json!({
                "name": case.name,
                "keyset": case.keyset,
                "kid": case.kid,
                "item": case.item,
                "field": case.field,
                "secret_hex": hex(&case.secret),
                "ephemeral_ikm_hex": hex(&case.ephemeral_ikm),
                "aad_hex": hex(&associated_data(1, &kid, binding).unwrap()),
                "plaintext": plaintext_of(&case.policy, &case.secret),
                "envelope": serde_json::from_str::<Value>(&envelope.to_json().unwrap()).unwrap(),
                "must_not_open": [
                    { "change": "item", "value": "other-item" },
                    { "change": "field", "value": "other_field" },
                    { "change": "keyset", "value": "other-keyset" },
                    { "change": "kid", "value": "other-kid" },
                    { "change": "private_key_hex", "value": hex(&OTHER_PRIVATE_KEY) },
                ],
            })
        })
        .collect();

    json!({
        "description": "Sealed values with fixed ephemeral keys. See docs/format.md. The keys are for these vectors only.",
        "suite": {
            "mode": "base",
            "kem": "DHKEM(X25519, HKDF-SHA256)",
            "kem_id": 32,
            "kdf": "HKDF-SHA256",
            "kdf_id": 1,
            "aead": "AES-256-GCM",
            "aead_id": 2,
            "info": "seal/v1",
        },
        "private_key_hex": hex(&PRIVATE_KEY),
        "public_key_hex": hex(public.as_bytes()),
        "cases": cases,
    })
}

fn policy_vectors() -> Value {
    let valid: Vec<Value> = valid_policies()
        .iter()
        .map(|(name, policy)| {
            json!({
                "name": name,
                "canonical": String::from_utf8(policy.canonical_json().unwrap()).unwrap(),
            })
        })
        .collect();
    let invalid: Vec<Value> = invalid_policies()
        .iter()
        .map(|(name, policy)| json!({ "name": name, "policy": policy }))
        .collect();
    json!({
        "description": "Policies a validator must accept, in canonical form, and refuse. See docs/policy.md.",
        "valid": valid,
        "invalid": invalid,
    })
}

/// Each file in `vectors/`, by name.
pub fn generate() -> Vec<(&'static str, String)> {
    vec![
        ("envelope.json", pretty(&envelope_vectors())),
        ("policy.json", pretty(&policy_vectors())),
    ]
}
