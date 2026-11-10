//! OAuth against real providers, with credentials from CI secrets. Ignored by default;
//! each test skips if its credentials are not set, and CI runs them only on the main
//! repository, never for a fork.
//!
//! - `SEAL_TEST_GOOGLE_SA_JSON`: a Google service account's JSON key.
//! - `SEAL_TEST_GITHUB_CLIENT_ID`, `SEAL_TEST_GITHUB_CLIENT_SECRET`,
//!   `SEAL_TEST_GITHUB_REFRESH_TOKEN`: a GitHub OAuth app with expiring tokens, and a
//!   refresh token for it. GitHub rotates refresh tokens, so a run uses this one up and
//!   prints nothing of the new one: the secret has to be renewed by hand afterwards.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

mod support;

use std::collections::BTreeMap;

use http::{HeaderValue, Method, header};
use seal_client::Mode;
use seal_format::policy::builder::{self, JwtOptions, OAuthClientAuth, OAuthConfig};
use seal_format::policy::{JwtAlg, JwtAudience, JwtClaims, JwtHeader, ResponseFormat};
use seal_testkit::canary::{Canary, CanaryRegistry};
use support::*;

fn credential(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn form_post(
    url: &str,
    sealed: &[(&str, &seal_format::Envelope)],
    text: &str,
) -> seal_client::SendRequest {
    let mut request = request(Method::POST, url, sealed, body(text.to_owned()));
    let headers = request.request.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    request
}

#[tokio::test]
#[ignore = "needs a Google service account; runs nightly with secrets"]
async fn google_service_account_jwt_bearer_grant() {
    let Some(json) = credential("SEAL_TEST_GOOGLE_SA_JSON") else {
        println!("skipped: SEAL_TEST_GOOGLE_SA_JSON is not set");
        return;
    };
    let account: serde_json::Value = serde_json::from_str(&json).unwrap();
    let token_url = account["token_uri"]
        .as_str()
        .unwrap_or("https://oauth2.googleapis.com/token");
    let options = JwtOptions {
        alg: JwtAlg::RS256,
        aud: JwtAudience::TokenEndpoint,
        claims: JwtClaims {
            iss: account["client_email"].as_str().unwrap().to_owned(),
            sub: None,
            scope: Some("https://www.googleapis.com/auth/cloud-platform.read-only".to_owned()),
            extra: BTreeMap::new(),
        },
        header: JwtHeader {
            kid: account["private_key_id"].as_str().map(str::to_owned),
            ..JwtHeader::default()
        },
        max_lifetime_s: 300,
    };
    let policies = builder::oauth_client(&OAuthConfig {
        token_url: token_url.to_owned(),
        revoke_url: None,
        api_base: "https://www.googleapis.com/".to_owned(),
        auth: OAuthClientAuth::JwtBearerGrant(options),
        response_format: ResponseFormat::Json,
        shared: false,
        access_token_claims: Vec::new(),
    })
    .unwrap();

    let instance = start(Mode::InProcess, Options::default(), &[]).await;
    let private_key = account["private_key"].as_str().unwrap();
    let sealed = instance
        .setup
        .seal("signing_key", private_key.as_bytes(), &policies.client)
        .await;
    let response = instance
        .client
        .send(form_post(
            token_url,
            &[("signing_key", &sealed)],
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
        ))
        .await
        .unwrap();
    assert_eq!(response.response.status(), 200);
    let access = response
        .sealed_fields
        .get(&field("access_token"))
        .cloned()
        .expect("a sealed access token");
    let body = text(response).await;
    let (plaintext, _) = instance.setup.open("access_token", &access).await;
    let mut registry = CanaryRegistry::new();
    registry.register(&Canary::from_value(String::from_utf8(plaintext).unwrap()));
    registry.register(&Canary::from_value(private_key));
    assert!(
        registry.scan("caller", &body).is_empty(),
        "the token reached the caller only sealed"
    );
}

#[tokio::test]
#[ignore = "needs a GitHub OAuth app; runs only on request, since it uses up its refresh token"]
async fn github_oauth_app_refresh() {
    let (Some(client_id), Some(secret), Some(refresh)) = (
        credential("SEAL_TEST_GITHUB_CLIENT_ID"),
        credential("SEAL_TEST_GITHUB_CLIENT_SECRET"),
        credential("SEAL_TEST_GITHUB_REFRESH_TOKEN"),
    ) else {
        println!("skipped: the SEAL_TEST_GITHUB_* credentials are not set");
        return;
    };
    let token_url = "https://github.com/login/oauth/access_token";
    let policies = builder::oauth_client(&OAuthConfig {
        token_url: token_url.to_owned(),
        revoke_url: None,
        api_base: "https://api.github.com/".to_owned(),
        auth: OAuthClientAuth::ClientSecretPost,
        response_format: ResponseFormat::Json,
        shared: false,
        access_token_claims: Vec::new(),
    })
    .unwrap();
    let refresh_policy = policies
        .client
        .for_response_field(&seal_format::PolicyName::new("refresh").unwrap())
        .unwrap();

    let instance = start(Mode::InProcess, Options::default(), &[]).await;
    let sealed_secret = instance
        .setup
        .seal("client_secret", secret.as_bytes(), &policies.client)
        .await;
    let sealed_refresh = instance
        .setup
        .seal("refresh_token", refresh.as_bytes(), &refresh_policy)
        .await;
    let response = instance
        .client
        .send(form_post(
            token_url,
            &[
                ("client_secret", &sealed_secret),
                ("refresh_token", &sealed_refresh),
            ],
            &format!("grant_type=refresh_token&client_id={client_id}"),
        ))
        .await
        .unwrap();
    assert_eq!(response.response.status(), 200);
    let access = response
        .sealed_fields
        .get(&field("access_token"))
        .cloned()
        .expect("a sealed access token");
    text(response).await;

    let mut api = get("https://api.github.com/user", &[("access_token", &access)]);
    api.request
        .headers_mut()
        .insert(header::USER_AGENT, HeaderValue::from_static("seal-tests"));
    let response = instance.client.send(api).await.unwrap();
    assert_eq!(response.response.status(), 200);
}
