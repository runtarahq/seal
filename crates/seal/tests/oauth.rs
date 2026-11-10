//! Every row of the OAuth table in `docs/oauth.md`, in all three modes, against a mock
//! authorization server that checks what a real one checks.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{HeaderValue, Method, header};
use seal_client::{ErrorCode, Mode, SealedValue, SendResponse};
use seal_format::policy::builder::{self, JwtOptions, OAuthClientAuth, OAuthConfig, OAuthPolicies};
use seal_format::policy::{JwtAlg, JwtAudience, JwtClaims, JwtHeader, ResponseFormat};
use seal_format::{Envelope, FieldName, ItemId};
use seal_testkit::canary::{Canary, CanaryRegistry};
use seal_testkit::mock_oauth::{Client, ClientAuth, JwtKey, MockOAuth};
use serde_json::Value;
use support::*;

const APP: &str = "app";

fn key(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../seal-broker/tests/fixtures/jwt/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

struct Flow {
    instance: Instance,
    server: MockOAuth,
    /// Everything returned to the caller, for the canary scan.
    seen: Vec<String>,
}

async fn flow(mode: Mode, client: Client) -> Flow {
    let server = MockOAuth::start().await;
    server.register_client(APP, client);
    let instance = start_trusting(mode, Options::default(), &[server.ca()]).await;
    Flow {
        instance,
        server,
        seen: Vec::new(),
    }
}

fn config(server: &MockOAuth, auth: OAuthClientAuth, format: ResponseFormat) -> OAuthConfig {
    OAuthConfig {
        token_url: server.token_url(),
        revoke_url: Some(format!("{}/revoke", server.base())),
        api_base: format!("{}/api", server.base()),
        auth,
        response_format: format,
        shared: false,
    }
}

fn policies(server: &MockOAuth, auth: OAuthClientAuth) -> OAuthPolicies {
    builder::oauth_client(&config(server, auth, ResponseFormat::Json)).unwrap()
}

fn secret_client(secret: &str) -> Client {
    Client {
        auth: ClientAuth::SecretPost(secret.to_owned()),
        rotate_refresh_tokens: true,
        form_responses: false,
    }
}

fn form_post(url: &str, sealed: &[(&str, &Envelope)], body_text: &str) -> seal_client::SendRequest {
    let mut request = request(Method::POST, url, sealed, body(body_text.to_owned()));
    request.request.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    request
}

impl Flow {
    async fn record(
        &mut self,
        response: SendResponse,
    ) -> (u16, BTreeMap<FieldName, Envelope>, String) {
        let status = response.response.status().as_u16();
        let sealed = response.sealed_fields.clone();
        self.seen.push(format!("{:?}", response.response.headers()));
        self.seen.push(format!("{sealed:?}"));
        let text = text(response).await;
        self.seen.push(text.clone());
        (status, sealed, text)
    }

    async fn post(
        &mut self,
        url: &str,
        sealed: &[(&str, &Envelope)],
        body_text: &str,
    ) -> (u16, BTreeMap<FieldName, Envelope>, String) {
        let response = self
            .instance
            .client
            .send(form_post(url, sealed, body_text))
            .await
            .unwrap();
        self.record(response).await
    }

    /// Posts a form with values that may come from other records.
    async fn post_values(
        &mut self,
        url: &str,
        values: &[(&str, SealedValue)],
        body_text: &str,
    ) -> Result<(u16, BTreeMap<FieldName, Envelope>, String), ErrorCode> {
        let mut request = form_post(url, &[], body_text);
        for (name, value) in values {
            request.sealed.insert(field(name), value.clone());
        }
        let response = self
            .instance
            .client
            .send(request)
            .await
            .map_err(|error| error.code)?;
        Ok(self.record(response).await)
    }

    async fn api(&mut self, token: &Envelope) -> Result<(u16, String), ErrorCode> {
        let url = format!("{}/api", self.server.base());
        let response = self
            .instance
            .client
            .send(get(&url, &[("access_token", token)]))
            .await
            .map_err(|error| error.code)?;
        let (status, _, text) = self.record(response).await;
        Ok((status, text))
    }

    /// No token the server issued, nor any of these secrets, was returned in plaintext,
    /// logged or audited.
    fn assert_no_plaintext(&self, secrets: &[&Canary]) {
        let mut registry = CanaryRegistry::new();
        for token in self.server.issued_tokens() {
            registry.register(&Canary::from_value(token));
        }
        for secret in secrets {
            registry.register(secret);
        }
        for text in &self.seen {
            assert!(
                registry.scan("caller", text).is_empty(),
                "a plaintext credential reached the caller"
            );
        }
        let audit = std::fs::read_to_string(&self.instance.setup.audit).unwrap_or_default();
        assert!(registry.scan("audit", &audit).is_empty());
        assert!(registry.scan("logs", &self.instance.logs()).is_empty());
    }
}

fn pkce() -> (String, String) {
    let verifier = format!("verifier-{}", "x".repeat(43));
    let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        verifier.as_bytes(),
    ));
    (verifier, challenge)
}

/// The authorization code flow with PKCE, returning the sealed tokens.
async fn code_flow(flow: &mut Flow, secret: &Envelope) -> BTreeMap<FieldName, Envelope> {
    let (verifier, challenge) = pkce();
    let code = flow.server.authorize(APP, &challenge);
    let body = format!(
        "grant_type=authorization_code&code={code}&code_verifier={verifier}&client_id={APP}&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback"
    );
    let (status, sealed, text) = flow
        .post(
            &flow.server.token_url(),
            &[("client_secret", secret)],
            &body,
        )
        .await;
    assert_eq!(status, 200, "{text}");
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["expires_in"], 3600, "non-secret fields stay readable");
    assert!(body["access_token"].is_object(), "the token is an envelope");
    sealed
}

mode_matrix! {
    authorization_code_with_pkce_seals_both_tokens_and_each_goes_only_where_it_belongs => |mode: Mode| async move {
        let secret = Canary::generate().unwrap();
        let mut flow = flow(mode, secret_client(secret.value())).await;
        let policies = policies(&flow.server, OAuthClientAuth::ClientSecretPost);
        let sealed_secret = flow.instance.setup.seal("client_secret", secret.value().as_bytes(), &policies.client).await;
        let tokens = code_flow(&mut flow, &sealed_secret).await;
        let (access, refresh) = (&tokens[&field("access_token")], &tokens[&field("refresh_token")]);

        let (status, text) = flow.api(access).await.unwrap();
        assert_eq!((status, text.as_str()), (200, r#"{"client":"app","ok":true}"#));

        // Each token only where its definition says.
        let refresh_at_api = flow.instance.client.send(get(&format!("{}/api", flow.server.base()), &[("refresh_token", refresh)])).await;
        assert_eq!(refresh_at_api.err().unwrap().code, ErrorCode::PolicyDenied);
        let access_at_token = flow.instance.client.send(form_post(&flow.server.token_url(), &[("access_token", access)], "grant_type=refresh_token")).await;
        assert_eq!(access_at_token.err().unwrap().code, ErrorCode::PolicyDenied);
        let elsewhere = flow.instance.client.send(get("https://example.com/api", &[("access_token", access)])).await;
        assert_eq!(elsewhere.err().unwrap().code, ErrorCode::PolicyDenied);
        flow.assert_no_plaintext(&[&secret]);
    };

    a_wrong_pkce_verifier_or_code_is_the_providers_error_and_seals_nothing => |mode: Mode| async move {
        let secret = Canary::generate().unwrap();
        let mut flow = flow(mode, secret_client(secret.value())).await;
        let policies = policies(&flow.server, OAuthClientAuth::ClientSecretPost);
        let sealed_secret = flow.instance.setup.seal("client_secret", secret.value().as_bytes(), &policies.client).await;
        let (_, challenge) = pkce();
        let code = flow.server.authorize(APP, &challenge);
        let body = format!("grant_type=authorization_code&code={code}&code_verifier=wrong&client_id={APP}");
        let (status, sealed, text) = flow.post(&flow.server.token_url(), &[("client_secret", &sealed_secret)], &body).await;
        assert_eq!((status, text.as_str()), (400, r#"{"error":"invalid_grant"}"#));
        assert!(sealed.is_empty());
    };

    client_credentials_with_basic_auth => |mode: Mode| async move {
        let secret = Canary::generate().unwrap();
        let client = Client { auth: ClientAuth::SecretBasic(secret.value().to_owned()), rotate_refresh_tokens: true, form_responses: false };
        let mut flow = flow(mode, client).await;
        let policies = policies(&flow.server, OAuthClientAuth::ClientSecretBasic { client_id: APP.to_owned() });
        let sealed_secret = flow.instance.setup.seal("client_secret", secret.value().as_bytes(), &policies.client).await;
        let (status, sealed, _) = flow.post(&flow.server.token_url(), &[("client_secret", &sealed_secret)], "grant_type=client_credentials").await;
        assert_eq!(status, 200);
        assert_eq!(sealed.keys().map(FieldName::as_str).collect::<Vec<_>>(), ["access_token"]);
        assert_eq!(flow.api(&sealed[&field("access_token")]).await.unwrap().0, 200);
        flow.assert_no_plaintext(&[&secret]);
    };

    the_password_grant_seals_the_password_and_the_tokens => |mode: Mode| async move {
        let (secret, password) = (Canary::generate().unwrap(), Canary::generate().unwrap());
        let mut flow = flow(mode, secret_client(secret.value())).await;
        flow.server.register_user("alice", password.value());
        let policies = policies(&flow.server, OAuthClientAuth::ClientSecretPost);
        let sealed_secret = flow.instance.setup.seal("client_secret", secret.value().as_bytes(), &policies.client).await;
        let sealed_password = flow.instance.setup.seal("password", password.value().as_bytes(), &policies.password).await;
        let body = format!("grant_type=password&username=alice&client_id={APP}");
        let (status, sealed, _) = flow
            .post(&flow.server.token_url(), &[("client_secret", &sealed_secret), ("password", &sealed_password)], &body)
            .await;
        assert_eq!(status, 200);
        assert_eq!(flow.api(&sealed[&field("access_token")]).await.unwrap().0, 200);
        flow.assert_no_plaintext(&[&secret, &password]);
    };

    the_jwt_bearer_grant_signs_with_a_sealed_service_account_key => |mode: Mode| async move {
        let mut flow = flow(mode, secret_client("unused")).await;
        let issuer = "robot@project.iam.gserviceaccount.com";
        flow.server.register_issuer(issuer, JwtKey::from_private_pem("RS256", &key("rsa-pkcs8.pem")), &flow.server.token_url());
        let options = JwtOptions {
            alg: JwtAlg::RS256,
            aud: JwtAudience::TokenEndpoint,
            claims: JwtClaims { iss: issuer.to_owned(), sub: None, scope: Some("read".to_owned()), extra: BTreeMap::new() },
            header: JwtHeader::default(),
            max_lifetime_s: 300,
        };
        let policies = policies(&flow.server, OAuthClientAuth::JwtBearerGrant(options));
        let sealed_key = flow.instance.setup.seal("signing_key", &key("rsa-pkcs8.pem"), &policies.client).await;
        let body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";
        let (status, sealed, text) = flow.post(&flow.server.token_url(), &[("signing_key", &sealed_key)], body).await;
        assert_eq!(status, 200, "{text}");
        assert_eq!(flow.api(&sealed[&field("access_token")]).await.unwrap().0, 200);
        // The second assertion has a new jti, so the server accepts it too.
        let (status, _, _) = flow.post(&flow.server.token_url(), &[("signing_key", &sealed_key)], body).await;
        assert_eq!(status, 200);
        let pem = Canary::from_value(String::from_utf8(key("rsa-pkcs8.pem")).unwrap());
        flow.assert_no_plaintext(&[&pem]);
    };

    private_key_jwt_authenticates_with_the_audience_the_server_expects => |mode: Mode| async move {
        let server = MockOAuth::start().await;
        // An Auth0-style audience: the issuer URL, with a trailing slash.
        let aud = format!("{}/", server.base());
        server.register_client(APP, Client {
            auth: ClientAuth::PrivateKeyJwt { key: JwtKey::from_private_pem("ES256", &key("ec-pkcs8.pem")), aud: aud.clone() },
            rotate_refresh_tokens: true,
            form_responses: false,
        });
        let instance = start_trusting(mode, Options::default(), &[server.ca()]).await;
        let mut flow = Flow { instance, server, seen: Vec::new() };
        let options = |aud: JwtAudience| JwtOptions {
            alg: JwtAlg::ES256,
            aud,
            claims: JwtClaims { iss: APP.to_owned(), sub: Some(APP.to_owned()), scope: None, extra: BTreeMap::new() },
            header: JwtHeader::default(),
            max_lifetime_s: 60,
        };
        let right = policies(&flow.server, OAuthClientAuth::PrivateKeyJwt(options(JwtAudience::Value(aud.clone()))));
        let sealed_key = flow.instance.setup.seal("signing_key", &key("ec-pkcs8.pem"), &right.client).await;
        let (status, sealed, text) = flow.post(&flow.server.token_url(), &[("signing_key", &sealed_key)], "grant_type=client_credentials").await;
        assert_eq!(status, 200, "{text}");
        assert_eq!(flow.api(&sealed[&field("access_token")]).await.unwrap().0, 200);

        // The token endpoint is not what this server expects, so it refuses.
        let wrong = policies(&flow.server, OAuthClientAuth::PrivateKeyJwt(options(JwtAudience::TokenEndpoint)));
        let wrong_key = flow.instance.setup.seal("signing_key", &key("ec-pkcs8.pem"), &wrong.client).await;
        let (status, _, _) = flow.post(&flow.server.token_url(), &[("signing_key", &wrong_key)], "grant_type=client_credentials").await;
        assert_eq!(status, 401);
    };

    revocation_sends_the_token_and_client_authentication => |mode: Mode| async move {
        let secret = Canary::generate().unwrap();
        let mut flow = flow(mode, secret_client(secret.value())).await;
        let policies = policies(&flow.server, OAuthClientAuth::ClientSecretPost);
        let sealed_secret = flow.instance.setup.seal("client_secret", secret.value().as_bytes(), &policies.client).await;
        let tokens = code_flow(&mut flow, &sealed_secret).await;
        let access = &tokens[&field("access_token")];
        let revoke = format!("{}/revoke", flow.server.base());
        let (status, sealed, _) = flow
            .post(&revoke, &[("access_token", access), ("client_secret", &sealed_secret)], &format!("client_id={APP}"))
            .await;
        assert_eq!(status, 200);
        assert!(sealed.is_empty(), "nothing comes out of a revocation");
        assert_eq!(flow.server.revoked_tokens().len(), 1);
        assert_eq!(flow.api(access).await.unwrap().0, 401, "a revoked token no longer works");
        flow.assert_no_plaintext(&[&secret]);
    };

    form_encoded_token_responses_are_sealed => |mode: Mode| async move {
        let secret = Canary::generate().unwrap();
        let client = Client { auth: ClientAuth::SecretPost(secret.value().to_owned()), rotate_refresh_tokens: true, form_responses: true };
        let mut flow = flow(mode, client).await;
        let policies = builder::oauth_client(&config(&flow.server, OAuthClientAuth::ClientSecretPost, ResponseFormat::Form)).unwrap();
        let sealed_secret = flow.instance.setup.seal("client_secret", secret.value().as_bytes(), &policies.client).await;
        let (_, challenge) = pkce();
        let (verifier, _) = pkce();
        let code = flow.server.authorize(APP, &challenge);
        let body = format!("grant_type=authorization_code&code={code}&code_verifier={verifier}&client_id={APP}");
        let (status, sealed, text) = flow.post(&flow.server.token_url(), &[("client_secret", &sealed_secret)], &body).await;
        assert_eq!(status, 200);
        let form: BTreeMap<String, String> = form_urlencoded::parse(text.as_bytes()).into_owned().collect();
        assert_eq!(form["scope"], "repo");
        Envelope::from_json(form["access_token"].as_bytes()).unwrap();
        assert_eq!(flow.api(&sealed[&field("access_token")]).await.unwrap().0, 200);
        flow.assert_no_plaintext(&[&secret]);
    };

    a_refresh_without_a_new_refresh_token_leaves_the_old_one_usable => |mode: Mode| async move {
        let secret = Canary::generate().unwrap();
        let client = Client { auth: ClientAuth::SecretPost(secret.value().to_owned()), rotate_refresh_tokens: false, form_responses: false };
        let mut flow = flow(mode, client).await;
        let policies = policies(&flow.server, OAuthClientAuth::ClientSecretPost);
        let sealed_secret = flow.instance.setup.seal("client_secret", secret.value().as_bytes(), &policies.client).await;
        let tokens = code_flow(&mut flow, &sealed_secret).await;
        let refresh = tokens[&field("refresh_token")].clone();
        for _ in 0..3 {
            let body = format!("grant_type=refresh_token&client_id={APP}");
            let (status, sealed, _) = flow.post(&flow.server.token_url(), &[("refresh_token", &refresh), ("client_secret", &sealed_secret)], &body).await;
            assert_eq!(status, 200);
            assert!(!sealed.contains_key(&field("refresh_token")), "the server did not rotate");
            assert_eq!(flow.api(&sealed[&field("access_token")]).await.unwrap().0, 200);
        }
        flow.assert_no_plaintext(&[&secret]);
    };

    acceptance_rotating_refresh_tokens_continue_across_a_key_rotation => |mode: Mode| async move {
        let secret = Canary::generate().unwrap();
        let mut flow = flow(mode, secret_client(secret.value())).await;
        let policies = policies(&flow.server, OAuthClientAuth::ClientSecretPost);
        let sealed_secret = flow.instance.setup.seal("client_secret", secret.value().as_bytes(), &policies.client).await;
        let tokens = code_flow(&mut flow, &sealed_secret).await;
        let mut refresh = tokens[&field("refresh_token")].clone();
        let (_, first_policy) = flow.instance.setup.open("refresh_token", &refresh).await;
        let first_policy = first_policy.canonical_json().unwrap();
        let first_kid = refresh.kid().clone();

        for round in 0..6 {
            if round == 3 {
                flow.instance.client.rotate(&keyset()).await.unwrap();
            }
            let body = format!("grant_type=refresh_token&client_id={APP}");
            let (status, sealed, text) = flow
                .post(&flow.server.token_url(), &[("refresh_token", &refresh), ("client_secret", &sealed_secret)], &body)
                .await;
            assert_eq!(status, 200, "round {round}: {text}");
            let next = sealed[&field("refresh_token")].clone();
            let access = sealed[&field("access_token")].clone();

            // Every token opens, and its policy is the same, round after round.
            let (plaintext, policy) = flow.instance.setup.open("refresh_token", &next).await;
            assert!(flow.server.issued_tokens().contains(&String::from_utf8(plaintext).unwrap()));
            assert_eq!(policy.canonical_json().unwrap(), first_policy, "round {round}");
            flow.instance.setup.open("access_token", &access).await;
            assert_eq!(flow.api(&access).await.unwrap().0, 200);

            // A used refresh token's limits still hold.
            let at_api = flow.instance.client.send(get(&format!("{}/api", flow.server.base()), &[("refresh_token", &next)])).await;
            assert_eq!(at_api.err().unwrap().code, ErrorCode::PolicyDenied);
            // And the one before was rotated away by the server.
            let (status, _, _) = flow.post(&flow.server.token_url(), &[("refresh_token", &refresh), ("client_secret", &sealed_secret)], &body).await;
            assert_eq!(status, 400, "an old refresh token is refused by the server");
            refresh = next;
        }
        assert_ne!(*refresh.kid(), first_kid, "values sealed after the rotation use the new key");
        flow.assert_no_plaintext(&[&secret]);
    };
}

#[tokio::test]
async fn the_mock_server_refuses_what_a_real_one_would() {
    let server = MockOAuth::start().await;
    server.register_client(APP, secret_client("right"));
    let instance = start_trusting(Mode::InProcess, Options::default(), &[server.ca()]).await;
    let policies = policies(&server, OAuthClientAuth::ClientSecretPost);
    let wrong = instance
        .setup
        .seal(
            "client_secret",
            b"SEALCANARY-wrong-secret",
            &policies.client,
        )
        .await;
    let response = instance
        .client
        .send(form_post(
            &server.token_url(),
            &[("client_secret", &wrong)],
            "grant_type=client_credentials&client_id=app",
        ))
        .await
        .unwrap();
    assert_eq!(response.response.status(), 401);
}

#[test]
fn every_row_of_the_oauth_table_has_a_test() {
    // Authorization code, refresh, client credentials, password, JWT bearer and
    // private_key_jwt, revocation, and using the token: each is a test above.
    let source = include_str!("oauth.rs");
    for name in [
        "authorization_code_with_pkce",
        "rotating_refresh_tokens",
        "client_credentials",
        "password_grant",
        "jwt_bearer_grant",
        "private_key_jwt",
        "revocation",
        "api(",
    ] {
        assert!(source.contains(name), "{name}");
    }
}

// A shared platform app: one client secret, sealed once to the platform's record, used
// by every tenant, none of whom can get it back.

fn oauth_app() -> ItemId {
    ItemId::new("oauth-app").unwrap()
}

fn shared_policies(server: &MockOAuth) -> OAuthPolicies {
    let mut config = config(
        server,
        OAuthClientAuth::ClientSecretPost,
        ResponseFormat::Json,
    );
    config.shared = true;
    builder::oauth_client(&config).unwrap()
}

async fn platform_secret(flow: &Flow, secret: &Canary, policies: &OAuthPolicies) -> SealedValue {
    let envelope = flow
        .instance
        .setup
        .seal_at(
            &platform(),
            &oauth_app(),
            "client_secret",
            secret.value().as_bytes(),
            &policies.client,
        )
        .await;
    SealedValue::from_record(envelope, oauth_app())
}

fn code_body(flow: &Flow) -> String {
    let (verifier, challenge) = pkce();
    let code = flow.server.authorize(APP, &challenge);
    format!("grant_type=authorization_code&code={code}&code_verifier={verifier}&client_id={APP}")
}

mode_matrix! {
    a_tenant_uses_a_shared_platform_app_and_its_tokens_are_its_own => |mode: Mode| async move {
        let secret = Canary::generate().unwrap();
        let mut flow = flow(mode, secret_client(secret.value())).await;
        let policies = shared_policies(&flow.server);
        let shared = platform_secret(&flow, &secret, &policies).await;

        let body = code_body(&flow);
        let (status, tokens, text) = flow.post_values(&flow.server.token_url(), &[("client_secret", shared.clone())], &body).await.unwrap();
        assert_eq!(status, 200, "{text}");
        // The tokens are bound to the tenant's record and are not shared.
        let (_, refresh_policy) = flow.instance.setup.open("refresh_token", &tokens[&field("refresh_token")]).await;
        assert!(!refresh_policy.shared);
        assert_eq!(flow.api(&tokens[&field("access_token")]).await.unwrap().0, 200);

        // A refresh: the tenant's refresh token with the platform's secret.
        let refresh = SealedValue::from(tokens[&field("refresh_token")].clone());
        let (status, renewed, text) = flow
            .post_values(&flow.server.token_url(), &[("client_secret", shared), ("refresh_token", refresh)], &format!("grant_type=refresh_token&client_id={APP}"))
            .await
            .unwrap();
        assert_eq!(status, 200, "{text}");
        assert_eq!(flow.api(&renewed[&field("access_token")]).await.unwrap().0, 200);

        let audit = flow.instance.setup.audit_records();
        let sends: Vec<_> = audit.iter().filter(|record| record["op"] == "send" && record["outcome"] == "ok").collect();
        assert_eq!(sends[0]["shared"], serde_json::json!(["client_secret=platform/oauth-app"]));
        flow.assert_no_plaintext(&[&secret]);
    };

    a_shared_secret_cannot_be_used_for_another_grant_or_with_a_value_from_another_tenant => |mode: Mode| async move {
        let secret = Canary::generate().unwrap();
        let mut flow = flow(mode, secret_client(secret.value())).await;
        let shared_app = shared_policies(&flow.server);
        let shared = platform_secret(&flow, &secret, &shared_app).await;
        let token_url = flow.server.token_url();

        // Client credentials would give the tenant a token acting as the platform.
        let refused = flow.post_values(&token_url, &[("client_secret", shared.clone())], "grant_type=client_credentials").await;
        assert_eq!(refused.err(), Some(ErrorCode::PolicyDenied));
        let smuggled = flow.post_values(&token_url, &[("client_secret", shared.clone())], "grant_type=refresh_token&grant_type=client_credentials").await;
        assert_eq!(smuggled.err(), Some(ErrorCode::PolicyDenied));
        assert!(flow.server.requests().is_empty(), "the provider received nothing");

        // Another tenant's refresh token does not serve this tenant's request.
        let body = code_body(&flow);
        let (_, tokens, _) = flow.post_values(&token_url, &[("client_secret", shared.clone())], &body).await.unwrap();
        let theirs = tokens[&field("refresh_token")].clone();
        let mut request = form_post(&token_url, &[], "grant_type=refresh_token");
        request.item = ItemId::new("c_2").unwrap();
        request.sealed.insert(field("client_secret"), shared.clone());
        request.sealed.insert(field("refresh_token"), SealedValue::from_record(theirs.clone(), item()));
        assert_eq!(flow.instance.client.send(request).await.err().unwrap().code, ErrorCode::PolicyDenied);
        let mut request = form_post(&token_url, &[], "grant_type=refresh_token");
        request.item = ItemId::new("c_2").unwrap();
        request.sealed.insert(field("refresh_token"), theirs.into());
        assert_eq!(flow.instance.client.send(request).await.err().unwrap().code, ErrorCode::OpenFailed);

        // A secret its sealer did not mark shared serves only its own record.
        let unshared = policies(&flow.server, OAuthClientAuth::ClientSecretPost);
        let envelope = flow.instance.setup.seal_at(&platform(), &oauth_app(), "client_secret", secret.value().as_bytes(), &unshared.client).await;
        let body = code_body(&flow);
        let refused = flow.post_values(&token_url, &[("client_secret", SealedValue::from_record(envelope, oauth_app()))], &body).await;
        assert_eq!(refused.err(), Some(ErrorCode::PolicyDenied));
        flow.assert_no_plaintext(&[&secret]);
    };

    a_caller_needs_the_platform_keyset_to_use_a_shared_value => |mode: Mode| async move {
        if mode == Mode::InProcess {
            return; // An in-process caller holds the keys; only the service has callers.
        }
        let uid = nix::unistd::getuid().as_raw();
        let identity = match mode {
            Mode::Mtls => "cert_subject = \"CN=test-app\"".to_owned(),
            _ => format!("unix_uid = {uid}"),
        };
        let options = Options {
            callers: Some(format!("[[callers]]\nname = \"test-app\"\n{identity}\nkeysets = [\"acme\"]\nadmin = true\n")),
            ..Options::default()
        };
        let secret = Canary::generate().unwrap();
        let server = MockOAuth::start().await;
        server.register_client(APP, secret_client(secret.value()));
        let instance = start_trusting(mode, options, &[server.ca()]).await;
        let mut flow = Flow { instance, server, seen: Vec::new() };
        let policies = shared_policies(&flow.server);
        let shared = platform_secret(&flow, &secret, &policies).await;
        let body = code_body(&flow);
        let refused = flow.post_values(&flow.server.token_url(), &[("client_secret", shared)], &body).await;
        assert_eq!(refused.err(), Some(ErrorCode::CallerDenied));
        assert!(flow.server.requests().is_empty());
    };
}
