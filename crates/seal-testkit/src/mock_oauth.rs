//! An OAuth 2.0 authorization server to test against, over TLS.
//!
//! It checks what a real server checks: PKCE, each client authentication method,
//! signed assertions (signature, issuer, audience byte for byte, lifetime, single use),
//! that a refresh token is current, and revocation. Every token it issues is a canary,
//! so tests can scan everything seal emits for them.
//!
//! | Path | |
//! |---|---|
//! | `POST /token` | Every grant in `docs/oauth.md` |
//! | `POST /revoke` | RFC 7009 revocation |
//! | `GET /api` | Accepts a current access token as `Bearer` |

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, KeyPair, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA256,
    UnparsedPublicKey, VerificationAlgorithm,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::canary::Canary;
use crate::pki::TestPki;

/// A public key that verifies JWTs.
#[derive(Clone, Debug)]
pub struct JwtKey {
    alg: String,
    public: Vec<u8>,
}

impl JwtKey {
    /// The public half of a PEM private key: PKCS#8 or PKCS#1 RSA, or PKCS#8 P-256.
    ///
    /// # Panics
    ///
    /// Panics if the key is not one of those, which is a mistake in the test.
    #[must_use]
    #[allow(clippy::panic, reason = "a wrong test key is a mistake in the test")]
    pub fn from_private_pem(alg: &str, pem: &[u8]) -> Self {
        let der =
            PrivateKeyDer::from_pem_slice(pem).unwrap_or_else(|_| panic!("a PEM private key"));
        let public = match (alg, der) {
            ("ES256", PrivateKeyDer::Pkcs8(der)) => ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                der.secret_pkcs8_der(),
                &ring::rand::SystemRandom::new(),
            )
            .map(|key| key.public_key().as_ref().to_vec()),
            (_, PrivateKeyDer::Pkcs8(der)) => {
                ring::signature::RsaKeyPair::from_pkcs8(der.secret_pkcs8_der())
                    .map(|key| key.public_key().as_ref().to_vec())
            }
            (_, PrivateKeyDer::Pkcs1(der)) => {
                ring::signature::RsaKeyPair::from_der(der.secret_pkcs1_der())
                    .map(|key| key.public_key().as_ref().to_vec())
            }
            _ => panic!("an unsupported test key"),
        }
        .unwrap_or_else(|_| panic!("a valid test key"));
        Self {
            alg: alg.to_owned(),
            public,
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let algorithm: &dyn VerificationAlgorithm = match self.alg.as_str() {
            "RS256" => &RSA_PKCS1_2048_8192_SHA256,
            "PS256" => &RSA_PSS_2048_8192_SHA256,
            "ES256" => &ECDSA_P256_SHA256_FIXED,
            _ => return false,
        };
        UnparsedPublicKey::new(algorithm, &self.public)
            .verify(message, signature)
            .is_ok()
    }
}

/// How a client authenticates to the token endpoint.
#[derive(Clone, Debug)]
pub enum ClientAuth {
    /// The secret in the form body.
    SecretPost(String),
    /// The secret as basic auth's password.
    SecretBasic(String),
    /// A signed client assertion, whose audience must be exactly `aud`.
    PrivateKeyJwt {
        /// The client's public key.
        key: JwtKey,
        /// The audience the server expects.
        aud: String,
    },
}

/// A registered client.
#[derive(Clone, Debug)]
pub struct Client {
    /// How it authenticates.
    pub auth: ClientAuth,
    /// Whether a refresh issues a new refresh token.
    pub rotate_refresh_tokens: bool,
    /// Whether token responses are form-encoded, as GitHub's legacy ones are.
    pub form_responses: bool,
}

#[derive(Clone, Debug)]
enum Token {
    Access { client: String },
    Refresh { client: String },
}

#[derive(Default)]
struct State {
    clients: HashMap<String, Client>,
    users: HashMap<String, String>,
    /// Issuers of the JWT bearer grant: their key and the audience expected.
    issuers: HashMap<String, (JwtKey, String)>,
    /// Authorization codes: client and PKCE challenge.
    codes: HashMap<String, (String, String)>,
    tokens: HashMap<String, Token>,
    used_jtis: HashSet<String>,
    issued: Vec<String>,
    revoked: Vec<String>,
    requests: Vec<(String, String)>,
}

/// A running authorization server. Stops when dropped.
pub struct MockOAuth {
    address: SocketAddr,
    ca: CertificateDer<'static>,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Drop for MockOAuth {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockOAuth {
    /// Starts a server on a loopback port, with a certificate for `localhost`.
    ///
    /// # Panics
    ///
    /// Panics if it cannot listen.
    pub async fn start() -> Self {
        let pki = TestPki::new("mock OAuth CA");
        let server = pki.server(&["localhost"]);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|_| unreachable!("protocol versions"))
            .with_no_client_auth()
            .with_single_cert(vec![server.cert_der.clone()], server.key_der())
            .unwrap_or_else(|_| unreachable!("a test certificate"));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|_| unreachable!("binding a loopback port"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|_| unreachable!("an address"));
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, state) = (acceptor.clone(), Arc::clone(&shared));
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request| {
                        let state = Arc::clone(&state);
                        async move { Ok::<_, Infallible>(handle(request, &state).await) }
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            address,
            ca: pki.ca_der.clone(),
            state,
            task,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The CA to trust.
    #[must_use]
    pub fn ca(&self) -> CertificateDer<'static> {
        self.ca.clone()
    }

    /// `https://localhost:<port>`.
    #[must_use]
    pub fn base(&self) -> String {
        format!("https://localhost:{}", self.address.port())
    }

    /// The token endpoint's URL.
    #[must_use]
    pub fn token_url(&self) -> String {
        format!("{}/token", self.base())
    }

    /// Registers a client.
    pub fn register_client(&self, id: &str, client: Client) {
        self.lock().clients.insert(id.to_owned(), client);
    }

    /// Registers a resource owner, for the password grant.
    pub fn register_user(&self, username: &str, password: &str) {
        self.lock()
            .users
            .insert(username.to_owned(), password.to_owned());
    }

    /// Registers an issuer of the JWT bearer grant.
    pub fn register_issuer(&self, iss: &str, key: JwtKey, aud: &str) {
        self.lock()
            .issuers
            .insert(iss.to_owned(), (key, aud.to_owned()));
    }

    /// What the user's consent produces: an authorization code bound to a PKCE
    /// challenge (`S256`). The application gets this from its own callback.
    #[must_use]
    pub fn authorize(&self, client: &str, code_challenge: &str) -> String {
        let code = format!("code-{}", random_hex());
        self.lock()
            .codes
            .insert(code.clone(), (client.to_owned(), code_challenge.to_owned()));
        code
    }

    /// Every token issued, which tests register as canaries.
    #[must_use]
    pub fn issued_tokens(&self) -> Vec<String> {
        self.lock().issued.clone()
    }

    /// Every token revoked.
    #[must_use]
    pub fn revoked_tokens(&self) -> Vec<String> {
        self.lock().revoked.clone()
    }

    /// Every request: method and path.
    #[must_use]
    pub fn requests(&self) -> Vec<(String, String)> {
        self.lock().requests.clone()
    }
}

fn random_hex() -> String {
    let mut bytes = [0_u8; 8];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
        .unwrap_or_else(|_| unreachable!("random bytes"));
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A new token: a canary, so that a leak anywhere is found.
fn new_token() -> String {
    Canary::generate()
        .unwrap_or_else(|_| unreachable!("random bytes"))
        .value()
        .to_owned()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn reply(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    if let Ok(value) = content_type.parse() {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response
}

fn error(status: StatusCode, code: &str) -> Response<Full<Bytes>> {
    reply(
        status,
        "application/json",
        json!({ "error": code }).to_string().into_bytes(),
    )
}

async fn handle(request: Request<Incoming>, state: &Mutex<State>) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_owned();
    state
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .requests
        .push((parts.method.to_string(), path.clone()));
    let Ok(body) = body.collect().await else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let form: HashMap<String, String> = form_urlencoded::parse(&body.to_bytes())
        .into_owned()
        .collect();
    let authorization = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
    match (parts.method.as_str(), path.as_str()) {
        ("POST", "/token") => token(&mut state, &form, authorization.as_deref()),
        ("POST", "/revoke") => revoke(&mut state, &form, authorization.as_deref()),
        ("GET", "/api") => api(&state, authorization.as_deref()),
        _ => error(StatusCode::NOT_FOUND, "not_found"),
    }
}

/// Checks a client's authentication, returning its id.
fn authenticate(
    state: &mut State,
    form: &HashMap<String, String>,
    authorization: Option<&str>,
) -> Option<String> {
    if let Some(basic) = authorization.and_then(|value| value.strip_prefix("Basic ")) {
        let decoded = String::from_utf8(STANDARD.decode(basic).ok()?).ok()?;
        let (id, secret) = decoded.split_once(':')?;
        return match &state.clients.get(id)?.auth {
            ClientAuth::SecretBasic(expected) if expected == secret => Some(id.to_owned()),
            _ => None,
        };
    }
    if let Some(assertion) = form.get("client_assertion") {
        if form.get("client_assertion_type").map(String::as_str)
            != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        {
            return None;
        }
        let claims = verify_jwt(assertion, |claims| {
            let id = claims["iss"].as_str()?;
            match &state.clients.get(id)?.auth {
                ClientAuth::PrivateKeyJwt { key, aud } => Some((key.clone(), aud.clone())),
                _ => None,
            }
        })?;
        let id = claims["iss"].as_str()?.to_owned();
        if claims["sub"].as_str() != Some(id.as_str()) {
            return None;
        }
        let jti = claims["jti"].as_str()?.to_owned();
        return state.used_jtis.insert(jti).then_some(id);
    }
    let id = form.get("client_id")?;
    match &state.clients.get(id)?.auth {
        ClientAuth::SecretPost(expected) if Some(expected) == form.get("client_secret") => {
            Some(id.clone())
        }
        _ => None,
    }
}

/// Verifies a JWT's signature, audience and lifetime. `key_for` finds the key and the
/// expected audience from the claims.
fn verify_jwt(
    jwt: &str,
    key_for: impl FnOnce(&Value) -> Option<(JwtKey, String)>,
) -> Option<Value> {
    let mut pieces = jwt.split('.');
    let (header, claims, signature) = (pieces.next()?, pieces.next()?, pieces.next()?);
    if pieces.next().is_some() {
        return None;
    }
    let decode = |piece: &str| -> Option<Value> {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(piece).ok()?).ok()
    };
    let (header_json, claims_json) = (decode(header)?, decode(claims)?);
    let (key, expected_aud) = key_for(&claims_json)?;
    if header_json["alg"].as_str() != Some(key.alg.as_str()) {
        return None;
    }
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    if !key.verify(format!("{header}.{claims}").as_bytes(), &signature) {
        return None;
    }
    // A single string, compared byte for byte, as RFC 7523 says.
    if claims_json["aud"].as_str() != Some(expected_aud.as_str()) {
        return None;
    }
    let (iat, exp) = (claims_json["iat"].as_u64()?, claims_json["exp"].as_u64()?);
    let now = now();
    if exp <= now || iat > now + 60 || exp.saturating_sub(iat) > 300 {
        return None;
    }
    Some(claims_json)
}

fn issue(
    state: &mut State,
    client: &str,
    with_refresh: bool,
    form_response: bool,
) -> Response<Full<Bytes>> {
    let access = new_token();
    state.tokens.insert(
        access.clone(),
        Token::Access {
            client: client.to_owned(),
        },
    );
    state.issued.push(access.clone());
    let refresh = with_refresh.then(|| {
        let refresh = new_token();
        state.tokens.insert(
            refresh.clone(),
            Token::Refresh {
                client: client.to_owned(),
            },
        );
        state.issued.push(refresh.clone());
        refresh
    });
    if form_response {
        let mut body = form_urlencoded::Serializer::new(String::new());
        body.append_pair("access_token", &access)
            .append_pair("token_type", "bearer")
            .append_pair("scope", "repo");
        if let Some(refresh) = &refresh {
            body.append_pair("refresh_token", refresh);
        }
        return reply(
            StatusCode::OK,
            "application/x-www-form-urlencoded",
            body.finish().into_bytes(),
        );
    }
    let mut body = json!({ "access_token": access, "token_type": "Bearer", "expires_in": 3600 });
    if let Some(refresh) = refresh {
        body["refresh_token"] = Value::from(refresh);
    }
    reply(
        StatusCode::OK,
        "application/json",
        body.to_string().into_bytes(),
    )
}

fn token(
    state: &mut State,
    form: &HashMap<String, String>,
    authorization: Option<&str>,
) -> Response<Full<Bytes>> {
    let grant = form
        .get("grant_type")
        .map(String::as_str)
        .unwrap_or_default();
    if grant == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
        let Some(assertion) = form.get("assertion") else {
            return error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        let issuers = state.issuers.clone();
        let Some(claims) = verify_jwt(assertion, |claims| {
            issuers.get(claims["iss"].as_str()?).cloned()
        }) else {
            return error(StatusCode::BAD_REQUEST, "invalid_grant");
        };
        let iss = claims["iss"].as_str().unwrap_or_default().to_owned();
        let jti = claims["jti"].as_str().unwrap_or_default().to_owned();
        if !state.used_jtis.insert(jti) {
            return error(StatusCode::BAD_REQUEST, "invalid_grant");
        }
        return issue(state, &iss, false, false);
    }

    let Some(client) = authenticate(state, form, authorization) else {
        return error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let (rotate, form_response) = state.clients.get(&client).map_or((true, false), |config| {
        (config.rotate_refresh_tokens, config.form_responses)
    });
    match grant {
        "authorization_code" => {
            let Some((owner, challenge)) =
                form.get("code").and_then(|code| state.codes.remove(code))
            else {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            };
            let verifier = form
                .get("code_verifier")
                .map(String::as_str)
                .unwrap_or_default();
            let computed = URL_SAFE_NO_PAD.encode(ring::digest::digest(
                &ring::digest::SHA256,
                verifier.as_bytes(),
            ));
            if owner != client || computed != challenge {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            issue(state, &client, true, form_response)
        }
        "refresh_token" => {
            let presented = form.get("refresh_token").cloned().unwrap_or_default();
            match state.tokens.get(&presented) {
                Some(Token::Refresh { client: owner }) if *owner == client => {}
                _ => return error(StatusCode::BAD_REQUEST, "invalid_grant"),
            }
            if rotate {
                state.tokens.remove(&presented);
            }
            issue(state, &client, rotate, form_response)
        }
        "client_credentials" => issue(state, &client, false, form_response),
        "password" => {
            let (Some(username), Some(password)) = (form.get("username"), form.get("password"))
            else {
                return error(StatusCode::BAD_REQUEST, "invalid_request");
            };
            if state.users.get(username) != Some(password) {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            issue(state, &client, true, form_response)
        }
        _ => error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

fn revoke(
    state: &mut State,
    form: &HashMap<String, String>,
    authorization: Option<&str>,
) -> Response<Full<Bytes>> {
    let Some(client) = authenticate(state, form, authorization) else {
        return error(StatusCode::UNAUTHORIZED, "invalid_client");
    };
    // RFC 7009: an unknown token is not an error.
    if let Some(token) = form.get("token") {
        let owned = matches!(
            state.tokens.get(token),
            Some(Token::Access { client: owner } | Token::Refresh { client: owner }) if *owner == client
        );
        if owned {
            state.tokens.remove(token);
            state.revoked.push(token.clone());
        }
    }
    reply(StatusCode::OK, "application/json", b"{}".to_vec())
}

fn api(state: &State, authorization: Option<&str>) -> Response<Full<Bytes>> {
    let token = authorization
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    match state.tokens.get(token) {
        Some(Token::Access { client }) => reply(
            StatusCode::OK,
            "application/json",
            json!({ "ok": true, "client": client })
                .to_string()
                .into_bytes(),
        ),
        _ => error(StatusCode::UNAUTHORIZED, "invalid_token"),
    }
}
