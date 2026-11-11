//! Helpers that produce correct policies for the common cases.
//!
//! Every builder validates what it returns, and accepts `https` endpoints only.
//! A rule that needs plain HTTP or a private address has to be written out, so
//! that the weakening flag is visible where it is used.

use std::collections::BTreeMap;

use super::{
    AzureService, Definition, Destination, HmacHash, Host, Inject, JwtAlg, JwtAudience, JwtClaims,
    JwtHeader, Part, PayloadMode, PgTls, Policy, ResponseFormat, Rule, Scheme, SealResponse,
    SealedField, Verify,
};
use crate::error::FormatError;
use crate::id::{FieldName, PolicyName};

const API_DEFINITION: &str = "api";
const REFRESH_DEFINITION: &str = "refresh";

/// Where one part of a composite credential comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PartSource {
    /// Fixed in the policy.
    Literal(String),
    /// A plain field the caller supplies, such as an access key id.
    Plain(FieldName),
    /// Another sealed field of the same record. It gets a policy of its own,
    /// which lets it be used here and nowhere else.
    Sealed(FieldName),
}

/// The policies of a composite credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialPolicies {
    /// The policy of the credential's main secret.
    pub secret: Policy,
    /// The policy of each sealed companion, by field name.
    pub companions: BTreeMap<FieldName, Policy>,
}

/// How an OAuth client authenticates to the token endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OAuthClientAuth {
    /// The client secret goes in the form body.
    ClientSecretPost,
    /// The client secret is the password in basic auth.
    ClientSecretBasic {
        /// The client id, which is the username.
        client_id: String,
    },
    /// A private key signs a client assertion.
    PrivateKeyJwt(JwtOptions),
    /// A private key signs the JWT bearer grant, as for Google service accounts.
    JwtBearerGrant(JwtOptions),
}

/// The options of a JWT that seal signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JwtOptions {
    /// The signing algorithm.
    pub alg: JwtAlg,
    /// The audience the provider expects.
    pub aud: JwtAudience,
    /// The claims.
    pub claims: JwtClaims,
    /// Optional header parameters.
    pub header: JwtHeader,
    /// The JWT's lifetime, at most 300 seconds.
    pub max_lifetime_s: u16,
}

/// What [`oauth_client`] needs to know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthConfig {
    /// The token endpoint.
    pub token_url: String,
    /// The revocation endpoint, if the provider has one.
    pub revoke_url: Option<String>,
    /// The API that access tokens may be sent to.
    pub api_base: String,
    /// How the client authenticates.
    pub auth: OAuthClientAuth,
    /// The format of token responses: JSON, or form for providers that use it.
    pub response_format: ResponseFormat,
    /// Whether the client's credential is the platform's, shared by every tenant who
    /// configures this app. It is then usable with any record, but only for the
    /// authorization code and refresh grants, so that no tenant can obtain a token that
    /// acts as the app itself.
    pub shared: bool,
    /// Claims of the access token to return in plaintext, if it is a JWT: such as
    /// `exp`, or the tenant it is for.
    pub access_token_claims: Vec<String>,
}

/// The grants a shared client secret may be used for: those that act for a user who
/// consented, never for the app.
pub const SHARED_GRANTS: &[&str] = &["authorization_code", "refresh_token"];

/// The policies of an OAuth client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuthPolicies {
    /// The policy of the client secret or signing key.
    pub client: Policy,
    /// The policy of a resource owner's password, for the password grant.
    pub password: Policy,
}

/// A bearer token sent to an API.
///
/// # Errors
///
/// Returns [`FormatError::InvalidPolicy`] if `api_base` is not a valid `https` URL.
pub fn bearer(api_base: &str) -> Result<Policy, FormatError> {
    finish(Policy::from_rule(bearer_rule(api_base)?))
}

/// An API key sent in a header.
///
/// # Errors
///
/// Returns [`FormatError::InvalidPolicy`] if `api_base` is not a valid `https`
/// URL, or a rule cannot inject into that header.
pub fn api_key_header(api_base: &str, name: &str) -> Result<Policy, FormatError> {
    finish(Policy::from_rule(Rule::new(
        endpoint(api_base)?,
        Inject::Header {
            name: name.to_owned(),
            format: "{}".to_owned(),
        },
    )))
}

/// A secret sent in the URL's path, before the caller's path: `prefix` is a template
/// such as `/bot{}`.
///
/// # Errors
///
/// Returns [`FormatError::InvalidPolicy`] if `api_base` is not a valid `https` URL, or
/// `prefix` is not whole path segments with one `{}`.
pub fn path_secret(api_base: &str, prefix: &str) -> Result<Policy, FormatError> {
    finish(Policy::from_rule(Rule::new(
        endpoint(api_base)?,
        Inject::Path {
            prefix: prefix.to_owned(),
        },
    )))
}

/// A secret that only checks messages: a webhook's signing secret. It can be sent
/// nowhere, and a caller learns only whether a message's HMAC is right.
///
/// # Errors
///
/// Returns [`FormatError::InvalidPolicy`] if the policy cannot be serialised.
pub fn webhook_hmac(hash: HmacHash) -> Result<Policy, FormatError> {
    finish(Policy {
        rules: Vec::new(),
        definitions: BTreeMap::new(),
        shared: false,
        verify: Some(Verify::Hmac { hash }),
    })
}

/// A password sent with basic auth.
///
/// # Errors
///
/// Returns [`FormatError::InvalidPolicy`] if `api_base` is not a valid `https` URL.
pub fn basic(api_base: &str, username: PartSource) -> Result<CredentialPolicies, FormatError> {
    let destination = endpoint(api_base)?;
    let mut parts = Parts::new(&destination);
    let username = parts.add(username);
    parts.finish(Inject::Basic { username })
}

/// The policies of an OAuth client, and the tokens it obtains.
///
/// The access token may go only to the API, and the refresh token only to the
/// token endpoint. The refresh token's definition names itself, so a provider
/// that rotates refresh tokens can do so indefinitely. Both revoke at the
/// revocation endpoint, if there is one.
///
/// # Errors
///
/// Returns [`FormatError::InvalidPolicy`] if a URL is not a valid `https` URL,
/// the format is not one a token response uses, or a JWT option is not valid.
pub fn oauth_client(config: &OAuthConfig) -> Result<OAuthPolicies, FormatError> {
    if config.shared && matches!(config.auth, OAuthClientAuth::JwtBearerGrant(_)) {
        // The grant acts as the key's owner: shared, it would make every tenant the
        // platform.
        return Err(FormatError::InvalidPolicy(
            "a JWT bearer grant key acts as the platform, so it cannot be shared",
        ));
    }
    let token = endpoint(&config.token_url)?;
    let revoke = config.revoke_url.as_deref().map(endpoint).transpose()?;
    let sealing = token_response_sealing(config.response_format, &config.access_token_claims)?;

    let revoke_with = |name: &str| {
        revoke.as_ref().map(|destination| {
            Rule::new(
                destination.clone(),
                Inject::FormField {
                    name: name.to_owned(),
                },
            )
        })
    };

    let mut access_rules = vec![bearer_rule(&config.api_base)?];
    access_rules.extend(revoke_with("token"));

    let mut refresh_at_token = Rule::new(
        token.clone(),
        Inject::FormField {
            name: "refresh_token".to_owned(),
        },
    );
    refresh_at_token.seal_response = Some(sealing.clone());
    let mut refresh_rules = vec![refresh_at_token];
    refresh_rules.extend(revoke_with("token"));

    let definitions = BTreeMap::from([
        (
            PolicyName::new(API_DEFINITION)?,
            Definition {
                rules: access_rules,
            },
        ),
        (
            PolicyName::new(REFRESH_DEFINITION)?,
            Definition {
                rules: refresh_rules,
            },
        ),
    ]);

    let mut at_token = Rule::new(token.clone(), client_injection(&config.auth));
    at_token.seal_response = Some(sealing.clone());
    if config.shared {
        at_token.require_form = BTreeMap::from([(
            "grant_type".to_owned(),
            SHARED_GRANTS
                .iter()
                .map(|grant| (*grant).to_owned())
                .collect(),
        )]);
    }
    let mut client_rules = vec![at_token];
    // The JWT bearer grant has no client authentication to revoke with.
    if !matches!(config.auth, OAuthClientAuth::JwtBearerGrant(_))
        && let Some(destination) = &revoke
    {
        client_rules.push(Rule::new(
            destination.clone(),
            client_injection(&config.auth),
        ));
    }

    let mut password_rule = Rule::new(
        token,
        Inject::FormField {
            name: "password".to_owned(),
        },
    );
    password_rule.seal_response = Some(sealing);

    Ok(OAuthPolicies {
        client: finish(Policy {
            rules: client_rules,
            definitions: definitions.clone(),
            shared: config.shared,
            verify: None,
        })?,
        // A resource owner's password is theirs, never shared.
        password: finish(Policy {
            rules: vec![password_rule],
            definitions,
            shared: false,
            verify: None,
        })?,
    })
}

/// A secret access key used with AWS Signature Version 4.
///
/// # Errors
///
/// Returns [`FormatError::InvalidPolicy`] if `endpoint_url` is not a valid
/// `https` URL, or the region, service or payload modes are not valid.
pub fn aws(
    region: &str,
    service: &str,
    endpoint_url: &str,
    access_key_id: PartSource,
    session_token: Option<PartSource>,
    payload: Vec<PayloadMode>,
) -> Result<CredentialPolicies, FormatError> {
    let destination = endpoint(endpoint_url)?;
    let mut parts = Parts::new(&destination);
    let access_key_id = parts.add(access_key_id);
    let session_token = session_token.map(|source| parts.add(source));
    parts.finish(Inject::AwsSigv4 {
        region: region.to_owned(),
        service: service.to_owned(),
        access_key_id,
        session_token,
        payload,
        allow_unsigned_payload: false,
        allow_headers: Vec::new(),
        allow_copy_from_any_bucket: false,
        allow_presign: None,
    })
}

/// An account key used with Azure Shared Key.
///
/// # Errors
///
/// Returns [`FormatError::InvalidPolicy`] if `endpoint_url` is not a valid `https` URL.
pub fn azure(
    account: PartSource,
    service: AzureService,
    endpoint_url: &str,
) -> Result<CredentialPolicies, FormatError> {
    let destination = endpoint(endpoint_url)?;
    let mut parts = Parts::new(&destination);
    let account = parts.add(account);
    parts.finish(Inject::AzureSharedKey {
        account,
        service,
        allow_presign: None,
    })
}

/// A TLS client certificate's private key.
///
/// # Errors
///
/// Returns [`FormatError::InvalidPolicy`] if `api_base` is not a valid `https` URL.
pub fn client_cert(
    api_base: &str,
    cert: PartSource,
    chain: Option<PartSource>,
) -> Result<CredentialPolicies, FormatError> {
    let destination = endpoint(api_base)?;
    let mut parts = Parts::new(&destination);
    let cert = parts.add(cert);
    let chain = chain.map(|source| parts.add(source));
    parts.finish(Inject::ClientCert {
        cert,
        chain,
        ca: None,
        server_name: None,
    })
}

/// A Postgres password, with the server verified and only SCRAM allowed.
///
/// # Errors
///
/// Returns [`FormatError::InvalidPolicy`] if the host, port or databases are not valid.
pub fn postgres(
    host: &str,
    port: u16,
    databases: Vec<String>,
    user: &str,
) -> Result<Policy, FormatError> {
    finish(Policy::from_rule(Rule::new(
        Destination::Postgres {
            host: Host::new(host)?,
            port,
            databases,
            user: Part::Literal(user.to_owned()),
            tls: PgTls::VerifyFull,
            allow_replication: false,
        },
        Inject::PgPassword {
            allow_md5: false,
            allow_cleartext_password: false,
            require_channel_binding: false,
        },
    )))
}

impl Policy {
    fn from_rule(rule: Rule) -> Self {
        Self {
            rules: vec![rule],
            definitions: BTreeMap::new(),
            shared: false,
            verify: None,
        }
    }
}

/// Collects a composite credential's parts as its rule is built.
struct Parts<'a> {
    destination: &'a Destination,
    plain: Vec<FieldName>,
    companions: BTreeMap<FieldName, Policy>,
}

impl<'a> Parts<'a> {
    fn new(destination: &'a Destination) -> Self {
        Self {
            destination,
            plain: Vec::new(),
            companions: BTreeMap::new(),
        }
    }

    fn add(&mut self, source: PartSource) -> Part {
        match source {
            PartSource::Literal(value) => Part::Literal(value),
            PartSource::Plain(field) => {
                self.plain.push(field.clone());
                Part::Field(field)
            }
            PartSource::Sealed(field) => {
                self.companions.insert(
                    field.clone(),
                    Policy::from_rule(Rule::new(self.destination.clone(), Inject::Companion {})),
                );
                Part::Field(field)
            }
        }
    }

    fn finish(self, inject: Inject) -> Result<CredentialPolicies, FormatError> {
        let mut rule = Rule::new(self.destination.clone(), inject);
        rule.plain = self.plain;
        for companion in self.companions.values() {
            companion.validate()?;
        }
        Ok(CredentialPolicies {
            secret: finish(Policy::from_rule(rule))?,
            companions: self.companions,
        })
    }
}

fn finish(policy: Policy) -> Result<Policy, FormatError> {
    policy.validate()?;
    Ok(policy)
}

fn bearer_rule(api_base: &str) -> Result<Rule, FormatError> {
    Ok(Rule::new(
        endpoint(api_base)?,
        Inject::Header {
            name: "Authorization".to_owned(),
            format: "Bearer {}".to_owned(),
        },
    ))
}

fn client_injection(auth: &OAuthClientAuth) -> Inject {
    match auth {
        OAuthClientAuth::ClientSecretPost => Inject::FormField {
            name: "client_secret".to_owned(),
        },
        OAuthClientAuth::ClientSecretBasic { client_id } => Inject::Basic {
            username: Part::Literal(client_id.clone()),
        },
        OAuthClientAuth::PrivateKeyJwt(options) => jwt_injection(options, "client_assertion"),
        OAuthClientAuth::JwtBearerGrant(options) => jwt_injection(options, "assertion"),
    }
}

fn jwt_injection(options: &JwtOptions, form_field: &str) -> Inject {
    Inject::JwtAssertion {
        alg: options.alg,
        aud: options.aud.clone(),
        claims: options.claims.clone(),
        header: options.header.clone(),
        form_field: form_field.to_owned(),
        max_lifetime_s: options.max_lifetime_s,
    }
}

fn token_response_sealing(
    format: ResponseFormat,
    access_token_claims: &[String],
) -> Result<SealResponse, FormatError> {
    let location = |name: &str| match format {
        ResponseFormat::Json => Ok(format!("/{name}")),
        ResponseFormat::Form => Ok(name.to_owned()),
        ResponseFormat::Xml => Err(FormatError::InvalidPolicy(
            "a token response is JSON or form-encoded",
        )),
    };
    Ok(SealResponse {
        format,
        fields: vec![
            SealedField {
                at: location("access_token")?,
                as_field: FieldName::new("access_token")?,
                policy: PolicyName::new(API_DEFINITION)?,
                expose_claims: access_token_claims.to_vec(),
            },
            SealedField {
                at: location("refresh_token")?,
                as_field: FieldName::new("refresh_token")?,
                policy: PolicyName::new(REFRESH_DEFINITION)?,
                expose_claims: Vec::new(),
            },
        ],
    })
}

/// Parses an `https` URL into a destination. Anything a destination cannot
/// express, such as credentials or a query, is refused rather than dropped.
fn endpoint(url: &str) -> Result<Destination, FormatError> {
    let parsed =
        url::Url::parse(url).map_err(|_| FormatError::InvalidPolicy("endpoint is not a URL"))?;
    if parsed.scheme() != "https" {
        return Err(FormatError::InvalidPolicy("a builder accepts https only"));
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(FormatError::InvalidPolicy(
            "endpoint has credentials, a query or a fragment",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or(FormatError::InvalidPolicy("endpoint has no host"))?;
    let path = parsed.path();
    Ok(Destination::Http {
        scheme: Scheme::Https,
        host: Host::new(host)?,
        port: parsed.port(),
        path_prefix: (path != "/").then(|| path.to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const API: &str = "https://api.example.com/v2/";
    const TOKEN: &str = "https://auth.example.com/oauth/token";
    const REVOKE: &str = "https://auth.example.com/oauth/revoke";

    fn name(value: &str) -> FieldName {
        FieldName::new(value).unwrap()
    }

    fn definition(value: &str) -> PolicyName {
        PolicyName::new(value).unwrap()
    }

    fn host_and_prefix(rule: &Rule) -> (String, Option<String>) {
        match &rule.destination {
            Destination::Http {
                host, path_prefix, ..
            } => (host.as_str().to_owned(), path_prefix.clone()),
            Destination::Postgres { .. } => panic!("not HTTP"),
        }
    }

    fn jwt_options() -> JwtOptions {
        JwtOptions {
            alg: JwtAlg::RS256,
            aud: JwtAudience::TokenEndpoint,
            claims: JwtClaims {
                iss: "client".to_owned(),
                sub: None,
                scope: None,
                extra: BTreeMap::new(),
            },
            header: JwtHeader::default(),
            max_lifetime_s: 300,
        }
    }

    fn oauth(auth: OAuthClientAuth) -> OAuthConfig {
        OAuthConfig {
            token_url: TOKEN.to_owned(),
            revoke_url: Some(REVOKE.to_owned()),
            api_base: API.to_owned(),
            auth,
            response_format: ResponseFormat::Json,
            shared: false,
            access_token_claims: Vec::new(),
        }
    }

    #[test]
    fn bearer_attaches_an_authorization_header() {
        let policy = bearer(API).unwrap();
        let rule = &policy.rules[0];
        assert_eq!(
            host_and_prefix(rule),
            ("api.example.com".to_owned(), Some("/v2/".to_owned()))
        );
        assert_eq!(
            rule.inject,
            Inject::Header {
                name: "Authorization".to_owned(),
                format: "Bearer {}".to_owned()
            }
        );
    }

    #[test]
    fn api_key_header_uses_the_named_header() {
        let policy = api_key_header(API, "X-Api-Key").unwrap();
        assert!(matches!(
            &policy.rules[0].inject,
            Inject::Header { name, format } if name == "X-Api-Key" && format == "{}"
        ));
        api_key_header(API, "Host").unwrap_err();
    }

    #[test]
    fn oauth_exposes_the_named_claims_of_access_tokens_on_every_grant() {
        let mut config = oauth(OAuthClientAuth::ClientSecretPost);
        config.access_token_claims = vec!["exp".to_owned()];
        let policies = oauth_client(&config).unwrap();
        let exposed = |rule: &Rule| -> Vec<Vec<String>> {
            let sealing = rule.seal_response.as_ref().unwrap();
            sealing
                .fields
                .iter()
                .map(|field| field.expose_claims.clone())
                .collect()
        };
        let refresh = &policies.client.definitions[&PolicyName::new(REFRESH_DEFINITION).unwrap()];
        for rule in [&policies.client.rules[0], &refresh.rules[0]] {
            assert_eq!(exposed(rule), [vec!["exp".to_owned()], Vec::new()]);
        }
    }

    #[test]
    fn a_webhook_secret_has_no_rules_and_only_verifies() {
        let policy = webhook_hmac(HmacHash::Sha256).unwrap();
        assert!(policy.rules.is_empty() && !policy.shared);
        assert_eq!(
            String::from_utf8(policy.canonical_json().unwrap()).unwrap(),
            r#"{"verify":{"hmac":{"hash":"sha256"}}}"#
        );
    }

    #[test]
    fn path_secret_puts_the_template_before_the_path() {
        let policy = path_secret("https://api.telegram.org", "/bot{}").unwrap();
        assert!(matches!(
            &policy.rules[0].inject,
            Inject::Path { prefix } if prefix == "/bot{}"
        ));
        path_secret("https://api.telegram.org", "/bot{}/").unwrap_err();
    }

    #[test]
    fn endpoints_must_be_exact_https_urls() {
        for url in [
            "http://api.example.com/",
            "ftp://api.example.com/",
            "not a url",
            "https://user:pass@api.example.com/",
            "https://api.example.com/?a=1",
            "https://api.example.com/#a",
            "https://api.example.com/../admin/%2e%2e/%2f",
        ] {
            assert!(bearer(url).is_err(), "{url}");
        }
    }

    #[test]
    fn endpoints_keep_a_non_default_port_and_drop_a_root_path() {
        let policy = bearer("https://api.example.com:8443").unwrap();
        assert_eq!(policy.rules[0].destination.effective_port(), 8443);
        assert_eq!(host_and_prefix(&policy.rules[0]).1, None);
    }

    #[test]
    fn a_literal_username_adds_nothing_else() {
        let policies = basic(API, PartSource::Literal("user".to_owned())).unwrap();
        assert!(policies.companions.is_empty());
        assert!(policies.secret.rules[0].plain.is_empty());
    }

    #[test]
    fn a_plain_part_is_listed_in_the_rule() {
        let policies = basic(API, PartSource::Plain(name("username"))).unwrap();
        assert_eq!(policies.secret.rules[0].plain, [name("username")]);
        assert!(policies.companions.is_empty());
    }

    #[test]
    fn a_sealed_part_gets_a_companion_rule_for_the_same_destination() {
        let policies = basic(API, PartSource::Sealed(name("username"))).unwrap();
        assert!(policies.secret.rules[0].plain.is_empty());
        let companion = &policies.companions[&name("username")].rules[0];
        assert_eq!(companion.inject, Inject::Companion {});
        assert_eq!(companion.destination, policies.secret.rules[0].destination);
    }

    #[test]
    fn aws_names_its_parts_and_refuses_unsigned_payloads() {
        let policies = aws(
            "eu-west-1",
            "s3",
            "https://s3.eu-west-1.amazonaws.com",
            PartSource::Plain(name("access_key_id")),
            Some(PartSource::Sealed(name("session_token"))),
            vec![PayloadMode::Computed, PayloadMode::CallerHash],
        )
        .unwrap();
        assert!(matches!(
            policies.secret.rules[0].inject,
            Inject::AwsSigv4 {
                allow_unsigned_payload: false,
                ..
            }
        ));
        assert_eq!(policies.secret.rules[0].plain, [name("access_key_id")]);
        assert!(policies.companions.contains_key(&name("session_token")));
        aws(
            "eu-west-1",
            "s3",
            API,
            PartSource::Plain(name("access_key_id")),
            None,
            vec![],
        )
        .unwrap_err();
    }

    #[test]
    fn azure_names_the_account() {
        let policies = azure(
            PartSource::Literal("acct".to_owned()),
            AzureService::Table,
            "https://acct.table.core.windows.net",
        )
        .unwrap();
        assert!(matches!(
            policies.secret.rules[0].inject,
            Inject::AzureSharedKey {
                service: AzureService::Table,
                ..
            }
        ));
    }

    #[test]
    fn client_cert_seals_the_chain_when_asked() {
        let policies = client_cert(
            API,
            PartSource::Plain(name("cert")),
            Some(PartSource::Sealed(name("chain"))),
        )
        .unwrap();
        assert_eq!(policies.secret.rules[0].plain, [name("cert")]);
        assert!(policies.companions.contains_key(&name("chain")));
    }

    #[test]
    fn postgres_allows_only_scram_on_a_verified_connection() {
        let policy = postgres("db.example.com", 5432, vec!["app".to_owned()], "app_user").unwrap();
        assert_eq!(
            policy.rules[0].inject,
            Inject::PgPassword {
                allow_md5: false,
                allow_cleartext_password: false,
                require_channel_binding: false,
            }
        );
        assert!(matches!(
            policy.rules[0].destination,
            Destination::Postgres {
                tls: PgTls::VerifyFull,
                allow_replication: false,
                ..
            }
        ));
        postgres("db.example.com", 5432, vec![], "u").unwrap_err();
        postgres("DB.example.com", 5432, vec!["a".to_owned()], "u").unwrap_err();
    }

    #[test]
    fn tokens_are_limited_to_where_they_belong() {
        let policies = oauth_client(&oauth(OAuthClientAuth::ClientSecretPost)).unwrap();
        let client = &policies.client;
        assert!(client.rules[0].seal_response.is_some());
        assert_eq!(
            client.rules[0].inject,
            Inject::FormField {
                name: "client_secret".to_owned()
            }
        );

        let access = client.for_response_field(&definition("api")).unwrap();
        assert_eq!(access.rules.len(), 2);
        assert_eq!(host_and_prefix(&access.rules[0]).0, "api.example.com");
        assert!(access.rules.iter().all(|rule| rule.seal_response.is_none()));

        let refresh = client.for_response_field(&definition("refresh")).unwrap();
        assert_eq!(
            host_and_prefix(&refresh.rules[0]),
            (
                "auth.example.com".to_owned(),
                Some("/oauth/token".to_owned())
            )
        );
        assert!(refresh.rules[0].seal_response.is_some());
        assert_eq!(
            host_and_prefix(&refresh.rules[1]).1,
            Some("/oauth/revoke".to_owned())
        );
    }

    #[test]
    fn a_rotating_refresh_token_keeps_the_same_policy() {
        let policies = oauth_client(&oauth(OAuthClientAuth::ClientSecretPost)).unwrap();
        let name = definition("refresh");
        let first = policies.client.for_response_field(&name).unwrap();
        let fields = &first.rules[0].seal_response.as_ref().unwrap().fields;
        assert!(fields.iter().any(|field| field.policy == name));

        let mut current = first.clone();
        for _ in 0..10 {
            current = current.for_response_field(&name).unwrap();
            current.validate().unwrap();
            assert_eq!(
                current.canonical_json().unwrap(),
                first.canonical_json().unwrap()
            );
        }
    }

    #[test]
    fn a_refresh_token_and_client_secret_agree_on_response_sealing() {
        let policies = oauth_client(&oauth(OAuthClientAuth::ClientSecretPost)).unwrap();
        let refresh = policies
            .client
            .for_response_field(&definition("refresh"))
            .unwrap();
        assert_eq!(
            refresh.rules[0].seal_response,
            policies.client.rules[0].seal_response
        );
        assert_eq!(refresh.definitions, policies.client.definitions);
        assert_eq!(
            policies.password.rules[0].seal_response,
            policies.client.rules[0].seal_response
        );
    }

    #[test]
    fn each_client_authentication_method_injects_its_own_way() {
        let basic = oauth_client(&oauth(OAuthClientAuth::ClientSecretBasic {
            client_id: "client".to_owned(),
        }))
        .unwrap();
        assert!(matches!(basic.client.rules[0].inject, Inject::Basic { .. }));

        let key_jwt = oauth_client(&oauth(OAuthClientAuth::PrivateKeyJwt(jwt_options()))).unwrap();
        assert!(matches!(
            &key_jwt.client.rules[0].inject,
            Inject::JwtAssertion { form_field, .. } if form_field == "client_assertion"
        ));
        assert_eq!(
            key_jwt.client.rules.len(),
            2,
            "also at the revocation endpoint"
        );

        let grant = oauth_client(&oauth(OAuthClientAuth::JwtBearerGrant(jwt_options()))).unwrap();
        assert!(matches!(
            &grant.client.rules[0].inject,
            Inject::JwtAssertion { form_field, .. } if form_field == "assertion"
        ));
        assert_eq!(grant.client.rules.len(), 1, "nothing to revoke with");
    }

    #[test]
    fn revocation_is_optional() {
        let mut config = oauth(OAuthClientAuth::ClientSecretPost);
        config.revoke_url = None;
        let policies = oauth_client(&config).unwrap();
        assert_eq!(policies.client.rules.len(), 1);
        let access = policies
            .client
            .for_response_field(&definition("api"))
            .unwrap();
        assert_eq!(access.rules.len(), 1);
    }

    #[test]
    fn form_encoded_token_responses_locate_fields_by_key() {
        let mut config = oauth(OAuthClientAuth::ClientSecretPost);
        config.response_format = ResponseFormat::Form;
        let policies = oauth_client(&config).unwrap();
        let sealing = policies.client.rules[0].seal_response.as_ref().unwrap();
        assert_eq!(sealing.fields[0].at, "access_token");

        config.response_format = ResponseFormat::Xml;
        oauth_client(&config).unwrap_err();
    }

    #[test]
    fn an_invalid_jwt_option_is_refused() {
        let mut options = jwt_options();
        options.max_lifetime_s = 301;
        oauth_client(&oauth(OAuthClientAuth::PrivateKeyJwt(options))).unwrap_err();
        let mut trailing = oauth(OAuthClientAuth::PrivateKeyJwt(jwt_options()));
        trailing.token_url = "https://auth.example.com/oauth/".to_owned();
        oauth_client(&trailing).unwrap_err();
    }

    #[test]
    fn a_shared_app_is_limited_to_grants_that_act_for_a_user() {
        let mut config = oauth(OAuthClientAuth::ClientSecretPost);
        config.shared = true;
        let policies = oauth_client(&config).unwrap();
        assert!(policies.client.shared);
        assert!(!policies.password.shared, "a password belongs to its owner");
        let at_token = &policies.client.rules[0];
        assert_eq!(
            at_token.require_form["grant_type"],
            ["authorization_code", "refresh_token"]
        );
        // Tokens sealed from its responses are the tenant's, never shared.
        for name in ["api", "refresh"] {
            assert!(
                !policies
                    .client
                    .for_response_field(&definition(name))
                    .unwrap()
                    .shared
            );
        }
        assert!(at_token.seal_response.is_some());
    }

    #[test]
    fn a_jwt_bearer_grant_key_cannot_be_shared() {
        let mut config = oauth(OAuthClientAuth::JwtBearerGrant(jwt_options()));
        config.shared = true;
        oauth_client(&config).unwrap_err();
        let mut config = oauth(OAuthClientAuth::PrivateKeyJwt(jwt_options()));
        config.shared = true;
        assert!(oauth_client(&config).unwrap().client.shared);
    }

    #[test]
    fn an_unshared_app_requires_nothing_of_the_body() {
        let policies = oauth_client(&oauth(OAuthClientAuth::ClientSecretPost)).unwrap();
        assert!(!policies.client.shared);
        assert!(policies.client.rules[0].require_form.is_empty());
    }

    #[test]
    fn built_policies_round_trip_through_their_canonical_form() {
        let policies = oauth_client(&oauth(OAuthClientAuth::PrivateKeyJwt(jwt_options()))).unwrap();
        let canonical = policies.client.canonical_json().unwrap();
        assert_eq!(Policy::from_json(&canonical).unwrap(), policies.client);
    }
}
