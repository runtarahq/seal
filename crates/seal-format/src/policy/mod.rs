//! Policies: the rules for where and how a secret may be used.
//!
//! A policy is sealed inside the value it governs, so neither seal nor the
//! caller needs a registry, and a compromised caller cannot change where an
//! existing secret goes. `docs/policy.md` describes the schema.

pub mod builder;
#[cfg(test)]
mod tests;
mod validate;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::FormatError;
use crate::id::{FieldName, PolicyName};

/// The largest serialised policy, including its definitions.
pub const MAX_POLICY_BYTES: usize = 16 * 1024;

fn is_false(value: &bool) -> bool {
    !value
}

/// The rules for using one secret. A request must match one of `rules`; checking a
/// message against the secret needs `verify`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Up to 16 rules, and at least one unless the policy has `verify`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// The policies that values sealed from a response get, named so that a
    /// policy can refer to itself. See [`Policy::for_response_field`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub definitions: BTreeMap<PolicyName, Definition>,
    /// Whether the value may be presented with requests for other records: a
    /// platform's shared credential, such as an OAuth app's client secret. Only the
    /// sealer decides this, and values sealed from responses are never shared.
    #[serde(default, skip_serializing_if = "is_false")]
    pub shared: bool,
    /// Lets a caller ask whether a message's authentication code was made with this
    /// secret, such as a webhook's signature, or whether a token is this secret. The
    /// answer is only yes or no.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<Verify>,
}

impl Policy {
    /// Parses and validates a policy.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidPolicy`] if the JSON does not match the
    /// schema or the policy breaks a validation rule. The error never includes
    /// any of the input.
    pub fn from_json(json: &[u8]) -> Result<Self, FormatError> {
        let policy: Self = serde_json::from_slice(json)
            .map_err(|_| FormatError::InvalidPolicy("does not match the schema"))?;
        policy.validate()?;
        Ok(policy)
    }

    /// The canonical form: no whitespace, fields in schema order, definitions
    /// sorted by name. Two equal policies have the same canonical form.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidPolicy`] if serialisation fails.
    pub fn canonical_json(&self) -> Result<Vec<u8>, FormatError> {
        serde_json::to_vec(self).map_err(|_| FormatError::InvalidPolicy("cannot be serialised"))
    }

    /// Checks every validation rule. Runs before sealing and after opening.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidPolicy`] naming the rule that is broken.
    pub fn validate(&self) -> Result<(), FormatError> {
        validate::policy(self)
    }

    /// The policy for a value sealed from a response field that names
    /// `definition`: that definition's rules, with the same `definitions`.
    ///
    /// A definition that names itself therefore produces a byte-identical
    /// policy on every rotation, so rotations are unlimited and do not grow.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidPolicy`] if no definition has that name.
    pub fn for_response_field(&self, definition: &PolicyName) -> Result<Self, FormatError> {
        let named = self
            .definitions
            .get(definition)
            .ok_or(FormatError::InvalidPolicy("names an unknown definition"))?;
        Ok(Self {
            rules: named.rules.clone(),
            definitions: self.definitions.clone(),
            // A token belongs to the record it was sealed for.
            shared: false,
            verify: None,
        })
    }
}

/// How a message may be checked against a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Verify {
    /// The secret is an HMAC key, and the caller presents a message and its code.
    Hmac {
        /// The hash.
        hash: HmacHash,
    },
    /// The secret is a token the provider sends back as it is, and the caller presents
    /// the one that came with a message.
    Equals,
}

/// The hash of an HMAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HmacHash {
    /// SHA-1, which some providers still sign webhooks with.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

/// A named list of rules in a policy's `definitions`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    /// Between 1 and 16 rules.
    pub rules: Vec<Rule>,
}

/// One way a secret may be used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Where the secret may go.
    pub destination: Destination,
    /// The HTTP methods allowed; any method if absent. HTTP only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<Method>>,
    /// How the secret is attached. The caller never places it.
    pub inject: Inject,
    /// The plain fields the caller may supply as companions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plain: Vec<FieldName>,
    /// Response fields that are always sealed. HTTP only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_response: Option<SealResponse>,
    /// Limits for this rule. These can only tighten global limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<RuleLimits>,
    /// Allows a private address, if the deployment's configuration permits it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_private_destination: bool,
    /// Allows plain HTTP. Required for, and only valid with, scheme `http`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_plain_http: bool,
    /// Form fields the caller's body must have, each exactly once with one of the
    /// listed values, such as `grant_type`. The body is then buffered and checked
    /// before anything is sent. HTTP only.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub require_form: BTreeMap<String, Vec<String>>,
    /// Lets this value go with one whose rule injects into the path with exactly this
    /// prefix, such as `/bot{}`. The request is then sent under that prefix, outside
    /// the path this rule matched: whoever holds a value for that prefix chooses what
    /// fills it. HTTP only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_injected_path: Option<String>,
}

impl Rule {
    /// A rule with the given destination and injection, and nothing else.
    #[must_use]
    pub fn new(destination: Destination, inject: Inject) -> Self {
        Self {
            destination,
            methods: None,
            inject,
            plain: Vec::new(),
            seal_response: None,
            limits: None,
            allow_private_destination: false,
            allow_plain_http: false,
            require_form: BTreeMap::new(),
            allow_injected_path: None,
        }
    }
}

/// An HTTP method. Others, including `CONNECT` and `TRACE`, cannot be allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
    /// `OPTIONS`
    Options,
}

/// The scheme of an HTTP destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `https`
    Https,
    /// `http`, which needs `allow_plain_http`.
    Http,
}

impl Scheme {
    fn default_port(self) -> u16 {
        match self {
            Self::Https => 443,
            Self::Http => 80,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
        }
    }
}

/// Where a secret may go. Scheme, host and port are exact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawDestination", into = "RawDestination")]
pub enum Destination {
    /// An HTTP endpoint.
    Http {
        /// The scheme.
        scheme: Scheme,
        /// The exact host.
        host: Host,
        /// The exact port; the scheme's default if absent.
        port: Option<u16>,
        /// A path prefix, matched on segment boundaries.
        path_prefix: Option<String>,
    },
    /// A Postgres server.
    Postgres {
        /// The exact host.
        host: Host,
        /// The exact port.
        port: u16,
        /// The databases a session may use. At least one.
        databases: Vec<String>,
        /// The user a session logs in as.
        user: Part,
        /// How the server's certificate is verified.
        tls: PgTls,
        /// Allows a replication session.
        allow_replication: bool,
    },
}

impl Destination {
    /// The port requests go to, applying the scheme's default.
    #[must_use]
    pub fn effective_port(&self) -> u16 {
        match self {
            Self::Http { scheme, port, .. } => port.unwrap_or_else(|| scheme.default_port()),
            Self::Postgres { port, .. } => *port,
        }
    }
}

/// How a Postgres server's certificate is verified.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PgTls {
    /// Against the configured roots, with the host name.
    #[default]
    VerifyFull,
    /// Against this CA, in PEM, with the host name.
    Ca(String),
}

/// The destination's flat JSON form, where `scheme` selects the variant.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDestination {
    scheme: String,
    host: Host,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    databases: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<Part>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<PgTls>,
    #[serde(default, skip_serializing_if = "is_false")]
    allow_replication: bool,
}

impl TryFrom<RawDestination> for Destination {
    type Error = FormatError;

    fn try_from(raw: RawDestination) -> Result<Self, FormatError> {
        let scheme = match raw.scheme.as_str() {
            "https" => Scheme::Https,
            "http" => Scheme::Http,
            "postgres" => {
                if raw.path_prefix.is_some() {
                    return Err(FormatError::InvalidPolicy(
                        "a Postgres destination has no path prefix",
                    ));
                }
                return Ok(Self::Postgres {
                    host: raw.host,
                    port: raw.port.ok_or(FormatError::InvalidPolicy(
                        "a Postgres destination needs a port",
                    ))?,
                    databases: raw.databases.ok_or(FormatError::InvalidPolicy(
                        "a Postgres destination needs databases",
                    ))?,
                    user: raw.user.ok_or(FormatError::InvalidPolicy(
                        "a Postgres destination needs a user",
                    ))?,
                    tls: raw.tls.unwrap_or_default(),
                    allow_replication: raw.allow_replication,
                });
            }
            _ => return Err(FormatError::InvalidPolicy("unknown scheme")),
        };
        if raw.databases.is_some()
            || raw.user.is_some()
            || raw.tls.is_some()
            || raw.allow_replication
        {
            return Err(FormatError::InvalidPolicy(
                "an HTTP destination has Postgres options",
            ));
        }
        Ok(Self::Http {
            scheme,
            host: raw.host,
            port: raw.port,
            path_prefix: raw.path_prefix,
        })
    }
}

impl From<Destination> for RawDestination {
    fn from(destination: Destination) -> Self {
        match destination {
            Destination::Http {
                scheme,
                host,
                port,
                path_prefix,
            } => Self {
                scheme: scheme.as_str().to_owned(),
                host,
                port,
                path_prefix,
                databases: None,
                user: None,
                tls: None,
                allow_replication: false,
            },
            Destination::Postgres {
                host,
                port,
                databases,
                user,
                tls,
                allow_replication,
            } => Self {
                scheme: "postgres".to_owned(),
                host,
                port: Some(port),
                path_prefix: None,
                databases: Some(databases),
                user: Some(user),
                // The default is left out, so a policy has one canonical form.
                tls: (tls != PgTls::VerifyFull).then_some(tls),
                allow_replication,
            },
        }
    }
}

/// A host name or IP literal, already lowercase and IDNA-normalised, with no
/// wildcards. A host that would change when normalised is refused, not rewritten.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Host(String);

impl Host {
    /// Validates a host.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::InvalidPolicy`] if the host is not normalised.
    pub fn new(value: impl Into<String>) -> Result<Self, FormatError> {
        let value = value.into();
        let parsed = url::Host::parse(&value)
            .map_err(|_| FormatError::InvalidPolicy("host is not valid"))?;
        if parsed.to_string() != value {
            return Err(FormatError::InvalidPolicy("host is not normalised"));
        }
        if value.contains('*') || value.ends_with('.') {
            return Err(FormatError::InvalidPolicy(
                "host has a wildcard or trailing dot",
            ));
        }
        Ok(Self(value))
    }

    /// The host as a string. An IPv6 address keeps its brackets.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Host {
    type Error = FormatError;

    fn try_from(value: String) -> Result<Self, FormatError> {
        Self::new(value)
    }
}

impl From<Host> for String {
    fn from(host: Host) -> Self {
        host.0
    }
}

/// How a secret is attached to a request.
///
/// The value whose policy holds a rule is that rule's own secret, so an
/// injection names only the other parts of a credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Inject {
    /// In a header, through a template such as `Bearer {}`.
    Header {
        /// The header's name.
        name: String,
        /// The value, with exactly one `{}` for the secret.
        format: String,
    },
    /// As the password in basic auth.
    Basic {
        /// The username.
        username: Part,
    },
    /// In a query parameter.
    Query {
        /// The parameter's name.
        name: String,
    },
    /// In the URL's path, before the caller's path, through a template such as
    /// `/bot{}`. Another value may be presented with it only if its own rule allows
    /// this prefix with `allow_injected_path`.
    Path {
        /// What is put before the caller's path, with exactly one `{}` for the secret.
        prefix: String,
    },
    /// In a field of a form-encoded body.
    FormField {
        /// The field's name.
        name: String,
    },
    /// At a pointer in a JSON body, where nothing may already exist.
    JsonField {
        /// An RFC 6901 pointer.
        pointer: String,
    },
    /// As a TLS client certificate's private key.
    ClientCert {
        /// The certificate, in PEM.
        cert: Part,
        /// Any intermediate certificates, in PEM.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chain: Option<Part>,
        /// A CA to verify the provider with, in PEM.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca: Option<String>,
        /// The name to verify the provider's certificate against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server_name: Option<Host>,
    },
    /// As the secret access key in AWS Signature Version 4.
    AwsSigv4 {
        /// The AWS region.
        region: String,
        /// The AWS service.
        service: String,
        /// The access key id.
        access_key_id: Part,
        /// The session token of temporary credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<Part>,
        /// The ways of hashing the payload that are allowed.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        payload: Vec<PayloadMode>,
        /// Also allows `UNSIGNED-PAYLOAD`.
        #[serde(default, skip_serializing_if = "is_false")]
        allow_unsigned_payload: bool,
        /// `X-Amz-*` headers the caller may also set, from [`OPT_IN_AMZ_HEADERS`].
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allow_headers: Vec<String>,
        /// Lets a copy read any object on the rule's host, for a rule with no path
        /// prefix that allows `x-amz-copy-source`. Only for an endpoint addressed by
        /// path, whose host is every bucket's: where the host is one bucket's, a copy
        /// could then read the others.
        #[serde(default, skip_serializing_if = "is_false")]
        allow_copy_from_any_bucket: bool,
        /// Also lets the caller have a presigned URL, which it can copy and pass on.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allow_presign: Option<Presign>,
    },
    /// As the account key in Azure Shared Key.
    AzureSharedKey {
        /// The storage account.
        account: Part,
        /// The Azure service.
        service: AzureService,
        /// Also lets the caller have a shared access signature for one blob, which it
        /// can copy and pass on.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allow_presign: Option<Presign>,
    },
    /// As the key that signs a short-lived JWT.
    JwtAssertion {
        /// The signing algorithm.
        alg: JwtAlg,
        /// The audience. Required: providers expect different values.
        aud: JwtAudience,
        /// The claims.
        claims: JwtClaims,
        /// Optional header parameters.
        #[serde(default, skip_serializing_if = "JwtHeader::is_empty")]
        header: JwtHeader,
        /// The form field that receives the JWT.
        form_field: String,
        /// The JWT's lifetime, at most 300 seconds.
        max_lifetime_s: u16,
    },
    /// As a Postgres password.
    PgPassword {
        /// Also allows MD5 authentication, over TLS.
        #[serde(default, skip_serializing_if = "is_false")]
        allow_md5: bool,
        /// Also allows cleartext passwords, over TLS.
        #[serde(default, skip_serializing_if = "is_false")]
        allow_cleartext_password: bool,
        /// Refuses a login that is not bound to its TLS connection: only
        /// SCRAM-SHA-256-PLUS will do.
        #[serde(default, skip_serializing_if = "is_false")]
        require_channel_binding: bool,
    },
    /// Not used directly: another field's rule uses this value at this
    /// destination, and it may go nowhere else.
    Companion {},
}

/// The longest a presigned URL may last: seven days, which is S3's own limit.
pub const MAX_PRESIGN_EXPIRY_S: u32 = 7 * 24 * 3600;

/// The methods a URL can be presigned for.
pub const PRESIGN_METHODS: &[Method] = &[Method::Get, Method::Head, Method::Put, Method::Delete];

/// The terms on which a caller may have a presigned URL: a credential for one object
/// that works without seal until it expires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presign {
    /// The longest a URL may last, in seconds.
    pub max_expiry_s: u32,
}

/// `X-Amz-*` headers a caller may set on any SigV4 request, by prefix. They change what
/// a request does at its destination, never how it is signed or where it goes.
pub const DEFAULT_AMZ_HEADER_PREFIXES: &[&str] = &[
    "x-amz-meta-",
    "x-amz-server-side-encryption",
    "x-amz-checksum-",
];

/// `X-Amz-*` headers a caller may set on any SigV4 request, exactly. `x-amz-target`
/// names the operation for the services that take one, such as SQS and DynamoDB: as a
/// method and a path do elsewhere, it says what the request does.
pub const DEFAULT_AMZ_HEADERS: &[&str] = &[
    "x-amz-storage-class",
    "x-amz-tagging",
    "x-amz-expected-bucket-owner",
    "x-amz-request-payer",
    "x-amz-target",
];

/// `X-Amz-*` headers a rule may allow in `allow_headers`. ACLs and grants can widen who
/// reads the data. `x-amz-copy-source` reads from the object it names, so it also allows
/// the rest of the copy headers, and seal checks that the source is within the rule's
/// path prefix, or on its host where the rule sets `allow_copy_from_any_bucket`.
pub const OPT_IN_AMZ_HEADERS: &[&str] = &[
    "x-amz-acl",
    "x-amz-grant-full-control",
    "x-amz-grant-read",
    "x-amz-grant-read-acp",
    "x-amz-grant-write",
    "x-amz-grant-write-acp",
    "x-amz-copy-source",
];

/// The headers that come with `x-amz-copy-source`, apart from its own family.
pub const COPY_HEADERS: &[&str] = &["x-amz-metadata-directive", "x-amz-tagging-directive"];

/// Whether a caller may set this lowercase `x-amz-*` header under a rule allowing
/// `allow_headers`. Headers that control signing are never allowed here.
#[must_use]
pub fn amz_header_allowed(name: &str, allow_headers: &[String]) -> bool {
    let opted = |header: &str| allow_headers.iter().any(|allowed| allowed == header);
    DEFAULT_AMZ_HEADER_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        || DEFAULT_AMZ_HEADERS.contains(&name)
        || (opted(name) && name != "x-amz-copy-source")
        || (opted("x-amz-copy-source")
            && (name.starts_with("x-amz-copy-source") || COPY_HEADERS.contains(&name)))
}

/// Another part of a credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Part {
    /// A field of the same record: sealed, or plain if the rule lists it.
    Field(FieldName),
    /// A value fixed in the policy.
    Literal(String),
}

/// A way of hashing a SigV4 payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadMode {
    /// seal buffers the body up to the cap, and hashes it.
    Computed,
    /// The caller supplies the hash, and the provider verifies it.
    CallerHash,
    /// Chunked signing with `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`.
    Streaming,
}

/// An Azure storage service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureService {
    /// Blob storage.
    Blob,
    /// Queue storage.
    Queue,
    /// File storage.
    File,
    /// Table storage, which has its own string to sign.
    Table,
}

/// A JWT signing algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwtAlg {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RS256,
    /// RSASSA-PSS with SHA-256.
    PS256,
    /// ECDSA with P-256 and SHA-256.
    ES256,
}

/// A JWT's audience, sent as a single string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum JwtAudience {
    /// The URL of the rule's destination.
    TokenEndpoint,
    /// Exactly this value, byte for byte.
    Value(String),
}

/// The claims a JWT's rule sets. seal adds `aud`, `iat`, `nbf`, `exp` and `jti`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtClaims {
    /// The issuer.
    pub iss: String,
    /// The subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// The scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Other string claims.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

/// Optional JWT header parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtHeader {
    /// The type; `JWT` if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// The signing key's id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// The base64url SHA-256 thumbprint of the certificate.
    #[serde(default, rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}

impl JwtHeader {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Response fields that are always sealed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealResponse {
    /// The response's format. Any other content type is refused.
    pub format: ResponseFormat,
    /// Between 1 and 8 fields.
    pub fields: Vec<SealedField>,
}

/// The format of a sealed response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormat {
    /// JSON, with fields located by RFC 6901 pointer.
    Json,
    /// Form-encoded, with fields located by key.
    Form,
    /// XML, with fields located by element path, such as `A/B/C`.
    Xml,
}

/// One response field to seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedField {
    /// Where the field is in the response.
    pub at: String,
    /// The field name of the new sealed value.
    #[serde(rename = "as")]
    pub as_field: FieldName,
    /// The definition that gives the new sealed value its policy.
    pub policy: PolicyName,
    /// Claims to return in plaintext beside the sealed value, if it is a JWT: such as
    /// `exp`, or the tenant a token is for. The token's signature is never returned.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expose_claims: Vec<String>,
}

/// A rule's limits. Each can only tighten the global limit of the same name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleLimits {
    /// The largest buffered body or response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer_cap_bytes: Option<u64>,
    /// How long a transfer may make no progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_s: Option<u32>,
    /// How long a connection may take.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_s: Option<u32>,
    /// How long the first response byte may take.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_byte_timeout_s: Option<u32>,
    /// The total deadline for a request holding a capped buffer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffered_total_timeout_s: Option<u32>,
    /// The total deadline for a streamed request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_stream_duration_s: Option<u32>,
    /// The longest Postgres session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg_max_session_s: Option<u32>,
}
