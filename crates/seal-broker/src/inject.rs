//! Attaches secrets to an outgoing request. The caller never places them.
//!
//! Buffers that hold a secret are wiped. Where a dependency copies a value (the
//! `http` crate's `HeaderValue` and `Uri`), the value is marked sensitive where it
//! can be, and the threat model records the copy.

pub mod azure;
pub mod civil;
pub mod jwt;
pub mod sigv4;

use std::collections::BTreeMap;
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};
use seal_format::policy::{Inject, Part};
use seal_format::{FieldName, Secret};
use zeroize::Zeroizing;

use crate::error::{BrokerError, ErrorCode};
use crate::json::Node;
use crate::matcher::Plan;
use crate::target::Target;

/// Headers that apply to one connection, and so never pass through.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Everything except RFC 3986's unreserved characters.
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Everything except the characters a path segment keeps as they are: RFC 3986's
/// unreserved characters, sub-delimiters, `:` and `@`. So `/`, `?`, `#` and `%` are
/// encoded, and a secret can never add a segment or end the path.
const PATH_SEGMENT: &AsciiSet = &QUERY_VALUE
    .remove(b'!')
    .remove(b'$')
    .remove(b'&')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')')
    .remove(b'*')
    .remove(b'+')
    .remove(b',')
    .remove(b';')
    .remove(b'=')
    .remove(b':')
    .remove(b'@');

/// The request to send, without its body.
#[derive(Debug)]
pub struct Outgoing {
    /// The path and query, with any injected parameter.
    pub path_and_query: Zeroizing<String>,
    /// The headers, with injected ones marked sensitive.
    pub headers: HeaderMap,
    /// What has to be added to the body, which means buffering it.
    pub body: Option<BodyInjection>,
    /// A signature over the final request, made once the body is known.
    pub signing: Option<Signing>,
    /// The client certificate to present, from the field holding its private key.
    pub client_cert: Option<crate::identity::ClientCertMaterial>,
    /// A secret injected into the path, as it is written there. A response header
    /// that repeats it, such as a redirect's `Location`, is not passed on.
    pub path_secret: Option<Zeroizing<Vec<u8>>>,
}

/// A signature still to be made over the final request.
#[derive(Debug)]
pub enum Signing {
    /// AWS Signature Version 4, with the payload modes the rule allows.
    Aws {
        /// The signer, whose payload mode the broker chooses.
        signer: sigv4::Signer,
        /// The modes the rule allows.
        allowed: Vec<seal_format::policy::PayloadMode>,
        /// Whether the rule also allows `UNSIGNED-PAYLOAD`.
        allow_unsigned: bool,
    },
    /// Azure Storage Shared Key.
    Azure(azure::Signer),
}

impl Signing {
    /// Signs the final head. The body is given if seal buffered it. For SigV4 this
    /// returns the signature, which seeds chunk signing.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::BadRequest`] for a header that cannot be signed.
    pub fn sign(
        &self,
        method: &str,
        path: &str,
        query: &str,
        headers: &mut HeaderMap,
        body: Option<&[u8]>,
    ) -> Result<Zeroizing<String>, BrokerError> {
        match self {
            Self::Aws { signer, .. } => signer.sign(method, path, query, headers, body),
            Self::Azure(signer) => {
                signer.sign(method, path, query, headers)?;
                Ok(Zeroizing::new(String::new()))
            }
        }
    }
}

/// Secrets that go in the request body.
pub enum BodyInjection {
    /// Fields of a form-encoded body.
    Form(Vec<(String, Zeroizing<Vec<u8>>)>),
    /// Locations in a JSON body.
    Json(Vec<(String, Zeroizing<Vec<u8>>)>),
}

impl std::fmt::Debug for BodyInjection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, entries) = match self {
            Self::Form(entries) => ("Form", entries),
            Self::Json(entries) => ("Json", entries),
        };
        let names: Vec<&String> = entries.iter().map(|(name, _)| name).collect();
        f.debug_tuple(kind).field(&names).finish()
    }
}

/// Everything an injection may read.
pub struct Sources<'a> {
    /// The opened secrets.
    pub secrets: &'a BTreeMap<FieldName, Secret>,
    /// The caller's plain fields.
    pub plain: &'a BTreeMap<FieldName, String>,
}

impl Sources<'_> {
    /// A part's bytes, wiped when dropped.
    pub(crate) fn part(&self, part: &Part) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
        match part {
            Part::Literal(value) => Ok(Zeroizing::new(value.as_bytes().to_vec())),
            Part::Field(name) => {
                if let Some(secret) = self.secrets.get(name) {
                    Ok(Zeroizing::new(secret.expose(<[u8]>::to_vec)))
                } else if let Some(value) = self.plain.get(name) {
                    Ok(Zeroizing::new(value.as_bytes().to_vec()))
                } else {
                    Err(BrokerError::for_field(
                        ErrorCode::Internal,
                        "a matched part is missing",
                        name,
                    ))
                }
            }
        }
    }
}

/// Builds the outgoing head: the caller's headers cleaned up, with `Host` from the
/// URL and each injection applied.
///
/// # Errors
///
/// Returns [`ErrorCode::BadRequest`] for a header that is refused or a secret that
/// cannot be used as the rule says, and [`ErrorCode::PolicyDenied`] for an injection
/// this version cannot perform.
pub fn build_head(
    plan: &Plan,
    target: &Target,
    caller_headers: &HeaderMap,
    sources: &Sources<'_>,
    now: SystemTime,
) -> Result<Outgoing, BrokerError> {
    let mut headers = clean_caller_headers(caller_headers)?;
    let host = HeaderValue::from_str(&target.authority())
        .map_err(|_| BrokerError::new(ErrorCode::BadRequest, "URL host is not a valid header"))?;
    headers.insert(header::HOST, host);
    if plan.response.is_some() {
        // A compressed response could not be parsed to seal its fields.
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
    }

    let mut path_and_query = Zeroizing::new(target.path.clone());
    let mut query = Zeroizing::new(target.query.clone().unwrap_or_default());
    let mut form = Vec::new();
    let mut json = Vec::new();
    let mut signing = None;
    let mut client_cert = None;
    let mut path_secret = None;

    for injection in &plan.injections {
        let secret = sources.secrets.get(&injection.field).ok_or_else(|| {
            BrokerError::for_field(
                ErrorCode::Internal,
                "a matched secret is missing",
                &injection.field,
            )
        })?;
        match &injection.inject {
            Inject::Header { name, format } => {
                let value = secret.expose(|bytes| fill_template(format, bytes));
                insert_sensitive(&mut headers, name, &value, &injection.field)?;
            }
            Inject::Basic { username } => {
                let username = sources.part(username)?;
                if username.contains(&b':') {
                    return Err(BrokerError::for_field(
                        ErrorCode::BadRequest,
                        "a basic auth username cannot contain a colon",
                        &injection.field,
                    ));
                }
                // Sized up front: a growing buffer would leave copies behind.
                let length = secret.expose(<[u8]>::len);
                let mut credentials =
                    Zeroizing::new(Vec::with_capacity(username.len() + 1 + length));
                credentials.extend_from_slice(&username);
                credentials.push(b':');
                secret.expose(|bytes| credentials.extend_from_slice(bytes));
                let encoded = Zeroizing::new(STANDARD.encode(&*credentials));
                let mut value = Zeroizing::new(Vec::with_capacity(6 + encoded.len()));
                value.extend_from_slice(b"Basic ");
                value.extend_from_slice(encoded.as_bytes());
                insert_sensitive(&mut headers, "authorization", &value, &injection.field)?;
            }
            Inject::Query { name } => {
                // At most three bytes per byte encoded, reserved before the secret goes in.
                let length = secret.expose(<[u8]>::len);
                reserve_exact(&mut query, 2 + 3 * (name.len() + length));
                if !query.is_empty() {
                    query.push('&');
                }
                query.extend(percent_encode(name.as_bytes(), QUERY_VALUE));
                query.push('=');
                secret.expose(|bytes| query.extend(percent_encode(bytes, QUERY_VALUE)));
            }
            Inject::Path { prefix } => {
                let (before, after) = prefix.split_once("{}").unwrap_or((prefix, ""));
                let written: Zeroizing<Vec<u8>> = secret.expose(|bytes| {
                    // At most three bytes per byte encoded, reserved before the secret
                    // goes in.
                    let mut written = Zeroizing::new(Vec::with_capacity(3 * bytes.len()));
                    written.extend(percent_encode(bytes, PATH_SEGMENT).flat_map(str::bytes));
                    written
                });
                // The segment the secret lands in, which must not become a dot segment.
                let start = before.rsplit('/').next().unwrap_or("");
                let end = after.split('/').next().unwrap_or("");
                let mut segment =
                    Zeroizing::new(Vec::with_capacity(start.len() + written.len() + end.len()));
                segment.extend_from_slice(start.as_bytes());
                segment.extend_from_slice(&written);
                segment.extend_from_slice(end.as_bytes());
                if written.is_empty() || matches!(segment.as_slice(), b"." | b"..") {
                    return Err(BrokerError::for_field(
                        ErrorCode::BadRequest,
                        "this field's secret cannot be sent in a path",
                        &injection.field,
                    ));
                }
                let mut path = Zeroizing::new(String::with_capacity(
                    before.len() + written.len() + after.len() + path_and_query.len(),
                ));
                path.push_str(before);
                // Percent-encoding leaves only ASCII.
                path.extend(written.iter().map(|byte| char::from(*byte)));
                path.push_str(after);
                path.push_str(&path_and_query);
                path_and_query = path;
                path_secret = Some(written);
            }
            Inject::FormField { name } => {
                form.push((name.clone(), secret.expose(|b| Zeroizing::new(b.to_vec()))));
            }
            Inject::JsonField { pointer } => {
                json.push((
                    pointer.clone(),
                    secret.expose(|b| Zeroizing::new(b.to_vec())),
                ));
            }
            Inject::JwtAssertion {
                alg,
                aud,
                claims,
                header,
                form_field,
                max_lifetime_s,
            } => {
                // The rule matched only the exact token endpoint, so the target is it.
                let token_endpoint = format!(
                    "{}://{}{}",
                    match target.scheme {
                        seal_format::policy::Scheme::Https => "https",
                        seal_format::policy::Scheme::Http => "http",
                    },
                    target.authority(),
                    target.path
                );
                let aud = match aud {
                    seal_format::policy::JwtAudience::TokenEndpoint => token_endpoint.as_str(),
                    seal_format::policy::JwtAudience::Value(value) => value.as_str(),
                };
                let parts = jwt::JwtParts {
                    alg: *alg,
                    aud,
                    claims,
                    header,
                    lifetime_s: *max_lifetime_s,
                    now,
                };
                let assertion = secret.expose(|key| jwt::sign(&parts, key))?;
                form.push((
                    form_field.clone(),
                    Zeroizing::new(assertion.as_bytes().to_vec()),
                ));
                if form_field == "client_assertion" {
                    form.push((
                        "client_assertion_type".to_owned(),
                        Zeroizing::new(jwt::CLIENT_ASSERTION_TYPE.as_bytes().to_vec()),
                    ));
                }
            }
            Inject::AwsSigv4 {
                region,
                service,
                access_key_id,
                session_token,
                payload,
                allow_unsigned_payload,
                ..
            } => {
                let access_key_id = sources.part(access_key_id)?;
                let session_token = session_token
                    .as_ref()
                    .map(|token| sources.part(token))
                    .transpose()?;
                let signer = secret.expose(|secret_key| {
                    sigv4::Signer::new(sigv4::SignerParts {
                        secret: secret_key,
                        access_key_id: &access_key_id,
                        session_token,
                        region,
                        service,
                        now,
                        payload: sigv4::Payload::Computed,
                    })
                })?;
                signing = Some(Signing::Aws {
                    signer,
                    allowed: payload.clone(),
                    allow_unsigned: *allow_unsigned_payload,
                });
            }
            Inject::AzureSharedKey {
                account, service, ..
            } => {
                let account = sources.part(account)?;
                let signer =
                    secret.expose(|key| azure::Signer::new(key, &account, *service, now))?;
                signing = Some(Signing::Azure(signer));
            }
            Inject::ClientCert {
                cert,
                chain,
                ca,
                server_name,
            } => {
                let cert = sources.part(cert)?;
                let chain = chain
                    .as_ref()
                    .map(|chain| sources.part(chain))
                    .transpose()?;
                let material = secret.expose(|key| {
                    crate::identity::ClientCertMaterial::parse(
                        &injection.field,
                        key,
                        &cert,
                        chain.as_deref().map(Vec::as_slice),
                        ca.as_deref(),
                        server_name.as_ref().map(seal_format::policy::Host::as_str),
                    )
                })?;
                client_cert = Some(material);
            }
            Inject::PgPassword { .. } => {
                return Err(BrokerError::for_field(
                    ErrorCode::PolicyDenied,
                    "this version cannot perform this field's injection",
                    &injection.field,
                ));
            }
            Inject::Companion {} => {}
        }
    }

    if !query.is_empty() {
        reserve_exact(&mut path_and_query, 1 + query.len());
        path_and_query.push('?');
        path_and_query.push_str(&query);
    }
    let body = match (form.is_empty(), json.is_empty()) {
        (true, true) => None,
        (false, true) => Some(BodyInjection::Form(form)),
        (true, false) => Some(BodyInjection::Json(json)),
        (false, false) => {
            return Err(BrokerError::new(
                ErrorCode::Conflict,
                "rules inject into both a form and a JSON body",
            ));
        }
    };
    Ok(Outgoing {
        path_and_query,
        headers,
        body,
        signing,
        client_cert,
        path_secret,
    })
}

/// Reserves room for `additional` bytes at once, so later pushes do not reallocate and
/// leave a copy of what came before.
fn reserve_exact(text: &mut Zeroizing<String>, additional: usize) {
    if text.capacity() - text.len() < additional {
        let mut grown = Zeroizing::new(String::with_capacity(text.len() + additional));
        grown.push_str(text);
        *text = grown;
    }
}

fn fill_template(format: &str, secret: &[u8]) -> Zeroizing<Vec<u8>> {
    let (before, after) = format.split_once("{}").unwrap_or((format, ""));
    let mut value = Zeroizing::new(Vec::with_capacity(
        before.len() + secret.len() + after.len(),
    ));
    value.extend_from_slice(before.as_bytes());
    value.extend_from_slice(secret);
    value.extend_from_slice(after.as_bytes());
    value
}

fn insert_sensitive(
    headers: &mut HeaderMap,
    name: &str,
    value: &[u8],
    field: &FieldName,
) -> Result<(), BrokerError> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
        BrokerError::for_field(ErrorCode::BadRequest, "header name is not valid", field)
    })?;
    let mut value = HeaderValue::from_bytes(value).map_err(|_| {
        BrokerError::for_field(
            ErrorCode::BadRequest,
            "this field's secret cannot be sent in a header",
            field,
        )
    })?;
    value.set_sensitive(true);
    headers.insert(name, value);
    Ok(())
}

/// Drops hop-by-hop headers, including any `Connection` names, and `Host`, which
/// comes from the URL. Refuses `Proxy-*` and a malformed or repeated `Content-Length`.
fn clean_caller_headers(caller: &HeaderMap) -> Result<HeaderMap, BrokerError> {
    let named_by_connection: Vec<String> = caller
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();

    let mut lengths = caller.get_all(header::CONTENT_LENGTH).iter();
    if let Some(length) = lengths.next() {
        let is_valid = length
            .to_str()
            .ok()
            .is_some_and(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
            && lengths.next().is_none();
        if !is_valid {
            return Err(BrokerError::new(
                ErrorCode::BadRequest,
                "Content-Length is not valid",
            ));
        }
    }

    let mut headers = HeaderMap::with_capacity(caller.len());
    for (name, value) in caller {
        let lower = name.as_str();
        if lower.starts_with("proxy-") && lower != "proxy-connection" {
            return Err(BrokerError::new(
                ErrorCode::BadRequest,
                "Proxy headers are refused",
            ));
        }
        if lower == "host"
            || HOP_BY_HOP.contains(&lower)
            || named_by_connection.iter().any(|named| named == lower)
        {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    Ok(headers)
}

/// Whether a header's media type is one of these, ignoring case and parameters.
pub fn media_type_is(headers: &HeaderMap, accepted: impl Fn(&str) -> bool) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media_type = value.split(';').next().unwrap_or("").trim();
            accepted(&media_type.to_ascii_lowercase())
        })
}

/// `serde_json`'s private token for numbers kept as written (`arbitrary_precision`).
const NUMBER_TOKEN: &[u8] = b"$serde_json::private::Number";

/// Whether any string in a JSON text, escapes decoded, is `serde_json`'s private number
/// token. A reader built with `arbitrary_precision` takes an object whose first key is
/// that token for a number, so the same bytes would mean one thing to it and another to
/// everything else. seal is not built that way, but the application or provider on
/// either side of it may be, and seal writes an object it reads in key order, which can
/// bring the token first. No real API uses it, so seal refuses any body that has it.
/// This reads the raw text, escapes decoded. Found by fuzzing.
#[must_use]
pub fn mentions_number_token(json: &[u8]) -> bool {
    let mut bytes = json.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte != b'"' {
            continue;
        }
        // Decode the string, keeping only as much as could still be the token.
        let mut decoded: Vec<u8> = Vec::with_capacity(NUMBER_TOKEN.len());
        let mut fits = true;
        let mut push = |decoded: &mut Vec<u8>, piece: &[u8]| {
            if fits && decoded.len() + piece.len() <= NUMBER_TOKEN.len() {
                decoded.extend_from_slice(piece);
            } else {
                fits = false;
            }
        };
        loop {
            let Some(byte) = bytes.next() else {
                return false;
            };
            match byte {
                b'"' => break,
                b'\\' => match bytes.next() {
                    Some(b'u') => {
                        let hex: Vec<u8> = bytes.by_ref().take(4).collect();
                        let unit = std::str::from_utf8(&hex)
                            .ok()
                            .and_then(|hex| u16::from_str_radix(hex, 16).ok());
                        // Every character of the token is ASCII; anything else cannot match.
                        match unit.and_then(|unit| u8::try_from(unit).ok()) {
                            Some(ascii) if ascii.is_ascii() => push(&mut decoded, &[ascii]),
                            _ => push(&mut decoded, &[0xff]),
                        }
                    }
                    Some(escaped) => push(&mut decoded, &[escaped]),
                    None => return false,
                },
                other => push(&mut decoded, &[other]),
            }
        }
        if fits && decoded == NUMBER_TOKEN {
            return true;
        }
    }
    false
}

/// Whether a media type means JSON.
#[must_use]
pub fn is_json(media_type: &str) -> bool {
    media_type == "application/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
}

/// Whether a media type means a form-encoded body.
#[must_use]
pub fn is_form(media_type: &str) -> bool {
    media_type == "application/x-www-form-urlencoded"
}

/// Adds secrets to a buffered request body, and returns the new body.
///
/// # Errors
///
/// Returns [`ErrorCode::BadRequest`] if the body is compressed, is not the right
/// type or cannot be parsed, and [`ErrorCode::Conflict`] if the caller already set
/// something an injection sets.
pub fn apply_to_body(
    injection: &BodyInjection,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    if headers.contains_key(header::CONTENT_ENCODING) {
        return Err(BrokerError::new(
            ErrorCode::BadRequest,
            "a compressed body cannot have fields injected",
        ));
    }
    match injection {
        BodyInjection::Form(fields) => {
            if !media_type_is(headers, is_form) {
                return Err(BrokerError::new(
                    ErrorCode::BadRequest,
                    "field injection needs a form-encoded body",
                ));
            }
            apply_to_form(fields, body)
        }
        BodyInjection::Json(fields) => {
            if !media_type_is(headers, is_json) {
                return Err(BrokerError::new(
                    ErrorCode::BadRequest,
                    "field injection needs a JSON body",
                ));
            }
            apply_to_json(fields, body)
        }
    }
}

/// Room for a form body with these fields added, so it never grows: a growing buffer
/// would leave copies of the secrets behind. Form encoding is at most three bytes per
/// byte.
fn form_room(fields: &[(String, Zeroizing<Vec<u8>>)], body: &[u8]) -> usize {
    body.len()
        + fields
            .iter()
            .map(|(name, value)| 2 + 3 * (name.len() + value.len()))
            .sum::<usize>()
}

/// Room for a JSON body with these values added at their pointers, so it never grows.
/// A value escapes to at most six bytes per byte (`\u00XX`), and each segment of a
/// pointer adds at most a quoted key, a colon, braces and a comma.
fn json_room(fields: &[(String, Zeroizing<Vec<u8>>)], body: &[u8]) -> usize {
    body.len()
        + fields
            .iter()
            .map(|(pointer, value)| 8 * (pointer.len() + 1) + 6 * value.len() + 2)
            .sum::<usize>()
}

fn apply_to_form(
    fields: &[(String, Zeroizing<Vec<u8>>)],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    for (key, _) in form_urlencoded::parse(body) {
        if fields.iter().any(|(name, _)| *name == key) {
            return Err(BrokerError::new(
                ErrorCode::Conflict,
                "the caller set a form field an injection sets",
            ));
        }
    }
    let mut output = Zeroizing::new(Vec::with_capacity(form_room(fields, body)));
    output.extend_from_slice(body);
    for (name, value) in fields {
        if !output.is_empty() {
            output.push(b'&');
        }
        output.extend(form_urlencoded::byte_serialize(name.as_bytes()).flat_map(str::bytes));
        output.push(b'=');
        output.extend(form_urlencoded::byte_serialize(value).flat_map(str::bytes));
    }
    Ok(output)
}

fn apply_to_json(
    fields: &[(String, Zeroizing<Vec<u8>>)],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    let mut document = Node::parse(body)
        .ok_or_else(|| BrokerError::new(ErrorCode::BadRequest, "body is not valid JSON"))?;
    if !document.is_object() {
        return Err(BrokerError::new(
            ErrorCode::BadRequest,
            "a JSON body must be an object to have fields injected",
        ));
    }
    if mentions_number_token(body) {
        return Err(BrokerError::new(
            ErrorCode::BadRequest,
            "the body has a key seal cannot pass on",
        ));
    }
    // The document borrows each secret, so the only copy made is the one written to
    // the output, which is sized up front and wiped when it is dropped.
    for (pointer, value) in fields {
        let text = std::str::from_utf8(value).map_err(|_| {
            BrokerError::new(
                ErrorCode::BadRequest,
                "a secret must be UTF-8 to go in a JSON body",
            )
        })?;
        insert_at_pointer(&mut document, pointer, text)?;
    }
    let mut output = Zeroizing::new(Vec::with_capacity(json_room(fields, body)));
    document
        .write(&mut output)
        .map_err(|_| BrokerError::new(ErrorCode::Internal, "could not write JSON"))?;
    Ok(output)
}

/// Inserts at an RFC 6901 pointer, creating objects on the way. Nothing may already
/// exist at the location, and it cannot go through anything but objects.
fn insert_at_pointer<'a>(
    document: &mut Node<'a>,
    pointer: &str,
    text: &'a str,
) -> Result<(), BrokerError> {
    let through_something_set = || {
        BrokerError::new(
            ErrorCode::Conflict,
            "a JSON injection's location goes through something the caller set",
        )
    };
    let segments: Vec<String> = pointer
        .split('/')
        .skip(1)
        .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
        .collect();
    let (last, parents) = segments
        .split_last()
        .ok_or_else(|| BrokerError::new(ErrorCode::Internal, "JSON pointer is empty"))?;
    // An object on the way that passed as JSON but cannot be read might hold the very
    // location, set by the caller, so the body is refused.
    let unreadable = |_| BrokerError::new(ErrorCode::BadRequest, "body is not valid JSON");
    let mut current = document;
    for segment in parents {
        current = current
            .object_mut()
            .map_err(unreadable)?
            .ok_or_else(through_something_set)?
            .entry(segment.clone())
            .or_insert_with(Node::empty_object);
    }
    let object = current
        .object_mut()
        .map_err(unreadable)?
        .ok_or_else(through_something_set)?;
    if object.contains_key(last) {
        return Err(BrokerError::new(
            ErrorCode::Conflict,
            "the caller set a JSON location an injection sets",
        ));
    }
    object.insert(last.clone(), Node::Text(text));
    Ok(())
}

#[cfg(test)]
mod tests;
