//! The rules a policy must meet, before sealing and after opening.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Definition, Destination, Inject, JwtAudience, JwtClaims, JwtHeader, MAX_POLICY_BYTES, Part,
    PgTls, Policy, ResponseFormat, Rule, RuleLimits, Scheme, SealResponse,
};
use crate::error::FormatError;
use crate::id::PolicyName;

const MAX_RULES: usize = 16;
const MAX_DEFINITIONS: usize = 8;
const MAX_SEALED_FIELDS: usize = 8;
const MAX_EXPOSED_CLAIMS: usize = 8;
const MAX_DATABASES: usize = 64;
const MAX_JWT_LIFETIME_S: u16 = 300;
const MAX_NAME_BYTES: usize = 256;
const MAX_AUDIENCE_BYTES: usize = 2048;
const MAX_REQUIRED_FIELDS: usize = 8;
const MAX_ALLOWED_VALUES: usize = 16;

/// Headers a rule may not inject into: hop-by-hop ones, and those seal sets.
const FORBIDDEN_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Claims seal sets itself, or that have their own field in [`JwtClaims`].
const RESERVED_CLAIMS: &[&str] = &["aud", "exp", "iat", "iss", "jti", "nbf", "scope", "sub"];

fn refuse<T>(reason: &'static str) -> Result<T, FormatError> {
    Err(FormatError::InvalidPolicy(reason))
}

fn require(condition: bool, reason: &'static str) -> Result<(), FormatError> {
    if condition { Ok(()) } else { refuse(reason) }
}

fn has_control_character(value: &str) -> bool {
    value.chars().any(char::is_control)
}

pub(super) fn policy(policy: &Policy) -> Result<(), FormatError> {
    require(
        policy.definitions.len() <= MAX_DEFINITIONS,
        "too many definitions",
    )?;
    // A policy that only verifies sends its secret nowhere, and has no rules.
    require(
        !policy.rules.is_empty() || policy.verify.is_some(),
        "a policy needs a rule or a verification",
    )?;
    if !policy.rules.is_empty() {
        rules(&policy.rules, &policy.definitions)?;
    }
    for definition in policy.definitions.values() {
        rules(&definition.rules, &policy.definitions)?;
    }
    require(
        policy.canonical_json()?.len() <= MAX_POLICY_BYTES,
        "serialised policy is too large",
    )
}

fn rules(
    rules: &[Rule],
    definitions: &BTreeMap<PolicyName, Definition>,
) -> Result<(), FormatError> {
    require(!rules.is_empty(), "a rule list is empty")?;
    require(rules.len() <= MAX_RULES, "too many rules")?;
    rules.iter().try_for_each(|r| rule(r, definitions))
}

fn rule(rule: &Rule, definitions: &BTreeMap<PolicyName, Definition>) -> Result<(), FormatError> {
    destination(&rule.destination)?;
    inject(&rule.inject)?;
    injection_fits_destination(rule)?;
    presign_names_its_methods(rule)?;
    plain_http(rule)?;
    if let Some(methods) = &rule.methods {
        require(!methods.is_empty(), "a method list is empty")?;
        require(
            matches!(rule.destination, Destination::Http { .. }),
            "only HTTP rules have methods",
        )?;
    }
    if let Some(response) = &rule.seal_response {
        require(
            matches!(rule.destination, Destination::Http { .. }),
            "only HTTP rules seal responses",
        )?;
        require(
            !matches!(rule.inject, Inject::Companion {}),
            "a companion rule cannot seal responses",
        )?;
        seal_response(response, definitions)?;
    }
    if matches!(rule.inject, Inject::Companion {}) {
        require(
            rule.plain.is_empty(),
            "a companion rule has no plain fields",
        )?;
    }
    required_form(rule)?;
    rule.limits.as_ref().map_or(Ok(()), limits)
}

fn required_form(rule: &Rule) -> Result<(), FormatError> {
    if rule.require_form.is_empty() {
        return Ok(());
    }
    require(
        matches!(rule.destination, Destination::Http { .. }),
        "only HTTP rules require form fields",
    )?;
    require(
        rule.require_form.len() <= MAX_REQUIRED_FIELDS,
        "too many required form fields",
    )?;
    let injected = match &rule.inject {
        Inject::FormField { name } => Some(name.as_str()),
        Inject::JwtAssertion { form_field, .. } => Some(form_field.as_str()),
        _ => None,
    };
    for (name, values) in &rule.require_form {
        parameter_name(name)?;
        // The caller would have to set it, and could not, since the rule injects it.
        require(
            Some(name.as_str()) != injected,
            "a rule cannot require a form field it injects",
        )?;
        require(
            !values.is_empty() && values.len() <= MAX_ALLOWED_VALUES,
            "a required form field needs between 1 and 16 allowed values",
        )?;
        for (index, value) in values.iter().enumerate() {
            require(
                !value.is_empty() && value.len() <= MAX_NAME_BYTES && !has_control_character(value),
                "an allowed form value is not valid",
            )?;
            require(
                !values[..index].contains(value),
                "an allowed form value repeats",
            )?;
        }
    }
    Ok(())
}

fn destination(destination: &Destination) -> Result<(), FormatError> {
    match destination {
        Destination::Http {
            port, path_prefix, ..
        } => {
            require(*port != Some(0), "port is zero")?;
            path_prefix.as_deref().map_or(Ok(()), self::path_prefix)
        }
        Destination::Postgres {
            port,
            databases,
            user,
            tls,
            ..
        } => {
            require(*port != 0, "port is zero")?;
            require(!databases.is_empty(), "a database list is empty")?;
            require(databases.len() <= MAX_DATABASES, "too many databases")?;
            for database in databases {
                require(
                    !database.is_empty() && !has_control_character(database),
                    "a database name is not valid",
                )?;
            }
            part(user)?;
            match tls {
                PgTls::VerifyFull => Ok(()),
                PgTls::Ca(ca) => pem(ca),
            }
        }
    }
}

/// Starts with `/`, with no dot segments, encoded separators or empty segments
/// that could make a path mean something other than it appears to.
fn path_prefix(prefix: &str) -> Result<(), FormatError> {
    require(prefix.starts_with('/'), "path prefix does not start with /")?;
    let lower = prefix.to_ascii_lowercase();
    require(
        !["%2e", "%2f", "%5c"]
            .iter()
            .any(|encoded| lower.contains(encoded)),
        "path prefix has an encoded dot or separator",
    )?;
    require(
        !prefix
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '\\' | '?' | '#')),
        "path prefix has a character that is not allowed",
    )?;
    let segments: Vec<&str> = prefix[1..].split('/').collect();
    let last = segments.len() - 1;
    for (index, segment) in segments.iter().enumerate() {
        require(
            !matches!(*segment, "." | ".."),
            "path prefix has a dot segment",
        )?;
        // Only the last segment may be empty, which is a trailing slash.
        require(
            !segment.is_empty() || index == last,
            "path prefix has an empty segment",
        )?;
    }
    Ok(())
}

/// What a path injection puts before the caller's path: whole segments, written only
/// with characters a path keeps as they are, with one `{}` for the secret. It does not
/// end with `/`, because the caller's path starts with one.
fn injected_path(prefix: &str) -> Result<(), FormatError> {
    require(
        prefix.len() <= MAX_NAME_BYTES && prefix.matches("{}").count() == 1,
        "an injected path needs exactly one {}",
    )?;
    let written = prefix.replacen("{}", "", 1);
    require(
        written
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&byte)),
        "an injected path has a character that is not allowed",
    )?;
    require(
        prefix.starts_with('/') && !prefix.ends_with('/'),
        "an injected path starts with / and does not end with one",
    )?;
    require(
        prefix[1..]
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | "..")),
        "an injected path has an empty or dot segment",
    )
}

fn inject(inject: &Inject) -> Result<(), FormatError> {
    match inject {
        Inject::Header { name, format } => {
            header_name(name)?;
            require(
                format.matches("{}").count() == 1 && !has_control_character(format),
                "header format needs exactly one {} and no control characters",
            )
        }
        Inject::Basic { username } => part(username),
        Inject::Query { name } | Inject::FormField { name } => parameter_name(name),
        Inject::Path { prefix } => injected_path(prefix),
        Inject::JsonField { pointer } => json_pointer(pointer),
        Inject::ClientCert {
            cert, chain, ca, ..
        } => {
            pem_part(cert)?;
            chain.as_ref().map_or(Ok(()), pem_part)?;
            ca.as_deref().map_or(Ok(()), pem)
        }
        Inject::AwsSigv4 {
            region,
            service,
            access_key_id,
            session_token,
            payload,
            allow_unsigned_payload,
            allow_headers,
            allow_presign,
        } => {
            if let Some(terms) = allow_presign {
                presign(terms)?;
                require(service == "s3", "only S3 URLs can be presigned")?;
            }
            for (index, header) in allow_headers.iter().enumerate() {
                require(
                    super::OPT_IN_AMZ_HEADERS.contains(&header.as_str()),
                    "an allowed X-Amz header is not one a rule can allow",
                )?;
                require(
                    !allow_headers[..index].contains(header),
                    "an allowed X-Amz header repeats",
                )?;
            }
            aws_scope(region)?;
            aws_scope(service)?;
            part(access_key_id)?;
            session_token.as_ref().map_or(Ok(()), part)?;
            require(
                !payload.is_empty() || *allow_unsigned_payload,
                "SigV4 needs a payload mode",
            )?;
            for (index, mode) in payload.iter().enumerate() {
                require(!payload[..index].contains(mode), "a payload mode repeats")?;
            }
            Ok(())
        }
        Inject::AzureSharedKey {
            account,
            service,
            allow_presign,
        } => {
            if let Some(terms) = allow_presign {
                presign(terms)?;
                require(
                    *service == super::AzureService::Blob,
                    "only a blob can have a shared access signature",
                )?;
            }
            part(account)
        }
        Inject::JwtAssertion {
            aud,
            claims,
            header,
            form_field,
            max_lifetime_s,
            ..
        } => {
            require(
                (1..=MAX_JWT_LIFETIME_S).contains(max_lifetime_s),
                "JWT lifetime must be between 1 and 300 seconds",
            )?;
            audience(aud)?;
            jwt_claims(claims)?;
            jwt_header(header)?;
            parameter_name(form_field)
        }
        Inject::PgPassword { .. } | Inject::Companion {} => Ok(()),
    }
}

fn presign(terms: &super::Presign) -> Result<(), FormatError> {
    require(
        (1..=super::MAX_PRESIGN_EXPIRY_S).contains(&terms.max_expiry_s),
        "a presigned URL lasts between a second and seven days",
    )
}

/// A presigned URL is used without seal, so its rule says which methods it may be for
/// rather than leaving every method open.
fn presign_names_its_methods(rule: &Rule) -> Result<(), FormatError> {
    let allows = matches!(
        &rule.inject,
        Inject::AwsSigv4 {
            allow_presign: Some(_),
            ..
        } | Inject::AzureSharedKey {
            allow_presign: Some(_),
            ..
        }
    );
    require(
        !allows || rule.methods.is_some(),
        "a rule that allows presigning names its methods",
    )
}

fn injection_fits_destination(rule: &Rule) -> Result<(), FormatError> {
    match (&rule.destination, &rule.inject) {
        (Destination::Postgres { .. }, Inject::PgPassword { .. } | Inject::ClientCert { .. })
        | (Destination::Postgres { .. } | Destination::Http { .. }, Inject::Companion {}) => Ok(()),
        (Destination::Postgres { .. }, _) => {
            refuse("a Postgres rule injects a password or a client certificate")
        }
        (Destination::Http { .. }, Inject::PgPassword { .. }) => {
            refuse("an HTTP rule cannot inject a Postgres password")
        }
        (
            Destination::Http {
                scheme,
                path_prefix,
                ..
            },
            inject,
        ) => {
            if let Inject::AwsSigv4 { allow_headers, .. } = inject
                && allow_headers
                    .iter()
                    .any(|header| header == "x-amz-copy-source")
            {
                // The source is checked against the prefix, so there must be one, naming
                // at least the bucket: a virtual-hosted bucket is in the host instead.
                require(
                    path_prefix.as_deref().is_some_and(|path| path.len() > 1),
                    "copy sources need a path prefix naming the bucket",
                )?;
            }
            if matches!(inject, Inject::ClientCert { .. }) {
                require(
                    *scheme == Scheme::Https,
                    "client certificates need scheme https",
                )?;
            }
            if matches!(inject, Inject::JwtAssertion { .. }) {
                // The JWT may go only to this exact endpoint.
                require(
                    path_prefix
                        .as_deref()
                        .is_some_and(|path| path.len() > 1 && !path.ends_with('/')),
                    "a JWT rule's path prefix must be the token endpoint's full path",
                )?;
            }
            Ok(())
        }
    }
}

fn plain_http(rule: &Rule) -> Result<(), FormatError> {
    let is_plain = matches!(
        rule.destination,
        Destination::Http {
            scheme: Scheme::Http,
            ..
        }
    );
    require(
        is_plain == rule.allow_plain_http,
        "scheme http and allow_plain_http go together",
    )
}

fn seal_response(
    response: &SealResponse,
    definitions: &BTreeMap<PolicyName, Definition>,
) -> Result<(), FormatError> {
    require(!response.fields.is_empty(), "seal_response has no fields")?;
    require(
        response.fields.len() <= MAX_SEALED_FIELDS,
        "seal_response has too many fields",
    )?;
    let mut names = BTreeSet::new();
    for field in &response.fields {
        require(
            names.insert(&field.as_field),
            "seal_response repeats a field name",
        )?;
        require(
            definitions.contains_key(&field.policy),
            "seal_response names an unknown definition",
        )?;
        require(
            field.expose_claims.len() <= MAX_EXPOSED_CLAIMS,
            "a sealed field exposes too many claims",
        )?;
        for (index, claim) in field.expose_claims.iter().enumerate() {
            parameter_name(claim)?;
            require(
                !field.expose_claims[..index].contains(claim),
                "an exposed claim repeats",
            )?;
        }
        match response.format {
            ResponseFormat::Json => {
                json_pointer(&field.at)?;
            }
            ResponseFormat::Form => parameter_name(&field.at)?,
            ResponseFormat::Xml => xml_path(&field.at)?,
        }
    }
    Ok(())
}

fn limits(limits: &RuleLimits) -> Result<(), FormatError> {
    let timeouts = [
        limits.idle_timeout_s,
        limits.connect_timeout_s,
        limits.first_byte_timeout_s,
        limits.buffered_total_timeout_s,
        limits.max_stream_duration_s,
        limits.pg_max_session_s,
    ];
    require(
        limits.buffer_cap_bytes != Some(0) && !timeouts.contains(&Some(0)),
        "a limit is zero",
    )
}

fn part(part: &Part) -> Result<(), FormatError> {
    match part {
        Part::Field(_) => Ok(()),
        Part::Literal(value) => require(
            !value.is_empty() && !has_control_character(value),
            "a literal value is empty or has control characters",
        ),
    }
}

/// A part that holds PEM, whose literal has lines: the only control characters it may
/// have are the ones that end them.
fn pem_part(part: &Part) -> Result<(), FormatError> {
    match part {
        Part::Field(_) => Ok(()),
        Part::Literal(value) => require(
            !value.is_empty()
                && !value
                    .chars()
                    .any(|c| c.is_control() && !matches!(c, '\r' | '\n')),
            "a certificate literal is empty or has control characters",
        ),
    }
}

/// An RFC 7230 token, which is not a header a rule may not inject into.
fn header_name(name: &str) -> Result<(), FormatError> {
    let is_token = !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte));
    require(is_token, "header name is not valid")?;
    let lower = name.to_ascii_lowercase();
    require(
        !FORBIDDEN_HEADERS.contains(&lower.as_str()) && !lower.starts_with("proxy-"),
        "header cannot be injected into",
    )
}

fn parameter_name(name: &str) -> Result<(), FormatError> {
    require(
        !name.is_empty() && name.len() <= MAX_NAME_BYTES && !has_control_character(name),
        "a field or parameter name is not valid",
    )
}

/// A non-empty RFC 6901 pointer, so that it never means the whole document.
fn json_pointer(pointer: &str) -> Result<(), FormatError> {
    require(
        pointer.starts_with('/') && pointer.len() <= MAX_NAME_BYTES,
        "JSON pointer must start with /",
    )?;
    let mut rest = pointer;
    while let Some(index) = rest.find('~') {
        rest = &rest[index + 1..];
        require(
            rest.starts_with('0') || rest.starts_with('1'),
            "JSON pointer has a bad ~ escape",
        )?;
    }
    require(
        !has_control_character(pointer),
        "JSON pointer has a control character",
    )
}

fn xml_path(path: &str) -> Result<(), FormatError> {
    require(
        path.len() <= MAX_NAME_BYTES
            && path.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
                    })
            }),
        "XML path is not valid",
    )
}

fn aws_scope(value: &str) -> Result<(), FormatError> {
    require(
        !value.is_empty()
            && value.len() <= MAX_NAME_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "AWS region or service is not valid",
    )
}

fn pem(value: &str) -> Result<(), FormatError> {
    require(value.starts_with("-----BEGIN "), "PEM value is not valid")
}

fn audience(audience: &JwtAudience) -> Result<(), FormatError> {
    match audience {
        JwtAudience::TokenEndpoint => Ok(()),
        JwtAudience::Value(value) => {
            require(
                !value.is_empty()
                    && value.len() <= MAX_AUDIENCE_BYTES
                    && !has_control_character(value),
                "JWT audience is not valid",
            )?;
            // RFC 7519: a StringOrURI with a colon must be a URI.
            // The whitespace check is needed because the parser would accept
            // and percent-encode it, and the value is sent byte for byte.
            require(
                !value.contains(':')
                    || (!value.chars().any(char::is_whitespace) && url::Url::parse(value).is_ok()),
                "JWT audience contains a colon but is not a URI",
            )
        }
    }
}

fn jwt_claims(claims: &JwtClaims) -> Result<(), FormatError> {
    let mut values = vec![claims.iss.as_str()];
    values.extend(claims.sub.as_deref());
    values.extend(claims.scope.as_deref());
    for (name, value) in &claims.extra {
        parameter_name(name)?;
        require(
            !RESERVED_CLAIMS.contains(&name.as_str()),
            "an extra JWT claim has a reserved name",
        )?;
        values.push(value);
    }
    require(
        values
            .iter()
            .all(|value| !value.is_empty() && !has_control_character(value)),
        "a JWT claim is empty or has control characters",
    )
}

fn jwt_header(header: &JwtHeader) -> Result<(), FormatError> {
    require(
        [&header.typ, &header.kid, &header.x5t_s256]
            .into_iter()
            .flatten()
            .all(|value| !value.is_empty() && !has_control_character(value)),
        "a JWT header parameter is empty or has control characters",
    )
}
