//! Decides whether a request may use the sealed values it presents.
//!
//! A pure function with no I/O and no access to plaintext: it sees the policies of
//! values that have already opened, never the secrets.
//!
//! Anyone with a keyset's public key can seal a new value with any policy, so every
//! policy here is untrusted input when values are combined. One value's rule must
//! never weaken how another value is used: conflicts refuse, and options that weaken
//! a guarantee apply only if every matched rule sets them.

use std::collections::{BTreeMap, BTreeSet};

use seal_format::policy::{Inject, Method, Part, Rule, RuleLimits, SealResponse};
use seal_format::{FieldName, Policy};

use crate::error::{BrokerError, ErrorCode};
use crate::target::Target;

/// One rule's use of a field's secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Injection {
    /// The field whose secret this injects.
    pub field: FieldName,
    /// The index of the matched rule in that field's policy.
    pub rule_index: usize,
    /// How the secret is attached.
    pub inject: Inject,
}

/// Response fields to seal, and the policy that names their definitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseSealing {
    /// The fields to seal.
    pub sealing: SealResponse,
    /// The policy the sealing rule came from.
    pub policy: Policy,
}

/// What the matcher decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The injections to apply, in field order.
    pub injections: Vec<Injection>,
    /// The index of the matched rule for every sealed field, for the audit record.
    pub rules: BTreeMap<FieldName, usize>,
    /// Response fields to seal, if any rule asks for it.
    pub response: Option<ResponseSealing>,
    /// The strictest of the matched rules' limits.
    pub limits: RuleLimits,
    /// Whether every matched rule allows a private destination.
    pub allow_private_destination: bool,
    /// Form fields the caller's body must have, from every matched rule: each must
    /// appear exactly once with one of the listed values.
    pub form_requirements: Vec<(String, Vec<String>)>,
}

/// Where a caller asks to go.
#[derive(Clone, Copy, Debug)]
pub enum Endpoint<'a> {
    /// An HTTP request's checked target.
    Http(&'a Target),
    /// A Postgres server.
    Postgres {
        /// The host, as the caller named it.
        host: &'a str,
        /// The port.
        port: u16,
    },
}

/// What a caller asks for, without the secrets.
#[derive(Clone, Copy, Debug)]
pub struct RequestHead<'a> {
    /// Where the request goes.
    pub endpoint: Endpoint<'a>,
    /// The method, for HTTP.
    pub method: Method,
    /// The names of the headers the caller sets.
    pub header_names: &'a [&'a str],
    /// The names of the plain fields the caller supplies.
    pub plain: &'a BTreeSet<FieldName>,
    /// The caller's `x-amz-copy-source`, which names an object to read.
    pub copy_source: Option<&'a str>,
}

/// Decides whether a request may use these values.
///
/// # Errors
///
/// Returns [`ErrorCode::PolicyDenied`] if a value's policy does not allow the
/// request, a part of a credential is missing or not permitted, or a value would go
/// unused; [`ErrorCode::Conflict`] if rules conflict or the caller sets something an
/// injection sets; and [`ErrorCode::BadRequest`] if nothing is presented.
pub fn decide(
    policies: &BTreeMap<FieldName, Policy>,
    head: &RequestHead<'_>,
) -> Result<Plan, BrokerError> {
    if policies.is_empty() {
        return Err(BrokerError::new(
            ErrorCode::BadRequest,
            "no sealed fields were presented",
        ));
    }

    // Step 1: each value must allow this request itself.
    let mut matched: BTreeMap<&FieldName, (usize, &Rule)> = BTreeMap::new();
    for (field, policy) in policies {
        let found = policy
            .rules
            .iter()
            .enumerate()
            .find(|(_, rule)| rule_matches(rule, head))
            .ok_or_else(|| {
                BrokerError::for_field(
                    ErrorCode::PolicyDenied,
                    "no rule allows this request",
                    field,
                )
            })?;
        matched.insert(field, found);
    }

    path_injection_stands_alone(&matched)?;

    // Step 2: resolve the parts each primary rule refers to.
    let mut used_as_companion: BTreeSet<&FieldName> = BTreeSet::new();
    let mut listed_plain: BTreeSet<&FieldName> = BTreeSet::new();
    for (field, (_, rule)) in &matched {
        if matches!(rule.inject, Inject::Companion {}) {
            continue;
        }
        for part in rule_parts(rule) {
            let Part::Field(name) = part else { continue };
            resolve_part(field, name, rule, &matched, head, &mut used_as_companion)?;
        }
        listed_plain.extend(rule.plain.iter());
    }

    // Step 3: no secrets along for the ride.
    for (field, (_, rule)) in &matched {
        if matches!(rule.inject, Inject::Companion {}) && !used_as_companion.contains(field) {
            return Err(BrokerError::for_field(
                ErrorCode::PolicyDenied,
                "no matched rule uses this field",
                field,
            ));
        }
    }
    for name in head.plain {
        if !listed_plain.contains(name) {
            return Err(BrokerError::for_field(
                ErrorCode::PolicyDenied,
                "no matched rule lists this plain field",
                name,
            ));
        }
    }

    // Step 4: conflicts.
    let primaries: Vec<(&FieldName, usize, &Rule)> = matched
        .iter()
        .filter(|(_, (_, rule))| !matches!(rule.inject, Inject::Companion {}))
        .map(|(field, (index, rule))| (*field, *index, *rule))
        .collect();
    if primaries.is_empty() {
        return Err(BrokerError::new(
            ErrorCode::PolicyDenied,
            "every presented value is a companion",
        ));
    }
    check_placements(&primaries, head)?;
    let response = agree_on_response_sealing(&primaries, policies)?;

    Ok(Plan {
        injections: primaries
            .iter()
            .map(|(field, index, rule)| Injection {
                field: (*field).clone(),
                rule_index: *index,
                inject: rule.inject.clone(),
            })
            .collect(),
        rules: matched
            .iter()
            .map(|(field, (index, _))| ((*field).clone(), *index))
            .collect(),
        response,
        limits: strictest_limits(matched.values().map(|(_, rule)| *rule)),
        allow_private_destination: matched
            .values()
            .all(|(_, rule)| rule.allow_private_destination),
        form_requirements: matched
            .values()
            .flat_map(|(_, rule)| rule.require_form.iter())
            .map(|(name, values)| (name.clone(), values.clone()))
            .collect(),
    })
}

fn rule_matches(rule: &Rule, head: &RequestHead<'_>) -> bool {
    match head.endpoint {
        Endpoint::Http(target) => {
            target.matches(&rule.destination)
                && rule
                    .methods
                    .as_ref()
                    .is_none_or(|methods| methods.contains(&head.method))
                && signs_only_for_its_exact_endpoint(rule, target)
        }
        Endpoint::Postgres { host, port } => matches!(
            &rule.destination,
            seal_format::policy::Destination::Postgres { host: allowed, port: allowed_port, .. }
                if allowed.as_str() == host && *allowed_port == port
        ),
    }
}

/// A signed assertion names its audience, and may go to that one endpoint only: not to
/// a longer path below it, whatever the prefix would otherwise allow.
fn signs_only_for_its_exact_endpoint(rule: &Rule, target: &Target) -> bool {
    match (&rule.inject, &rule.destination) {
        (
            Inject::JwtAssertion { .. },
            seal_format::policy::Destination::Http { path_prefix, .. },
        ) => path_prefix.as_deref() == Some(target.path.as_str()),
        (Inject::JwtAssertion { .. }, _) => false,
        _ => true,
    }
}

/// The other parts of a credential a rule names: its injection's, and a Postgres
/// destination's user.
fn rule_parts(rule: &Rule) -> Vec<&Part> {
    let mut parts = parts_of(&rule.inject);
    if let seal_format::policy::Destination::Postgres { user, .. } = &rule.destination {
        parts.push(user);
    }
    parts
}

/// The other parts of a credential that an injection names.
fn parts_of(inject: &Inject) -> Vec<&Part> {
    match inject {
        Inject::Basic { username } => vec![username],
        Inject::ClientCert { cert, chain, .. } => {
            std::iter::once(cert).chain(chain.as_ref()).collect()
        }
        Inject::AwsSigv4 {
            access_key_id,
            session_token,
            ..
        } => std::iter::once(access_key_id)
            .chain(session_token.as_ref())
            .collect(),
        Inject::AzureSharedKey { account, .. } => vec![account],
        Inject::Header { .. }
        | Inject::Query { .. }
        | Inject::Path { .. }
        | Inject::FormField { .. }
        | Inject::JsonField { .. }
        | Inject::JwtAssertion { .. }
        | Inject::PgPassword { .. }
        | Inject::Companion {} => Vec::new(),
    }
}

fn resolve_part<'a>(
    field: &FieldName,
    name: &'a FieldName,
    rule: &Rule,
    matched: &BTreeMap<&'a FieldName, (usize, &Rule)>,
    head: &RequestHead<'_>,
    used_as_companion: &mut BTreeSet<&'a FieldName>,
) -> Result<(), BrokerError> {
    if name == field {
        return Err(BrokerError::for_field(
            ErrorCode::PolicyDenied,
            "a rule names its own field as a part",
            field,
        ));
    }
    let sealed = matched.get(name);
    let plain = head.plain.contains(name);
    match (sealed, plain) {
        (Some(_), true) => Err(BrokerError::for_field(
            ErrorCode::PolicyDenied,
            "a part was presented both sealed and plain",
            name,
        )),
        (Some((_, companion)), false) => {
            if matches!(companion.inject, Inject::Companion {}) {
                used_as_companion.insert(name);
                Ok(())
            } else {
                Err(BrokerError::for_field(
                    ErrorCode::PolicyDenied,
                    "this field's rule does not allow use as a companion here",
                    name,
                ))
            }
        }
        (None, true) if rule.plain.contains(name) => Ok(()),
        (None, true) => Err(BrokerError::for_field(
            ErrorCode::PolicyDenied,
            "the rule does not list this plain field",
            name,
        )),
        (None, false) => Err(BrokerError::for_field(
            ErrorCode::PolicyDenied,
            "a part of the credential is missing",
            name,
        )),
    }
}

/// A path injection changes the path every presented value is sent to, after each rule
/// matched the path the caller named. Anyone can seal a value with such a rule, so it may
/// not be combined with any other value: otherwise it would move another value's
/// credential outside that value's path prefix.
fn path_injection_stands_alone(
    matched: &BTreeMap<&FieldName, (usize, &Rule)>,
) -> Result<(), BrokerError> {
    let injects_path = matched
        .iter()
        .find(|(_, (_, rule))| matches!(rule.inject, Inject::Path { .. }));
    match injects_path {
        Some((field, _)) if matched.len() > 1 => Err(BrokerError::for_field(
            ErrorCode::Conflict,
            "a path injection cannot be combined with other values",
            field,
        )),
        _ => Ok(()),
    }
}

/// A place an injection writes to, normalised so that overlaps compare equal.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Placement {
    Header(String),
    Query(String),
    Form(String),
    Json(String),
    /// Client certificates and other injections with one place each.
    Unique(&'static str),
}

fn placements_of(inject: &Inject) -> Vec<Placement> {
    match inject {
        Inject::Header { name, .. } => vec![Placement::Header(name.to_ascii_lowercase())],
        Inject::Basic { .. } => vec![Placement::Header("authorization".to_owned())],
        Inject::Query { name } => vec![Placement::Query(name.clone())],
        Inject::Path { .. } => vec![Placement::Unique("path")],
        Inject::FormField { name } => vec![Placement::Form(name.clone())],
        Inject::JsonField { pointer } => vec![Placement::Json(pointer.clone())],
        Inject::JwtAssertion { form_field, .. } => vec![
            Placement::Form(form_field.clone()),
            Placement::Form("client_assertion_type".to_owned()),
        ],
        Inject::AwsSigv4 { .. } => vec![
            Placement::Header("authorization".to_owned()),
            Placement::Header("x-amz-date".to_owned()),
            Placement::Header("x-amz-content-sha256".to_owned()),
            Placement::Header("x-amz-security-token".to_owned()),
        ],
        Inject::AzureSharedKey { .. } => vec![
            Placement::Header("authorization".to_owned()),
            Placement::Header("x-ms-date".to_owned()),
            Placement::Header("date".to_owned()),
        ],
        Inject::ClientCert { .. } => vec![Placement::Unique("client certificate")],
        Inject::PgPassword { .. } => vec![Placement::Unique("Postgres login")],
        Inject::Companion {} => Vec::new(),
    }
}

fn check_placements(
    primaries: &[(&FieldName, usize, &Rule)],
    head: &RequestHead<'_>,
) -> Result<(), BrokerError> {
    let mut seen = BTreeSet::new();
    for (field, _, rule) in primaries {
        refuse_amz_headers(field, rule, head)?;
        for placement in placements_of(&rule.inject) {
            if let Placement::Header(name) = &placement
                && head
                    .header_names
                    .iter()
                    .any(|header| header.eq_ignore_ascii_case(name))
            {
                // X-Amz-Content-SHA256 in caller-hash mode is checked with signing.
                let caller_hash = name == "x-amz-content-sha256"
                    && matches!(
                        &rule.inject,
                        Inject::AwsSigv4 { payload, .. }
                            if payload.contains(&seal_format::policy::PayloadMode::CallerHash)
                    );
                if !caller_hash {
                    return Err(BrokerError::for_field(
                        ErrorCode::Conflict,
                        "the caller set a header this field's injection sets",
                        field,
                    ));
                }
            }
            if let Placement::Query(name) = &placement
                && matches!(head.endpoint, Endpoint::Http(target) if query_has(target, name))
            {
                return Err(BrokerError::for_field(
                    ErrorCode::Conflict,
                    "the caller set a query parameter this field's injection sets",
                    field,
                ));
            }
            if !seen.insert(placement) {
                return Err(BrokerError::for_field(
                    ErrorCode::Conflict,
                    "two rules inject into the same place",
                    field,
                ));
            }
        }
    }
    json_pointers_do_not_overlap(&seen)
}

/// `X-Amz-*` headers that control signing are SigV4's own, so a caller cannot choose
/// what is signed or how. A caller may set those that only change what the request
/// does, and those its rule allows; `X-Amz-Content-SHA256` only where the rule allows
/// the caller's hash, its form checked when the payload mode is chosen. A copy reads
/// the object its source names, so the source must be within the rule's destination.
fn refuse_amz_headers(
    field: &FieldName,
    rule: &Rule,
    head: &RequestHead<'_>,
) -> Result<(), BrokerError> {
    let Inject::AwsSigv4 {
        payload,
        allow_headers,
        ..
    } = &rule.inject
    else {
        return Ok(());
    };
    let caller_hash = payload.contains(&seal_format::policy::PayloadMode::CallerHash);
    for name in head.header_names {
        let lower = name.to_ascii_lowercase();
        let allowed = (caller_hash && lower == "x-amz-content-sha256")
            || seal_format::policy::amz_header_allowed(&lower, allow_headers);
        if lower.starts_with("x-amz-") && !allowed {
            return Err(BrokerError::for_field(
                ErrorCode::Conflict,
                "the caller set an X-Amz header this rule does not allow",
                field,
            ));
        }
    }
    if let (Some(source), Endpoint::Http(target)) = (head.copy_source, head.endpoint)
        && !copy_source_within(source, &rule.destination, target)
    {
        return Err(BrokerError::for_field(
            ErrorCode::PolicyDenied,
            "the copy source is not within the rule's destination",
            field,
        ));
    }
    Ok(())
}

/// Whether `x-amz-copy-source`, `bucket/key` or `/bucket/key` with an optional
/// `?versionId=`, names an object within the destination. It is read as a path at the
/// request's own scheme, host and port, with the same refusals as a request's URL.
fn copy_source_within(
    source: &str,
    destination: &seal_format::policy::Destination,
    target: &Target,
) -> bool {
    let path = if source.starts_with('/') {
        source.to_owned()
    } else {
        format!("/{source}")
    };
    let (path, query) = path.split_once('?').unwrap_or((path.as_str(), ""));
    let only_a_version =
        query.is_empty() || (query.starts_with("versionId=") && !query[10..].contains(['&', '=']));
    let scheme = match target.scheme {
        seal_format::policy::Scheme::Https => "https",
        seal_format::policy::Scheme::Http => "http",
    };
    let has_prefix = matches!(
        destination,
        seal_format::policy::Destination::Http { path_prefix: Some(prefix), .. } if prefix.len() > 1
    );
    has_prefix
        && only_a_version
        && Target::parse(&format!("{scheme}://{}{path}", target.authority()))
            .is_ok_and(|source| source.matches(destination))
}

/// `/a` and `/a/b` conflict: one would overwrite or be nested in the other.
fn json_pointers_do_not_overlap(placements: &BTreeSet<Placement>) -> Result<(), BrokerError> {
    let pointers: Vec<&str> = placements
        .iter()
        .filter_map(|placement| match placement {
            Placement::Json(pointer) => Some(pointer.as_str()),
            _ => None,
        })
        .collect();
    for (index, first) in pointers.iter().enumerate() {
        for second in &pointers[index + 1..] {
            let nested = |outer: &str, inner: &str| {
                inner
                    .strip_prefix(outer)
                    .is_some_and(|rest| rest.starts_with('/'))
            };
            if nested(first, second) || nested(second, first) {
                return Err(BrokerError::new(
                    ErrorCode::Conflict,
                    "two rules inject into overlapping JSON locations",
                ));
            }
        }
    }
    Ok(())
}

/// Whether a query parameter is present, comparing decoded names.
fn query_has(target: &Target, name: &str) -> bool {
    target
        .query
        .as_deref()
        .is_some_and(|query| form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == name))
}

/// Rules must agree exactly, including all agreeing that there is no sealing.
/// Otherwise a value presented alongside another could strip its sealing, or change
/// where the tokens may go, and a caller could read them.
fn agree_on_response_sealing(
    primaries: &[(&FieldName, usize, &Rule)],
    policies: &BTreeMap<FieldName, Policy>,
) -> Result<Option<ResponseSealing>, BrokerError> {
    let conflict = |field| {
        BrokerError::for_field(
            ErrorCode::Conflict,
            "rules declare different response sealing",
            field,
        )
    };
    let mut agreed: Option<(&SealResponse, &Policy, Vec<u8>)> = None;
    for (position, (field, _, rule)) in primaries.iter().enumerate() {
        let policy = policies.get(*field).ok_or_else(|| conflict(field))?;
        match (&rule.seal_response, &agreed) {
            (None, Some(_)) => return Err(conflict(field)),
            (None, None) => {}
            (Some(_), None) if position > 0 => return Err(conflict(field)),
            (Some(sealing), None) => {
                let form = sealing_canonical_form(sealing, policy)?;
                agreed = Some((sealing, policy, form));
            }
            (Some(sealing), Some((_, _, form))) => {
                if sealing_canonical_form(sealing, policy)? != *form {
                    return Err(conflict(field));
                }
            }
        }
    }
    Ok(agreed.map(|(sealing, policy, _)| ResponseSealing {
        sealing: sealing.clone(),
        policy: policy.clone(),
    }))
}

/// The sealing and every definition it names, directly or indirectly, as bytes.
fn sealing_canonical_form(sealing: &SealResponse, policy: &Policy) -> Result<Vec<u8>, BrokerError> {
    let invalid = || BrokerError::new(ErrorCode::Internal, "could not compare response sealing");
    let mut reachable = BTreeMap::new();
    let mut pending: Vec<&SealResponse> = vec![sealing];
    while let Some(next) = pending.pop() {
        for field in &next.fields {
            if reachable.contains_key(&field.policy) {
                continue;
            }
            let definition = policy.definitions.get(&field.policy).ok_or_else(invalid)?;
            reachable.insert(field.policy.clone(), definition);
            pending.extend(
                definition
                    .rules
                    .iter()
                    .filter_map(|rule| rule.seal_response.as_ref()),
            );
        }
    }
    serde_json::to_vec(&(sealing, reachable)).map_err(|_| invalid())
}

fn strictest_limits<'a>(rules: impl Iterator<Item = &'a Rule>) -> RuleLimits {
    fn tighter<T: Ord + Copy>(first: Option<T>, second: Option<T>) -> Option<T> {
        match (first, second) {
            (Some(first), Some(second)) => Some(first.min(second)),
            (first, second) => first.or(second),
        }
    }
    rules
        .filter_map(|rule| rule.limits)
        .fold(RuleLimits::default(), |all, limits| RuleLimits {
            buffer_cap_bytes: tighter(all.buffer_cap_bytes, limits.buffer_cap_bytes),
            idle_timeout_s: tighter(all.idle_timeout_s, limits.idle_timeout_s),
            connect_timeout_s: tighter(all.connect_timeout_s, limits.connect_timeout_s),
            first_byte_timeout_s: tighter(all.first_byte_timeout_s, limits.first_byte_timeout_s),
            buffered_total_timeout_s: tighter(
                all.buffered_total_timeout_s,
                limits.buffered_total_timeout_s,
            ),
            max_stream_duration_s: tighter(all.max_stream_duration_s, limits.max_stream_duration_s),
            pg_max_session_s: tighter(all.pg_max_session_s, limits.pg_max_session_s),
        })
}

#[cfg(test)]
mod tests;

/// What every matched rule allows for a Postgres session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PgTerms {
    /// The user to log in as.
    pub user: Part,
    /// The databases a session may use: those every matched rule allows.
    pub databases: Vec<String>,
    /// How the server's certificate is verified.
    pub tls: seal_format::policy::PgTls,
    /// Whether every matched rule allows replication.
    pub allow_replication: bool,
    /// The field holding the password, if one was presented, and the weaker methods its
    /// rule allows.
    pub password: Option<PgPassword>,
    /// The field holding a client certificate's private key, with its rule's injection.
    pub client_cert: Option<(FieldName, Inject)>,
}

/// A password and the methods its rule allows besides SCRAM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PgPassword {
    /// The field holding the password.
    pub field: FieldName,
    /// MD5, over TLS.
    pub allow_md5: bool,
    /// A cleartext password, over TLS.
    pub allow_cleartext: bool,
    /// Only a login bound to its TLS connection.
    pub require_channel_binding: bool,
}

/// The terms of a Postgres session, from a plan made for a Postgres endpoint. Matched
/// rules must agree on the user and on TLS; a session may use only the databases all of
/// them allow, and replication only if all of them do.
///
/// # Errors
///
/// [`ErrorCode::PolicyDenied`] if the rules disagree, allow no database in common, or
/// present two passwords or two client certificates.
pub fn postgres_terms(
    policies: &BTreeMap<FieldName, Policy>,
    plan: &Plan,
) -> Result<PgTerms, BrokerError> {
    let denied =
        |detail, field: &FieldName| BrokerError::for_field(ErrorCode::PolicyDenied, detail, field);
    let mut terms: Option<PgTerms> = None;
    for injection in &plan.injections {
        let field = &injection.field;
        let rule = policies
            .get(field)
            .and_then(|policy| policy.rules.get(injection.rule_index))
            .ok_or_else(|| {
                BrokerError::for_field(ErrorCode::Internal, "a matched rule is missing", field)
            })?;
        let seal_format::policy::Destination::Postgres {
            databases,
            user,
            tls,
            allow_replication,
            ..
        } = &rule.destination
        else {
            return Err(denied("this rule is not for a Postgres server", field));
        };
        let current = terms.get_or_insert_with(|| PgTerms {
            user: user.clone(),
            databases: databases.clone(),
            tls: tls.clone(),
            allow_replication: *allow_replication,
            password: None,
            client_cert: None,
        });
        if current.user != *user || current.tls != *tls {
            return Err(denied("rules disagree on the user or on TLS", field));
        }
        current
            .databases
            .retain(|database| databases.contains(database));
        current.allow_replication &= *allow_replication;
        match &injection.inject {
            Inject::PgPassword {
                allow_md5,
                allow_cleartext_password,
                require_channel_binding,
            } => {
                if current.password.is_some() {
                    return Err(denied("two passwords were presented", field));
                }
                current.password = Some(PgPassword {
                    field: field.clone(),
                    allow_md5: *allow_md5,
                    allow_cleartext: *allow_cleartext_password,
                    require_channel_binding: *require_channel_binding,
                });
            }
            Inject::ClientCert { .. } => {
                if current.client_cert.is_some() {
                    return Err(denied("two client certificates were presented", field));
                }
                current.client_cert = Some((field.clone(), injection.inject.clone()));
            }
            _ => return Err(denied("this rule does not log in to Postgres", field)),
        }
    }
    let terms =
        terms.ok_or_else(|| BrokerError::new(ErrorCode::PolicyDenied, "nothing logs in"))?;
    if terms.databases.is_empty() {
        return Err(BrokerError::new(
            ErrorCode::PolicyDenied,
            "the rules allow no database in common",
        ));
    }
    Ok(terms)
}
