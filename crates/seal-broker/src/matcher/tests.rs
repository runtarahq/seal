use proptest::prelude::*;
use seal_format::policy::builder::{self, OAuthClientAuth, OAuthConfig, PartSource};
use seal_format::policy::{Destination, ResponseFormat};
use serde_json::{Value, json};

use super::*;

const API: &str = "https://api.example.com/v2/orders";

fn field(name: &str) -> FieldName {
    FieldName::new(name).unwrap()
}

fn policy(value: &Value) -> Policy {
    Policy::from_json(value.to_string().as_bytes()).unwrap()
}

fn rule(inject: &Value) -> Value {
    json!({
        "destination": { "scheme": "https", "host": "api.example.com" },
        "inject": inject,
    })
}

fn one_rule(inject: &Value) -> Policy {
    policy(&json!({ "rules": [rule(inject)] }))
}

fn bearer() -> Policy {
    builder::bearer("https://api.example.com/v2/").unwrap()
}

fn fields(entries: &[(&str, Policy)]) -> BTreeMap<FieldName, Policy> {
    entries
        .iter()
        .map(|(name, policy)| (field(name), policy.clone()))
        .collect()
}

/// A request with the given method, headers and plain fields.
struct Request {
    target: Target,
    method: Method,
    headers: Vec<&'static str>,
    plain: BTreeSet<FieldName>,
    copy_source: Option<&'static str>,
}

impl Request {
    fn to(url: &str) -> Self {
        Self {
            target: Target::parse(url).unwrap(),
            method: Method::Get,
            headers: Vec::new(),
            plain: BTreeSet::new(),
            copy_source: None,
        }
    }

    fn decide(&self, policies: &BTreeMap<FieldName, Policy>) -> Result<Plan, BrokerError> {
        decide(
            policies,
            &RequestHead {
                endpoint: Endpoint::Http(&self.target),
                method: self.method,
                header_names: &self.headers,
                plain: &self.plain,
                copy_source: self.copy_source,
            },
        )
    }
}

fn refusal(result: Result<Plan, BrokerError>) -> ErrorCode {
    result.unwrap_err().code()
}

// Every value authorises its own use.

#[test]
fn a_matching_rule_gives_a_plan() {
    let plan = Request::to(API)
        .decide(&fields(&[("token", bearer())]))
        .unwrap();
    assert_eq!(plan.injections.len(), 1);
    assert_eq!(plan.injections[0].field, field("token"));
    assert_eq!(plan.injections[0].rule_index, 0);
    assert_eq!(plan.rules[&field("token")], 0);
    assert_eq!(plan.response, None);
    assert!(!plan.allow_private_destination);
}

#[test]
fn nothing_presented_is_refused() {
    assert_eq!(
        refusal(Request::to(API).decide(&BTreeMap::new())),
        ErrorCode::BadRequest
    );
}

#[test]
fn another_destination_is_refused() {
    let policies = fields(&[("token", bearer())]);
    for url in [
        "https://evil.example/v2/orders",
        "https://api.example.com/v3/orders",
        "https://api.example.com:8443/v2/orders",
        "http://api.example.com/v2/orders",
    ] {
        assert_eq!(
            refusal(Request::to(url).decide(&policies)),
            ErrorCode::PolicyDenied,
            "{url}"
        );
    }
}

#[test]
fn a_method_the_rule_does_not_list_is_refused() {
    let mut limited = rule(&json!({ "header": { "name": "A", "format": "{}" } }));
    limited["methods"] = json!(["GET"]);
    let policies = fields(&[("token", policy(&json!({ "rules": [limited] })))]);
    let mut request = Request::to(API);
    assert!(request.decide(&policies).is_ok());
    request.method = Method::Post;
    assert_eq!(refusal(request.decide(&policies)), ErrorCode::PolicyDenied);
}

#[test]
fn the_first_matching_rule_is_used() {
    let wide = rule(&json!({ "header": { "name": "First", "format": "{}" } }));
    let later = rule(&json!({ "header": { "name": "Second", "format": "{}" } }));
    let mut limited = rule(&json!({ "header": { "name": "Limited", "format": "{}" } }));
    limited["methods"] = json!(["POST"]);
    let policies = fields(&[("token", policy(&json!({ "rules": [limited, wide, later] })))]);
    let plan = Request::to(API).decide(&policies).unwrap();
    assert_eq!(plan.injections[0].rule_index, 1);
    assert!(matches!(&plan.injections[0].inject, Inject::Header { name, .. } if name == "First"));
}

#[test]
fn one_value_cannot_lend_its_authority_to_another() {
    // The second value's policy allows another destination only.
    let elsewhere = builder::bearer("https://elsewhere.example/").unwrap();
    let policies = fields(&[
        (
            "good",
            one_rule(&json!({ "header": { "name": "A", "format": "{}" } })),
        ),
        ("other", elsewhere),
    ]);
    let error = Request::to(API).decide(&policies).unwrap_err();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);
    assert!(
        error.detail().contains("other"),
        "the refusal names the field"
    );
}

// Companions.

fn basic_with_sealed_username() -> BTreeMap<FieldName, Policy> {
    let policies = builder::basic(
        "https://api.example.com/",
        PartSource::Sealed(field("username")),
    )
    .unwrap();
    fields(&[
        ("password", policies.secret),
        ("username", policies.companions[&field("username")].clone()),
    ])
}

#[test]
fn a_sealed_companion_is_allowed_when_a_primary_uses_it() {
    let plan = Request::to(API)
        .decide(&basic_with_sealed_username())
        .unwrap();
    assert_eq!(
        plan.injections.len(),
        1,
        "a companion has no injection of its own"
    );
    assert_eq!(plan.injections[0].field, field("password"));
    assert_eq!(plan.rules.len(), 2);
}

#[test]
fn a_missing_part_is_refused() {
    let mut policies = basic_with_sealed_username();
    policies.remove(&field("username"));
    assert_eq!(
        refusal(Request::to(API).decide(&policies)),
        ErrorCode::PolicyDenied
    );
}

#[test]
fn a_companion_no_rule_uses_is_refused() {
    let companion = policy(&json!({ "rules": [rule(&json!({ "companion": {} }))] }));
    let policies = fields(&[("token", bearer()), ("spare", companion)]);
    let error = Request::to(API).decide(&policies).unwrap_err();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);
    assert!(error.detail().contains("spare"));
}

#[test]
fn only_companions_is_refused() {
    let companion = policy(&json!({ "rules": [rule(&json!({ "companion": {} }))] }));
    assert_eq!(
        refusal(Request::to(API).decide(&fields(&[("spare", companion)]))),
        ErrorCode::PolicyDenied
    );
}

#[test]
fn a_field_whose_own_rule_is_not_a_companion_cannot_be_used_as_one() {
    let basic = builder::basic(
        "https://api.example.com/",
        PartSource::Sealed(field("username")),
    )
    .unwrap();
    // A secret with a real rule of its own, here, cannot be pulled in as a part.
    let policies = fields(&[("password", basic.secret), ("username", bearer())]);
    assert_eq!(
        refusal(Request::to(API).decide(&policies)),
        ErrorCode::PolicyDenied
    );
}

#[test]
fn a_companion_cannot_go_where_its_own_rule_does_not_allow() {
    let basic = builder::basic(
        "https://api.example.com/",
        PartSource::Sealed(field("username")),
    )
    .unwrap();
    let elsewhere = builder::basic(
        "https://elsewhere.example/",
        PartSource::Sealed(field("username")),
    )
    .unwrap();
    let policies = fields(&[
        ("password", basic.secret),
        ("username", elsewhere.companions[&field("username")].clone()),
    ]);
    assert_eq!(
        refusal(Request::to(API).decide(&policies)),
        ErrorCode::PolicyDenied
    );
}

#[test]
fn a_rule_cannot_name_its_own_field_as_a_part() {
    let policies = fields(&[(
        "password",
        one_rule(&json!({ "basic": { "username": { "field": "password" } } })),
    )]);
    assert_eq!(
        refusal(Request::to(API).decide(&policies)),
        ErrorCode::PolicyDenied
    );
}

// Plain parts.

fn basic_with_plain_username() -> BTreeMap<FieldName, Policy> {
    let policies = builder::basic(
        "https://api.example.com/",
        PartSource::Plain(field("username")),
    )
    .unwrap();
    fields(&[("password", policies.secret)])
}

#[test]
fn a_plain_part_needs_the_rule_to_list_it() {
    let mut request = Request::to(API);
    request.plain.insert(field("username"));
    assert!(request.decide(&basic_with_plain_username()).is_ok());

    let unlisted = fields(&[(
        "password",
        one_rule(&json!({ "basic": { "username": { "field": "username" } } })),
    )]);
    assert_eq!(refusal(request.decide(&unlisted)), ErrorCode::PolicyDenied);
}

#[test]
fn a_missing_plain_part_is_refused() {
    assert_eq!(
        refusal(Request::to(API).decide(&basic_with_plain_username())),
        ErrorCode::PolicyDenied
    );
}

#[test]
fn a_plain_field_no_rule_lists_is_refused() {
    let mut request = Request::to(API);
    request.plain.insert(field("anything"));
    assert_eq!(
        refusal(request.decide(&fields(&[("token", bearer())]))),
        ErrorCode::PolicyDenied
    );
}

#[test]
fn a_part_presented_both_sealed_and_plain_is_refused() {
    let mut request = Request::to(API);
    request.plain.insert(field("username"));
    assert_eq!(
        refusal(request.decide(&basic_with_sealed_username())),
        ErrorCode::PolicyDenied
    );
}

// Conflicts.

/// A path injection moves the request after every rule matched the caller's path, so
/// a value anyone could seal must not carry another value's credential with it.
#[test]
fn a_path_injection_cannot_be_combined_with_another_value() {
    let path = one_rule(&json!({ "path": { "prefix": "/admin{}" } }));
    let alone = Request::to(API)
        .decide(&fields(&[("token", path.clone())]))
        .unwrap();
    assert_eq!(alone.injections.len(), 1);

    let companion = one_rule(&json!({ "companion": {} }));
    for other in [bearer(), path.clone(), companion] {
        let policies = fields(&[("genuine", other), ("moved", path.clone())]);
        assert_eq!(
            refusal(Request::to(API).decide(&policies)),
            ErrorCode::Conflict
        );
    }
}

#[test]
fn two_rules_injecting_into_the_same_place_conflict() {
    let same = |first: Value, second: Value| {
        refusal(Request::to(API).decide(&fields(&[
            ("a", one_rule(&first)),
            ("b", one_rule(&second)),
        ])))
    };
    let header = |name: &str| json!({ "header": { "name": name, "format": "{}" } });
    assert_eq!(same(header("X-Key"), header("X-Key")), ErrorCode::Conflict);
    assert_eq!(
        same(header("X-Key"), header("x-key")),
        ErrorCode::Conflict,
        "names ignore case"
    );
    assert_eq!(
        same(
            json!({ "query": { "name": "k" } }),
            json!({ "query": { "name": "k" } })
        ),
        ErrorCode::Conflict
    );
    assert_eq!(
        same(
            json!({ "form_field": { "name": "k" } }),
            json!({ "form_field": { "name": "k" } })
        ),
        ErrorCode::Conflict
    );
    assert_eq!(
        same(
            json!({ "json_field": { "pointer": "/a" } }),
            json!({ "json_field": { "pointer": "/a" } })
        ),
        ErrorCode::Conflict
    );
}

#[test]
fn basic_auth_conflicts_with_an_authorization_header() {
    let policies = fields(&[
        (
            "a",
            one_rule(&json!({ "header": { "name": "Authorization", "format": "{}" } })),
        ),
        (
            "b",
            one_rule(&json!({ "basic": { "username": { "literal": "u" } } })),
        ),
    ]);
    assert_eq!(
        refusal(Request::to(API).decide(&policies)),
        ErrorCode::Conflict
    );
}

#[test]
fn overlapping_json_locations_conflict() {
    let pointer = |value: &str| one_rule(&json!({ "json_field": { "pointer": value } }));
    let decide = |first: &str, second: &str| {
        Request::to(API).decide(&fields(&[("a", pointer(first)), ("b", pointer(second))]))
    };
    assert_eq!(refusal(decide("/a", "/a/b")), ErrorCode::Conflict);
    assert_eq!(refusal(decide("/a/b", "/a")), ErrorCode::Conflict);
    assert!(decide("/a", "/ab").is_ok(), "only a whole segment nests");
    assert!(decide("/a/b", "/a/c").is_ok());
}

#[test]
fn different_places_do_not_conflict() {
    let policies = fields(&[
        (
            "a",
            one_rule(&json!({ "header": { "name": "A", "format": "{}" } })),
        ),
        (
            "b",
            one_rule(&json!({ "header": { "name": "B", "format": "{}" } })),
        ),
        ("c", one_rule(&json!({ "query": { "name": "a" } }))),
        ("d", one_rule(&json!({ "form_field": { "name": "a" } }))),
    ]);
    assert_eq!(
        Request::to(API).decide(&policies).unwrap().injections.len(),
        4
    );
}

// What the caller may not set.

#[test]
fn the_caller_cannot_set_an_injected_header() {
    let policies = fields(&[("token", bearer())]);
    for name in ["Authorization", "authorization", "AUTHORIZATION"] {
        let mut request = Request::to(API);
        request.headers = vec![name];
        assert_eq!(
            refusal(request.decide(&policies)),
            ErrorCode::Conflict,
            "{name}"
        );
    }
}

#[test]
fn the_caller_can_set_other_headers() {
    let mut request = Request::to(API);
    request.headers = vec!["Accept", "X-Request-Id"];
    assert!(request.decide(&fields(&[("token", bearer())])).is_ok());
}

#[test]
fn the_caller_cannot_set_authorization_with_basic_auth() {
    let mut request = Request::to(API);
    request.headers = vec!["authorization"];
    let policies = fields(&[(
        "p",
        one_rule(&json!({ "basic": { "username": { "literal": "u" } } })),
    )]);
    assert_eq!(refusal(request.decide(&policies)), ErrorCode::Conflict);
}

#[test]
fn the_caller_cannot_set_an_injected_query_parameter_even_encoded() {
    let policies = fields(&[("key", one_rule(&json!({ "query": { "name": "api_key" } })))]);
    assert!(
        Request::to("https://api.example.com/a?other=1")
            .decide(&policies)
            .is_ok()
    );
    for url in [
        "https://api.example.com/a?api_key=x",
        "https://api.example.com/a?other=1&api_key=x",
        "https://api.example.com/a?api%5Fkey=x",
        "https://api.example.com/a?api_key",
    ] {
        assert_eq!(
            refusal(Request::to(url).decide(&policies)),
            ErrorCode::Conflict,
            "{url}"
        );
    }
}

// Response sealing.

fn sealing(policy_name: &str) -> Value {
    json!({
        "format": "json",
        "fields": [{ "at": "/access_token", "as": "access_token", "policy": policy_name }]
    })
}

fn sealing_policy(inject: &Value, api_host: &str) -> Policy {
    let mut sealing_rule = rule(inject);
    sealing_rule["seal_response"] = sealing("api");
    policy(&json!({
        "rules": [sealing_rule],
        "definitions": { "api": { "rules": [{
            "destination": { "scheme": "https", "host": api_host },
            "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } }
        }] } }
    }))
}

fn form(name: &str) -> Value {
    json!({ "form_field": { "name": name } })
}

#[test]
fn response_sealing_goes_into_the_plan() {
    let plan = Request::to(API)
        .decide(&fields(&[(
            "secret",
            sealing_policy(&form("a"), "api.example.com"),
        )]))
        .unwrap();
    let response = plan.response.unwrap();
    assert_eq!(response.sealing.fields[0].at, "/access_token");
    assert_eq!(response.policy.definitions.len(), 1);
}

#[test]
fn rules_that_agree_on_sealing_are_accepted() {
    let policies = fields(&[
        ("a", sealing_policy(&form("a"), "api.example.com")),
        ("b", sealing_policy(&form("b"), "api.example.com")),
    ]);
    assert!(
        Request::to(API)
            .decide(&policies)
            .unwrap()
            .response
            .is_some()
    );
}

/// A sealed value made by the attacker must not strip another value's sealing, or
/// the attacker reads the tokens in the response.
#[test]
fn a_value_without_sealing_cannot_strip_another_values_sealing() {
    let genuine = sealing_policy(&form("client_secret"), "api.example.com");
    let plain = one_rule(&form("z_attacker"));
    let early = one_rule(&form("a_attacker"));
    for attacker in ["a_attacker", "z_attacker"] {
        let policies = if attacker == "a_attacker" {
            fields(&[
                ("a_attacker", early.clone()),
                ("m_genuine", genuine.clone()),
            ])
        } else {
            fields(&[
                ("m_genuine", genuine.clone()),
                ("z_attacker", plain.clone()),
            ])
        };
        assert_eq!(
            refusal(Request::to(API).decide(&policies)),
            ErrorCode::Conflict,
            "{attacker}"
        );
    }
}

/// Nor may it have a token's claims returned in plaintext, where the genuine value's
/// policy exposes none.
#[test]
fn a_value_cannot_expose_claims_another_values_sealing_does_not() {
    let genuine = sealing_policy(&form("client_secret"), "api.example.com");
    let mut exposing = sealing_policy(&form("x"), "api.example.com");
    let sealing = exposing.rules[0].seal_response.as_mut().unwrap();
    sealing.fields[0].expose_claims = vec!["sub".to_owned()];
    let policies = fields(&[("a_attacker", exposing), ("m_genuine", genuine)]);
    assert_eq!(
        refusal(Request::to(API).decide(&policies)),
        ErrorCode::Conflict
    );
}

/// Nor may it send the tokens somewhere it can read them, by naming a definition
/// with the same name and different rules.
#[test]
fn a_value_cannot_change_where_sealed_tokens_may_go() {
    let policies = fields(&[
        ("a_attacker", sealing_policy(&form("x"), "evil.example")),
        (
            "m_genuine",
            sealing_policy(&form("client_secret"), "api.example.com"),
        ),
    ]);
    assert_eq!(
        refusal(Request::to(API).decide(&policies)),
        ErrorCode::Conflict
    );
}

#[test]
fn indirectly_named_definitions_are_compared_too() {
    let with_nested = |host: &str| {
        let mut outer = rule(&form("a"));
        outer["seal_response"] = sealing("first");
        let mut first =
            rule(&json!({ "header": { "name": "Authorization", "format": "Bearer {}" } }));
        first["seal_response"] = sealing("second");
        policy(&json!({
            "rules": [outer],
            "definitions": {
                "first": { "rules": [first] },
                "second": { "rules": [{
                    "destination": { "scheme": "https", "host": host },
                    "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } }
                }] }
            }
        }))
    };
    let mut other_field = with_nested("api.example.com");
    other_field.rules[0].inject = Inject::FormField {
        name: "b".to_owned(),
    };
    assert!(
        Request::to(API)
            .decide(&fields(&[
                ("a", with_nested("api.example.com")),
                ("b", other_field.clone())
            ]))
            .is_ok()
    );

    let mut attacker = with_nested("evil.example");
    attacker.rules[0].inject = Inject::FormField {
        name: "b".to_owned(),
    };
    assert_eq!(
        refusal(Request::to(API).decide(&fields(&[
            ("a", with_nested("api.example.com")),
            ("b", attacker)
        ]))),
        ErrorCode::Conflict
    );
}

#[test]
fn the_oauth_builders_refresh_token_and_client_secret_agree() {
    let policies = builder::oauth_client(&OAuthConfig {
        token_url: "https://auth.example.com/token".to_owned(),
        revoke_url: None,
        api_base: "https://api.example.com/".to_owned(),
        auth: OAuthClientAuth::ClientSecretPost,
        response_format: ResponseFormat::Json,
        shared: false,
        access_token_claims: Vec::new(),
    })
    .unwrap();
    let refresh = policies
        .client
        .for_response_field(&seal_format::PolicyName::new("refresh").unwrap())
        .unwrap();
    let plan = Request::to("https://auth.example.com/token")
        .decide(&fields(&[
            ("client_secret", policies.client),
            ("refresh_token", refresh),
        ]))
        .unwrap();
    assert_eq!(plan.injections.len(), 2);
    assert!(plan.response.is_some());
}

#[test]
fn a_companion_does_not_need_to_declare_sealing() {
    let mut primary = rule(&json!({ "basic": { "username": { "field": "user" } } }));
    primary["seal_response"] = sealing("api");
    let primary = policy(&json!({
        "rules": [primary],
        "definitions": { "api": { "rules": [rule(&form("x"))] } }
    }));
    let companion = policy(&json!({ "rules": [rule(&json!({ "companion": {} }))] }));
    let plan = Request::to(API)
        .decide(&fields(&[("password", primary), ("user", companion)]))
        .unwrap();
    assert!(plan.response.is_some());
}

// Options merged across values.

fn with_private(value: bool) -> Policy {
    let mut flagged =
        rule(&json!({ "header": { "name": if value { "A" } else { "B" }, "format": "{}" } }));
    flagged["allow_private_destination"] = json!(value);
    policy(&json!({ "rules": [flagged] }))
}

#[test]
fn private_destinations_need_every_matched_rule_to_allow_them() {
    let decide = |entries: &[(&str, Policy)]| {
        Request::to(API)
            .decide(&fields(entries))
            .unwrap()
            .allow_private_destination
    };
    assert!(decide(&[("a", with_private(true))]));
    assert!(!decide(&[("a", with_private(false))]));
    assert!(
        !decide(&[("a", with_private(true)), ("b", with_private(false))]),
        "a value made by an attacker cannot widen another value's destination"
    );
}

#[test]
fn limits_merge_to_the_strictest() {
    let limited = |name: &str, limits: Value| {
        let mut value = rule(&json!({ "header": { "name": name, "format": "{}" } }));
        value["limits"] = limits;
        policy(&json!({ "rules": [value] }))
    };
    let plan = Request::to(API)
        .decide(&fields(&[
            (
                "a",
                limited("A", json!({ "idle_timeout_s": 30, "connect_timeout_s": 5 })),
            ),
            (
                "b",
                limited(
                    "B",
                    json!({ "idle_timeout_s": 10, "buffer_cap_bytes": 100 }),
                ),
            ),
            (
                "c",
                one_rule(&json!({ "header": { "name": "C", "format": "{}" } })),
            ),
        ]))
        .unwrap();
    assert_eq!(plan.limits.idle_timeout_s, Some(10));
    assert_eq!(plan.limits.connect_timeout_s, Some(5));
    assert_eq!(plan.limits.buffer_cap_bytes, Some(100));
    assert_eq!(plan.limits.first_byte_timeout_s, None);
}

// Errors.

#[test]
fn errors_name_fields_and_never_literals() {
    let policies = fields(&[(
        "password",
        one_rule(&json!({ "basic": { "username": { "field": "missing_user" } } })),
    )]);
    let error = Request::to(API).decide(&policies).unwrap_err();
    assert!(error.detail().contains("missing_user"));
    let literal = fields(&[(
        "token",
        one_rule(&json!({ "basic": { "username": { "literal": "SECRETVALUE" } } })),
    )]);
    let mut request = Request::to("https://evil.example/");
    request.headers = vec!["authorization"];
    let error = request.decide(&literal).unwrap_err();
    assert!(!error.to_string().contains("SECRETVALUE"));
}

// Properties.

fn segment() -> impl Strategy<Value = String> {
    "[a-z0-9]{1,4}"
}

fn path() -> impl Strategy<Value = String> {
    proptest::collection::vec(segment(), 0..4).prop_flat_map(|segments| {
        let joined = format!("/{}", segments.join("/"));
        prop_oneof![
            Just(joined.clone()),
            Just(format!("{}/", joined.trim_end_matches('/')))
        ]
    })
}

fn any_method() -> impl Strategy<Value = Method> {
    prop_oneof![
        Just(Method::Get),
        Just(Method::Head),
        Just(Method::Post),
        Just(Method::Put),
        Just(Method::Patch),
        Just(Method::Delete),
        Just(Method::Options),
    ]
}

fn host() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("a.example.com".to_owned()),
        Just("b.example.com".to_owned()),
        Just("a.example.com.evil.example".to_owned()),
    ]
}

fn scheme() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("https"), Just("http")]
}

fn port() -> impl Strategy<Value = Option<u16>> {
    prop_oneof![
        Just(None),
        Just(Some(443)),
        Just(Some(80)),
        Just(Some(8443))
    ]
}

fn random_rule() -> impl Strategy<Value = Rule> {
    (
        scheme(),
        host(),
        port(),
        proptest::option::of(path()),
        proptest::option::of(proptest::collection::vec(any_method(), 1..4)),
    )
        .prop_map(|(scheme, host, port, prefix, methods)| {
            let mut value = json!({
                "destination": { "scheme": scheme, "host": host },
                "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } },
            });
            if let Some(port) = port {
                value["destination"]["port"] = json!(port);
            }
            if let Some(prefix) = prefix {
                value["destination"]["path_prefix"] = json!(prefix);
            }
            if let Some(methods) = methods {
                value["methods"] = serde_json::to_value(methods).unwrap();
            }
            if scheme == "http" {
                value["allow_plain_http"] = json!(true);
            }
            serde_json::from_value(value).unwrap()
        })
}

/// Simple, slow and obviously correct, working from the written strings only.
fn reference_allows(rule: &Rule, url: &str, method: Method) -> bool {
    let Destination::Http {
        scheme,
        host,
        port,
        path_prefix,
    } = &rule.destination
    else {
        return false;
    };
    let scheme_text = match scheme {
        seal_format::policy::Scheme::Https => "https",
        seal_format::policy::Scheme::Http => "http",
    };
    let default_port = if scheme_text == "https" { 443 } else { 80 };
    let Some(rest) = url.strip_prefix(&format!("{scheme_text}://")) else {
        return false;
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap());
    let (written_host, written_port) = authority
        .split_once(':')
        .map_or((authority, default_port), |(h, p)| (h, p.parse().unwrap()));
    if written_host != host.as_str() || written_port != port.unwrap_or(default_port) {
        return false;
    }
    if rule
        .methods
        .as_ref()
        .is_some_and(|methods| !methods.contains(&method))
    {
        return false;
    }
    match path_prefix {
        None => true,
        Some(prefix) => {
            let wanted: Vec<&str> = prefix
                .trim_matches('/')
                .split('/')
                .filter(|s| !s.is_empty())
                .collect();
            let actual: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if prefix.ends_with('/') {
                // Must be below the prefix, or the prefix itself with its slash.
                path.starts_with(prefix.as_str())
            } else {
                actual.len() >= wanted.len() && actual[..wanted.len()] == wanted[..]
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// The matcher never accepts what the reference refuses, and the reverse.
    #[test]
    fn the_matcher_agrees_with_a_simple_reference(
        rule in random_rule(),
        request_scheme in scheme(),
        request_host in host(),
        request_port in port(),
        request_path in path(),
        method in any_method(),
    ) {
        let authority = request_port.map_or(request_host.clone(), |port| format!("{request_host}:{port}"));
        let url = format!("{request_scheme}://{authority}{request_path}");
        let policy = Policy { rules: vec![rule.clone()], definitions: BTreeMap::new(), shared: false, verify: None };
        prop_assume!(policy.validate().is_ok());
        let target = Target::parse(&url).unwrap();
        let plain = BTreeSet::new();
        let result = decide(
            &BTreeMap::from([(field("token"), policy)]),
            &RequestHead { endpoint: Endpoint::Http(&target), method, header_names: &[], plain: &plain, copy_source: None },
        );
        prop_assert_eq!(result.is_ok(), reference_allows(&rule, &url, method), "{}", url);
    }

    /// Whatever it accepts really is within the rule.
    #[test]
    fn what_the_matcher_accepts_is_within_the_rule(
        rule in random_rule(),
        request_scheme in scheme(),
        request_host in host(),
        request_port in port(),
        request_path in path(),
        method in any_method(),
    ) {
        let authority = request_port.map_or(request_host.clone(), |port| format!("{request_host}:{port}"));
        let target = Target::parse(&format!("{request_scheme}://{authority}{request_path}")).unwrap();
        let policy = Policy { rules: vec![rule.clone()], definitions: BTreeMap::new(), shared: false, verify: None };
        prop_assume!(policy.validate().is_ok());
        let plain = BTreeSet::new();
        let accepted = decide(
            &BTreeMap::from([(field("token"), policy)]),
            &RequestHead { endpoint: Endpoint::Http(&target), method, header_names: &[], plain: &plain, copy_source: None },
        ).is_ok();
        if accepted {
            let Destination::Http { host, path_prefix, .. } = &rule.destination else {
                panic!("not HTTP");
            };
            prop_assert_eq!(host.as_str(), target.host.as_str());
            prop_assert_eq!(rule.destination.effective_port(), target.port);
            if let Some(prefix) = path_prefix {
                prop_assert!(target.path.starts_with(prefix.as_str()));
                let rest = &target.path[prefix.len()..];
                prop_assert!(prefix.ends_with('/') || rest.is_empty() || rest.starts_with('/'));
            }
            if let Some(methods) = &rule.methods {
                prop_assert!(methods.contains(&method));
            }
        }
    }

    /// Adding a value never turns a refusal into an acceptance.
    #[test]
    fn adding_a_value_never_widens_what_is_allowed(
        first in random_rule(),
        second in random_rule(),
        request_host in host(),
        request_path in path(),
    ) {
        let target = Target::parse(&format!("https://{request_host}{request_path}")).unwrap();
        let wrap = |rule: Rule| Policy { rules: vec![rule], definitions: BTreeMap::new(), shared: false, verify: None };
        let (first, second) = (wrap(first), wrap(second));
        prop_assume!(first.validate().is_ok() && second.validate().is_ok());
        let plain = BTreeSet::new();
        let head = RequestHead { endpoint: Endpoint::Http(&target), method: Method::Get, header_names: &[], plain: &plain, copy_source: None };
        let alone = decide(&BTreeMap::from([(field("a"), first.clone())]), &head).is_ok();
        let together = decide(&BTreeMap::from([(field("a"), first), (field("b"), second)]), &head).is_ok();
        prop_assert!(alone || !together);
    }

    /// Whatever two valid policies say, the matcher never lets a sealing rule be
    /// dropped: if either value's matched rule seals, the matched plan seals or it refuses.
    #[test]
    fn response_sealing_can_never_be_dropped(attacker in random_rule(), name in "[a-z]{1,8}") {
        let genuine = sealing_policy(&form("client_secret"), "api.example.com");
        let mut attacker = attacker;
        attacker.inject = Inject::FormField { name };
        attacker.destination = rule_destination();
        attacker.allow_plain_http = false;
        let attacker = Policy { rules: vec![attacker], definitions: BTreeMap::new(), shared: false, verify: None };
        prop_assume!(attacker.validate().is_ok());
        let target = Target::parse(API).unwrap();
        let plain = BTreeSet::new();
        let head = RequestHead { endpoint: Endpoint::Http(&target), method: Method::Get, header_names: &[], plain: &plain, copy_source: None };
        if let Ok(plan) = decide(&BTreeMap::from([(field("a"), attacker), (field("b"), genuine)]), &head) {
            prop_assert!(plan.response.is_some());
        }
    }
}

fn rule_destination() -> Destination {
    serde_json::from_value(json!({ "scheme": "https", "host": "api.example.com" })).unwrap()
}

// X-Amz headers and copy sources.

fn s3(allow_headers: &[&str], prefix: &str) -> Policy {
    policy(&json!({ "rules": [{
        "destination": { "scheme": "https", "host": "s3.example.com", "path_prefix": prefix },
        "inject": { "aws_sigv4": {
            "region": "us-east-1", "service": "s3",
            "access_key_id": { "literal": "AKIA" }, "payload": ["computed"],
            "allow_headers": allow_headers,
        } },
    }] }))
}

fn s3_request(path: &str, headers: &[&'static str], copy_source: Option<&'static str>) -> Request {
    let mut request = Request::to(&format!("https://s3.example.com{path}"));
    request.method = Method::Put;
    request.headers = headers.to_vec();
    if copy_source.is_some() {
        request.headers.push("x-amz-copy-source");
    }
    request.copy_source = copy_source;
    request
}

fn code(result: Result<Plan, BrokerError>) -> Option<ErrorCode> {
    result.err().map(|error| error.code())
}

#[test]
fn ordinary_amz_headers_pass_and_signing_ones_do_not() {
    let policies = fields(&[("secret", s3(&[], "/bucket/"))]);
    let ok = s3_request(
        "/bucket/key",
        &[
            "x-amz-meta-owner",
            "X-Amz-Storage-Class",
            "x-amz-server-side-encryption",
            "x-amz-checksum-sha256",
            "content-type",
        ],
        None,
    );
    assert_eq!(code(ok.decide(&policies)), None);
    for header in [
        "x-amz-date",
        "x-amz-security-token",
        "x-amz-decoded-content-length",
        "x-amz-trailer",
        "x-amz-acl",
        "x-amz-grant-read",
        "x-amz-object-lock-mode",
    ] {
        let request = s3_request("/bucket/key", &[header], None);
        assert_eq!(
            code(request.decide(&policies)),
            Some(ErrorCode::Conflict),
            "{header}"
        );
    }
    let policies = fields(&[("secret", s3(&["x-amz-acl"], "/bucket/"))]);
    assert_eq!(
        code(s3_request("/bucket/key", &["x-amz-acl"], None).decide(&policies)),
        None
    );
    assert_eq!(
        code(s3_request("/bucket/key", &["x-amz-grant-read"], None).decide(&policies)),
        Some(ErrorCode::Conflict)
    );
}

#[test]
fn a_copy_needs_the_rule_to_allow_it() {
    let policies = fields(&[("secret", s3(&[], "/bucket/"))]);
    let request = s3_request("/bucket/copy", &[], Some("/bucket/original"));
    assert_eq!(code(request.decide(&policies)), Some(ErrorCode::Conflict));
}

#[test]
fn a_copy_source_must_be_within_the_rules_prefix() {
    let policies = fields(&[("secret", s3(&["x-amz-copy-source"], "/bucket/"))]);
    for source in [
        "/bucket/original",
        "bucket/original",
        "bucket/dir/a%20b",
        "/bucket/original?versionId=3HL4kqtJlcpXroDTDmJ",
    ] {
        let request = s3_request(
            "/bucket/copy",
            &["x-amz-metadata-directive", "x-amz-copy-source-range"],
            Some(source),
        );
        assert_eq!(code(request.decide(&policies)), None, "{source}");
    }
    for source in [
        "/other-bucket/secret",
        "/bucket-two/secret",
        "/bucket",
        "/bucket/../other/secret",
        "/bucket/%2e%2e/other/secret",
        "/bucket/a%2fb",
        "/bucket/original?versionId=1&x=2",
        "/bucket/original?partNumber=1",
        "arn:aws:s3:us-east-1:123456789012:accesspoint/ap/object/key",
        "//other/secret",
    ] {
        let request = s3_request("/bucket/copy", &[], Some(source));
        assert_eq!(
            code(request.decide(&policies)),
            Some(ErrorCode::PolicyDenied),
            "{source}"
        );
    }
}

// Postgres sessions.

fn pg_policy(databases: &[&str], user: &str, inject: Value, plain: &[&str]) -> Policy {
    policy(&json!({ "rules": [{
        "destination": { "scheme": "postgres", "host": "db.example.com", "port": 5432, "databases": databases, "user": { "literal": user } },
        "inject": inject,
        "plain": plain,
    }] }))
}

fn pg_head<'a>(port: u16, plain: &'a BTreeSet<FieldName>) -> RequestHead<'a> {
    RequestHead {
        endpoint: Endpoint::Postgres {
            host: "db.example.com",
            port,
        },
        method: Method::Get,
        header_names: &[],
        plain,
        copy_source: None,
    }
}

fn password() -> Value {
    json!({ "pg_password": { "allow_md5": true } })
}

#[test]
fn a_postgres_session_gets_the_rules_terms() {
    let policies = fields(&[(
        "password",
        pg_policy(&["app", "reports"], "app_user", password(), &[]),
    )]);
    let plain = BTreeSet::new();
    let plan = decide(&policies, &pg_head(5432, &plain)).unwrap();
    let terms = postgres_terms(&policies, &plan).unwrap();
    assert_eq!(terms.user, Part::Literal("app_user".to_owned()));
    assert_eq!(terms.databases, ["app", "reports"]);
    assert!(!terms.allow_replication);
    let password = terms.password.unwrap();
    assert_eq!(password.field, field("password"));
    assert!(password.allow_md5 && !password.allow_cleartext);
    assert!(terms.client_cert.is_none());

    // Another port, or an HTTP value, does not match.
    assert_eq!(
        decide(&policies, &pg_head(5433, &plain))
            .unwrap_err()
            .code(),
        ErrorCode::PolicyDenied
    );
    let http = fields(&[("token", bearer())]);
    assert_eq!(
        decide(&http, &pg_head(5432, &plain)).unwrap_err().code(),
        ErrorCode::PolicyDenied
    );
}

#[test]
fn a_password_and_a_client_certificate_share_the_databases_both_allow() {
    let cert = json!({ "client_cert": { "cert": { "field": "cert" } } });
    let policies = fields(&[
        (
            "password",
            pg_policy(&["app", "reports"], "app_user", password(), &[]),
        ),
        (
            "client_key",
            pg_policy(&["reports", "other"], "app_user", cert.clone(), &["cert"]),
        ),
    ]);
    let plain = BTreeSet::from([field("cert")]);
    let plan = decide(&policies, &pg_head(5432, &plain)).unwrap();
    let terms = postgres_terms(&policies, &plan).unwrap();
    assert_eq!(terms.databases, ["reports"]);
    assert!(terms.password.is_some() && terms.client_cert.is_some());

    // They must agree on the user, and share a database.
    let policies = fields(&[
        ("password", pg_policy(&["app"], "app_user", password(), &[])),
        (
            "client_key",
            pg_policy(&["app"], "someone_else", cert.clone(), &["cert"]),
        ),
    ]);
    let plan = decide(&policies, &pg_head(5432, &plain)).unwrap();
    assert_eq!(
        postgres_terms(&policies, &plan).unwrap_err().code(),
        ErrorCode::PolicyDenied
    );
    let policies = fields(&[
        ("password", pg_policy(&["app"], "app_user", password(), &[])),
        (
            "client_key",
            pg_policy(&["other"], "app_user", cert, &["cert"]),
        ),
    ]);
    let plan = decide(&policies, &pg_head(5432, &plain)).unwrap();
    assert_eq!(
        postgres_terms(&policies, &plan).unwrap_err().code(),
        ErrorCode::PolicyDenied
    );
}

#[test]
fn two_passwords_are_refused() {
    let policies = fields(&[
        ("first", pg_policy(&["app"], "app_user", password(), &[])),
        ("second", pg_policy(&["app"], "app_user", password(), &[])),
    ]);
    let plain = BTreeSet::new();
    let result =
        decide(&policies, &pg_head(5432, &plain)).and_then(|plan| postgres_terms(&policies, &plan));
    assert!(matches!(
        result.unwrap_err().code(),
        ErrorCode::PolicyDenied | ErrorCode::Conflict
    ));
}
