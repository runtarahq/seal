use serde_json::{Value, json};

use super::*;

fn bearer_rule() -> Value {
    json!({
        "destination": { "scheme": "https", "host": "api.example.com", "port": 443, "path_prefix": "/v2/" },
        "methods": ["GET", "POST"],
        "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } }
    })
}

fn parse(policy: &Value) -> Result<Policy, FormatError> {
    Policy::from_json(policy.to_string().as_bytes())
}

/// A policy with one rule, built by changing the bearer rule.
fn with_rule(change: impl FnOnce(&mut Value)) -> Result<Policy, FormatError> {
    let mut rule = bearer_rule();
    change(&mut rule);
    parse(&json!({ "rules": [rule] }))
}

fn with_destination(destination: Value) -> Result<Policy, FormatError> {
    with_rule(|rule| rule["destination"] = destination)
}

fn with_inject(inject: Value) -> Result<Policy, FormatError> {
    with_rule(|rule| rule["inject"] = inject)
}

fn https_host(host: &str) -> Value {
    json!({ "scheme": "https", "host": host })
}

fn https_prefix(prefix: &str) -> Value {
    json!({ "scheme": "https", "host": "api.example.com", "path_prefix": prefix })
}

fn token_endpoint() -> Value {
    json!({ "scheme": "https", "host": "auth.example.com", "path_prefix": "/oauth/token" })
}

fn jwt(change: impl FnOnce(&mut Value)) -> Result<Policy, FormatError> {
    let mut inject = json!({
        "alg": "RS256",
        "aud": "token_endpoint",
        "claims": { "iss": "client" },
        "form_field": "assertion",
        "max_lifetime_s": 300
    });
    change(&mut inject);
    with_rule(|rule| {
        rule["destination"] = token_endpoint();
        rule["inject"] = json!({ "jwt_assertion": inject });
    })
}

fn postgres(change: impl FnOnce(&mut Value)) -> Result<Policy, FormatError> {
    let mut destination = json!({
        "scheme": "postgres", "host": "db.example.com", "port": 5432,
        "databases": ["app"], "user": { "literal": "app_user" }
    });
    change(&mut destination);
    parse(&json!({ "rules": [{ "destination": destination, "inject": { "pg_password": {} } }] }))
}

// Accepting the schema.

#[test]
fn accepts_a_policy_with_sealed_tokens_and_definitions() {
    let policy = parse(&json!({
        "rules": [{
            "destination": { "scheme": "https", "host": "api.example.com", "port": 443, "path_prefix": "/v2/" },
            "methods": ["GET", "POST"],
            "inject": { "header": { "name": "Authorization", "format": "Bearer {}" } },
            "seal_response": {
                "format": "json",
                "fields": [
                    { "at": "/access_token", "as": "access_token", "policy": "api" },
                    { "at": "/refresh_token", "as": "refresh_token", "policy": "refresh" }
                ]
            }
        }],
        "definitions": {
            "api": { "rules": [bearer_rule()] },
            "refresh": { "rules": [{
                "destination": token_endpoint(),
                "inject": { "form_field": { "name": "refresh_token" } },
                "seal_response": {
                    "format": "json",
                    "fields": [
                        { "at": "/access_token", "as": "access_token", "policy": "api" },
                        { "at": "/refresh_token", "as": "refresh_token", "policy": "refresh" }
                    ]
                }
            }] }
        }
    }))
    .unwrap();
    assert_eq!(policy.definitions.len(), 2);
}

#[test]
fn accepts_every_inject_kind() {
    let injects = [
        json!({ "header": { "name": "X-Api-Key", "format": "{}" } }),
        json!({ "basic": { "username": { "literal": "user" } } }),
        json!({ "basic": { "username": { "field": "username" } } }),
        json!({ "query": { "name": "api_key" } }),
        json!({ "path": { "prefix": "/bot{}" } }),
        json!({ "form_field": { "name": "password" } }),
        json!({ "json_field": { "pointer": "/auth/token" } }),
        json!({ "client_cert": {
            "cert": { "field": "cert" }, "chain": { "field": "chain" },
            "ca": "-----BEGIN CERTIFICATE-----", "server_name": "provider.example.com"
        } }),
        json!({ "aws_sigv4": {
            "region": "eu-west-1", "service": "s3",
            "access_key_id": { "field": "access_key_id" },
            "session_token": { "field": "session_token" },
            "payload": ["computed", "caller_hash", "streaming"],
            "allow_unsigned_payload": true
        } }),
        json!({ "azure_shared_key": { "account": { "literal": "acct" }, "service": "table" } }),
        json!({ "companion": {} }),
    ];
    for inject in injects {
        with_inject(inject.clone()).unwrap_or_else(|e| panic!("{inject}: {e}"));
    }
}

#[test]
fn accepts_a_postgres_rule_with_each_login() {
    postgres(|_| {}).unwrap();
    let certificate = parse(&json!({ "rules": [{
        "destination": {
            "scheme": "postgres", "host": "db.example.com", "port": 5432,
            "databases": ["app"], "user": { "field": "user" },
            "tls": { "ca": "-----BEGIN CERTIFICATE-----" }, "allow_replication": true
        },
        "inject": { "client_cert": { "cert": { "field": "cert" } } }
    }] }));
    certificate.unwrap();
}

#[test]
fn accepts_both_audience_forms() {
    jwt(|_| {}).unwrap();
    let policy = jwt(|inject| inject["aud"] = json!({ "value": "https://login.salesforce.com" }));
    let Inject::JwtAssertion { aud, .. } = &policy.unwrap().rules[0].inject else {
        panic!("not a JWT rule");
    };
    assert_eq!(
        *aud,
        JwtAudience::Value("https://login.salesforce.com".to_owned())
    );
}

#[test]
fn accepts_every_jwt_algorithm_and_header_parameter() {
    for alg in ["RS256", "PS256", "ES256"] {
        jwt(|inject| inject["alg"] = json!(alg)).unwrap();
    }
    jwt(|inject| {
        inject["header"] =
            json!({ "typ": "client-authentication+jwt", "kid": "k1", "x5t#S256": "abc" });
    })
    .unwrap();
}

// Refusing what the schema does not allow.

#[test]
fn refuses_unknown_fields_everywhere() {
    let mut cases = vec![json!({ "rules": [bearer_rule()], "extra": 1 })];
    let mut rule = bearer_rule();
    rule["allow_everything"] = json!(true);
    cases.push(json!({ "rules": [rule] }));
    let mut rule = bearer_rule();
    rule["destination"]["wildcard"] = json!(true);
    cases.push(json!({ "rules": [rule] }));
    let mut rule = bearer_rule();
    rule["inject"]["header"]["typo"] = json!(1);
    cases.push(json!({ "rules": [rule] }));
    cases.push(json!({ "rules": [bearer_rule()], "definitions": { "a": { "rules": [bearer_rule()], "definitions": {} } } }));
    for case in cases {
        assert_eq!(
            parse(&case).unwrap_err(),
            FormatError::InvalidPolicy("does not match the schema"),
            "{case}"
        );
    }
}

#[test]
fn refuses_unknown_kinds_and_values() {
    with_inject(json!({ "telepathy": {} })).unwrap_err();
    with_destination(json!({ "scheme": "ftp", "host": "a.example.com" })).unwrap_err();
    with_rule(|rule| rule["methods"] = json!(["CONNECT"])).unwrap_err();
    with_rule(|rule| rule["methods"] = json!(["TRACE"])).unwrap_err();
    with_rule(|rule| rule["methods"] = json!(["get"])).unwrap_err();
    with_inject(
        json!({ "azure_shared_key": { "account": { "literal": "a" }, "service": "disk" } }),
    )
    .unwrap_err();
    jwt(|inject| inject["alg"] = json!("none")).unwrap_err();
    jwt(|inject| inject["alg"] = json!("HS256")).unwrap_err();
}

#[test]
fn refuses_not_json_and_errors_do_not_echo_the_input() {
    let error = Policy::from_json(b"{\"rules\": \"SECRETVALUE\"}").unwrap_err();
    assert!(!error.to_string().contains("SECRETVALUE"));
    Policy::from_json(b"not json").unwrap_err();
    Policy::from_json(b"").unwrap_err();
}

#[test]
fn refuses_an_empty_or_oversized_rule_list() {
    parse(&json!({ "rules": [] })).unwrap_err();
    parse(&json!({})).unwrap_err();
    let rules = vec![bearer_rule(); 16];
    parse(&json!({ "rules": rules })).unwrap();
    let rules = vec![bearer_rule(); 17];
    parse(&json!({ "rules": rules })).unwrap_err();
    with_rule(|rule| rule["methods"] = json!([])).unwrap_err();
}

#[test]
fn a_policy_may_verify_instead_of_having_rules() {
    for hash in ["sha1", "sha256", "sha512"] {
        let policy = parse(&json!({ "verify": { "hmac": { "hash": hash } } })).unwrap();
        assert!(policy.rules.is_empty());
        let canonical = policy.canonical_json().unwrap();
        assert_eq!(Policy::from_json(&canonical).unwrap(), policy);
    }
    // And may do both, or be shared: a platform's webhook secret.
    parse(&json!({ "rules": [bearer_rule()], "verify": { "hmac": { "hash": "sha256" } } }))
        .unwrap();
    parse(&json!({ "verify": { "hmac": { "hash": "sha256" } }, "shared": true })).unwrap();

    for verify in [
        json!({}),
        json!("hmac"),
        json!({ "hmac": {} }),
        json!({ "hmac": { "hash": "md5" } }),
        json!({ "hmac": { "hash": "SHA256" } }),
        json!({ "hmac": { "hash": "sha256", "truncate": 8 } }),
        json!({ "rsa": { "hash": "sha256" } }),
    ] {
        assert!(parse(&json!({ "verify": verify })).is_err(), "{verify}");
    }
    assert_eq!(
        parse(&json!({})).unwrap_err(),
        FormatError::InvalidPolicy("a policy needs a rule or a verification")
    );
    // A definition's rules are what a sealed token gets, so it always has some.
    parse(&json!({
        "verify": { "hmac": { "hash": "sha256" } },
        "definitions": { "p": { "rules": [] } }
    }))
    .unwrap_err();
}

/// A token sealed from a response is for sending, whatever its parent verified.
#[test]
fn a_value_sealed_from_a_response_never_verifies() {
    let mut value = json!({
        "rules": [bearer_rule()],
        "definitions": { "p": { "rules": [bearer_rule()] } },
        "verify": { "hmac": { "hash": "sha256" } }
    });
    value["rules"][0]["seal_response"] =
        json!({ "format": "json", "fields": [{ "at": "/a", "as": "a", "policy": "p" }] });
    let policy = parse(&value).unwrap();
    let child = policy
        .for_response_field(&PolicyName::new("p").unwrap())
        .unwrap();
    assert_eq!(child.verify, None);
}

// Hosts.

#[test]
fn refuses_hosts_that_are_not_normalised() {
    for host in [
        "API.example.com",
        "*.example.com",
        "*",
        "example.com.",
        "bücher.example",
        "127.1",
        "0x7f.0.0.1",
        "[::FFFF:1.2.3.4]",
        "",
        "a b.example.com",
        "user@example.com",
        "example.com:443",
        "example.com/path",
        "%65xample.com",
        "xn--0.example.com",
    ] {
        assert!(with_destination(https_host(host)).is_err(), "{host:?}");
    }
}

#[test]
fn accepts_normalised_hosts_and_ip_literals() {
    for host in [
        "api.example.com",
        "xn--bcher-kva.example",
        "127.0.0.1",
        "[::1]",
        "localhost",
    ] {
        with_destination(https_host(host)).unwrap_or_else(|e| panic!("{host}: {e}"));
    }
}

// Path prefixes.

#[test]
fn refuses_path_prefixes_that_could_mean_something_else() {
    for prefix in [
        "v2/",
        "",
        "/v2/../admin",
        "/..",
        "/.",
        "/./a",
        "/v2/%2e%2e/admin",
        "/v2/%2E./admin",
        "/v2%2fadmin",
        "/v2%2Fadmin",
        "/v2%5cadmin",
        "/v2\\admin",
        "//evil.example",
        "/a//b",
        "/a?x=1",
        "/a#b",
        "/a b",
        "/a\n",
    ] {
        assert!(
            with_destination(https_prefix(prefix)).is_err(),
            "{prefix:?}"
        );
    }
}

#[test]
fn accepts_ordinary_path_prefixes() {
    for prefix in ["/", "/v2", "/v2/", "/a/b/c", "/a.b/c..d", "/%41"] {
        with_destination(https_prefix(prefix)).unwrap_or_else(|e| panic!("{prefix}: {e}"));
    }
}

#[test]
fn refuses_port_zero() {
    with_destination(json!({ "scheme": "https", "host": "a.example.com", "port": 0 })).unwrap_err();
    postgres(|d| d["port"] = json!(0)).unwrap_err();
}

#[test]
fn the_port_defaults_by_scheme() {
    let host = Host::new("a.example.com").unwrap();
    let destination = |scheme, port| Destination::Http {
        scheme,
        host: host.clone(),
        port,
        path_prefix: None,
    };
    assert_eq!(destination(Scheme::Https, None).effective_port(), 443);
    assert_eq!(destination(Scheme::Http, None).effective_port(), 80);
    assert_eq!(
        destination(Scheme::Https, Some(8443)).effective_port(),
        8443
    );
}

// Injection details.

#[test]
fn header_templates_need_exactly_one_placeholder() {
    for format in ["Bearer", "{} {}", "", "Bearer {}\r\nX: y"] {
        let inject = json!({ "header": { "name": "Authorization", "format": format } });
        assert!(with_inject(inject).is_err(), "{format:?}");
    }
}

#[test]
fn refuses_headers_a_rule_may_not_inject_into() {
    for name in [
        "Host",
        "host",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Keep-Alive",
        "TE",
        "Trailer",
        "Upgrade",
        "Proxy-Authorization",
        "Proxy-Anything",
        "",
        "Bad Header",
        "Bad:Header",
        "Bad\nHeader",
    ] {
        let inject = json!({ "header": { "name": name, "format": "{}" } });
        assert!(with_inject(inject).is_err(), "{name:?}");
    }
}

#[test]
fn json_pointers_must_be_valid_and_not_the_whole_document() {
    for pointer in ["", "token", "/a~", "/a~2", "/a~b"] {
        let inject = json!({ "json_field": { "pointer": pointer } });
        assert!(with_inject(inject).is_err(), "{pointer:?}");
    }
    with_inject(json!({ "json_field": { "pointer": "/a~0b/c~1d" } })).unwrap();
}

#[test]
fn an_injected_path_is_whole_segments_with_one_place_for_the_secret() {
    for prefix in ["/bot{}", "/{}", "/v1/{}/api", "/a:b@c/key={}"] {
        with_inject(json!({ "path": { "prefix": prefix } }))
            .unwrap_or_else(|error| panic!("{error} for {prefix:?}"));
    }
    for prefix in [
        "", "/bot", "bot{}", "/bot{}/", "/{}{}", "/a//{}", "/../{}", "/./{}", "/{}/..", "/a?b={}",
        "/a#{}", "/a%2f{}", "/a b{}", "/a\\{}", "/{x}{}", "/é{}",
    ] {
        let inject = json!({ "path": { "prefix": prefix } });
        assert!(with_inject(inject).is_err(), "{prefix:?}");
    }
}

#[test]
fn refuses_bad_parts_and_names() {
    with_inject(json!({ "basic": { "username": { "literal": "" } } })).unwrap_err();
    with_inject(json!({ "basic": { "username": { "field": ".." } } })).unwrap_err();
    with_inject(json!({ "basic": { "username": "user" } })).unwrap_err();
    with_inject(json!({ "query": { "name": "" } })).unwrap_err();
    with_inject(json!({ "form_field": { "name": "a\nb" } })).unwrap_err();
    with_rule(|rule| rule["plain"] = json!([".."])).unwrap_err();
}

#[test]
fn sigv4_needs_a_payload_mode_and_valid_scope() {
    let sigv4 = |change: fn(&mut Value)| {
        let mut inject = json!({
            "region": "eu-west-1", "service": "s3",
            "access_key_id": { "literal": "AKIA" }, "payload": ["computed"]
        });
        change(&mut inject);
        with_inject(json!({ "aws_sigv4": inject }))
    };
    sigv4(|_| {}).unwrap();
    sigv4(|i| i["payload"] = json!([])).unwrap_err();
    sigv4(|i| {
        i["payload"] = json!([]);
        i["allow_unsigned_payload"] = json!(true);
    })
    .unwrap();
    sigv4(|i| i["payload"] = json!(["computed", "computed"])).unwrap_err();
    sigv4(|i| i["payload"] = json!(["unsigned"])).unwrap_err();
    sigv4(|i| i["region"] = json!("EU")).unwrap_err();
    sigv4(|i| i["service"] = json!("")).unwrap_err();
}

#[test]
fn sigv4_rules_allow_only_opt_in_amz_headers() {
    let sigv4 = |headers: Value, prefix: Option<&str>| {
        with_rule(|rule| {
            rule["inject"] = json!({ "aws_sigv4": {
                "region": "eu-west-1", "service": "s3",
                "access_key_id": { "literal": "AKIA" }, "payload": ["computed"],
                "allow_headers": headers,
            } });
            rule["destination"] = match prefix {
                Some(prefix) => https_prefix(prefix),
                None => https_host("api.example.com"),
            };
        })
    };
    let policy = sigv4(json!(["x-amz-acl", "x-amz-grant-read"]), None).unwrap();
    // It round-trips, and an empty list is left out.
    assert_eq!(
        parse(&serde_json::to_value(&policy).unwrap()).unwrap(),
        policy
    );
    let plain = sigv4(json!([]), None).unwrap();
    assert!(
        !serde_json::to_string(&plain)
            .unwrap()
            .contains("allow_headers")
    );

    // Headers that control signing, or that are allowed anyway, are not opt-in.
    for header in [
        "x-amz-date",
        "x-amz-security-token",
        "x-amz-content-sha256",
        "x-amz-meta-a",
        "X-Amz-Acl",
        "authorization",
    ] {
        sigv4(json!([header]), None).unwrap_err();
    }
    sigv4(json!(["x-amz-acl", "x-amz-acl"]), None).unwrap_err();

    // Copies are checked against the path prefix, so they need one naming a bucket.
    sigv4(json!(["x-amz-copy-source"]), None).unwrap_err();
    sigv4(json!(["x-amz-copy-source"]), Some("/")).unwrap_err();
    sigv4(json!(["x-amz-copy-source"]), Some("/bucket/")).unwrap();
}

#[test]
fn which_amz_headers_a_caller_may_set() {
    use super::amz_header_allowed;
    let none: &[String] = &[];
    for name in [
        "x-amz-meta-owner",
        "x-amz-storage-class",
        "x-amz-tagging",
        "x-amz-server-side-encryption",
        "x-amz-server-side-encryption-customer-key",
        "x-amz-checksum-crc32",
        "x-amz-expected-bucket-owner",
        "x-amz-request-payer",
    ] {
        assert!(amz_header_allowed(name, none), "{name}");
    }
    for name in [
        "x-amz-date",
        "x-amz-security-token",
        "x-amz-content-sha256",
        "x-amz-decoded-content-length",
        "x-amz-trailer",
        "x-amz-acl",
        "x-amz-grant-read",
        "x-amz-copy-source",
        "x-amz-metadata-directive",
        "x-amz-object-lock-mode",
    ] {
        assert!(!amz_header_allowed(name, none), "{name}");
    }
    let acl = ["x-amz-acl".to_owned()];
    assert!(amz_header_allowed("x-amz-acl", &acl));
    assert!(!amz_header_allowed("x-amz-grant-read", &acl));
    let copy = ["x-amz-copy-source".to_owned()];
    for name in [
        "x-amz-copy-source",
        "x-amz-copy-source-range",
        "x-amz-copy-source-if-match",
        "x-amz-metadata-directive",
        "x-amz-tagging-directive",
    ] {
        assert!(amz_header_allowed(name, &copy), "{name}");
    }
    assert!(!amz_header_allowed("x-amz-date", &copy));
}

#[test]
fn client_certificates_need_valid_pem_and_https() {
    let cert = json!({ "client_cert": { "cert": { "field": "cert" } } });
    with_inject(json!({ "client_cert": { "cert": { "field": "cert" }, "ca": "not pem" } }))
        .unwrap_err();
    with_rule(|rule| {
        rule["destination"] = json!({ "scheme": "http", "host": "a.example.com" });
        rule["allow_plain_http"] = json!(true);
        rule["inject"] = cert;
    })
    .unwrap_err();
}

// JWT assertions.

#[test]
fn jwt_lifetime_is_capped_at_five_minutes() {
    jwt(|inject| inject["max_lifetime_s"] = json!(301)).unwrap_err();
    jwt(|inject| inject["max_lifetime_s"] = json!(0)).unwrap_err();
    jwt(|inject| inject["max_lifetime_s"] = json!(1)).unwrap();
}

#[test]
fn jwt_audience_is_required_and_a_single_valid_string() {
    jwt(|inject| {
        inject.as_object_mut().unwrap().remove("aud");
    })
    .unwrap_err();
    for aud in [
        json!({ "value": "" }),
        json!({ "value": ["a", "b"] }),
        json!(["https://a.example"]),
        json!("https://a.example"),
        json!({ "value": "has:colon but not uri" }),
        json!({ "value": "a\nb" }),
        json!({ "value": "a".repeat(2049) }),
    ] {
        assert!(jwt(|inject| inject["aud"] = aud.clone()).is_err(), "{aud}");
    }
    jwt(|inject| inject["aud"] = json!({ "value": "plain-string" })).unwrap();
}

#[test]
fn an_exact_audience_is_kept_byte_for_byte() {
    let trailing_slash = "https://tenant.auth0.com/";
    let policy = jwt(|inject| inject["aud"] = json!({ "value": trailing_slash })).unwrap();
    let canonical = String::from_utf8(policy.canonical_json().unwrap()).unwrap();
    assert!(canonical.contains(&format!("\"{trailing_slash}\"")));
}

#[test]
fn a_jwt_rule_must_name_the_exact_token_endpoint() {
    for prefix in [None, Some("/"), Some("/oauth/")] {
        let mut destination = json!({ "scheme": "https", "host": "auth.example.com" });
        if let Some(prefix) = prefix {
            destination["path_prefix"] = json!(prefix);
        }
        let result = with_rule(|rule| {
            rule["destination"] = destination;
            rule["inject"] = json!({ "jwt_assertion": {
                "alg": "ES256", "aud": "token_endpoint", "claims": { "iss": "c" },
                "form_field": "assertion", "max_lifetime_s": 60
            } });
        });
        assert!(result.is_err(), "{prefix:?}");
    }
}

#[test]
fn jwt_claims_cannot_override_what_seal_sets() {
    for claim in ["aud", "exp", "iat", "nbf", "jti", "iss", "sub", "scope"] {
        let result = jwt(|inject| inject["claims"]["extra"] = json!({ claim: "x" }));
        assert!(result.is_err(), "{claim}");
    }
    jwt(|inject| inject["claims"]["extra"] = json!({ "tenant": "x" })).unwrap();
    jwt(|inject| inject["claims"]["iss"] = json!("")).unwrap_err();
    jwt(|inject| inject["claims"]["aud"] = json!("x")).unwrap_err();
    jwt(|inject| inject["header"] = json!({ "kid": "" })).unwrap_err();
    jwt(|inject| inject["header"] = json!({ "alg": "none" })).unwrap_err();
}

// What fits which destination.

#[test]
fn injection_must_fit_the_destination() {
    with_inject(json!({ "pg_password": {} })).unwrap_err();
    let on_postgres = |inject: Value| {
        parse(&json!({ "rules": [{
            "destination": {
                "scheme": "postgres", "host": "db.example.com", "port": 5432,
                "databases": ["app"], "user": { "literal": "u" }
            },
            "inject": inject
        }] }))
    };
    on_postgres(json!({ "header": { "name": "A", "format": "{}" } })).unwrap_err();
    on_postgres(json!({ "form_field": { "name": "a" } })).unwrap_err();
    on_postgres(json!({ "companion": {} })).unwrap();
}

#[test]
fn postgres_destinations_need_their_fields_and_no_http_ones() {
    postgres(|d| {
        d.as_object_mut().unwrap().remove("port");
    })
    .unwrap_err();
    postgres(|d| {
        d.as_object_mut().unwrap().remove("databases");
    })
    .unwrap_err();
    postgres(|d| {
        d.as_object_mut().unwrap().remove("user");
    })
    .unwrap_err();
    postgres(|d| d["databases"] = json!([])).unwrap_err();
    postgres(|d| d["databases"] = json!([""])).unwrap_err();
    postgres(|d| d["path_prefix"] = json!("/a")).unwrap_err();
    postgres(|d| d["tls"] = json!({ "ca": "not pem" })).unwrap_err();
    with_destination(json!({ "scheme": "https", "host": "a.example.com", "databases": ["a"] }))
        .unwrap_err();
    with_destination(
        json!({ "scheme": "https", "host": "a.example.com", "allow_replication": true }),
    )
    .unwrap_err();
}

#[test]
fn methods_and_response_sealing_are_http_only() {
    let base = json!({
        "destination": {
            "scheme": "postgres", "host": "db.example.com", "port": 5432,
            "databases": ["app"], "user": { "literal": "u" }
        },
        "inject": { "pg_password": {} }
    });
    let mut methods = base.clone();
    methods["methods"] = json!(["GET"]);
    parse(&json!({ "rules": [methods] })).unwrap_err();

    let mut sealing = base;
    sealing["seal_response"] = json!({
        "format": "json", "fields": [{ "at": "/a", "as": "a", "policy": "p" }]
    });
    parse(&json!({ "rules": [sealing], "definitions": { "p": { "rules": [bearer_rule()] } } }))
        .unwrap_err();
}

#[test]
fn plain_http_needs_its_flag_and_the_flag_needs_plain_http() {
    let http = json!({ "scheme": "http", "host": "a.example.com" });
    with_destination(http.clone()).unwrap_err();
    with_rule(|rule| {
        rule["destination"] = http;
        rule["allow_plain_http"] = json!(true);
    })
    .unwrap();
    with_rule(|rule| rule["allow_plain_http"] = json!(true)).unwrap_err();
}

#[test]
fn weakening_flags_default_to_off() {
    let policy = with_rule(|_| {}).unwrap();
    assert!(!policy.rules[0].allow_plain_http);
    assert!(!policy.rules[0].allow_private_destination);
    let Inject::PgPassword {
        allow_md5,
        allow_cleartext_password,
    } = postgres(|_| {}).unwrap().rules[0].inject
    else {
        panic!("not a Postgres rule");
    };
    assert!(!allow_md5 && !allow_cleartext_password);
}

#[test]
fn a_companion_rule_only_permits_use_by_another_rule() {
    with_rule(|rule| {
        rule["inject"] = json!({ "companion": {} });
        rule["plain"] = json!(["a"]);
    })
    .unwrap_err();
    let sealing = with_rule(|rule| {
        rule["inject"] = json!({ "companion": {} });
        rule["seal_response"] = json!({
            "format": "json", "fields": [{ "at": "/a", "as": "a", "policy": "p" }]
        });
    });
    sealing.unwrap_err();
}

#[test]
fn limits_cannot_be_zero() {
    with_rule(|rule| rule["limits"] = json!({ "idle_timeout_s": 30, "buffer_cap_bytes": 1024 }))
        .unwrap();
    with_rule(|rule| rule["limits"] = json!({ "idle_timeout_s": 0 })).unwrap_err();
    with_rule(|rule| rule["limits"] = json!({ "buffer_cap_bytes": 0 })).unwrap_err();
    with_rule(|rule| rule["limits"] = json!({ "unknown_limit": 1 })).unwrap_err();
}

// Definitions and response sealing.

fn sealing(fields: Value, format: &str, definitions: Value) -> Result<Policy, FormatError> {
    let mut rule = bearer_rule();
    rule["seal_response"] = json!({ "format": format, "fields": fields });
    parse(&json!({ "rules": [rule], "definitions": definitions }))
}

#[test]
fn response_fields_must_name_a_known_definition() {
    let error = sealing(
        json!([{ "at": "/a", "as": "a", "policy": "missing" }]),
        "json",
        json!({ "other": { "rules": [bearer_rule()] } }),
    )
    .unwrap_err();
    assert_eq!(
        error,
        FormatError::InvalidPolicy("seal_response names an unknown definition")
    );
}

#[test]
fn a_nested_policy_is_not_accepted_any_more() {
    sealing(
        json!([{ "at": "/a", "as": "a", "policy": { "rules": [bearer_rule()] } }]),
        "json",
        json!({}),
    )
    .unwrap_err();
}

#[test]
fn response_field_lists_are_bounded_and_have_unique_names() {
    let definitions = json!({ "p": { "rules": [bearer_rule()] } });
    sealing(json!([]), "json", definitions.clone()).unwrap_err();
    let field = |index: usize| json!({ "at": format!("/f{index}"), "as": format!("f{index}"), "policy": "p" });
    let eight: Vec<Value> = (0..8).map(field).collect();
    sealing(json!(eight), "json", definitions.clone()).unwrap();
    let nine: Vec<Value> = (0..9).map(field).collect();
    sealing(json!(nine), "json", definitions.clone()).unwrap_err();
    sealing(
        json!([{ "at": "/a", "as": "x", "policy": "p" }, { "at": "/b", "as": "x", "policy": "p" }]),
        "json",
        definitions,
    )
    .unwrap_err();
}

#[test]
fn exposed_claims_are_bounded_named_and_unique() {
    let definitions = json!({ "p": { "rules": [bearer_rule()] } });
    let exposing = |claims: Value| {
        sealing(
            json!([{ "at": "/a", "as": "a", "policy": "p", "expose_claims": claims }]),
            "json",
            definitions.clone(),
        )
    };
    let policy = exposing(json!(["exp", "authentication_event_id"])).unwrap();
    let fields = &policy.rules[0].seal_response.as_ref().unwrap().fields;
    assert_eq!(fields[0].expose_claims, ["exp", "authentication_event_id"]);
    exposing(json!(["a", "b", "c", "d", "e", "f", "g", "h"])).unwrap();
    exposing(json!(["a", "b", "c", "d", "e", "f", "g", "h", "i"])).unwrap_err();
    exposing(json!(["exp", "exp"])).unwrap_err();
    exposing(json!([""])).unwrap_err();
    exposing(json!(["a\nb"])).unwrap_err();
    exposing(json!("exp")).unwrap_err();

    // A policy that exposes nothing is written as it always was.
    let none = exposing(json!([])).unwrap();
    assert!(
        !String::from_utf8(none.canonical_json().unwrap())
            .unwrap()
            .contains("expose_claims")
    );
}

#[test]
fn field_locations_must_suit_the_format() {
    let definitions = json!({ "p": { "rules": [bearer_rule()] } });
    let at = |format: &str, at: &str| {
        sealing(
            json!([{ "at": at, "as": "a", "policy": "p" }]),
            format,
            definitions.clone(),
        )
    };
    at("json", "/access_token").unwrap();
    at("json", "access_token").unwrap_err();
    at("json", "").unwrap_err();
    at("form", "access_token").unwrap();
    at("form", "").unwrap_err();
    at(
        "xml",
        "AssumeRoleResponse/AssumeRoleResult/Credentials/SecretAccessKey",
    )
    .unwrap();
    at("xml", "/Absolute").unwrap_err();
    at("xml", "a//b").unwrap_err();
    at("xml", "a b").unwrap_err();
    at("yaml", "a").unwrap_err();
}

#[test]
fn definitions_are_bounded_and_validated() {
    let definition = json!({ "rules": [bearer_rule()] });
    let many = |count: usize| {
        let definitions: serde_json::Map<String, Value> = (0..count)
            .map(|index| (format!("d{index}"), definition.clone()))
            .collect();
        parse(&json!({ "rules": [bearer_rule()], "definitions": definitions }))
    };
    many(8).unwrap();
    many(9).unwrap_err();
    parse(&json!({ "rules": [bearer_rule()], "definitions": { "..": definition } })).unwrap_err();
    parse(&json!({ "rules": [bearer_rule()], "definitions": { "a": { "rules": [] } } }))
        .unwrap_err();
    let mut bad = bearer_rule();
    bad["destination"]["host"] = json!("*.example.com");
    parse(&json!({ "rules": [bearer_rule()], "definitions": { "a": { "rules": [bad] } } }))
        .unwrap_err();
    let mut dangling = bearer_rule();
    dangling["seal_response"] = json!({
        "format": "json", "fields": [{ "at": "/a", "as": "a", "policy": "missing" }]
    });
    parse(&json!({ "rules": [bearer_rule()], "definitions": { "a": { "rules": [dangling] } } }))
        .unwrap_err();
}

#[test]
fn a_definition_can_name_itself_and_rotation_does_not_change_the_policy() {
    let mut refresh = bearer_rule();
    refresh["seal_response"] = json!({
        "format": "json", "fields": [{ "at": "/refresh_token", "as": "refresh_token", "policy": "refresh" }]
    });
    let policy = parse(&json!({
        "rules": [bearer_rule()],
        "definitions": { "refresh": { "rules": [refresh] } }
    }))
    .unwrap();

    let name = PolicyName::new("refresh").unwrap();
    let first = policy.for_response_field(&name).unwrap();
    first.validate().unwrap();
    let mut current = first.clone();
    for _ in 0..100 {
        current = current.for_response_field(&name).unwrap();
        current.validate().unwrap();
        assert_eq!(
            current.canonical_json().unwrap(),
            first.canonical_json().unwrap()
        );
    }
}

#[test]
fn a_cycle_between_definitions_is_allowed() {
    let names = |other: &str| {
        let mut rule = bearer_rule();
        rule["seal_response"] = json!({
            "format": "json", "fields": [{ "at": "/t", "as": "t", "policy": other }]
        });
        json!({ "rules": [rule] })
    };
    parse(&json!({
        "rules": [bearer_rule()],
        "definitions": { "a": names("b"), "b": names("a") }
    }))
    .unwrap();
}

#[test]
fn for_response_field_refuses_an_unknown_name() {
    let policy = with_rule(|_| {}).unwrap();
    let name = PolicyName::new("missing").unwrap();
    policy.for_response_field(&name).unwrap_err();
}

// Size and the canonical form.

#[test]
fn the_size_limit_includes_definitions() {
    let padded = |length: usize| {
        let mut rule = bearer_rule();
        rule["inject"] = json!({ "header": { "name": "X-Padding", "format": format!("{}{{}}", "a".repeat(length)) } });
        rule
    };
    parse(&json!({ "rules": [padded(16 * 1024)] })).unwrap_err();
    parse(&json!({
        "rules": [bearer_rule()],
        "definitions": { "a": { "rules": [padded(16 * 1024)] } }
    }))
    .unwrap_err();
    parse(&json!({ "rules": [padded(15 * 1024)] })).unwrap();
}

#[test]
fn the_canonical_form_round_trips_and_ignores_input_formatting() {
    let compact = with_rule(|_| {}).unwrap();
    let spaced = br#"{ "rules" : [ {
        "inject": { "header": { "format": "Bearer {}", "name": "Authorization" } },
        "methods": [ "GET", "POST" ],
        "destination": { "path_prefix": "/v2/", "port": 443, "host": "api.example.com", "scheme": "https" }
    } ] }"#;
    let spaced = Policy::from_json(spaced).unwrap();
    assert_eq!(compact, spaced);
    let canonical = compact.canonical_json().unwrap();
    assert_eq!(canonical, spaced.canonical_json().unwrap());
    assert_eq!(Policy::from_json(&canonical).unwrap(), compact);
}

#[test]
fn default_values_do_not_appear_in_the_canonical_form() {
    let canonical = postgres(|d| d["tls"] = json!("verify_full")).unwrap();
    let text = String::from_utf8(canonical.canonical_json().unwrap()).unwrap();
    assert!(!text.contains("verify_full"));
    assert!(!text.contains("allow_"));
    assert_eq!(canonical, postgres(|_| {}).unwrap());
}

// Shared values and required form fields.

#[test]
fn a_shared_policy_round_trips_and_defaults_to_not_shared() {
    assert!(!with_rule(|_| {}).unwrap().shared);
    let shared = parse(&json!({ "rules": [bearer_rule()], "shared": true })).unwrap();
    assert!(shared.shared);
    let canonical = String::from_utf8(shared.canonical_json().unwrap()).unwrap();
    assert!(canonical.ends_with(r#""shared":true}"#), "{canonical}");
    assert_eq!(Policy::from_json(canonical.as_bytes()).unwrap(), shared);
    parse(&json!({ "rules": [bearer_rule()], "shared": "yes" })).unwrap_err();
}

#[test]
fn a_value_sealed_from_a_response_is_never_shared() {
    let mut refresh = bearer_rule();
    refresh["seal_response"] = json!({
        "format": "json", "fields": [{ "at": "/t", "as": "t", "policy": "refresh" }]
    });
    let policy = parse(&json!({
        "rules": [refresh.clone()],
        "definitions": { "refresh": { "rules": [refresh] } },
        "shared": true
    }))
    .unwrap();
    let token = policy
        .for_response_field(&PolicyName::new("refresh").unwrap())
        .unwrap();
    assert!(!token.shared);
}

#[test]
fn required_form_fields_are_validated() {
    let require = |value: Value| with_rule(|rule| rule["require_form"] = value);
    require(json!({ "grant_type": ["authorization_code", "refresh_token"] })).unwrap();
    for bad in [
        json!({ "grant_type": [] }),
        json!({ "grant_type": [""] }),
        json!({ "grant_type": ["a", "a"] }),
        json!({ "": ["a"] }),
        json!({ "grant_type": "refresh_token" }),
        json!({ "a\nb": ["x"] }),
    ] {
        assert!(require(bad.clone()).is_err(), "{bad}");
    }
    let many: serde_json::Map<String, Value> = (0..9)
        .map(|index| (format!("f{index}"), json!(["x"])))
        .collect();
    require(Value::Object(many)).unwrap_err();
}

#[test]
fn a_rule_cannot_require_a_field_it_injects_or_require_on_postgres() {
    let result = with_rule(|rule| {
        rule["inject"] = json!({ "form_field": { "name": "client_secret" } });
        rule["require_form"] = json!({ "client_secret": ["x"] });
    });
    result.unwrap_err();
    postgres(|_| {}).unwrap();
    let pg = parse(&json!({ "rules": [{
        "destination": { "scheme": "postgres", "host": "db.example.com", "port": 5432, "databases": ["a"], "user": { "literal": "u" } },
        "inject": { "pg_password": {} },
        "require_form": { "a": ["b"] }
    }] }));
    pg.unwrap_err();
}
