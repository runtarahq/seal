use std::collections::BTreeSet;

use seal_format::Policy;
use seal_format::policy::Method;
use serde_json::json;

use super::*;
use crate::matcher::{Endpoint, RequestHead, decide};

const URL: &str = "https://api.example.com/v2/orders";

fn field(name: &str) -> FieldName {
    FieldName::new(name).unwrap()
}

fn one_rule(inject: &Value) -> Policy {
    let value = json!({ "rules": [{
        "destination": { "scheme": "https", "host": "api.example.com" },
        "inject": inject,
    }] });
    Policy::from_json(value.to_string().as_bytes()).unwrap()
}

/// Builds the head for one field with this injection and secret.
fn head_for(
    inject: &Value,
    secret: &[u8],
    url: &str,
    caller: &HeaderMap,
) -> Result<Outgoing, BrokerError> {
    let target = Target::parse(url).unwrap();
    let policies = BTreeMap::from([(field("secret"), one_rule(inject))]);
    let plain = BTreeSet::new();
    let plan = decide(
        &policies,
        &RequestHead {
            endpoint: Endpoint::Http(&target),
            method: Method::Get,
            header_names: &[],
            plain: &plain,
            copy_source: None,
        },
    )
    .unwrap();
    let secrets = BTreeMap::from([(field("secret"), Secret::new(secret))]);
    let plain = BTreeMap::new();
    build_head(
        &plan,
        &target,
        caller,
        &Sources {
            secrets: &secrets,
            plain: &plain,
        },
        std::time::SystemTime::now(),
    )
}

fn headers(entries: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in entries {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn bearer() -> Value {
    json!({ "header": { "name": "Authorization", "format": "Bearer {}" } })
}

#[test]
fn a_header_uses_the_template_and_is_marked_sensitive() {
    let head = head_for(&bearer(), b"s3cret", URL, &HeaderMap::new()).unwrap();
    let value = &head.headers["authorization"];
    assert_eq!(value, "Bearer s3cret");
    assert!(value.is_sensitive());
    assert!(head.body.is_none());
    assert_eq!(&*head.path_and_query, "/v2/orders");
}

#[test]
fn a_template_can_have_text_after_the_secret() {
    let inject = json!({ "header": { "name": "X-Key", "format": "a {} b" } });
    let head = head_for(&inject, b"s3cret", URL, &HeaderMap::new()).unwrap();
    assert_eq!(head.headers["x-key"], "a s3cret b");
}

#[test]
fn a_secret_that_is_not_valid_in_a_header_is_refused_and_not_echoed() {
    for secret in [&b"a\r\nX-Evil: 1"[..], b"a\nb", b"\0"] {
        let error = head_for(&bearer(), secret, URL, &HeaderMap::new()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::BadRequest);
        assert!(!error.to_string().contains("Evil"));
    }
}

#[test]
fn basic_auth_encodes_username_and_password() {
    let inject = json!({ "basic": { "username": { "literal": "user" } } });
    let head = head_for(&inject, b"hunter2", URL, &HeaderMap::new()).unwrap();
    // base64 of "user:hunter2".
    assert_eq!(head.headers["authorization"], "Basic dXNlcjpodW50ZXIy");
    assert!(head.headers["authorization"].is_sensitive());
}

#[test]
fn a_basic_auth_username_cannot_contain_a_colon() {
    let inject = json!({ "basic": { "username": { "literal": "us:er" } } });
    let error = head_for(&inject, b"x", URL, &HeaderMap::new()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::BadRequest);
}

#[test]
fn parts_come_from_sealed_and_plain_fields() {
    let target = Target::parse(URL).unwrap();
    let policy = Policy::from_json(
        json!({ "rules": [{
            "destination": { "scheme": "https", "host": "api.example.com" },
            "inject": { "basic": { "username": { "field": "username" } } },
            "plain": ["username"],
        }] })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    let names = BTreeSet::from([field("username")]);
    let plan = decide(
        &BTreeMap::from([(field("password"), policy.clone())]),
        &RequestHead {
            endpoint: Endpoint::Http(&target),
            method: Method::Get,
            header_names: &[],
            plain: &names,
            copy_source: None,
        },
    )
    .unwrap();
    let secrets = BTreeMap::from([(field("password"), Secret::new(b"hunter2"))]);
    let plain = BTreeMap::from([(field("username"), "user".to_owned())]);
    let head = build_head(
        &plan,
        &target,
        &HeaderMap::new(),
        &Sources {
            secrets: &secrets,
            plain: &plain,
        },
        std::time::SystemTime::now(),
    )
    .unwrap();
    assert_eq!(head.headers["authorization"], "Basic dXNlcjpodW50ZXIy");
}

#[test]
fn a_query_parameter_is_encoded_and_kept_after_the_callers() {
    let inject = json!({ "query": { "name": "api_key" } });
    let head = head_for(&inject, b"a b&c=d/+", URL, &HeaderMap::new()).unwrap();
    assert_eq!(
        &*head.path_and_query,
        "/v2/orders?api_key=a%20b%26c%3Dd%2F%2B"
    );
    let head = head_for(
        &inject,
        b"x",
        "https://api.example.com/a?b=1%202",
        &HeaderMap::new(),
    )
    .unwrap();
    assert_eq!(&*head.path_and_query, "/a?b=1%202&api_key=x");
}

// The caller's headers.

#[test]
fn hop_by_hop_headers_are_dropped() {
    let caller = headers(&[
        ("connection", "close, x-drop-me"),
        ("keep-alive", "timeout=5"),
        ("proxy-connection", "keep-alive"),
        ("te", "trailers"),
        ("trailer", "x-a"),
        ("transfer-encoding", "chunked"),
        ("upgrade", "websocket"),
        ("x-drop-me", "1"),
        ("x-keep-me", "1"),
    ]);
    let head = head_for(&bearer(), b"x", URL, &caller).unwrap();
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-drop-me",
    ] {
        assert!(!head.headers.contains_key(name), "{name}");
    }
    assert_eq!(head.headers["x-keep-me"], "1");
}

#[test]
fn host_always_comes_from_the_url() {
    let caller = headers(&[("host", "evil.example")]);
    let head = head_for(&bearer(), b"x", URL, &caller).unwrap();
    assert_eq!(head.headers["host"], "api.example.com");
    assert_eq!(head.headers.get_all("host").iter().count(), 1);
}

#[test]
fn proxy_headers_are_refused() {
    for name in [
        "proxy-authorization",
        "proxy-authenticate",
        "proxy-anything",
    ] {
        let error = head_for(&bearer(), b"x", URL, &headers(&[(name, "1")])).unwrap_err();
        assert_eq!(error.code(), ErrorCode::BadRequest, "{name}");
    }
}

#[test]
fn a_malformed_or_repeated_content_length_is_refused() {
    for caller in [
        headers(&[("content-length", "abc")]),
        headers(&[("content-length", "-1")]),
        headers(&[("content-length", "")]),
        headers(&[("content-length", "1, 2")]),
        headers(&[("content-length", "1"), ("content-length", "1")]),
    ] {
        let error = head_for(&bearer(), b"x", URL, &caller).unwrap_err();
        assert_eq!(error.code(), ErrorCode::BadRequest);
    }
    let head = head_for(&bearer(), b"x", URL, &headers(&[("content-length", "12")])).unwrap();
    assert_eq!(head.headers["content-length"], "12");
}

#[test]
fn repeated_caller_headers_are_kept() {
    let caller = headers(&[("x-a", "1"), ("x-a", "2")]);
    let head = head_for(&bearer(), b"x", URL, &caller).unwrap();
    assert_eq!(head.headers.get_all("x-a").iter().count(), 2);
}

#[test]
fn a_client_certificate_that_does_not_parse_is_refused() {
    let inject = json!({ "client_cert": { "cert": { "literal": "-----BEGIN CERTIFICATE-----" } } });
    let error = head_for(&inject, b"not a key", URL, &HeaderMap::new()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::BadRequest);
}

// Body injection.

fn form_body(injected: &[(&str, &[u8])]) -> BodyInjection {
    BodyInjection::Form(
        injected
            .iter()
            .map(|(name, value)| ((*name).to_owned(), Zeroizing::new(value.to_vec())))
            .collect(),
    )
}

fn json_body(injected: &[(&str, &[u8])]) -> BodyInjection {
    BodyInjection::Json(
        injected
            .iter()
            .map(|(name, value)| ((*name).to_owned(), Zeroizing::new(value.to_vec())))
            .collect(),
    )
}

fn form_type() -> HeaderMap {
    headers(&[(
        "content-type",
        "application/x-www-form-urlencoded; charset=utf-8",
    )])
}

fn json_type() -> HeaderMap {
    headers(&[("content-type", "application/json")])
}

fn text(output: &[u8]) -> &str {
    std::str::from_utf8(output).unwrap()
}

#[test]
fn a_form_field_is_encoded_and_appended() {
    let output = apply_to_body(
        &form_body(&[("password", b"a b&c")]),
        &form_type(),
        b"user=me",
    )
    .unwrap();
    assert_eq!(text(&output), "user=me&password=a+b%26c");
    let output = apply_to_body(&form_body(&[("password", b"x")]), &form_type(), b"").unwrap();
    assert_eq!(text(&output), "password=x");
}

#[test]
fn the_caller_cannot_set_an_injected_form_field_even_encoded() {
    for body in [
        &b"password=x"[..],
        b"a=1&password=",
        b"pass%77ord=x",
        b"password",
    ] {
        let error =
            apply_to_body(&form_body(&[("password", b"s")]), &form_type(), body).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Conflict, "{}", text(body));
    }
}

#[test]
fn form_injection_needs_a_form_body() {
    for caller in [
        HeaderMap::new(),
        json_type(),
        headers(&[("content-type", "text/plain")]),
    ] {
        let error = apply_to_body(&form_body(&[("a", b"s")]), &caller, b"x=1").unwrap_err();
        assert_eq!(error.code(), ErrorCode::BadRequest);
    }
}

#[test]
fn a_json_field_is_inserted() {
    let output = apply_to_body(
        &json_body(&[("/token", b"s3cret")]),
        &json_type(),
        br#"{"a":1}"#,
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value, json!({ "a": 1, "token": "s3cret" }));
}

#[test]
fn a_json_field_creates_objects_on_the_way() {
    let output = apply_to_body(
        &json_body(&[("/auth/inner/token", b"s")]),
        &json_type(),
        br#"{"auth":{"x":1}}"#,
    )
    .unwrap();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        value,
        json!({ "auth": { "x": 1, "inner": { "token": "s" } } })
    );
}

#[test]
fn a_json_pointer_is_unescaped() {
    let output = apply_to_body(&json_body(&[("/a~1b/c~0d", b"s")]), &json_type(), b"{}").unwrap();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value, json!({ "a/b": { "c~d": "s" } }));
}

#[test]
fn the_caller_cannot_set_an_injected_json_location() {
    for (pointer, body) in [
        ("/token", &br#"{"token":"mine"}"#[..]),
        ("/token", br#"{"token":null}"#),
        ("/token", br#"{"token":"escaped"}"#),
        ("/a/b", br#"{"a":{"b":1}}"#),
        ("/a/b", br#"{"a":"string"}"#),
        ("/a/b", br#"{"a":[1]}"#),
    ] {
        let error = apply_to_body(&json_body(&[(pointer, b"s")]), &json_type(), body).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Conflict, "{}", text(body));
    }
}

#[test]
fn json_injection_needs_a_json_object() {
    for body in [&b"[1]"[..], b"1", b"\"a\"", b"null", b"not json", b""] {
        let error = apply_to_body(&json_body(&[("/a", b"s")]), &json_type(), body).unwrap_err();
        assert_eq!(error.code(), ErrorCode::BadRequest, "{}", text(body));
    }
    let error = apply_to_body(&json_body(&[("/a", b"s")]), &form_type(), b"{}").unwrap_err();
    assert_eq!(error.code(), ErrorCode::BadRequest);
}

#[test]
fn json_structured_suffixes_are_accepted() {
    let caller = headers(&[("content-type", "application/vnd.api+json; charset=utf-8")]);
    apply_to_body(&json_body(&[("/a", b"s")]), &caller, b"{}").unwrap();
}

#[test]
fn a_secret_that_is_not_utf8_cannot_go_in_json() {
    let error = apply_to_body(&json_body(&[("/a", b"\xff")]), &json_type(), b"{}").unwrap_err();
    assert_eq!(error.code(), ErrorCode::BadRequest);
}

#[test]
fn numbers_in_a_json_body_keep_their_precision() {
    let body = br#"{"big":12345678901234567890123,"exact":0.1000000000000000000001}"#;
    let output = apply_to_body(&json_body(&[("/a", b"s")]), &json_type(), body).unwrap();
    let written = text(&output);
    assert!(written.contains("12345678901234567890123"), "{written}");
    assert!(written.contains("0.1000000000000000000001"), "{written}");
}

#[test]
fn a_compressed_body_is_refused() {
    let mut caller = form_type();
    caller.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    let error = apply_to_body(&form_body(&[("a", b"s")]), &caller, b"x").unwrap_err();
    assert_eq!(error.code(), ErrorCode::BadRequest);
}

#[test]
fn errors_from_body_injection_do_not_echo_the_body() {
    let error =
        apply_to_body(&json_body(&[("/a", b"s")]), &json_type(), b"SECRETVALUE").unwrap_err();
    assert!(!error.to_string().contains("SECRETVALUE"));
}

#[test]
fn debug_of_a_body_injection_does_not_show_values() {
    let debug = format!("{:?}", form_body(&[("password", b"SECRETVALUE")]));
    assert!(debug.contains("password"));
    assert!(!debug.contains("SECRETVALUE"));
}

/// Buffers that hold a secret are sized up front: one that grew would leave a copy of
/// what it held behind.
#[test]
fn bodies_with_secrets_never_grow() {
    // Every byte of this secret is escaped or encoded at its longest.
    let worst: Vec<u8> = (0_u8..32)
        .chain([b'"', b'\\', b'&', b'=', b'%', 0xff])
        .collect();
    let fields = vec![("a b/c".to_owned(), Zeroizing::new(worst.clone()))];
    let body = b"x=1&y=%20";
    let room = form_room(&fields, body);
    let output = apply_to_form(&fields, body).unwrap();
    assert!(output.len() <= room);
    assert_eq!(output.capacity(), room, "the form body grew");

    let text: Vec<u8> = (1_u8..32).chain(*b"\"\\").collect();
    let fields = vec![("/a/b/c/d/e".to_owned(), Zeroizing::new(text))];
    let body = br#"{"x":1}"#;
    let room = json_room(&fields, body);
    let output = apply_to_json(&fields, body).unwrap();
    assert!(output.len() <= room);
    assert_eq!(output.capacity(), room, "the JSON body grew");
}

/// Found by fuzzing: a body with `serde_json`'s private number token as a key is
/// refused.
#[test]
fn a_json_body_with_the_number_token_as_a_key_is_refused() {
    let fields = vec![("/token".to_owned(), Zeroizing::new(b"secret".to_vec()))];
    for body in [
        &br#"{"a":"x","$serde_json::private::Number":"1"}"#[..],
        // First in its object, it parses as a number and is gone from the document.
        br#"{"a":[{"b":{"$serde_json::private::Number":"1"}}]}"#,
        br#"{"\u0024serde_json::private::Number":"1"}"#,
        br#"{"a":"x","$serde_json\u003a:private::Number":"1"}"#,
    ] {
        let error = apply_to_json(&fields, body).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::BadRequest,
            "{}",
            String::from_utf8_lossy(body)
        );
    }
    for ordinary in [
        &br#"{"a":[1,2.50,{"b":null}],"c":"\"$serde_json\""}"#[..],
        br#"{"$serde_json::private::Numbers":"1","x":"\u00e9"}"#,
    ] {
        assert!(
            !mentions_number_token(ordinary),
            "{}",
            String::from_utf8_lossy(ordinary)
        );
    }
}
