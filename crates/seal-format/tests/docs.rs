//! Keeps `docs/policy.md` true: every example is a valid policy, and every option
//! in the schema is documented with an example.

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use seal_format::Policy;
use serde_json::Value;

/// Every option name in the schema. Adding an option without adding it here and
/// to the document is caught by the check on the built examples below.
const OPTIONS: &[&str] = &[
    "allow_headers",
    "rules",
    "definitions",
    "destination",
    "methods",
    "inject",
    "plain",
    "seal_response",
    "limits",
    "allow_private_destination",
    "allow_plain_http",
    "scheme",
    "host",
    "port",
    "path_prefix",
    "databases",
    "user",
    "tls",
    "ca",
    "allow_replication",
    "header",
    "name",
    "format",
    "basic",
    "username",
    "field",
    "literal",
    "query",
    "path",
    "prefix",
    "form_field",
    "json_field",
    "pointer",
    "client_cert",
    "cert",
    "chain",
    "server_name",
    "aws_sigv4",
    "region",
    "service",
    "access_key_id",
    "session_token",
    "payload",
    "allow_unsigned_payload",
    "azure_shared_key",
    "account",
    "jwt_assertion",
    "alg",
    "aud",
    "value",
    "claims",
    "iss",
    "sub",
    "scope",
    "extra",
    "typ",
    "kid",
    "x5t#S256",
    "max_lifetime_s",
    "pg_password",
    "allow_md5",
    "allow_cleartext_password",
    "require_channel_binding",
    "companion",
    "fields",
    "at",
    "as",
    "policy",
    "expose_claims",
    "buffer_cap_bytes",
    "idle_timeout_s",
    "connect_timeout_s",
    "first_byte_timeout_s",
    "buffered_total_timeout_s",
    "max_stream_duration_s",
    "pg_max_session_s",
    "shared",
    "require_form",
    "verify",
    "hmac",
    "hash",
    "allow_presign",
    "max_expiry_s",
    "allow_copy_from_any_bucket",
    "allow_injected_path",
];

fn policy_doc() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/policy.md")).unwrap()
}

fn json_examples(document: &str) -> Vec<&str> {
    document
        .split("```json\n")
        .skip(1)
        .map(|rest| rest.split("\n```").next().unwrap())
        .collect()
}

/// Every key in a JSON value, at any depth, except the names of definitions, extra
/// claims and required form fields, which are chosen by the author.
fn collect_keys(value: &Value, keys: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                keys.insert(key.clone());
                if key == "definitions" || key == "extra" || key == "require_form" {
                    for grandchild in child.as_object().unwrap().values() {
                        collect_keys(grandchild, keys);
                    }
                } else {
                    collect_keys(child, keys);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_keys(item, keys)),
        _ => {}
    }
}

#[test]
fn every_example_in_the_policy_document_is_a_valid_policy() {
    let document = policy_doc();
    let examples = json_examples(&document);
    assert!(examples.len() > 15, "found {}", examples.len());
    for example in examples {
        Policy::from_json(example.as_bytes())
            .unwrap_or_else(|error| panic!("{error} in:\n{example}"));
    }
}

#[test]
fn every_option_appears_in_an_example() {
    let document = policy_doc();
    let mut keys = BTreeSet::new();
    for example in json_examples(&document) {
        collect_keys(&serde_json::from_str(example).unwrap(), &mut keys);
    }
    let expected: BTreeSet<String> = OPTIONS.iter().map(|option| (*option).to_owned()).collect();
    let undocumented: Vec<_> = expected.difference(&keys).collect();
    let unlisted: Vec<_> = keys.difference(&expected).collect();
    assert!(undocumented.is_empty(), "no example uses {undocumented:?}");
    assert!(unlisted.is_empty(), "add to OPTIONS: {unlisted:?}");
}

/// The string values of enumerations, which the key check above cannot see.
#[test]
fn every_enumerated_value_is_documented() {
    let document = policy_doc();
    for value in [
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "computed",
        "caller_hash",
        "streaming",
        "blob",
        "queue",
        "file",
        "table",
        "RS256",
        "PS256",
        "ES256",
        "json",
        "form",
        "xml",
        "verify_full",
        "token_endpoint",
        "sha1",
        "sha256",
        "sha512",
    ] {
        assert!(document.contains(value), "{value}");
    }
}
