//! Checks the committed files in `vectors/`.

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/vectors.rs"]
mod support;

use std::fs;
use std::path::PathBuf;

use seal_format::id::KeyId;
use seal_format::seal::associated_data;
use seal_format::{
    Binding, Envelope, FieldName, FormatError, ItemId, KeysetId, Policy, PrivateKey, open,
};
use serde_json::Value;

fn vectors_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

fn read_json(name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(vectors_directory().join(name)).unwrap()).unwrap()
}

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a string"))
}

fn private_key(hex: &str) -> PrivateKey {
    PrivateKey::from_bytes(&unhex(hex)).unwrap()
}

/// A change here is a compatibility break: values sealed earlier would no
/// longer match the documented format.
#[test]
fn committed_vectors_match_the_generator() {
    for (name, generated) in support::generate() {
        let committed = fs::read_to_string(vectors_directory().join(name)).unwrap();
        assert!(
            committed == generated,
            "vectors/{name} differs from the generator. If the format really changed, \
             that breaks stored values: see docs/format.md."
        );
    }
}

#[test]
fn the_public_key_matches_the_private_key() {
    let vectors = read_json("envelope.json");
    let private = private_key(string(&vectors, "private_key_hex"));
    assert_eq!(
        private.public_key().unwrap().as_bytes().as_slice(),
        unhex(string(&vectors, "public_key_hex"))
    );
}

#[test]
fn every_committed_envelope_opens_to_its_secret_and_policy() {
    let vectors = read_json("envelope.json");
    let private = private_key(string(&vectors, "private_key_hex"));
    let cases = vectors["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let keyset = KeysetId::new(string(case, "keyset")).unwrap();
        let item = ItemId::new(string(case, "item")).unwrap();
        let field = FieldName::new(string(case, "field")).unwrap();
        let binding = Binding {
            keyset: &keyset,
            item: &item,
            field: &field,
        };
        let envelope = Envelope::from_json(case["envelope"].to_string().as_bytes()).unwrap();
        let opened = open(&private, &envelope, binding).unwrap();

        assert_eq!(
            opened.secret.expose(<[u8]>::to_vec),
            unhex(string(case, "secret_hex")),
            "{}",
            string(case, "name")
        );
        let plaintext: Value = serde_json::from_str(string(case, "plaintext")).unwrap();
        assert_eq!(
            opened.policy,
            Policy::from_json(plaintext["policy"].to_string().as_bytes()).unwrap()
        );
        let kid = KeyId::new(string(case, "kid")).unwrap();
        assert_eq!(
            associated_data(1, &kid, binding).unwrap(),
            unhex(string(case, "aad_hex"))
        );
    }
}

#[test]
fn every_committed_envelope_fails_to_open_under_each_changed_binding() {
    let vectors = read_json("envelope.json");
    for case in vectors["cases"].as_array().unwrap() {
        let changes = case["must_not_open"].as_array().unwrap();
        assert_eq!(changes.len(), 5);
        for change in changes {
            let what = string(change, "change");
            let value = string(change, "value");
            let mut envelope = case["envelope"].clone();
            let mut keyset = string(case, "keyset").to_owned();
            let mut item = string(case, "item").to_owned();
            let mut field = string(case, "field").to_owned();
            let mut key = private_key(string(&vectors, "private_key_hex"));
            match what {
                "item" => item = value.to_owned(),
                "field" => field = value.to_owned(),
                "keyset" => {
                    // Rewritten in the envelope too, so that the refusal comes
                    // from decryption and not the earlier comparison.
                    keyset = value.to_owned();
                    envelope["keyset"] = Value::from(value);
                }
                "kid" => envelope["kid"] = Value::from(value),
                "private_key_hex" => key = private_key(value),
                other => panic!("unknown change {other}"),
            }
            let (keyset, item, field) = (
                KeysetId::new(keyset).unwrap(),
                ItemId::new(item).unwrap(),
                FieldName::new(field).unwrap(),
            );
            let parsed = Envelope::from_json(envelope.to_string().as_bytes()).unwrap();
            let result = open(
                &key,
                &parsed,
                Binding {
                    keyset: &keyset,
                    item: &item,
                    field: &field,
                },
            );
            assert_eq!(result.unwrap_err(), FormatError::OpenFailed, "{what}");
        }
    }
}

#[test]
fn every_valid_policy_vector_is_accepted_and_canonical() {
    let vectors = read_json("policy.json");
    let valid = vectors["valid"].as_array().unwrap();
    assert!(!valid.is_empty());
    for case in valid {
        let canonical = string(case, "canonical");
        let policy = Policy::from_json(canonical.as_bytes())
            .unwrap_or_else(|e| panic!("{}: {e}", string(case, "name")));
        assert_eq!(policy.canonical_json().unwrap(), canonical.as_bytes());
    }
}

#[test]
fn every_invalid_policy_vector_is_refused() {
    let vectors = read_json("policy.json");
    let invalid = vectors["invalid"].as_array().unwrap();
    assert!(!invalid.is_empty());
    for case in invalid {
        assert!(
            Policy::from_json(case["policy"].to_string().as_bytes()).is_err(),
            "{}",
            string(case, "name")
        );
    }
}
