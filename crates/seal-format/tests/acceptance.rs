//! The acceptance criteria that this crate can show. `docs/acceptance.md`
//! maps every criterion to its tests.

#![cfg(not(target_arch = "wasm32"))]
#![allow(clippy::unwrap_used)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use seal_format::id::KeyId;
use seal_format::policy::builder;
use seal_format::{
    Binding, Envelope, FieldName, FormatError, ItemId, KeysetId, Policy, PrivateKey, open, seal,
};
use serde_json::Value;

struct Stored {
    private: PrivateKey,
    envelope: Envelope,
    keyset: KeysetId,
    item: ItemId,
    field: FieldName,
}

fn stored_value(policy: &Policy) -> Stored {
    let (private, public) = PrivateKey::generate();
    let keyset = KeysetId::new("acme").unwrap();
    let item = ItemId::new("connection-1").unwrap();
    let field = FieldName::new("api_key").unwrap();
    let envelope = seal(
        &public,
        &KeyId::new("k1").unwrap(),
        Binding {
            keyset: &keyset,
            item: &item,
            field: &field,
        },
        b"secret",
        policy,
    )
    .unwrap();
    Stored {
        private,
        envelope,
        keyset,
        item,
        field,
    }
}

fn policy() -> Policy {
    builder::bearer("https://api.example.com/").unwrap()
}

#[test]
fn acceptance_a_value_moved_to_another_item_does_not_open() {
    let value = stored_value(&policy());
    let other = ItemId::new("connection-2").unwrap();
    let binding = Binding {
        keyset: &value.keyset,
        item: &other,
        field: &value.field,
    };
    assert_eq!(
        open(&value.private, &value.envelope, binding).unwrap_err(),
        FormatError::OpenFailed
    );
}

#[test]
fn acceptance_a_value_moved_to_another_field_does_not_open() {
    let value = stored_value(&policy());
    let other = FieldName::new("password").unwrap();
    let binding = Binding {
        keyset: &value.keyset,
        item: &value.item,
        field: &other,
    };
    assert_eq!(
        open(&value.private, &value.envelope, binding).unwrap_err(),
        FormatError::OpenFailed
    );
}

#[test]
fn acceptance_a_value_moved_to_another_keyset_does_not_open() {
    let value = stored_value(&policy());
    let other = KeysetId::new("other-tenant").unwrap();
    let binding = Binding {
        keyset: &other,
        item: &value.item,
        field: &value.field,
    };
    assert_eq!(
        open(&value.private, &value.envelope, binding).unwrap_err(),
        FormatError::KeysetMismatch
    );

    // Rewriting the envelope to claim the other keyset does not help either.
    let mut json: Value = serde_json::from_str(&value.envelope.to_json().unwrap()).unwrap();
    json["keyset"] = Value::from(other.as_str());
    let rewritten = Envelope::from_json(json.to_string().as_bytes()).unwrap();
    assert_eq!(
        open(&value.private, &rewritten, binding).unwrap_err(),
        FormatError::OpenFailed
    );
}

/// The policy is inside the ciphertext, so changing it means changing ciphertext
/// bytes. Every byte is covered, including those that hold the policy.
#[test]
fn acceptance_a_changed_policy_does_not_open() {
    let value = stored_value(&policy());
    let binding = Binding {
        keyset: &value.keyset,
        item: &value.item,
        field: &value.field,
    };
    let json: Value = serde_json::from_str(&value.envelope.to_json().unwrap()).unwrap();
    let ciphertext = URL_SAFE_NO_PAD
        .decode(json["ct"].as_str().unwrap())
        .unwrap();
    for index in 0..ciphertext.len() {
        let mut changed = ciphertext.clone();
        changed[index] ^= 0x80;
        let mut altered = json.clone();
        altered["ct"] = Value::from(URL_SAFE_NO_PAD.encode(changed));
        let envelope = Envelope::from_json(altered.to_string().as_bytes()).unwrap();
        assert_eq!(
            open(&value.private, &envelope, binding).unwrap_err(),
            FormatError::OpenFailed,
            "byte {index}"
        );
    }
}
