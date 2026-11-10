//! Opens an envelope from standard input, natively, with the key from
//! `vectors/envelope.json`. `scripts/wasm-roundtrip.sh` feeds it envelopes sealed
//! in WebAssembly. Exits nonzero if the value does not open to what is expected.

#![allow(clippy::unwrap_used, clippy::print_stdout)]

use std::io::Read;

use seal_format::{Binding, Envelope, FieldName, ItemId, KeysetId, Policy, PrivateKey, open};
use serde_json::Value;

fn main() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();

    let manifest = env!("CARGO_MANIFEST_DIR");
    let vectors: Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{manifest}/../../vectors/envelope.json")).unwrap(),
    )
    .unwrap();
    let key = vectors["private_key_hex"].as_str().unwrap();
    let key: Vec<u8> = (0..key.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&key[index..index + 2], 16).unwrap())
        .collect();
    let private = PrivateKey::from_bytes(&key).unwrap();

    let (keyset, item, field) = (
        KeysetId::new("acme").unwrap(),
        ItemId::new("c_123").unwrap(),
        FieldName::new("api_key").unwrap(),
    );
    let envelope = Envelope::from_json(trim(&input)).unwrap();
    let opened = open(
        &private,
        &envelope,
        Binding {
            keyset: &keyset,
            item: &item,
            field: &field,
        },
    )
    .unwrap();

    let expected = std::env::args().nth(1).unwrap();
    assert_eq!(opened.secret.expose(<[u8]>::to_vec), expected.as_bytes());
    Policy::from_json(&opened.policy.canonical_json().unwrap()).unwrap();
    println!("opened natively");
}

fn trim(input: &[u8]) -> &[u8] {
    input.strip_suffix(b"\n").unwrap_or(input)
}
