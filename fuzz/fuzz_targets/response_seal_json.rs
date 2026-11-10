//! Whatever a provider returns, a declared field never comes back in plaintext.

#![no_main]

use std::collections::BTreeMap;

use http::{HeaderMap, HeaderValue, header};
use libfuzzer_sys::fuzz_target;
use seal_broker::response_seal::seal_response_fields;
use seal_format::id::KeyId;
use seal_format::policy::{ResponseFormat, SealResponse, SealedField, builder};
use seal_format::{Binding, FieldName, ItemId, KeysetId, PolicyName, PublicKey, seal};
use serde_json::value::RawValue;

/// An object's members, each as written. Responses are read this way, not into a tree:
/// seal passes a number on as the provider wrote it, and one too large for a float is
/// still JSON.
type Members<'a> = BTreeMap<String, &'a RawValue>;

/// Whether an object's `token` is written as this kind of value.
fn token_starts_with(members: &Members, first: char) -> bool {
    members.get("token").is_some_and(|token| token.get().trim_start().starts_with(first))
}

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let sealing = SealResponse {
        format: ResponseFormat::Json,
        fields: vec![SealedField {
            at: "/token".to_owned(),
            as_field: FieldName::new("token").expect("valid"),
            policy: PolicyName::new("api").expect("valid"),
            expose_claims: Vec::new(),
        }],
    };
    let public = PublicKey::from_bytes(&[9; 32]).expect("valid");
    let policy = builder::bearer("https://api.example.com/").expect("valid");
    let (keyset, item) = (KeysetId::new("a").expect("valid"), ItemId::new("b").expect("valid"));
    let result = seal_response_fields(&sealing, &headers, data, |field, plaintext| {
        let binding = Binding { keyset: &keyset, item: &item, field: &field.as_field };
        Ok(seal(&public, &KeyId::new("k").expect("valid"), binding, plaintext, &policy)
            .expect("sealing works"))
    });
    if let Ok(output) = result {
        // An empty response has nothing to seal, and stays empty.
        if !data.is_empty() {
            serde_json::from_slice::<&RawValue>(&output.body).expect("the output is valid JSON");
        }
        // A response whose `token` is a string comes back with an envelope there instead,
        // or not at all.
        if serde_json::from_slice::<Members>(data).is_ok_and(|input| token_starts_with(&input, '"'))
        {
            let output: Members =
                serde_json::from_slice(&output.body).expect("the output is a JSON object");
            assert!(token_starts_with(&output, '{'));
        }
    }
});
