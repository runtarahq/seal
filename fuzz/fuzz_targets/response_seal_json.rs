//! Whatever a provider returns, a declared field never comes back in plaintext.

#![no_main]

use http::{HeaderMap, HeaderValue, header};
use libfuzzer_sys::fuzz_target;
use seal_broker::response_seal::seal_response_fields;
use seal_format::id::KeyId;
use seal_format::policy::{ResponseFormat, SealResponse, SealedField, builder};
use seal_format::{Binding, FieldName, ItemId, KeysetId, PolicyName, PublicKey, seal};

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
    if let (Ok(output), Ok(input)) = (result, serde_json::from_slice::<serde_json::Value>(data)) {
        let output: serde_json::Value = serde_json::from_slice(&output.body).expect("valid JSON");
        if let Some(serde_json::Value::String(_)) = input.pointer("/token") {
            assert!(output.pointer("/token").is_some_and(serde_json::Value::is_object));
        }
    }
});
