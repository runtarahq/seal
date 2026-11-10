//! Whatever the caller's JSON says, the injected value is where the rule says, and the
//! caller cannot have set it.

#![no_main]

use http::{HeaderMap, HeaderValue, header};
use libfuzzer_sys::fuzz_target;
use seal_broker::inject::{BodyInjection, apply_to_body};
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let injection =
        BodyInjection::Json(vec![("/a/secret".to_owned(), Zeroizing::new(b"INJECTED".to_vec()))]);
    if let Ok(output) = apply_to_body(&injection, &headers, data) {
        let value: serde_json::Value =
            serde_json::from_slice(&output).expect("the output is valid JSON");
        assert_eq!(value.pointer("/a/secret"), Some(&serde_json::json!("INJECTED")));
    }
});
