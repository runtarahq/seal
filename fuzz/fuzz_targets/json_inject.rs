//! Whatever the caller's JSON says, the injected value is where the rule says, and the
//! caller cannot have set it.

#![no_main]

use std::collections::BTreeMap;

use http::{HeaderMap, HeaderValue, header};
use libfuzzer_sys::fuzz_target;
use seal_broker::inject::{BodyInjection, apply_to_body};
use serde_json::value::RawValue;
use zeroize::Zeroizing;

/// An object's members, each as written. The output is read this way, not into a tree:
/// seal passes a number on as the caller wrote it, and one too large for a float is still
/// JSON.
type Members<'a> = BTreeMap<String, &'a RawValue>;

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let injection =
        BodyInjection::Json(vec![("/a/secret".to_owned(), Zeroizing::new(b"INJECTED".to_vec()))]);
    if let Ok(output) = apply_to_body(&injection, &headers, data) {
        let body: Members = serde_json::from_slice(&output).expect("the output is a JSON object");
        let a: Members = serde_json::from_str(body.get("a").expect("`a` is there").get())
            .expect("`a` is an object");
        let secret: String =
            serde_json::from_str(a.get("secret").expect("the secret is there").get())
                .expect("the secret is a string");
        assert_eq!(secret, "INJECTED");
    }
});
