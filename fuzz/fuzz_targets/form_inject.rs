//! Whatever the caller's form says, the injected value appears exactly once, and the
//! caller cannot have set it.

#![no_main]

use http::{HeaderMap, HeaderValue, header};
use libfuzzer_sys::fuzz_target;
use seal_broker::inject::{BodyInjection, apply_to_body};
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    let injection =
        BodyInjection::Form(vec![("secret".to_owned(), Zeroizing::new(b"INJECTED".to_vec()))]);
    if let Ok(output) = apply_to_body(&injection, &headers, data) {
        let values: Vec<_> = form_urlencoded::parse(&output)
            .filter(|(key, _)| key == "secret")
            .collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].1, "INJECTED");
    }
});
