//! Whatever a provider's token says, what seal exposes of it is a JSON object holding
//! only the claims the policy names, each within the size limit.

#![no_main]

use libfuzzer_sys::fuzz_target;
use seal_broker::claims::{MAX_CLAIM_BYTES, exposed};

fuzz_target!(|data: &[u8]| {
    let names = ["exp".to_owned(), "tenant".to_owned()];
    if let Some(json) = exposed(data, &names) {
        let claims: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&json).expect("the output is a JSON object");
        assert!(!claims.is_empty());
        for (name, value) in &claims {
            assert!(names.contains(name), "only named claims are exposed");
            let written = serde_json::to_vec(value).expect("a claim can be written");
            assert!(written.len() <= MAX_CLAIM_BYTES);
        }
    }
});
