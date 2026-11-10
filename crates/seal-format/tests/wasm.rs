//! Runs inside WebAssembly, under Node. `scripts/wasm-roundtrip.sh` covers the
//! other half: sealing in WebAssembly and opening natively.

#![cfg(all(target_arch = "wasm32", feature = "wasm"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use seal_format::Envelope;
use seal_format::wasm::seal;
use wasm_bindgen_test::wasm_bindgen_test;

/// The public key from `vectors/envelope.json`.
const PUBLIC_KEY: &str = "OmuDz0Tdc7vF6Cuc5RAhMCgpbH--sv4KbUkKCxpZkVk";
const POLICY: &str = r#"{"rules":[{"destination":{"scheme":"https","host":"api.example.com"},"inject":{"header":{"name":"Authorization","format":"Bearer {}"}}}]}"#;

fn seal_fixture(secret: &[u8]) -> Result<String, String> {
    seal(PUBLIC_KEY, "k3", "acme", "c_123", "api_key", secret, POLICY)
}

#[wasm_bindgen_test]
fn seals_to_a_valid_envelope() {
    let json = seal_fixture(b"hunter2").unwrap();
    let envelope = Envelope::from_json(json.as_bytes()).unwrap();
    assert_eq!(envelope.keyset().as_str(), "acme");
    assert_eq!(envelope.kid().as_str(), "k3");
    assert!(!json.contains("hunter2"));
}

/// Shows that the browser's random source is really being used.
#[wasm_bindgen_test]
fn sealing_twice_gives_different_envelopes() {
    assert_ne!(
        seal_fixture(b"hunter2").unwrap(),
        seal_fixture(b"hunter2").unwrap()
    );
}

#[wasm_bindgen_test]
fn refuses_invalid_input_and_names_what_is_wrong() {
    let seal_with = |key: &str, keyset: &str, policy: &str| {
        seal(key, "k3", keyset, "c_123", "api_key", b"x", policy).unwrap_err()
    };
    assert_eq!(seal_with("not base64!", "acme", POLICY), "invalid key");
    assert_eq!(seal_with(PUBLIC_KEY, "..", POLICY), "invalid keyset");
    assert!(seal_with(PUBLIC_KEY, "acme", "{}").starts_with("invalid policy"));
}

#[wasm_bindgen_test]
fn errors_do_not_echo_the_input() {
    let error = seal(
        PUBLIC_KEY,
        "k3",
        "acme",
        "c_123",
        "api_key",
        b"x",
        "SECRETVALUE",
    )
    .unwrap_err();
    assert!(!error.contains("SECRETVALUE"));
}
