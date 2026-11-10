//! Parsing and validation must never panic, and an accepted policy must have one
//! canonical form, which is itself accepted.

#![no_main]

use libfuzzer_sys::fuzz_target;
use seal_format::Policy;

fuzz_target!(|data: &[u8]| {
    let Ok(policy) = Policy::from_json(data) else {
        return;
    };
    let canonical = policy.canonical_json().expect("an accepted policy serialises");
    let reparsed = Policy::from_json(&canonical).expect("canonical form is accepted");
    assert_eq!(policy, reparsed);
    assert_eq!(
        canonical,
        reparsed.canonical_json().expect("serialises again"),
    );
});
