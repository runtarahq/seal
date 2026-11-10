//! Parsing must never panic, and an accepted envelope must have one written form.

#![no_main]

use libfuzzer_sys::fuzz_target;
use seal_format::Envelope;

fuzz_target!(|data: &[u8]| {
    let Ok(envelope) = Envelope::from_json(data) else {
        return;
    };
    let json = envelope.to_json().expect("an accepted envelope serialises");
    let reparsed = Envelope::from_json(json.as_bytes()).expect("written form parses");
    assert_eq!(envelope, reparsed);
    assert_eq!(json, reparsed.to_json().expect("serialises again"));
});
