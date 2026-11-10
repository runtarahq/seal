//! Whatever bytes a caller sends as a `SendHead`, decoding and checking them never
//! panics, and a head that passes has a well-formed keyset, item and fields.

#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;
use seal::service::parse_send_head;
use seal_proto::v1::SendHead;

fuzz_target!(|data: &[u8]| {
    let Ok(head) = SendHead::decode(data) else {
        return;
    };
    if let Ok(parsed) = parse_send_head(head) {
        assert!(!parsed.keyset.as_str().is_empty());
        for value in parsed.sealed.values() {
            assert!(!value.envelope.keyset().as_str().is_empty());
        }
    }
});
