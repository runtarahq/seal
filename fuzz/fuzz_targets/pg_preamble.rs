//! A caller's first Postgres packet never panics the parser, and a startup message
//! that parses encodes back to one that parses the same.

#![no_main]

use libfuzzer_sys::fuzz_target;
use seal_broker::pg::wire::{Preamble, parse_preamble};

fuzz_target!(|data: &[u8]| {
    if let Ok(Preamble::Startup(startup)) = parse_preamble(data) {
        let encoded = startup.encode();
        assert_eq!(
            parse_preamble(&encoded[4..]).expect("its own encoding parses"),
            Preamble::Startup(startup)
        );
    }
});
