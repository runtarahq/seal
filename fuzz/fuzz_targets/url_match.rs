//! Parsing a target must never panic, and whatever is accepted within a prefix must
//! really be below it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use seal_broker::target::Target;
use seal_format::policy::{Destination, Host, Scheme};

fuzz_target!(|data: &str| {
    let Ok(target) = Target::parse(data) else {
        return;
    };
    let destination = Destination::Http {
        scheme: Scheme::Https,
        host: Host::new("api.example.com").expect("a valid host"),
        port: None,
        path_prefix: Some("/v2/".to_owned()),
    };
    if target.matches(&destination) {
        assert_eq!(target.host, "api.example.com");
        assert_eq!(target.port, 443);
        assert!(target.path.starts_with("/v2/"));
        assert!(!target.path.contains("/../"));
        assert!(!target.path.contains("/./"));
    }
});
