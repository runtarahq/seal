//! An address that is permitted by default must never be one that reaches something
//! internal, however it is embedded.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use seal_broker::address::{AddressClass, NetworkPolicy, classify, unembed};

fuzz_target!(|data: [u8; 16]| {
    let policy = NetworkPolicy::default();
    let v6 = IpAddr::V6(Ipv6Addr::from(data));
    let v4 = IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
    for address in [v6, v4] {
        let class = classify(address);
        assert_eq!(policy.permits(address, true), class == AddressClass::Public);
        assert_eq!(classify(unembed(address)), class);
    }
});
