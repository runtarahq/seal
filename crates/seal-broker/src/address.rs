//! Which addresses seal may connect to.
//!
//! A destination's host is only checked against a policy by name, so a name that
//! resolves to an internal address could otherwise reach anything seal can reach.
//! Every address is checked after resolving, and seal connects to the address it
//! checked, with no second lookup.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::error::{BrokerError, ErrorCode};

/// What kind of address something is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressClass {
    /// Routable on the internet.
    Public,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// RFC 1918.
    Private,
    /// `100.64.0.0/10`.
    SharedAddressSpace,
    /// `fc00::/7`.
    UniqueLocal,
    /// `169.254.0.0/16`, `fe80::/10`.
    LinkLocal,
    /// A cloud metadata service outside the link-local ranges.
    Metadata,
    /// `0.0.0.0/8`, `::`.
    Unspecified,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// Documentation and benchmarking ranges.
    Documentation,
    /// Everything else not routable, including all IPv6 outside `2000::/3`.
    Reserved,
}

impl AddressClass {
    /// Whether a rule's `allow_private_destination` can permit this class.
    ///
    /// It covers internal services, not link-local or metadata addresses, which
    /// have never been a sensible destination for a credential. Those need an
    /// operator's `allow_private_cidrs`.
    #[must_use]
    pub fn rule_may_allow(self) -> bool {
        matches!(
            self,
            Self::Loopback | Self::Private | Self::SharedAddressSpace | Self::UniqueLocal
        )
    }
}

/// Classifies an address. IPv4 embedded in IPv6 is classified as the IPv4 address.
#[must_use]
pub fn classify(address: IpAddr) -> AddressClass {
    match unembed(address) {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// The address a connection would really reach: the IPv4 address embedded in an
/// IPv4-mapped, IPv4-compatible, NAT64 or 6to4 address, or the address itself.
#[must_use]
pub fn unembed(address: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = address else {
        return address;
    };
    let segments = v6.segments();
    let last_32 = || {
        let [.., a, b, c, d] = v6.octets();
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    };
    match segments {
        // IPv4-mapped.
        [0, 0, 0, 0, 0, 0xffff, ..] => last_32(),
        // IPv4-compatible (deprecated), leaving out `::` and `::1`.
        [0, 0, 0, 0, 0, 0, high, _] if high != 0 => last_32(),
        // NAT64, well-known prefix.
        [0x64, 0xff9b, 0, 0, 0, 0, ..] => last_32(),
        // 6to4: the address follows the prefix.
        [0x2002, high, low, ..] => IpAddr::V4(Ipv4Addr::new(
            (high >> 8) as u8,
            (high & 0xff) as u8,
            (low >> 8) as u8,
            (low & 0xff) as u8,
        )),
        _ => address,
    }
}

fn classify_v4(address: Ipv4Addr) -> AddressClass {
    let [a, b, c, d] = address.octets();
    match (a, b, c, d) {
        (0, ..) => AddressClass::Unspecified,
        (127, ..) => AddressClass::Loopback,
        (10, ..) | (172, 16..=31, ..) | (192, 168, ..) => AddressClass::Private,
        // Alibaba Cloud's metadata service, inside the shared address space.
        (100, 100, 100, 200) => AddressClass::Metadata,
        (100, 64..=127, ..) => AddressClass::SharedAddressSpace,
        (169, 254, ..) => AddressClass::LinkLocal,
        // Azure's wireserver.
        (168, 63, 129, 16) => AddressClass::Metadata,
        (192, 0, 2, _) | (198, 51, 100, _) | (203, 0, 113, _) | (198, 18..=19, ..) => {
            AddressClass::Documentation
        }
        (255, 255, 255, 255) => AddressClass::Broadcast,
        (224..=239, ..) => AddressClass::Multicast,
        (240..=255, ..) | (192, 0, 0, _) | (192, 88, 99, _) => AddressClass::Reserved,
        _ => AddressClass::Public,
    }
}

fn classify_v6(address: Ipv6Addr) -> AddressClass {
    let segments = address.segments();
    match segments {
        [0, 0, 0, 0, 0, 0, 0, 0] => AddressClass::Unspecified,
        [0, 0, 0, 0, 0, 0, 0, 1] => AddressClass::Loopback,
        // The instance metadata services of AWS and Google Cloud over IPv6, inside the
        // unique local range.
        [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254] | [0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x254] => {
            AddressClass::Metadata
        }
        [first, ..] if first & 0xfe00 == 0xfc00 => AddressClass::UniqueLocal,
        [first, ..] if first & 0xffc0 == 0xfe80 => AddressClass::LinkLocal,
        [first, ..] if first & 0xff00 == 0xff00 => AddressClass::Multicast,
        [0x2001, 0xdb8, ..] => AddressClass::Documentation,
        [0x3fff, second, ..] if second & 0xf000 == 0 => AddressClass::Documentation,
        // Teredo and other IETF special-purpose addresses, including tunnels that
        // could reach an embedded IPv4 address this check cannot see.
        [0x2001, second, ..] if second & 0xfe00 == 0 => AddressClass::Reserved,
        [first, ..] if first & 0xe000 == 0x2000 => AddressClass::Public,
        _ => AddressClass::Reserved,
    }
}

/// An address range, written like `10.0.0.0/8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Whether the range contains an address, after unembedding it.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, unembed(address)) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let shift = 32 - u32::from(self.prefix);
                let (network, address) = (u32::from(network), u32::from(address));
                shift == 32 || network >> shift == address >> shift
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let shift = 128 - u32::from(self.prefix);
                let (network, address) = (u128::from(network), u128::from(address));
                shift == 128 || network >> shift == address >> shift
            }
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = BrokerError;

    fn from_str(text: &str) -> Result<Self, BrokerError> {
        let invalid = || BrokerError::new(ErrorCode::BadRequest, "address range is not valid");
        let (network, prefix) = text.split_once('/').ok_or_else(invalid)?;
        let network: IpAddr = network.parse().map_err(|_| invalid())?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(invalid());
        }
        Ok(Self { network, prefix })
    }
}

/// The network part of the configuration.
#[derive(Clone, Debug, Default)]
pub struct NetworkPolicy {
    /// Always refused. Takes priority over everything else.
    pub deny_cidrs: Vec<Cidr>,
    /// Allowed whatever their class, for this deployment.
    pub allow_private_cidrs: Vec<Cidr>,
    /// Whether a rule's `allow_private_destination` has any effect. Off by default.
    pub honour_private_rules: bool,
}

impl NetworkPolicy {
    /// Whether an address may be connected to, for a request whose matched rules
    /// all set `allow_private_destination` if `rule_allows_private` is true.
    #[must_use]
    pub fn permits(&self, address: IpAddr, rule_allows_private: bool) -> bool {
        if self.deny_cidrs.iter().any(|cidr| cidr.contains(address)) {
            return false;
        }
        if self
            .allow_private_cidrs
            .iter()
            .any(|cidr| cidr.contains(address))
        {
            return true;
        }
        let class = classify(address);
        class == AddressClass::Public
            || (class.rule_may_allow() && rule_allows_private && self.honour_private_rules)
    }
}

#[cfg(test)]
mod tests {
    use super::AddressClass::{
        Broadcast, Documentation, LinkLocal, Loopback, Metadata, Multicast, Private, Public,
        Reserved, SharedAddressSpace, UniqueLocal, Unspecified,
    };
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// At least one address per range, and the boundaries either side of each.
    const TABLE: &[(&str, AddressClass)] = &[
        ("0.0.0.0", Unspecified),
        ("0.255.255.255", Unspecified),
        ("1.0.0.0", Public),
        ("9.255.255.255", Public),
        ("10.0.0.0", Private),
        ("10.255.255.255", Private),
        ("11.0.0.0", Public),
        ("100.63.255.255", Public),
        ("100.64.0.0", SharedAddressSpace),
        ("100.100.100.100", SharedAddressSpace),
        ("100.127.255.255", SharedAddressSpace),
        ("100.128.0.0", Public),
        ("126.255.255.255", Public),
        ("127.0.0.0", Loopback),
        ("127.0.0.1", Loopback),
        ("127.255.255.255", Loopback),
        ("128.0.0.0", Public),
        ("168.63.129.15", Public),
        ("168.63.129.16", Metadata),
        ("100.100.100.200", Metadata),
        ("100.100.100.201", SharedAddressSpace),
        ("fd00:ec2::254", Metadata),
        ("fd20:ce::254", Metadata),
        ("fd00:ec2::253", UniqueLocal),
        ("168.63.129.17", Public),
        ("169.253.255.255", Public),
        ("169.254.0.0", LinkLocal),
        ("169.254.169.254", LinkLocal),
        ("169.254.255.255", LinkLocal),
        ("169.255.0.0", Public),
        ("172.15.255.255", Public),
        ("172.16.0.0", Private),
        ("172.31.255.255", Private),
        ("172.32.0.0", Public),
        ("191.255.255.255", Public),
        ("192.0.0.0", Reserved),
        ("192.0.0.255", Reserved),
        ("192.0.1.0", Public),
        ("192.0.2.0", Documentation),
        ("192.0.2.255", Documentation),
        ("192.0.3.0", Public),
        ("192.88.98.255", Public),
        ("192.88.99.0", Reserved),
        ("192.88.100.0", Public),
        ("192.167.255.255", Public),
        ("192.168.0.0", Private),
        ("192.168.255.255", Private),
        ("192.169.0.0", Public),
        ("198.17.255.255", Public),
        ("198.18.0.0", Documentation),
        ("198.19.255.255", Documentation),
        ("198.20.0.0", Public),
        ("198.51.99.255", Public),
        ("198.51.100.0", Documentation),
        ("198.51.101.0", Public),
        ("203.0.112.255", Public),
        ("203.0.113.0", Documentation),
        ("203.0.114.0", Public),
        ("223.255.255.255", Public),
        ("224.0.0.0", Multicast),
        ("239.255.255.255", Multicast),
        ("240.0.0.0", Reserved),
        ("255.255.255.254", Reserved),
        ("255.255.255.255", Broadcast),
        ("8.8.8.8", Public),
        ("::", Unspecified),
        ("::1", Loopback),
        ("::2", Reserved),
        ("100::1", Reserved),
        ("1fff:ffff::", Reserved),
        ("2000::", Public),
        ("2001:0:1::", Reserved),
        ("2001:1ff::", Reserved),
        ("2001:200::", Public),
        ("2001:db7:ffff::", Public),
        ("2001:db8::", Documentation),
        ("2001:db8:ffff::", Documentation),
        ("2001:db9::", Public),
        ("2606:4700:4700::1111", Public),
        ("3ffe:ffff::", Public),
        ("3fff::", Documentation),
        ("3fff:fff::", Documentation),
        ("3fff:1000::", Public),
        ("4000::", Reserved),
        ("fbff::", Reserved),
        ("fc00::", UniqueLocal),
        ("fd00:ec2::1", UniqueLocal),
        ("fdff:ffff::", UniqueLocal),
        ("fe00::", Reserved),
        ("fe7f::", Reserved),
        ("fe80::", LinkLocal),
        ("febf:ffff::", LinkLocal),
        ("fec0::", Reserved),
        ("ff00::", Multicast),
        ("ffff::", Multicast),
    ];

    #[test]
    fn every_range_is_classified_including_its_boundaries() {
        for (address, class) in TABLE {
            assert_eq!(classify(ip(address)), *class, "{address}");
        }
    }

    #[test]
    fn embedded_ipv4_is_classified_as_the_address_it_reaches() {
        for (address, class) in [
            // IPv4-mapped.
            ("::ffff:127.0.0.1", Loopback),
            ("::ffff:10.0.0.1", Private),
            ("::ffff:169.254.169.254", LinkLocal),
            ("::ffff:8.8.8.8", Public),
            // IPv4-compatible.
            ("::127.0.0.1", Loopback),
            ("::10.0.0.1", Private),
            ("::8.8.8.8", Public),
            // NAT64.
            ("64:ff9b::127.0.0.1", Loopback),
            ("64:ff9b::a00:1", Private),
            ("64:ff9b::a9fe:a9fe", LinkLocal),
            ("64:ff9b::808:808", Public),
            // 6to4.
            ("2002:7f00:1::", Loopback),
            ("2002:a00:1::", Private),
            ("2002:a9fe:a9fe::", LinkLocal),
            ("2002:808:808::", Public),
        ] {
            assert_eq!(classify(ip(address)), class, "{address}");
        }
    }

    #[test]
    fn other_nat64_prefixes_are_not_treated_as_public() {
        // The local-use prefix can hide an internal address that this check cannot
        // find, so it falls through to Reserved.
        assert_eq!(classify(ip("64:ff9b:1::a00:1")), Reserved);
    }

    #[test]
    fn nothing_internal_is_permitted_by_default() {
        let policy = NetworkPolicy::default();
        for (address, class) in TABLE {
            assert_eq!(
                policy.permits(ip(address), false),
                *class == Public,
                "{address}"
            );
            assert_eq!(
                policy.permits(ip(address), true),
                *class == Public,
                "{address}: a rule's flag has no effect until configuration honours it"
            );
        }
    }

    #[test]
    fn a_rule_can_allow_internal_services_only_if_configuration_honours_it() {
        let policy = NetworkPolicy {
            honour_private_rules: true,
            ..NetworkPolicy::default()
        };
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(policy.permits(ip(address), true), "{address}");
            assert!(!policy.permits(ip(address), false), "{address}");
        }
    }

    #[test]
    fn a_rule_can_never_allow_metadata_or_other_non_internal_ranges() {
        let policy = NetworkPolicy {
            honour_private_rules: true,
            ..NetworkPolicy::default()
        };
        for address in [
            "169.254.169.254",
            "100.100.100.200",
            "::ffff:100.100.100.200",
            "fd00:ec2::254",
            "fd20:ce::254",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2002:a9fe:a9fe::",
            "fe80::1",
            "168.63.129.16",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.2.1",
        ] {
            assert!(!policy.permits(ip(address), true), "{address}");
        }
    }

    #[test]
    fn configuration_can_allow_a_private_range() {
        let policy = NetworkPolicy {
            allow_private_cidrs: vec!["10.1.0.0/16".parse().unwrap()],
            ..NetworkPolicy::default()
        };
        assert!(policy.permits(ip("10.1.2.3"), false));
        assert!(policy.permits(ip("::ffff:10.1.2.3"), false));
        assert!(!policy.permits(ip("10.2.0.1"), false));
    }

    #[test]
    fn denied_ranges_win_over_everything() {
        let policy = NetworkPolicy {
            deny_cidrs: vec![
                "8.8.8.0/24".parse().unwrap(),
                "10.1.2.3/32".parse().unwrap(),
            ],
            allow_private_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
            honour_private_rules: true,
        };
        assert!(!policy.permits(ip("8.8.8.8"), true));
        assert!(!policy.permits(ip("::ffff:8.8.8.8"), true));
        assert!(!policy.permits(ip("2002:808:808::"), true));
        assert!(!policy.permits(ip("10.1.2.3"), true));
        assert!(policy.permits(ip("10.1.2.4"), true));
        assert!(policy.permits(ip("8.8.9.8"), false));
    }

    #[test]
    fn cidrs_parse_and_match_at_the_boundaries() {
        let cidr: Cidr = "192.168.1.0/24".parse().unwrap();
        assert!(cidr.contains(ip("192.168.1.0")));
        assert!(cidr.contains(ip("192.168.1.255")));
        assert!(!cidr.contains(ip("192.168.0.255")));
        assert!(!cidr.contains(ip("192.168.2.0")));
        assert!(!cidr.contains(ip("fd00::1")));

        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(ip("1.2.3.4")));
        let all: Cidr = "::/0".parse().unwrap();
        assert!(all.contains(ip("fd00::1")));
        assert!(!all.contains(ip("1.2.3.4")));

        let one: Cidr = "fd00::1/128".parse().unwrap();
        assert!(one.contains(ip("fd00::1")));
        assert!(!one.contains(ip("fd00::2")));

        for bad in [
            "",
            "10.0.0.0",
            "10.0.0.0/33",
            "fd00::/129",
            "x/8",
            "10.0.0.0/x",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
    }
}
