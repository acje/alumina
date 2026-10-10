use std::net::{Ipv4Addr, Ipv6Addr};

/// An IPv4 or IPv6 address candidate as a numeric value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumericAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl NumericAddr {
    /// Returns whether this address is an eligible destination.
    pub fn is_eligible(self) -> bool {
        match self {
            NumericAddr::V4(addr) => ipv4_is_eligible(addr),
            NumericAddr::V6(addr) => ipv6_is_eligible(addr),
        }
    }
}

const fn v4_in(addr: u32, net: u32, prefix: u8) -> bool {
    (addr >> (32 - prefix as u32)) == (net >> (32 - prefix as u32))
}

const fn v6_in(addr: u128, net: u128, prefix: u8) -> bool {
    (addr >> (128 - prefix as u32)) == (net >> (128 - prefix as u32))
}

const V4_EXCLUSIONS: &[(u32, u8)] = &[
    (0x0000_0000, 8),
    (0x0a00_0000, 8),
    (0x6440_0000, 10),
    (0x7f00_0000, 8),
    (0xa9fe_0000, 16),
    (0xac10_0000, 12),
    (0xc000_0000, 24),
    (0xc000_0200, 24),
    (0xc058_6300, 24),
    (0xc0a8_0000, 16),
    (0xc612_0000, 15),
    (0xc633_6400, 24),
    (0xcb00_7100, 24),
    (0xe000_0000, 4),
    (0xf000_0000, 4),
];

const V6_EXCLUSIONS: &[(u128, u8)] = &[
    (0x2001_0000_0000_0000_0000_0000_0000_0000, 23),
    (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32),
    (0x2002_0000_0000_0000_0000_0000_0000_0000, 16),
    (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20),
];

/// Returns whether an IPv4 address is an eligible destination.
pub fn ipv4_is_eligible(addr: Ipv4Addr) -> bool {
    let a = u32::from(addr);
    !V4_EXCLUSIONS
        .iter()
        .any(|&(net, prefix)| v4_in(a, net, prefix))
}

/// Returns whether an IPv6 address is an eligible destination.
///
/// Acceptance requires `2000::/3` membership and exclusion of `2001::/23`,
/// `2001:db8::/32`, `2002::/16`, and `3fff::/20`; IPv4-embedded forms
/// (mapped, compatible, NAT64, 6to4, Teredo) fall outside that set.
pub fn ipv6_is_eligible(addr: Ipv6Addr) -> bool {
    let a = u128::from(addr);
    (a >> 125) == 0b001
        && !V6_EXCLUSIONS
            .iter()
            .any(|&(net, prefix)| v6_in(a, net, prefix))
}
