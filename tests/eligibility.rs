use alumina::eligibility::{NumericAddr, ipv4_is_eligible, ipv6_is_eligible};
use std::net::{Ipv4Addr, Ipv6Addr};

struct V4Range {
    net: u32,
    prefix: u8,
    before_ok: bool,
    after_ok: bool,
}

const V4_RANGES: &[V4Range] = &[
    V4Range {
        net: 0x0000_0000,
        prefix: 8,
        before_ok: false,
        after_ok: true,
    },
    V4Range {
        net: 0x0a00_0000,
        prefix: 8,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0x6440_0000,
        prefix: 10,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0x7f00_0000,
        prefix: 8,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0xa9fe_0000,
        prefix: 16,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0xac10_0000,
        prefix: 12,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0xc000_0000,
        prefix: 24,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0xc000_0200,
        prefix: 24,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0xc058_6300,
        prefix: 24,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0xc0a8_0000,
        prefix: 16,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0xc612_0000,
        prefix: 15,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0xc633_6400,
        prefix: 24,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0xcb00_7100,
        prefix: 24,
        before_ok: true,
        after_ok: true,
    },
    V4Range {
        net: 0xe000_0000,
        prefix: 4,
        before_ok: true,
        after_ok: false,
    },
    V4Range {
        net: 0xf000_0000,
        prefix: 4,
        before_ok: false,
        after_ok: false,
    },
];

struct V6Range {
    net: u128,
    prefix: u8,
}

const V6_RANGES: &[V6Range] = &[
    V6Range {
        net: 0x2001_0000_0000_0000_0000_0000_0000_0000,
        prefix: 23,
    },
    V6Range {
        net: 0x2001_0db8_0000_0000_0000_0000_0000_0000,
        prefix: 32,
    },
    V6Range {
        net: 0x2002_0000_0000_0000_0000_0000_0000_0000,
        prefix: 16,
    },
    V6Range {
        net: 0x3fff_0000_0000_0000_0000_0000_0000_0000,
        prefix: 20,
    },
];

const V4_ELIGIBLE: &[u32] = &[
    0x0101_0101,
    0x0808_0808,
    0x0b00_0000,
    0x6400_0000,
    0xdf00_0000,
    0xc633_6300,
];

const V4_INELIGIBLE: &[u32] = &[
    0x0000_0000,
    0x0a00_0000,
    0x6450_0000,
    0x7f00_0001,
    0xa9fe_0001,
    0xac10_0001,
    0xc000_0001,
    0xc000_0201,
    0xc058_6301,
    0xc0a8_0001,
    0xc612_0001,
    0xc633_6401,
    0xcb00_7101,
    0xe000_0001,
    0xf000_0001,
    0xffff_ffff,
];

const V6_ELIGIBLE: &[u128] = &[
    0x2001_4860_4860_0000_0000_0000_0000_8888,
    0x2606_4700_4700_0000_0000_0000_0000_1111,
    0x2000_0000_0000_0000_0000_0000_0000_0000,
    0x2001_0200_0000_0000_0000_0000_0000_0000,
    0x2003_0000_0000_0000_0000_0000_0000_0000,
];

const V6_INELIGIBLE: &[u128] = &[
    0x0000_0000_0000_0000_0000_0000_0000_0000,
    0x0000_0000_0000_0000_0000_0000_0000_0001,
    0xfe80_0000_0000_0000_0000_0000_0000_0001,
    0x1fff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
    0x4000_0000_0000_0000_0000_0000_0000_0000,
    0x2001_0000_0000_0000_0000_0000_0000_0000,
    0x2001_0000_4136_e378_8000_63bf_3fff_fdd2,
    0x2001_0db8_0000_0000_0000_0000_0000_0001,
    0x2002_0000_0000_0000_0000_0000_0000_0001,
    0x3fff_0000_0000_0000_0000_0000_0000_0001,
    0x0064_ff9b_0000_0000_0000_0000_a9fe_a9fe,
    0x0064_ff9b_0001_0000_0000_0000_0000_0001,
    0x0000_0000_0000_0000_0000_ffff_0a00_0001,
    0x0000_0000_0000_0000_0000_ffff_0808_0808,
    0x0000_0000_0000_0000_0000_0000_0a00_0001,
    0x2002_a9fe_a9fe_0000_0000_0000_0000_0001,
];

#[test]
fn ipv4_every_exclusion_range_boundary() {
    for range in V4_RANGES {
        let end = range.net | ((1u32 << (32 - range.prefix)) - 1);
        assert!(!ipv4_is_eligible(Ipv4Addr::from(range.net)));
        assert!(!ipv4_is_eligible(Ipv4Addr::from(end)));
        assert_eq!(
            ipv4_is_eligible(Ipv4Addr::from(range.net.wrapping_sub(1))),
            range.before_ok,
            "before 0x{:08x}/{}",
            range.net,
            range.prefix
        );
        assert_eq!(
            ipv4_is_eligible(Ipv4Addr::from(end.wrapping_add(1))),
            range.after_ok,
            "after 0x{:08x}/{}",
            range.net,
            range.prefix
        );
    }
}

#[test]
fn ipv6_every_exclusion_range_boundary() {
    for range in V6_RANGES {
        let end = range.net | ((1u128 << (128 - range.prefix)) - 1);
        assert!(!ipv6_is_eligible(Ipv6Addr::from(range.net)));
        assert!(!ipv6_is_eligible(Ipv6Addr::from(end)));
        assert!(
            ipv6_is_eligible(Ipv6Addr::from(range.net.wrapping_sub(1))),
            "before 0x{:032x}/{}",
            range.net,
            range.prefix
        );
        assert!(
            ipv6_is_eligible(Ipv6Addr::from(end.wrapping_add(1))),
            "after 0x{:032x}/{}",
            range.net,
            range.prefix
        );
    }
}

#[test]
fn ipv4_golden_corpus() {
    for &addr in V4_ELIGIBLE {
        assert!(
            ipv4_is_eligible(Ipv4Addr::from(addr)),
            "0x{addr:08x} eligible"
        );
    }
    for &addr in V4_INELIGIBLE {
        assert!(
            !ipv4_is_eligible(Ipv4Addr::from(addr)),
            "0x{addr:08x} ineligible"
        );
    }
}

#[test]
fn ipv6_golden_corpus() {
    for &addr in V6_ELIGIBLE {
        assert!(
            ipv6_is_eligible(Ipv6Addr::from(addr)),
            "0x{addr:032x} eligible"
        );
    }
    for &addr in V6_INELIGIBLE {
        assert!(
            !ipv6_is_eligible(Ipv6Addr::from(addr)),
            "0x{addr:032x} ineligible"
        );
    }
}

#[test]
fn numeric_addr_enum_corresponds() {
    for &addr in V4_ELIGIBLE {
        assert!(NumericAddr::V4(Ipv4Addr::from(addr)).is_eligible());
    }
    for &addr in V4_INELIGIBLE {
        assert!(!NumericAddr::V4(Ipv4Addr::from(addr)).is_eligible());
    }
    for &addr in V6_ELIGIBLE {
        assert!(NumericAddr::V6(Ipv6Addr::from(addr)).is_eligible());
    }
    for &addr in V6_INELIGIBLE {
        assert!(!NumericAddr::V6(Ipv6Addr::from(addr)).is_eligible());
    }
}

#[test]
#[cfg(feature = "alloc-witness")]
fn eligibility_witness_positive_control_then_zero() {
    use alumina::alloc::{self, Phase};
    let (_, positive) = alloc::run_phase(Phase::BackgroundRefresh, || {
        let bytes = Box::new([0u8; 64]);
        std::hint::black_box(bytes);
    });
    assert!(
        positive.allocs > 0 && positive.deallocs > 0,
        "counter must attribute a local alloc/dealloc: {positive:?}"
    );

    let (_, counts) = alloc::run_phase(Phase::BackgroundRefresh, || {
        let boundary_v4: u64 = V4_RANGES
            .iter()
            .map(|r| {
                let end = r.net | ((1u32 << (32 - r.prefix)) - 1);
                u64::from(ipv4_is_eligible(Ipv4Addr::from(r.net)))
                    | u64::from(ipv4_is_eligible(Ipv4Addr::from(end)))
                    | u64::from(ipv4_is_eligible(Ipv4Addr::from(r.net.wrapping_sub(1))))
                    | u64::from(ipv4_is_eligible(Ipv4Addr::from(end.wrapping_add(1))))
            })
            .sum();
        let boundary_v6: u64 = V6_RANGES
            .iter()
            .map(|r| {
                let end = r.net | ((1u128 << (128 - r.prefix)) - 1);
                u64::from(ipv6_is_eligible(Ipv6Addr::from(r.net)))
                    | u64::from(ipv6_is_eligible(Ipv6Addr::from(end)))
                    | u64::from(ipv6_is_eligible(Ipv6Addr::from(r.net.wrapping_sub(1))))
                    | u64::from(ipv6_is_eligible(Ipv6Addr::from(end.wrapping_add(1))))
            })
            .sum();
        let control_v4: u64 = V4_ELIGIBLE
            .iter()
            .chain(V4_INELIGIBLE)
            .map(|&a| u64::from(ipv4_is_eligible(Ipv4Addr::from(a))))
            .sum();
        let control_v6: u64 = V6_ELIGIBLE
            .iter()
            .chain(V6_INELIGIBLE)
            .map(|&a| u64::from(ipv6_is_eligible(Ipv6Addr::from(a))))
            .sum();
        std::hint::black_box(boundary_v4 + boundary_v6 + control_v4 + control_v6);
    });
    assert!(counts.all_zero(), "predicate must not allocate: {counts:?}");
}
