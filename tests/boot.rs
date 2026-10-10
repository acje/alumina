use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use alumina::config::{self, ConfigError};
use alumina::inventory::{self, BootInventory, TrafficStorage};
use alumina::preflight::{self, KernelFacts, PreflightError};
use alumina::resolver;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("alumina-boot-{}-{}-{}", tag, process::id(), n));
        fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, body).expect("write temp fixture");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const VALID_CONFIG: &str = r#"
allowlist = ["example.com", "sub.example.org."]
listen = "0.0.0.0:8080"
startup_unresolved_allowance = 1
"#;

#[test]
fn config_valid_minimal_parses_without_coercion() {
    let cfg = config::parse_config_document(VALID_CONFIG).expect("valid config");
    assert_eq!(cfg.allowlist().len(), 2);
    assert_eq!(
        cfg.allowlist().get(0).map(|f| f.as_str()),
        Some("example.com")
    );
    assert_eq!(
        cfg.allowlist().get(1).map(|f| f.as_str()),
        Some("sub.example.org")
    );
    assert_eq!(cfg.listen().port(), 8080);
    assert_eq!(cfg.startup_unresolved_allowance(), 1);
}

#[test]
fn config_4096_exact_bound_ok_and_oversize_rejected_without_truncation() {
    let mut doc = VALID_CONFIG.trim_end_matches('\n').to_owned();
    while doc.len() < config::CONFIG_DOC_LIMIT {
        doc.push('#');
    }
    assert_eq!(doc.len(), config::CONFIG_DOC_LIMIT);
    assert!(
        config::parse_config_document(&doc).is_ok(),
        "an exactly-{:?}-byte document must be accepted",
        config::CONFIG_DOC_LIMIT
    );

    let oversized = format!("{}x", doc);
    assert_eq!(oversized.len(), config::CONFIG_DOC_LIMIT + 1);
    assert!(matches!(
        config::parse_config_document(&oversized),
        Err(ConfigError::OversizedDocument { .. })
    ));

    let dir = TempDir::new("oversize");
    let path = dir.write("config.toml", &oversized);
    assert!(matches!(
        config::load_config_document(&path.to_string_lossy()),
        Err(ConfigError::OversizedDocument { .. })
    ));
}

#[test]
fn config_all_mandatory_fields_fail_when_missing() {
    for (field, doc) in [
        (
            "allowlist",
            "listen = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n",
        ),
        (
            "listen",
            "allowlist = [\"a.example\"]\nstartup_unresolved_allowance = 0\n",
        ),
        (
            "startup_unresolved_allowance",
            "allowlist = [\"a.example\"]\nlisten = \"0.0.0.0:8080\"\n",
        ),
    ] {
        assert!(
            matches!(
                config::parse_config_document(doc),
                Err(ConfigError::MissingField(f)) if f == field
            ),
            "config missing {} must fail with MissingField({})",
            field,
            field
        );
    }
}

#[test]
fn config_unknown_key_and_unknown_table_fail() {
    assert!(matches!(
        config::parse_config_document(
            "allowlist = [\"a.example\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\nbogus = 1\n"
        ),
        Err(ConfigError::UnknownKey(_))
    ));
    assert!(matches!(
        config::parse_config_document(
            "allowlist = [\"a.example\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[bogus]\nx = 1\n"
        ),
        Err(ConfigError::UnknownTable(_))
    ));
}

#[test]
fn config_duplicate_key_and_duplicate_table_fail() {
    let dup_key = "allowlist = [\"a.example\"]\nallowlist = [\"b.example\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n";
    assert!(matches!(
        config::parse_config_document(dup_key),
        Err(ConfigError::ParseToml {
            message,
            ..
        }) if !message.is_empty()
    ));

    let dup_table = "allowlist = [\"a.example\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n[one]\n[one]\n";
    assert!(matches!(
        config::parse_config_document(dup_table),
        Err(ConfigError::ParseToml {
            message,
            ..
        }) if !message.is_empty()
    ));
}

#[test]
fn config_wrong_types_fail_without_coercion() {
    for (name, doc) in [
        (
            "allowance-string",
            "allowlist = [\"a.example\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = \"1\"\n",
        ),
        (
            "allowlist-string",
            "allowlist = \"a.example\"\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n",
        ),
        (
            "allowlist-integer-entry",
            "allowlist = [1]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n",
        ),
        (
            "listen-integer",
            "allowlist = [\"a.example\"]\nlisten = 8080\nstartup_unresolved_allowance = 0\n",
        ),
        (
            "allowlist-boolean-entry",
            "allowlist = [true]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n",
        ),
    ] {
        assert!(
            matches!(
                config::parse_config_document(doc),
                Err(ConfigError::WrongType(_))
            ),
            "config {} must fail as WrongType, never coerce",
            name
        );
    }
}

#[test]
fn config_allowlist_empty_and_over_32_fail() {
    assert!(matches!(
        config::parse_config_document(
            "allowlist = []\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n"
        ),
        Err(ConfigError::AllowlistEmpty)
    ));
    let mut names = Vec::new();
    for i in 0..33usize {
        names.push(format!("\"n{}.example\"", i));
    }
    let doc = format!(
        "allowlist = [{}]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n",
        names.join(",")
    );
    assert!(matches!(
        config::parse_config_document(&doc),
        Err(ConfigError::AllowlistTooMany { .. })
    ));
}

#[test]
fn config_duplicate_allowlist_names_rejected_after_normalization() {
    let dup_exact = "allowlist = [\"a.example\", \"a.example\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\n";
    assert!(matches!(
        config::parse_config_document(dup_exact),
        Err(ConfigError::DuplicateAllowlistName(_))
    ));
    let dup_normalized = "allowlist = [\"a.example\", \"a.example.\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\n";
    assert!(matches!(
        config::parse_config_document(dup_normalized),
        Err(ConfigError::DuplicateAllowlistName(_))
    ));
}

#[test]
fn config_invalid_fqdn_rejected() {
    for (name, fqdn) in [
        ("uppercase", "Example.COM"),
        ("underscore", "bad_name.example"),
        ("empty-label", ".example.com"),
        ("trailing-hyphen", "bad-.example.com"),
        (
            "long-label",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
        ),
    ] {
        let doc = format!(
            "allowlist = [\"{}\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n",
            fqdn
        );
        assert!(
            config::parse_config_document(&doc).is_err(),
            "FQDN {} must be rejected",
            name
        );
    }
}

#[test]
fn config_allowance_out_of_range_fails() {
    let eq_len = "allowlist = [\"a.example\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\n";
    assert!(matches!(
        config::parse_config_document(eq_len),
        Err(ConfigError::AllowanceOutOfRange { .. })
    ));
    let negative = "allowlist = [\"a.example\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = -1\n";
    assert!(matches!(
        config::parse_config_document(negative),
        Err(ConfigError::AllowanceOutOfRange { .. })
    ));
    let zero_ok = "allowlist = [\"a.example\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n";
    assert!(config::parse_config_document(zero_ok).is_ok());
}

#[test]
fn config_listen_variants() {
    for (name, listen) in [
        ("no-port", "1.2.3.4"),
        ("port-zero", "1.2.3.4:0"),
        ("port-overflow", "1.2.3.4:65536"),
        ("non-numeric-port", "1.2.3.4:abc"),
        ("unbracketed-ipv6", "2001:db8::1:8080"),
        ("bracketed-no-port", "[2001:db8::1]"),
        ("hostname-listen", "localhost:8080"),
        ("empty", ""),
    ] {
        let doc = format!(
            "allowlist = [\"a.example\"]\nlisten = \"{}\"\nstartup_unresolved_allowance = 0\n",
            listen
        );
        assert!(
            config::parse_config_document(&doc).is_err(),
            "listen {} must be rejected",
            name
        );
    }
    let ipv6_ok = "allowlist = [\"a.example\"]\nlisten = \"[2001:db8::1]:8080\"\nstartup_unresolved_allowance = 0\n";
    let cfg = config::parse_config_document(ipv6_ok).expect("bracketed IPv6 listen");
    assert_eq!(cfg.listen().port(), 8080);
    assert_eq!(cfg.listen().ip().to_string(), "2001:db8::1");
}

#[test]
fn config_allowlist_32_max_fits_document_bound() {
    let mut names = Vec::with_capacity(32);
    for i in 0..32usize {
        names.push(format!("\"{}.example.com\"", i));
    }
    let doc = format!(
        "allowlist = [{}]\n# trailing comment padding\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n",
        names.join(",")
    );
    assert!(doc.len() <= config::CONFIG_DOC_LIMIT);
    let cfg = config::parse_config_document(&doc).expect("32-name allowlist fits");
    assert_eq!(cfg.allowlist().len(), 32);
}

#[test]
fn config_load_missing_file_fails() {
    let dir = TempDir::new("missing");
    assert!(matches!(
        config::load_config_document(&dir.path().join("nope.toml").to_string_lossy()),
        Err(ConfigError::Unreadable { .. })
    ));
}

#[test]
fn config_non_utf8_document_fails_with_dedicated_encoding_error() {
    let dir = TempDir::new("nonutf8");
    let path = dir.write("config.toml", "");
    std::fs::write(&path, [0x66, 0x6f, 0x6f, 0xff, 0xfe]).expect("write invalid UTF-8 fixture");
    let err = config::load_config_document(&path.to_string_lossy());
    assert!(
        matches!(err, Err(ConfigError::NotUtf8 { .. })),
        "invalid UTF-8 config must be a dedicated encoding error, not a parse error"
    );
}

#[test]
fn resolver_first_nameserver_numeric_unicast_no_zone_port53() {
    let ns = resolver::parse_resolver_config("nameserver 1.1.1.1\n").expect("ipv4");
    assert_eq!(ns.addr().to_string(), "1.1.1.1");
    assert_eq!(ns.port(), 53);

    let ns6 = resolver::parse_resolver_config("nameserver 2606:4700:4700::1111\n").expect("ipv6");
    assert_eq!(ns6.addr().to_string(), "2606:4700:4700::1111");
    assert_eq!(ns6.port(), 53);
}

#[test]
fn resolver_selects_first_declared_not_later() {
    let doc =
        "# comment\nsearch example.org\noptions ndots:2\nnameserver 9.9.9.9\nnameserver 8.8.8.8\n";
    let ns = resolver::parse_resolver_config(doc).expect("first nameserver");
    assert_eq!(ns.addr().to_string(), "9.9.9.9", "first nameserver only");
}

#[test]
fn resolver_invalid_first_cannot_skip_to_later() {
    let doc = "nameserver not-an-address\nnameserver 8.8.8.8\n";
    assert!(resolver::parse_resolver_config(doc).is_err());
    let doc = "nameserver 224.0.0.1\nnameserver 8.8.8.8\n";
    assert!(resolver::parse_resolver_config(doc).is_err());
}

#[test]
fn resolver_missing_and_unreadable_fail() {
    assert!(resolver::parse_resolver_config("").is_err());
    assert!(resolver::parse_resolver_config("search example.org\noptions ndots:2\n").is_err());
    let dir = TempDir::new("missing-resolv");
    assert!(
        resolver::read_resolver_config_file(&dir.path().join("resolv.conf").to_string_lossy())
            .is_err()
    );
}

#[test]
fn resolver_rejects_non_unicast_and_zoned_addresses() {
    for (case, addr) in [
        ("broadcast", "255.255.255.255"),
        ("unspecified", "0.0.0.0"),
        ("multicast", "224.0.0.1"),
        ("ipv6-multicast", "ff02::1"),
        ("ipv6-unspecified", "::"),
        ("zone-id", "fe80::1%eth0"),
    ] {
        assert!(
            resolver::parse_resolver_config(&format!("nameserver {}\n", addr)).is_err(),
            "{} must be rejected: {}",
            case,
            addr
        );
    }
}

#[test]
fn resolver_overlong_invalid_address_rejected_without_arbitrary_line_cap() {
    let mut line = String::from("nameserver ");
    line.push_str(&"1.".repeat(300));
    line.push('\n');
    assert!(matches!(
        resolver::parse_resolver_config(&line),
        Err(resolver::ResolverError::InvalidAddress { .. })
    ));
}

#[test]
fn resolver_tab_first_then_space_second_selects_first() {
    let doc = "nameserver\t9.9.9.9\nnameserver 8.8.8.8\n";
    let ns = resolver::parse_resolver_config(doc).expect("tab-delimited first nameserver");
    assert_eq!(ns.addr().to_string(), "9.9.9.9");
}

#[test]
fn resolver_bare_first_declaration_fails() {
    let bare = "nameserver\nnameserver 8.8.8.8\n";
    assert!(matches!(
        resolver::parse_resolver_config(bare),
        Err(resolver::ResolverError::BareNameserver)
    ));
    let comment = "nameserver # nothing here\nnameserver 8.8.8.8\n";
    assert!(matches!(
        resolver::parse_resolver_config(comment),
        Err(resolver::ResolverError::BareNameserver)
    ));
}

#[test]
fn resolver_long_valid_first_padding_accepted() {
    let huge_ws = " ".repeat(150_000);
    let huge_comment = "#".repeat(60_000);
    let doc = format!("nameserver{}1.1.1.1  {}\n", huge_ws, huge_comment);
    let ns = resolver::parse_resolver_config(&doc).expect("huge nameserver-line padding accepted");
    assert_eq!(ns.addr().to_string(), "1.1.1.1");
}

#[test]
fn resolver_ignored_huge_newline_free_directive_streamed() {
    let huge = format!("search {}\nnameserver 1.1.1.1\n", "aaaa. ".repeat(150_000));
    let ns = resolver::parse_resolver_config(&huge).expect("huge ignored line then nameserver");
    assert_eq!(ns.addr().to_string(), "1.1.1.1");
    let only_huge = format!("options {}\n", "aaaa".repeat(150_000));
    assert!(matches!(
        resolver::parse_resolver_config(&only_huge),
        Err(resolver::ResolverError::MissingNameserver)
    ));
}

#[test]
#[cfg(feature = "alloc-witness")]
fn resolver_scanner_retention_bounded_independent_of_input_size() {
    use alumina::alloc::{self, Phase};
    let expect_zero = |doc: &str| {
        let (r, counts) =
            alloc::run_phase(Phase::StartupDns, || resolver::parse_resolver_config(doc));
        let ns = r.expect("parse");
        assert_eq!(ns.addr().to_string(), "1.1.1.1");
        counts
    };
    let small = expect_zero("nameserver 1.1.1.1\n");
    let huge_ignored = expect_zero(&format!(
        "search {}\nnameserver 1.1.1.1\n",
        "aaaa. ".repeat(100_000)
    ));
    let huge_padding = expect_zero(&format!(
        "nameserver{}1.1.1.1  {}\n",
        " ".repeat(100_000),
        "#".repeat(50_000)
    ));
    assert!(
        small.all_zero(),
        "small parse must not allocate: {:?}",
        small
    );
    assert!(
        huge_ignored.all_zero(),
        "huge ignored line must be streamed without allocation: {:?}",
        huge_ignored
    );
    assert!(
        huge_padding.all_zero(),
        "huge padding must be skipped without allocation: {:?}",
        huge_padding
    );
    assert_eq!(
        small, huge_ignored,
        "retention must not scale with input size"
    );
}

fn good_facts() -> KernelFacts {
    KernelFacts {
        ruid: 1000,
        euid: 1000,
        suid: 1000,
        fsuid: 1000,
        cap_eff: 0,
        cap_prm: 0,
        cap_amb: 0,
        no_new_privs: true,
    }
}

#[test]
fn preflight_accepts_nonroot_empty_caps_with_no_new_privs() {
    assert!(preflight::check(good_facts()).is_ok());
}

#[test]
fn preflight_rejects_root_real_saved_filesystem_and_effective_uids() {
    for (axis, facts) in [
        (
            "real",
            KernelFacts {
                ruid: 0,
                ..good_facts()
            },
        ),
        (
            "effective",
            KernelFacts {
                euid: 0,
                ..good_facts()
            },
        ),
        (
            "saved",
            KernelFacts {
                suid: 0,
                ..good_facts()
            },
        ),
        (
            "filesystem",
            KernelFacts {
                fsuid: 0,
                ..good_facts()
            },
        ),
    ] {
        assert!(
            matches!(preflight::check(facts), Err(PreflightError::Root)),
            "{} UID axis 0 must be rejected (all four != 0)",
            axis
        );
    }
}

#[test]
fn preflight_rejects_each_unmet_prerequisite_independently() {
    assert!(matches!(
        preflight::check(KernelFacts {
            euid: 0,
            ..good_facts()
        }),
        Err(PreflightError::Root)
    ));
    assert!(matches!(
        preflight::check(KernelFacts {
            cap_eff: 1,
            ..good_facts()
        }),
        Err(PreflightError::NonEmptyEffective)
    ));
    assert!(matches!(
        preflight::check(KernelFacts {
            cap_prm: 1,
            ..good_facts()
        }),
        Err(PreflightError::NonEmptyPermitted)
    ));
    assert!(matches!(
        preflight::check(KernelFacts {
            cap_amb: 1,
            ..good_facts()
        }),
        Err(PreflightError::NonEmptyAmbient)
    ));
    assert!(matches!(
        preflight::check(KernelFacts {
            no_new_privs: false,
            ..good_facts()
        }),
        Err(PreflightError::MissingNoNewPrivs)
    ));
}

#[test]
fn preflight_parses_proc_status_fixture() {
    let text = "Name:\talumina\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
    let facts = preflight::parse_proc_status(text).expect("parse");
    assert_eq!(facts.euid, 1000);
    assert!(facts.no_new_privs);
    assert!(preflight::check(facts).is_ok());

    let caps = "Name:\talumina\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000001\nCapPrm:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
    let facts = preflight::parse_proc_status(caps).expect("parse");
    assert_eq!(facts.cap_eff, 1);
    assert!(matches!(
        preflight::check(facts),
        Err(PreflightError::NonEmptyEffective)
    ));
}

#[test]
fn preflight_malformed_proc_status_is_error_not_verdict() {
    assert!(preflight::parse_proc_status("Name:\talumina\nUid:\tnot-a-number\n").is_err());
    assert!(preflight::parse_proc_status("").is_err());
}

#[test]
fn inventory_traffic_storage_is_exactly_128_mib() {
    assert_eq!(
        inventory::TRAFFIC_STORAGE_BYTES,
        128 * 2 * 512 * 1024,
        "128 slots x 2 directional buffers x 512 KiB"
    );
    assert_eq!(inventory::TRAFFIC_STORAGE_BYTES, 134_217_728);
    assert_eq!(inventory::TUNNEL_SLOTS, 128);
    assert_eq!(inventory::BUFFERS_PER_SLOT, 2);
    assert_eq!(inventory::BUFFER_BYTES, 512 * 1024);
}

#[test]
fn inventory_actually_initializes_full_traffic_storage() {
    let storage = TrafficStorage::allocate().unwrap();
    assert_eq!(
        storage.len(),
        inventory::TRAFFIC_STORAGE_BYTES,
        "full 128 MiB must be actually initialized"
    );
    assert_eq!(storage.as_slice().len(), inventory::TRAFFIC_STORAGE_BYTES);
    let inv = BootInventory::phase1();
    assert_eq!(
        inv.retained_initialized_bytes(),
        inventory::TRAFFIC_STORAGE_BYTES,
        "retained = 128 MiB traffic storage"
    );
    assert_eq!(
        inv.transient_scratch_bytes(),
        inventory::CONFIG_DOC_BUFFER_BYTES
    );
    assert!(inv.reserved_future_bytes() > 0);
    assert_ne!(
        inv.retained_initialized_bytes(),
        inv.reserved_future_bytes()
    );
}

#[test]
fn inventory_reports_retained_vs_transient_vs_reserved_honestly() {
    let inv = BootInventory::phase1();
    assert_eq!(
        inv.retained_initialized_bytes(),
        134_217_728,
        "only the retained traffic storage is initialized"
    );
    assert_eq!(
        inv.transient_scratch_bytes(),
        4096,
        "config parse buffer is transient scratch, not retained"
    );
    assert!(inv.reserved_future_bytes() > 0);
    assert_ne!(
        inv.retained_initialized_bytes(),
        inv.reserved_future_bytes()
    );
}
