use std::fmt;

use crate::config::{self, Config, ConfigError};
use crate::inventory::{self, BootInventory, StorageUnavailable, TrafficStorage};
use crate::preflight::{self, KernelFacts, PreflightError};
use crate::resolver::{self, Nameserver, ResolverError};

pub const EX_CONFIG: i32 = 78;

#[derive(Debug)]
pub enum BootError {
    Config(ConfigError),
    Resolver(ResolverError),
    Preflight(PreflightError),
    Storage(StorageUnavailable),
}

impl BootError {
    pub fn exit_status(&self) -> i32 {
        EX_CONFIG
    }
}

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootError::Config(err) => write!(f, "{}", err),
            BootError::Resolver(err) => write!(f, "{}", err),
            BootError::Preflight(err) => write!(f, "{}", err),
            BootError::Storage(err) => write!(f, "{}", err),
        }
    }
}

#[derive(Debug)]
pub struct BootReport {
    pub config: Config,
    pub nameserver: Nameserver,
    pub storage: TrafficStorage,
    pub inventory: BootInventory,
}

pub fn run_boot(config_path: &str, resolver_path: &str) -> Result<BootReport, BootError> {
    let facts = preflight::read_kernel_facts().map_err(BootError::Preflight)?;
    run_boot_with_facts(config_path, resolver_path, facts)
}

fn run_boot_with_facts(
    config_path: &str,
    resolver_path: &str,
    facts: KernelFacts,
) -> Result<BootReport, BootError> {
    preflight::check(facts).map_err(BootError::Preflight)?;
    let config = config::load_config_document(config_path).map_err(BootError::Config)?;
    let nameserver =
        resolver::read_resolver_config_file(resolver_path).map_err(BootError::Resolver)?;
    let storage = TrafficStorage::allocate().map_err(BootError::Storage)?;
    let inventory = inventory::BootInventory::phase1();
    Ok(BootReport {
        config,
        nameserver,
        storage,
        inventory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process;

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

    const VALID_CONFIG: &str = "allowlist = [\"example.com\", \"sub.example.org.\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\n";

    #[test]
    fn boot_with_good_facts_reports_and_stops_at_phase1_boundary() {
        let dir = TempDir::new("good");
        dir.write("config.toml", VALID_CONFIG);
        dir.write("resolv.conf", "nameserver 1.1.1.1\n");
        let config_path = dir
            .path()
            .join("config.toml")
            .to_string_lossy()
            .into_owned();
        let resolver_path = dir
            .path()
            .join("resolv.conf")
            .to_string_lossy()
            .into_owned();

        let report = run_boot_with_facts(&config_path, &resolver_path, good_facts())
            .expect("boot with good facts");
        assert_eq!(report.config.allowlist().len(), 2);
        assert_eq!(report.nameserver.addr().to_string(), "1.1.1.1");
        assert_eq!(report.storage.len(), inventory::TRAFFIC_STORAGE_BYTES);
        assert_eq!(
            report.inventory.retained_initialized_bytes(),
            inventory::TRAFFIC_STORAGE_BYTES
        );
    }

    #[test]
    fn boot_rejects_each_stage_with_ex_config78() {
        let dir = TempDir::new("stages");
        let config_path = dir
            .path()
            .join("config.toml")
            .to_string_lossy()
            .into_owned();
        let resolver_path = dir
            .path()
            .join("resolv.conf")
            .to_string_lossy()
            .into_owned();

        let err = run_boot_with_facts(&config_path, &resolver_path, good_facts())
            .expect_err("missing config must fail");
        assert_eq!(err.exit_status(), EX_CONFIG);

        dir.write("config.toml", VALID_CONFIG);
        let err = run_boot_with_facts(&config_path, &resolver_path, good_facts())
            .expect_err("missing resolver must fail");
        assert_eq!(err.exit_status(), EX_CONFIG);

        dir.write("resolv.conf", "nameserver 1.1.1.1\n");
        let err = run_boot_with_facts(
            &config_path,
            &resolver_path,
            KernelFacts {
                euid: 0,
                ..good_facts()
            },
        )
        .expect_err("root must fail preflight");
        assert_eq!(err.exit_status(), EX_CONFIG);
    }

    #[test]
    fn boot_error_carries_ex_config78_across_all_kinds() {
        assert_eq!(EX_CONFIG, 78);
        let cfg_err = config::parse_config_document("bogus").unwrap_err();
        assert_eq!(BootError::Config(cfg_err).exit_status(), EX_CONFIG);
        let res_err = resolver::parse_resolver_config("").unwrap_err();
        assert_eq!(BootError::Resolver(res_err).exit_status(), EX_CONFIG);
        let pre_err = PreflightError::Root;
        assert_eq!(BootError::Preflight(pre_err).exit_status(), EX_CONFIG);
    }

    #[test]
    fn boot_allocation_failure_maps_to_ex_config78() {
        let dir = TempDir::new("allocfault");
        dir.write("config.toml", VALID_CONFIG);
        dir.write("resolv.conf", "nameserver 1.1.1.1\n");
        let config_path = dir
            .path()
            .join("config.toml")
            .to_string_lossy()
            .into_owned();
        let resolver_path = dir
            .path()
            .join("resolv.conf")
            .to_string_lossy()
            .into_owned();

        crate::inventory::arm_alloc_failure();
        let err = run_boot_with_facts(&config_path, &resolver_path, good_facts())
            .expect_err("armed allocation fault must fail boot with StorageUnavailable");
        crate::inventory::clear_alloc_failure();
        assert!(matches!(err, BootError::Storage(_)));
        assert_eq!(err.exit_status(), EX_CONFIG);
    }
}
