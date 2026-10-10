//! Alumina phase-1 binary: fixed documented config/resolver inputs, no CLI or
//! environment policy overrides. Runs the boot harness (privilege check,
//! config + resolver reads, 128 MiB storage init), the boot-owned startup DNS
//! window, then applies the canonical readiness rule: the listener opens for a
//! serving decision, and an unresolved count beyond the allowance exits
//! EX_TEMPFAIL (75). A boot or startup failure exits EX_CONFIG (78) with a
//! diagnostic naming the field/source. The serving loop is not yet wired, so
//! a serving decision still exits EX_SOFTWARE (70) rather than claiming the
//! process is in service.

use alumina::boot::{EX_CONFIG, run_boot};
use alumina::serve::{ServeStorage, StartupDecision};

/// Fixed documented input paths, relative to the working directory. No CLI
/// arguments or environment variables are read as policy (see README).
const CONFIG_PATH: &str = "config.toml";
const RESOLVER_PATH: &str = "resolv.conf";
const EX_TEMPFAIL: i32 = 75;
const EX_SOFTWARE: i32 = 70;

/// Cache and startup time are process-relative whole seconds; receipt and
/// readiness snapshots share this origin.
const PROCESS_EPOCH_SECS: u64 = 0;

fn main() {
    emit_kernel_facts();
    match run_boot(CONFIG_PATH, RESOLVER_PATH) {
        Ok(report) => {
            let mut serving = match ServeStorage::boot(&report.config) {
                Ok(storage) => storage,
                Err(err) => {
                    eprintln!("alumina: serving storage: {err}");
                    std::process::exit(EX_CONFIG);
                }
            };
            println!(
                "inventory retained initialized traffic-storage bytes: {}",
                report.storage.len()
            );
            println!(
                "inventory transient scratch (config doc buffer, not retained): {}",
                report.inventory.transient_scratch_bytes()
            );
            println!(
                "inventory reserved-future (not initialized in phase 1): {}",
                report.inventory.reserved_future_bytes()
            );
            println!(
                "resolver first nameserver: {} port {}",
                report.nameserver.addr(),
                report.nameserver.port()
            );
            println!(
                "allowlist entries: {} allowance: {} listen: {}:{}",
                report.config.allowlist().len(),
                report.config.startup_unresolved_allowance(),
                report.config.listen().ip(),
                report.config.listen().port()
            );
            println!(
                "serving storage retained: cache names: {} schedules: {}",
                serving.cache().name_count(),
                serving.schedules().name_count()
            );
            let nameserver =
                std::net::SocketAddr::new(report.nameserver.addr(), report.nameserver.port());
            match serving.run_startup(nameserver, PROCESS_EPOCH_SECS) {
                Ok(outcome) => match outcome.decision {
                    StartupDecision::Serve(mode) => {
                        let bound = outcome
                            .listener
                            .as_ref()
                            .and_then(|listener| listener.local_addr().ok())
                            .map(|addr| addr.to_string())
                            .unwrap_or_else(|| "unavailable".to_string());
                        println!(
                            "startup-decision: {mode:?} listener {bound} exchanges {} failed {} resolved {}",
                            outcome.report.exchanges,
                            outcome.report.failed,
                            outcome.report.resolved_names,
                        );
                        eprintln!(
                            "alumina: serving loop not implemented in phase 1; scaffold exits EX_SOFTWARE"
                        );
                        std::process::exit(EX_SOFTWARE);
                    }
                    StartupDecision::Exit75 { unresolved } => {
                        println!(
                            "startup-failure: {unresolved} unresolved names exceed allowance; exiting 75"
                        );
                        std::process::exit(EX_TEMPFAIL);
                    }
                },
                Err(err) => {
                    eprintln!("alumina: startup: {err}");
                    std::process::exit(EX_CONFIG);
                }
            }
        }
        Err(err) => {
            eprintln!("alumina: {}", err);
            std::process::exit(EX_CONFIG);
        }
    }
}

#[cfg(feature = "fixture-facts")]
fn emit_kernel_facts() {
    match alumina::preflight::read_kernel_facts() {
        Ok(facts) => eprintln!(
            "kernel-facts: ruid={} euid={} suid={} fsuid={} cap_eff={:x} cap_prm={:x} cap_amb={:x} no_new_privs={}",
            facts.ruid,
            facts.euid,
            facts.suid,
            facts.fsuid,
            facts.cap_eff,
            facts.cap_prm,
            facts.cap_amb,
            u8::from(facts.no_new_privs)
        ),
        Err(err) => eprintln!("kernel-facts: unreadable: {}", err),
    }
}

#[cfg(not(feature = "fixture-facts"))]
fn emit_kernel_facts() {}
