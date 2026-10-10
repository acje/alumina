//! Alumina binary: fixed documented config/resolver inputs, no CLI or
//! environment policy overrides. Runs the boot harness (privilege check,
//! config + resolver reads, 128 MiB traffic store + serving workspaces), then
//! continues the same owner into the shared-readiness runtime: the serving
//! workspaces are preallocated before the boot-owned startup DNS window, the
//! canonical readiness rule runs (the listener opens for a serving decision;
//! an unresolved count beyond the allowance exits EX_TEMPFAIL 75), and a
//! serving decision attaches the startup listener and enters the serving loop
//! for the process lifetime. A boot or startup failure exits EX_CONFIG (78)
//! with a diagnostic naming the field/source.

use alumina::boot::{EX_CONFIG, run_boot};
use alumina::runtime::Preallocated;
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
            let storage = match ServeStorage::boot(&report.config) {
                Ok(storage) => storage,
                Err(err) => {
                    eprintln!("alumina: serving storage: {err}");
                    std::process::exit(EX_CONFIG);
                }
            };
            let mut owner = match Preallocated::preallocate(storage, report.storage) {
                Ok(owner) => owner,
                Err(err) => {
                    eprintln!("alumina: serving workspace: {err}");
                    std::process::exit(EX_CONFIG);
                }
            };
            println!(
                "inventory named fixed buffers (lower bound): {} (traffic {} + serving workspace {} + dns named buffers {})",
                report.inventory.named_fixed_buffer_bytes(),
                report.inventory.traffic_storage_bytes(),
                report.inventory.serving_workspace_bytes(),
                report.inventory.dns_named_buffer_bytes(),
            );
            println!(
                "inventory transient scratch (config doc buffer, not retained): {}",
                report.inventory.transient_scratch_bytes()
            );
            println!(
                "inventory reserved-future (log queue, deferred): {}",
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
            let nameserver =
                std::net::SocketAddr::new(report.nameserver.addr(), report.nameserver.port());
            match owner.run_startup(nameserver, PROCESS_EPOCH_SECS) {
                Ok(outcome) => match outcome.decision {
                    StartupDecision::Serve(mode) => {
                        let Some(listener) = outcome.listener else {
                            eprintln!("alumina: serving decision without a bound listener");
                            std::process::exit(EX_SOFTWARE);
                        };
                        let bound = listener
                            .local_addr()
                            .map(|addr| addr.to_string())
                            .unwrap_or_else(|_| "unavailable".to_string());
                        println!(
                            "startup-decision: {mode:?} listener {bound} exchanges {} failed {} resolved {}",
                            outcome.report.exchanges,
                            outcome.report.failed,
                            outcome.report.resolved_names,
                        );
                        let runtime = match owner.attach(listener) {
                            Ok(runtime) => runtime,
                            Err(err) => {
                                eprintln!("alumina: serving: {err}");
                                std::process::exit(EX_SOFTWARE);
                            }
                        };
                        match runtime.serve() {
                            Err(err) => {
                                eprintln!("alumina: serving: {err}");
                                std::process::exit(EX_SOFTWARE);
                            }
                            Ok(never) => match never {},
                        }
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
