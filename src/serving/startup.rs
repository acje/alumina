use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::cache::{CacheError, Family};
use crate::serve::{StartupError, StartupOutcome};
use crate::startup_dns::{
    EXCHANGE_DEADLINE_SECS, FailureReason, PublishedKind, StartupDnsError, TurnResult, WindowLedger,
};

use super::Serving;

/// The counted-exchange tallies of one startup window, accumulated by the
/// cooperative shared owner exactly as the private driver does: published
/// exchanges, counted failures, and the first failure's name ordinal and
/// family (for the single `startup_warning`).
#[derive(Default)]
struct StartupTallies {
    exchanges: u32,
    failed: u32,
    first_failure: Option<(u16, Family)>,
}

impl Serving {
    /// Drives the startup DNS window cooperatively over the single serving
    /// poll. The retained DNS transport is attached to the serving poll
    /// *before* selection starts, so the boot-armed poll carries the SIGTERM
    /// self-pipe, DNS freshness, and the listener together: a first-observed
    /// SIGTERM during the window is seen within one bounded poll instead of
    /// being invisible for the window's full duration, and it settles as the
    /// typed terminated outcome that never binds a listener. Each iteration
    /// advances the in-flight cooperative exchange, selects the next due step
    /// only while idle, and folds a single bounded wait over the serving poll
    /// (signal priority is handled inside [`Self::run_once`]).
    pub(crate) fn run_startup_window(
        &mut self,
        nameserver: SocketAddr,
        now0: u64,
        window: Duration,
    ) -> Result<StartupOutcome, StartupError> {
        self.attach_dns_shared().map_err(|err| {
            StartupError::Dns(StartupDnsError::Transport {
                kind: err.kind,
                detail: "shared",
            })
        })?;
        let window_deadline = self
            .storage
            .dns_mut()
            .begin_window(nameserver, now0, window)?;
        let names = self.storage.config().allowlist().len();
        for ordinal in 0..names {
            for family in Family::ALL {
                self.storage
                    .schedules_mut()
                    .overwrite_due_at(ordinal, family, now0)
                    .map_err(StartupDnsError::from)?;
            }
        }
        let mut ledger = WindowLedger::new(names);
        let mut tallies = StartupTallies::default();
        let mut terminated = false;
        loop {
            if self.is_shutdown() {
                terminated = true;
                break;
            }
            if ledger.all_resolved() {
                break;
            }
            if Instant::now() >= window_deadline {
                break;
            }
            if let Some((ordinal, ex_family)) = self.storage.dns().active_identity() {
                match self.storage.advance_dns()? {
                    None => {}
                    Some(TurnResult::Pending) => {}
                    Some(TurnResult::Published) => {
                        tallies.exchanges += 1;
                        let kind = self
                            .storage
                            .dns_mut()
                            .take_published_kind()
                            .unwrap_or(PublishedKind::ResolvedPositive);
                        let name_index = self
                            .storage
                            .cache()
                            .name_index(ordinal)
                            .ok_or(StartupDnsError::Cache(CacheError::NameOutOfRange))?;
                        let has = !self
                            .storage
                            .cache()
                            .entry(name_index, ex_family)?
                            .bindings()
                            .is_empty();
                        ledger.mark_published(ordinal, kind);
                        ledger.resolve(ordinal, has);
                    }
                    Some(TurnResult::Failed) => {
                        tallies.failed += 1;
                        if tallies.first_failure.is_none() {
                            tallies.first_failure = Some((ordinal as u16, ex_family));
                            let now = self.storage.dns().now_u64();
                            self.storage.startup_warning_first(now, ordinal, ex_family);
                        }
                        let reason = self
                            .storage
                            .dns_mut()
                            .take_failed_reason()
                            .unwrap_or(FailureReason::Receive);
                        ledger.mark_failed(ordinal, reason);
                    }
                }
            }
            if !self.storage.dns().has_active_exchange() {
                let secs = self.storage.dns().now_u64();
                let selected = self
                    .storage
                    .schedules_mut()
                    .select_due(secs)
                    .map_err(StartupDnsError::from)?;
                if let Some(token) = selected {
                    let ordinal = token.name();
                    let family = token.family();
                    if ledger.is_resolved(ordinal) {
                        self.storage
                            .schedules_mut()
                            .release_selection(ordinal, family)
                            .map_err(StartupDnsError::from)?;
                        continue;
                    }
                    let remaining = window_deadline.saturating_duration_since(Instant::now());
                    let deadline =
                        Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS).min(remaining);
                    ledger.track_attempt(ordinal, family);
                    self.storage
                        .start_dns_exchange(nameserver, ordinal, family, deadline)?;
                    continue;
                }
            }

            self.sync_dns_shared().map_err(|err| {
                StartupError::Dns(StartupDnsError::Transport {
                    kind: err.kind,
                    detail: "shared",
                })
            })?;
            if self.is_shutdown() {
                terminated = true;
                break;
            }
            let now_i = Instant::now();
            let remaining = window_deadline.saturating_duration_since(now_i);
            let exchange_wait = self
                .storage
                .dns()
                .exchange_deadline()
                .map(|d| d.saturating_duration_since(Instant::now()));
            let dns_wait = match exchange_wait {
                Some(exchange_wait) => exchange_wait.min(remaining),
                None => self
                    .storage
                    .dns()
                    .next_due_wait(self.storage.schedules(), &ledger)?
                    .min(remaining),
            };
            let log_wait = self
                .storage
                .logs()
                .next_drain(now_i)
                .map(|retry| retry.saturating_duration_since(Instant::now()));
            let wait = match log_wait {
                Some(log_wait) => dns_wait.min(log_wait),
                None => dns_wait,
            };
            self.storage.logs_mut().drain_sink();
            #[cfg(test)]
            if let Some(hook) = self.pre_poll.as_ref() {
                (hook.as_ref())(self);
            }
            self.run_once(Some(wait)).map_err(|err| {
                StartupError::Dns(StartupDnsError::Transport {
                    kind: err.kind,
                    detail: "startup-serve",
                })
            })?;
        }
        if !terminated {
            #[cfg(test)]
            if let Some(hook) = self.pre_settlement.take() {
                hook();
            }
            self.run_once(Some(Duration::ZERO)).map_err(|err| {
                StartupError::Dns(StartupDnsError::Transport {
                    kind: err.kind,
                    detail: "startup-settle",
                })
            })?;
            terminated = self.is_shutdown();
        }
        if terminated {
            self.storage.dns_mut().cancel_for_shutdown();
        }
        self.sync_dns_shared().map_err(|err| {
            StartupError::Dns(StartupDnsError::Transport {
                kind: err.kind,
                detail: "shared",
            })
        })?;
        let elapsed = self.storage.dns().window_start().elapsed().as_secs();
        self.storage.dns_mut().conclude_shared_transport()?;
        self.storage.settle_startup(
            now0,
            ledger.finish(tallies.exchanges, tallies.failed, tallies.first_failure),
            elapsed,
            terminated,
        )
    }
}
