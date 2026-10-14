//! Single-process shared-readiness owner.
//!
//! The runtime owns the boot-completed storage and one serving loop. It joins
//! DNS freshness and traffic readiness into a single wait by attaching the
//! retained DNS transport to the serving poll, advances the cooperative DNS
//! exchange in bounded turns alongside dispatched traffic, and folds the
//! outstanding DNS deadline into the serving earliest-deadline authority. It
//! allocates nothing after construction: every retained workspace pre-exists
//! from boot and serving construction.

use std::time::{Duration, Instant};

use mio::Token;
use mio::net::TcpListener;

use crate::serve::{ServeStorage, StartupError, StartupOutcome};
use crate::serving::{ServeError, Serving, Shutdown, ShutdownExit};
use crate::startup_dns::{
    EXCHANGE_DEADLINE_SECS, STARTUP_WINDOW_SECS, StartupDnsError, TurnResult,
};

/// The bounded number of cooperative DNS advances a single owner turn may make,
/// so a chatty or stalled peer can never starve traffic within a turn.
const DNS_ADVANCE_BOUND: usize = 8;

/// The pre-attach owner: the retained serving workspaces are preallocated over
/// boot-completed storage, and the startup window runs over that complete
/// owner, exactly as main wires it. It carries no serving loop: [`Self::turn`]
/// and an entry loop only exist on the attached [`Runtime`] returned by the
/// consuming [`Self::attach`], so serving without a listener is
/// unrepresentable (a preallocated owner cannot be turned or served; a second
/// attach is excluded because [`Self::attach`] consumes `self`).
///
/// ```compile_fail,E0599
/// use alumina::runtime::Preallocated;
/// fn probe(owner: Preallocated) {
///     owner.serve();
/// }
/// ```
pub struct Preallocated {
    serving: Serving,
    dns_token: Token,
}

impl Preallocated {
    /// Test-only writable handle to the SIGTERM self-pipe retained by the
    /// pre-attach serving workspaces, so host tests drive the exact
    /// signal-observation path (a real self-pipe readable edge) without a
    /// process-wide raise.
    #[cfg(test)]
    pub(crate) fn wake_signal_test(&mut self) -> Option<&mut std::os::unix::net::UnixStream> {
        self.serving.signal_wake_mut()
    }

    /// Builds the owner's retained serving workspaces over boot-completed
    /// storage and the boot-owned traffic store, before the startup DNS
    /// window runs. The owner is complete except for the startup-opened
    /// listener and the shared DNS registration, which [`Self::attach`] adds
    /// once a serving decision is taken.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the serving poll cannot be created.
    pub fn preallocate(
        storage: ServeStorage,
        traffic: crate::inventory::TrafficStorage,
    ) -> Result<Preallocated, ServeError> {
        let dns_token = Serving::dns_token();
        let serving = Serving::preallocate(storage, traffic)?;
        Ok(Preallocated { serving, dns_token })
    }

    /// Arms the production stdout sink (fd 1 nonblocking) on the owner's
    /// retained storage. The binary calls this once after boot, before any
    /// serving stdout write; the library and tests never flip the descriptor.
    ///
    /// # Errors
    ///
    /// Returns the sink preparation error when fd 1 cannot be made nonblocking.
    pub fn prepare_stdout_log_sink(&mut self) -> Result<(), StartupDnsError> {
        self.serving.storage_mut().prepare_stdout_log_sink()
    }

    /// Emits one stdout-only fatal record and performs one bounded drain on
    /// the owner's boot-owned log store, for the post-sink-switch fatal paths
    /// in main that must not write to stderr (docs/alumina-proxy.md:149, B1). The
    /// message is formatted directly into the fixed slot (no heap String).
    pub fn emit_fatal_and_drain(&mut self, args: std::fmt::Arguments<'_>) {
        self.serving.storage_mut().emit_fatal_and_drain(args);
    }

    /// Runs the canonical startup DNS window and readiness decision over the
    /// retained serving poll, exactly as main wires it: the DNS transport is
    /// attached to the shared poll *before* selection so a first-observed
    /// SIGTERM during the window settles as the typed terminated outcome
    /// (never binding a listener) rather than stalling the window. The
    /// listener opens inside, at the moment a serving decision is taken.
    ///
    /// # Errors
    ///
    /// Returns the underlying fatal DNS/readiness error, or `Listener` when
    /// the configured listen socket cannot be bound.
    pub fn run_startup(
        &mut self,
        nameserver: std::net::SocketAddr,
        now0: u64,
    ) -> Result<StartupOutcome, StartupError> {
        self.serving
            .run_startup_window(nameserver, now0, Duration::from_secs(STARTUP_WINDOW_SECS))
    }

    /// The shortened-window startup core for the loopback test seam.
    #[cfg(test)]
    pub(crate) fn run_startup_within(
        &mut self,
        nameserver: std::net::SocketAddr,
        now0: u64,
        window: std::time::Duration,
    ) -> Result<StartupOutcome, StartupError> {
        self.serving.run_startup_window(nameserver, now0, window)
    }

    /// Emits the single typed shutdown record and performs one bounded drain,
    /// for the terminated-startup owner path and process-fatal serving exits
    /// that follow with [`std::process::exit`]: a Drained or Forced verdict is
    /// never silently lost to the immediate exit that drops the log queue.
    pub fn emit_shutdown_and_drain(&mut self) {
        let secs = self.serving.storage().cache_secs(Instant::now());
        let status = self
            .serving
            .shutdown_exit()
            .map(|exit| exit.status())
            .unwrap_or(crate::log::ShutdownStatus::Drained);
        self.serving
            .storage_mut()
            .logs_mut()
            .shutdown_final(secs, status);
        self.serving.storage_mut().logs_mut().drain_sink();
    }

    /// Completes the owner after the startup window opened the listener,
    /// returning the attached owner that owns the serving loop: the listener
    /// is registered and the retained DNS transport attaches to the single
    /// serving poll so one wait observes both DNS freshness and traffic
    /// readiness. Consumes `self`, so the same owner cannot be attached twice.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the listener registration or the shared DNS
    /// registration fails.
    pub fn attach(mut self, listener: TcpListener) -> Result<Runtime, ServeError> {
        if let Err(err) = self.serving.attach_listener(listener) {
            self.serving
                .storage_mut()
                .emit_fatal_and_drain(format_args!("attach listener failed: {err}"));
            return Err(err);
        }
        if let Err(err) = self.serving.attach_dns_shared() {
            self.serving
                .storage_mut()
                .emit_fatal_and_drain(format_args!("attach dns failed: {err}"));
            return Err(err);
        }
        Ok(Runtime {
            serving: self.serving,
            dns_token: self.dns_token,
            #[cfg(test)]
            dns_advances_last_turn: 0,
        })
    }

    /// The serving engine, for host observation of pre-attach readiness state.
    pub fn serving(&self) -> &Serving {
        &self.serving
    }
}

/// The attached shared-readiness owner: one process owner whose single wait
/// sees both DNS freshness and traffic readiness, and whose turn policy
/// decides when DNS work is due (a freshness event, a send that can proceed
/// without waiting, or the exchange deadline). Constructed only by the
/// consuming [`Preallocated::attach`] or the equivalent [`Runtime::new`], so
/// it always owns an attached listener and all `sized` serving workspaces:
/// the serve loop and per-turn dispatch are reachable only here.
pub struct Runtime {
    serving: Serving,
    dns_token: Token,
    /// Test-only count of cooperative DNS advances actually made on the most
    /// recent owner turn, so fixtures assert the eight-step turn bound against
    /// an observable counter rather than inferring it from the step label.
    #[cfg(test)]
    pub(crate) dns_advances_last_turn: usize,
}

impl Runtime {
    /// Builds the attached owner over boot-completed storage, the boot-owned
    /// traffic store, and an already-bound listener, attaching the retained
    /// DNS transport to the single serving poll. Equivalent to
    /// [`Preallocated::preallocate`] then [`Preallocated::attach`].
    ///
    /// # Errors
    ///
    /// Returns a serve error when the serving poll, the listener registration,
    /// or the shared DNS registration fails.
    pub fn new(
        storage: ServeStorage,
        listener: TcpListener,
        traffic: crate::inventory::TrafficStorage,
    ) -> Result<Runtime, ServeError> {
        Preallocated::preallocate(storage, traffic)?.attach(listener)
    }

    /// The serving engine, for host observation.
    pub fn serving(&self) -> &Serving {
        &self.serving
    }

    /// Test-only mutable handle to the serving engine, so the allocation
    /// witness injects an established relay and drives the exact self-pipe
    /// shutdown through [`Self::turn`] (the production path) rather than a
    /// detached helper.
    #[cfg(all(test, feature = "alloc-witness"))]
    pub(crate) fn serving_mut(&mut self) -> &mut Serving {
        &mut self.serving
    }

    /// The token the retained DNS source is attached under on the single poll.
    pub fn dns_token(&self) -> Token {
        self.dns_token
    }

    /// The owner's shutdown phase, for host observation of the lifecycle.
    pub fn shutdown(&self) -> Shutdown {
        self.serving.shutdown()
    }

    /// One owner turn: a single wait over DNS freshness and traffic readiness
    /// (the serving poll carries both), then dispatch and a bounded
    /// cooperative DNS advance when DNS work is due, then a re-alignment of
    /// the shared DNS interest to its phase. The wait never outlives the
    /// outstanding exchange because the deadline is folded into the serving
    /// timeout. During shutdown the cooperative DNS turn is skipped entirely:
    /// the retained transport was cancelled at the first SIGTERM and no DNS
    /// deadline may outlive it or delay the drain.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the poll, a registration, or a cooperative
    /// DNS turn fails.
    pub fn turn(&mut self, timeout: Option<Duration>) -> Result<(), ServeError> {
        self.serving.run_once(timeout)?;
        #[cfg(test)]
        {
            self.dns_advances_last_turn = 0;
        }
        if !self.serving.is_shutdown() {
            self.starts_due_dns_if_idle()?;
            let event_seen = self.serving.take_dns_event();
            let sendable = self.dns_sendable_without_wait();
            let deadline_due = self.dns_deadline_due();
            if event_seen || sendable || deadline_due {
                self.cooperative_dns_turn()?;
            }
            self.serving.sync_dns_shared()?;
        }
        self.serving.storage_mut().logs_mut().drain_sink();
        Ok(())
    }

    fn starts_due_dns_if_idle(&mut self) -> Result<(), ServeError> {
        if self.serving.storage().dns().has_active_exchange() {
            return Ok(());
        }
        let secs = self.serving.storage().dns().now_u64();
        let Some(selected) = self
            .serving
            .storage_mut()
            .schedules_mut()
            .select_due(secs)
            .map_err(StartupDnsError::from)
            .map_err(ServeError::from)?
        else {
            return Ok(());
        };
        let nameserver = self.serving.storage().dns().peer();
        let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
        self.serving
            .storage_mut()
            .start_dns_exchange(nameserver, selected.name(), selected.family(), deadline)
            .map_err(ServeError::from)?;
        Ok(())
    }

    /// Enter the serving loop for the process lifetime: the attached listener
    /// keeps the owner taking single waits over DNS freshness and traffic
    /// readiness and dispatching bounded turns. The owner is always attached
    /// by construction ([`Preallocated::attach`] or [`Runtime::new`]).
    ///
    /// The loop never yields `Ok`: [`std::convert::Infallible`] is
    /// uninhabited, so a caller cannot mistake a returned `Ok` for a clean
    /// serving exit. On shutdown the owner exits in place with
    /// [`std::process::exit`], which skips the owner's destructors, so the
    /// boot-owned heap (traffic store, serving workspaces, log queue, retained
    /// DNS transport) is never freed before the operating system reclaims it
    /// at process exit (docs/alumina-proxy.md:150,206): a clean drain exits 0, and a
    /// deadline-forced closure of remaining sockets exits `EX_SOFTWARE` (70).
    ///
    /// # Errors
    ///
    /// Returns a serve error when a poll or cooperative DNS turn fails.
    pub fn serve(mut self) -> Result<std::convert::Infallible, ServeError> {
        loop {
            if let Err(err) = self.turn(None) {
                self.serving
                    .storage_mut()
                    .emit_fatal_and_drain(format_args!("serving failed: {err}"));
                return Err(err);
            }
            if let Some(exit) = self.serving.shutdown_exit() {
                self.emit_shutdown_record_and_drain(exit);
                std::process::exit(exit.code());
            }
        }
    }

    /// Emits the single typed shutdown record and performs one bounded drain
    /// for a settled forced or drained serving exit, before the immediate
    /// [`std::process::exit`] in [`Self::serve`] drops the retained log
    /// queue. The production serving loop and the allocation witness share
    /// this exact path, so a forced-closure failure is never silently lost to
    /// an exit while the drain still bounds a stalled sink.
    pub(crate) fn emit_shutdown_record_and_drain(&mut self, exit: ShutdownExit) {
        let secs = self.serving.storage().cache_secs(Instant::now());
        self.serving
            .storage_mut()
            .logs_mut()
            .shutdown_final(secs, exit.status());
        self.serving.storage_mut().logs_mut().drain_sink();
    }

    /// DNS work is due without a freshness event when the outstanding exchange
    /// can proceed on its own (the next write attempts without waiting) and
    /// must not be starved by a quiet traffic set.
    fn dns_sendable_without_wait(&self) -> bool {
        self.serving.storage().dns().has_active_exchange()
            && !self.serving.storage().dns().needs_wait()
    }

    /// DNS work is due at the exchange deadline so a stalled exchange settles
    /// as the counted failure it is rather than parking the owner forever.
    fn dns_deadline_due(&self) -> bool {
        self.serving
            .storage()
            .dns()
            .exchange_deadline()
            .is_some_and(|d| d <= Instant::now())
    }

    fn cooperative_dns_turn(&mut self) -> Result<(), ServeError> {
        for _ in 0..DNS_ADVANCE_BOUND {
            #[cfg(test)]
            {
                self.dns_advances_last_turn += 1;
            }
            match self.serving.storage_mut().advance_dns()? {
                None => break,
                Some(TurnResult::Pending) => continue,
                Some(TurnResult::Failed) | Some(TurnResult::Published) => break,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
