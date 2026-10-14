//! Startup DNS-over-TCP transport (docs/alumina-proxy.md:62-68, 82, 171, 180): a single
//! reusable connection with one outstanding query, transaction ids drawn from
//! the OS CSPRNG, and publication of only fully validated outcomes into the
//! cache and schedule.
//!
//! The exchange deadline is 2 seconds, clipped to the caller's absolute
//! startup window deadline. On timeout, malformed, mismatched, truncated or
//! oversized responses the connection is closed, nothing is published, and the
//! exchange counts as failed. Startup readiness evaluation from the published
//! cache remains a caller concern.
//!
//! Cooperative turns never wait: [`StartupDns::advance_exchange`] performs at
//! most one nonblocking I/O attempt and returns [`TurnResult::Pending`] when
//! more readiness is needed; the single process owner owns the wait.
//! [`StartupDns::exchange_deadline`] and [`StartupDns::wait_dns_readiness`]
//! export the deadline and a wakeup the owner folds into its one combined
//! wait, so the shared reactor can observe traffic, log, and shutdown
//! readiness without DNS-internal blocking (docs/alumina-proxy.md:146).

use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Registry, Token};

use crate::cache::{Cache, CacheError, Family};
use crate::config::{ALLOWLIST_MAX, Config, Fqdn};
use crate::dns::{self, DNS_MSG_LIMIT, DnsError, ResponseWorkspace};
use crate::log;
use crate::schedule::{ScheduleError, Schedules};

pub const EXCHANGE_DEADLINE_SECS: u64 = 2;
pub const STARTUP_WINDOW_SECS: u64 = 90;
pub const QUERY_BUF_LEN: usize = 512;
pub const RECV_BUF_LEN: usize = DNS_MSG_LIMIT + 2;

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupDnsError {
    Dns(DnsError),
    Cache(CacheError),
    Schedule(ScheduleError),
    /// A counted per-exchange network failure (connect refused, write
    /// failure, socket error, deadline). It increments `StartupReport.failed`
    /// and advances the schedule backoff; it is never returned by `resolve`
    /// and does not abort resolution.
    Exchange {
        kind: io::ErrorKind,
        detail: &'static str,
    },
    /// A non-allocating fatal lifecycle refusal: `kind` carries the OS error
    /// class and `detail` names the stage (register, deregister, poll). Both
    /// fields are `Copy`.
    Transport {
        kind: io::ErrorKind,
        detail: &'static str,
    },
    /// The boot-owned log queue or its stdout sink could not be prepared.
    LogStore(log::LogStoreError),
    /// The OS entropy source failed while drawing a transaction id.
    Entropy,
    /// The monotonic poll-token generation is exhausted; no token is reused.
    TokenExhausted,
    /// The monotonic clock cannot represent the startup window deadline; the
    /// window is not extended, shortened, or clamped.
    DeadlineOverflow,
    /// The cooperative driver was asked to advance an exchange that is not in
    /// progress; start one first.
    ExchangeInactive,
    /// A start was requested while an exchange is already in progress; the
    /// outstanding exchange, its schedule accounting, and its connection are
    /// preserved untouched rather than silently replaced.
    ExchangeActive,
    /// The retained transport was asked to join the shared owner's registry
    /// while it still holds an open connection bound to the DNS-private poll.
    /// Attach only a transport with no open connection; a source can belong to
    /// exactly one registry.
    SharedAttachConflict,
}

impl fmt::Display for StartupDnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupDnsError::Dns(err) => write!(f, "startup DNS: {err}"),
            StartupDnsError::Cache(err) => write!(f, "startup DNS cache: {err}"),
            StartupDnsError::Schedule(err) => write!(f, "startup DNS schedule: {err:?}"),
            StartupDnsError::Exchange { kind, detail } => {
                write!(f, "startup DNS exchange ({detail}): {kind}")
            }
            StartupDnsError::Transport { kind, detail } => {
                write!(f, "startup DNS transport ({detail}): {kind}")
            }
            StartupDnsError::Entropy => write!(f, "startup DNS entropy unavailable"),
            StartupDnsError::TokenExhausted => {
                write!(f, "startup DNS poll-token generation exhausted")
            }
            StartupDnsError::DeadlineOverflow => write!(
                f,
                "startup DNS window deadline not representable on this clock"
            ),
            StartupDnsError::ExchangeInactive => {
                write!(f, "startup DNS exchange not in progress")
            }
            StartupDnsError::ExchangeActive => {
                write!(f, "startup DNS exchange already in progress")
            }
            StartupDnsError::SharedAttachConflict => {
                write!(f, "startup DNS transport holds a private-poll connection")
            }
            StartupDnsError::LogStore(err) => write!(f, "startup log store: {err:?}"),
        }
    }
}

impl From<log::LogStoreError> for StartupDnsError {
    fn from(err: log::LogStoreError) -> Self {
        StartupDnsError::LogStore(err)
    }
}

impl From<DnsError> for StartupDnsError {
    fn from(err: DnsError) -> Self {
        StartupDnsError::Dns(err)
    }
}

impl From<CacheError> for StartupDnsError {
    fn from(err: CacheError) -> Self {
        StartupDnsError::Cache(err)
    }
}

impl From<ScheduleError> for StartupDnsError {
    fn from(err: ScheduleError) -> Self {
        StartupDnsError::Schedule(err)
    }
}

/// What a fully validated published exchange left in the cache, so the
/// startup report can tell a validated negative from an attempted positive
/// with no eligible bindings instead of collapsing both into one catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishedKind {
    /// A positive answer published at least one eligible binding.
    ResolvedPositive,
    /// A positive answer whose candidates were all ineligible; nothing was
    /// published.
    NoEligible,
    /// A validated NXDOMAIN or NODATA answer was applied.
    Negative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExchangeResult {
    Published(PublishedKind),
    Failed(FailureReason),
}

/// The full legal context of one outstanding cooperative exchange, owned as a
/// single value on [`StartupDns`] so that at most one exchange can exist. A
/// transaction id, identity, deadline, per-stage state, and any deferred
/// synchronous connect error travel together; `None` means no exchange is in
/// progress. The step state advances by at most one stage per cooperative
/// turn.
#[derive(Debug)]
struct ActiveExchange {
    ordinal: usize,
    family: Family,
    deadline: Instant,
    step: ExchangeStep,
    /// `query_buf[..qlen]` is the length-prefixed query awaiting writes.
    qlen: usize,
    /// A synchronous connect error deferred to the first connecting turn so it
    /// settles as the counted failure it is, never aborted.
    connect_err: Option<io::ErrorKind>,
    tid: u16,
}

/// The stage of one outstanding exchange, advanced by at most one stage each
/// cooperative turn by [`StartupDns::advance_exchange`]. Turns never wait for
/// readiness (docs/alumina-proxy.md:146); the owner decides when to advance again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangeStep {
    /// A nonblocking connect is in progress toward the exchange deadline; the
    /// query is not written until the socket is verifiably connected.
    Connecting,
    /// The length-prefixed query is not yet fully written and the send can
    /// proceed without waiting; the next turn attempts another nonblocking
    /// write.
    SendReady,
    /// The last nonblocking write refused the socket (WouldBlock); the
    /// backpressure is recorded in the type and the owner must wait for a
    /// writable edge before another send attempt. No kernel or peer send-buffer
    /// capacity is assumed.
    AwaitWritable,
    /// Awaiting or assembling a response within the exchange deadline.
    Receiving,
}

/// The outcome of one cooperative turn, returned by
/// [`StartupDns::advance_exchange`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TurnResult {
    /// The exchange needs another turn; the worker may do other bounded work
    /// and then call [`StartupDns::advance_exchange`] again.
    Pending,
    /// A fully validated response was applied to the cache and schedule.
    Published,
    /// A counted per-exchange network failure; the connection is closed and
    /// the schedule backoff has been advanced exactly once.
    Failed,
}

/// The progress of one nonblocking connect step.
enum ConnectStep {
    /// The connection is not yet established; the exchange stays in scope.
    Waiting,
    /// The socket is connected; advance moves to the sending stage next turn.
    Transition,
    /// A counted failure; the exchange has been settled and closed.
    Failed,
}

/// The progress of one nonblocking query-write step.
enum SendStep {
    /// Some or all of the query remains unsent and the send can proceed without
    /// waiting; the exchange stays able to retry next turn.
    Waiting,
    /// The socket refused the write (WouldBlock); the exchange is held in
    /// AwaitWritable and the owner waits for a writable edge before retrying.
    Blocked,
    /// The query is fully written; advance moves to the receiving stage next
    /// turn (the readiness interest switches to reads).
    Transition,
    /// A counted failure; the exchange has been settled and closed.
    Failed,
}

/// The progress of one nonblocking response-read step.
enum RecvStep {
    Waiting,
    Failed,
    Published,
}

/// The reason a startup exchange failed, captured at the step where the
/// failure was first observable (connect, send, recv, or deadline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    Connect,
    Send,
    Receive,
    Timeout,
}

impl FailureReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            FailureReason::Connect => "connect",
            FailureReason::Send => "send",
            FailureReason::Receive => "receive",
            FailureReason::Timeout => "timeout",
        }
    }
}

/// The reason a name was never attempted inside the startup window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAttemptedReason {
    /// The fixed startup window closed before any exchange for the name was
    /// attempted (the only not-attempted state the window produces).
    WindowClosed,
}

impl NotAttemptedReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            NotAttemptedReason::WindowClosed => "window_closed",
        }
    }
}

/// The per-name terminal outcome of a single exchanged result, as the resolve
/// loops track it: `Resolved` is terminal (a usable name is never re-attempted),
/// otherwise the latest concluded exchange's outcome or reason is kept (704q:
/// capture where still known, never infer at formatting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Latest {
    Unattempted,
    Failed(FailureReason),
    NoEligible,
    Negative,
    Resolved,
}

impl Latest {
    fn merge(&mut self, result: ExchangeResult) {
        if *self == Latest::Resolved {
            return;
        }
        *self = match result {
            ExchangeResult::Published(PublishedKind::ResolvedPositive) => Latest::Resolved,
            ExchangeResult::Published(PublishedKind::Negative) => Latest::Negative,
            ExchangeResult::Published(PublishedKind::NoEligible) => Latest::NoEligible,
            ExchangeResult::Failed(reason) => Latest::Failed(reason),
        };
    }

    fn to_outcome(self) -> NameOutcome {
        match self {
            Latest::Resolved => NameOutcome::Resolved,
            Latest::Negative => NameOutcome::Negative,
            Latest::NoEligible => NameOutcome::NoEligible,
            Latest::Failed(reason) => NameOutcome::Failed(reason),
            Latest::Unattempted => NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed),
        }
    }
}

/// The per-name terminal outcome of the startup window, carried inline by the
/// single final startup record. A name is reported from its actual latest
/// exchange results: a validated negative (NXDOMAIN or empty NODATA answer)
/// stays distinct from an attempted positive with no eligible bindings and
/// from an exchange failure with its reason, so the final entry never collapses
/// distinct outcome classes into one catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameOutcome {
    /// At least one family holds an eligible non-retired positive binding.
    Resolved,
    /// The latest published outcome for the name was a validated negative
    /// (NXDOMAIN, or an NODATA answer with no eligible bindings).
    Negative,
    /// The latest published outcome was a positive answer whose candidates
    /// were all ineligible, so no binding was published.
    NoEligible,
    /// The latest concluded exchange for the name failed with this reason.
    Failed(FailureReason),
    /// No exchange for the name concluded inside the window.
    NotAttempted(NotAttemptedReason),
}

impl Default for NameOutcome {
    fn default() -> Self {
        NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StartupReport {
    pub exchanges: u32,
    pub failed: u32,
    pub cancelled: u32,
    pub not_attempted: u32,
    pub resolved_names: u32,
    /// One entry per configured name in allowlist ordinal order.
    pub outcomes: [NameOutcome; ALLOWLIST_MAX],
    /// The first counted exchange failure: name ordinal plus address family.
    pub first_failure: Option<(u16, Family)>,
}

impl StartupReport {
    /// Records the first counted exchange failure (name ordinal + family) if
    /// none has been captured yet.
    pub(crate) fn record_first_failure(&mut self, ordinal: usize, family: Family) {
        if self.first_failure.is_none() {
            self.first_failure = Some((ordinal as u16, family));
        }
    }
}

/// The per-name, per-family bookkeeping of one startup window, shared between
/// the private blocking driver (`resolve_window`) and the shared owner's
/// cooperative window so both produce the identical typed report from the
/// identical selection/backoff rule set. Kept here so the private [`Latest`]
/// classification and [`PublishedKind`] resolution stay encapsulated: the
/// selected/exchanged/report math never leaks raw stages to an owner.
#[derive(Debug)]
pub(crate) struct WindowLedger {
    resolved: [bool; ALLOWLIST_MAX],
    attempted: [bool; ALLOWLIST_MAX * 2],
    latest: [Latest; ALLOWLIST_MAX],
    names: usize,
}

impl WindowLedger {
    pub(crate) fn new(names: usize) -> WindowLedger {
        WindowLedger {
            resolved: [false; ALLOWLIST_MAX],
            attempted: [false; ALLOWLIST_MAX * 2],
            latest: [Latest::Unattempted; ALLOWLIST_MAX],
            names,
        }
    }

    pub(crate) fn names(&self) -> usize {
        self.names
    }

    pub(crate) fn resolved(&self) -> &[bool] {
        &self.resolved[..self.names]
    }

    pub(crate) fn is_resolved(&self, ordinal: usize) -> bool {
        self.resolved[ordinal]
    }

    pub(crate) fn all_resolved(&self) -> bool {
        self.resolved[..self.names].iter().all(|&r| r)
    }

    pub(crate) fn track_attempt(&mut self, ordinal: usize, family: Family) {
        self.attempted[ordinal * 2 + family_index(family)] = true;
    }

    /// Merges a concluded exchange into the ledger: a resolved-positive answer
    /// (with at least one eligible binding) marks the name usable and terminal;
    /// a validated negative or no-eligible answer is recorded as its own class
    /// and never re-attempted as resolved.
    pub(crate) fn mark_published(&mut self, ordinal: usize, kind: PublishedKind) {
        match kind {
            PublishedKind::ResolvedPositive => self.resolved[ordinal] = true,
            PublishedKind::Negative | PublishedKind::NoEligible => {}
        }
        self.latest[ordinal].merge(ExchangeResult::Published(kind));
    }

    /// Overlays the "usable name" binding check: a name counts as resolved only
    /// when a published positive answer actually left at least one eligible
    /// binding, exactly as the private driver computes it.
    pub(crate) fn resolve(&mut self, ordinal: usize, has: bool) {
        self.resolved[ordinal] |= has;
    }

    pub(crate) fn mark_failed(&mut self, ordinal: usize, reason: FailureReason) {
        self.latest[ordinal].merge(ExchangeResult::Failed(reason));
    }

    /// Finishes the window ledger into the typed startup report, applying the
    /// canonical count and outcome rules: attempted per name-family pair,
    /// not-attempted as the remainder, resolved names where a usable binding
    /// was published, and each unresolved name reported from its latest
    /// classified outcome rather than inferred.
    pub(crate) fn finish(
        &self,
        exchanges: u32,
        failed: u32,
        first_failure: Option<(u16, Family)>,
    ) -> StartupReport {
        let attempted_count = self.attempted[..self.names * 2]
            .iter()
            .filter(|&&t| t)
            .count() as u32;
        let resolved_names = self.resolved[..self.names].iter().filter(|&&r| r).count() as u32;
        let mut report = StartupReport {
            exchanges,
            failed,
            cancelled: 0,
            not_attempted: (self.names * 2) as u32 - attempted_count,
            resolved_names,
            outcomes: [NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed); ALLOWLIST_MAX],
            first_failure,
        };
        for ordinal in 0..self.names {
            report.outcomes[ordinal] = if self.resolved[ordinal] {
                NameOutcome::Resolved
            } else {
                self.latest[ordinal].to_outcome()
            };
        }
        report
    }
}

/// A tightly scoped test hook that substitutes the outcome of the next
/// nonblocking send attempt, so a deterministically forced send backpressure
/// (a real WouldBlock) can be exercised without depending on any kernel or
/// peer send-buffer capacity.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
enum WriteForce {
    WouldBlock,
    Partial(usize),
}

/// Whether the retained transport belongs to this transport's own private poll
/// or to the shared owner's single serving poll. A source has exactly one
/// registry (mio rejects a second); the variants make the two owners
/// mutually exclusive, and `armed` records the interest currently registered
/// for the shared registry's stream: `Some(interest)` while registered,
/// `None` while the stream is fresh or closed. Only `Private` ever touches the
/// DNS-private poll.
#[derive(Debug)]
enum Registration {
    Private,
    Shared {
        token: Token,
        armed: Option<Interest>,
    },
}

/// A boot-owned reusable DNS transport. Constructed once before the
/// startup-window phase so the exchange loop performs no heap allocation or
/// deallocation: the poll registry, fixed query/recv buffers, and the response
/// workspace all pre-exist.
pub struct StartupDns {
    poll: Poll,
    events: Events,
    stream: Option<TcpStream>,
    query_buf: [u8; QUERY_BUF_LEN],
    recv_buf: [u8; RECV_BUF_LEN],
    workspace: ResponseWorkspace,
    written: usize,
    filled: usize,
    msglen: Option<usize>,
    now0: u64,
    start: Instant,
    addr: SocketAddr,
    watch: Token,
    token_gen: usize,
    registration: Registration,
    active: Option<ActiveExchange>,
    /// Whether the owner is currently inside a startup window. Within the
    /// window the transport keeps its single connection warm and reusable
    /// across every allowlist name, exactly as private mode does; the
    /// per-publish conclusion is withheld until the window ends. Outside a
    /// window a concluded shared exchange closes the transport so a serving
    /// refresh never leaves an idle socket under the serving poll.
    window_open: bool,
    /// The classification of the most recently published outcome, read out by
    /// the blocking driver when the exchange concludes (never inferred from
    /// the cache afterwards, where negative and no-eligible are ambiguous).
    last_published: Option<PublishedKind>,
    /// The failure reason of the most recently failed step, read out by the
    /// blocking driver when the exchange concludes.
    last_failed: Option<FailureReason>,
    #[cfg(test)]
    poll_ticks: u64,
    #[cfg(test)]
    force_write: Option<WriteForce>,
}

/// The borrowed startup-window resolution context fed to
/// [`StartupDns::resolve_window`]: the config, cache, schedules, nameserver,
/// process-relative second anchor, and window duration are the single startup
/// input set, bundled so the resolve seam stays within the clippy argument
/// budget (L1). The boot-owned log store stays a separate per-run parameter
/// because the witness hoists a pre-reserved store into the measured window.
pub(crate) struct WindowInputs<'a> {
    pub(crate) config: &'a Config,
    pub(crate) cache: &'a mut Cache,
    pub(crate) schedules: &'a mut Schedules,
    pub(crate) nameserver: SocketAddr,
    pub(crate) now0: u64,
    pub(crate) window: Duration,
}

impl StartupDns {
    /// Constructs the transport and its registration backing.
    ///
    /// # Errors
    ///
    /// Returns `Transport` when the poll registry cannot be created.
    pub fn new() -> Result<StartupDns, StartupDnsError> {
        let poll = Poll::new().map_err(|e| StartupDnsError::Transport {
            kind: e.kind(),
            detail: "poll",
        })?;
        let events = Events::with_capacity(8);
        Ok(StartupDns {
            poll,
            events,
            stream: None,
            query_buf: [0; QUERY_BUF_LEN],
            recv_buf: [0; RECV_BUF_LEN],
            workspace: ResponseWorkspace::default(),
            written: 0,
            filled: 0,
            msglen: None,
            now0: 0,
            start: Instant::now(),
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            watch: Token(0),
            token_gen: 0,
            registration: Registration::Private,
            active: None,
            window_open: false,
            last_published: None,
            last_failed: None,
            #[cfg(test)]
            poll_ticks: 0,
            #[cfg(test)]
            force_write: None,
        })
    }

    fn fresh_tid(&mut self) -> Result<u16, StartupDnsError> {
        let mut bytes = [0u8; 2];
        getrandom::fill(&mut bytes).map_err(|_| StartupDnsError::Entropy)?;
        Ok(u16::from_be_bytes(bytes))
    }

    /// Resolve the whole-second DNS epoch clock from the window anchor; the
    /// private driver and the shared owner read the same seconds value.
    pub(crate) fn now_u64(&self) -> u64 {
        self.now0.saturating_add(self.start.elapsed().as_secs())
    }

    /// The exact monotonic origin of the most recent `resolve_window` run —
    /// the single elapsed base startup receipts were written on. The owning
    /// storage re-anchors its serving clock to this origin so cache seconds
    /// continue seamlessly from startup into serving (one anchor, 1cws M2r).
    pub(crate) fn window_start(&self) -> Instant {
        self.start
    }

    /// Starts a startup window on the retained transport without owning the
    /// wait: it anchors the DNS epoch and monotonic origin, pins the
    /// nameserver peer, and returns the absolute window deadline. From here
    /// the shared owner drives selection and cooperative exchanges over the
    /// serving poll and reports through [`Self::finalize_window`]; the private
    /// driver uses the same anchor inside [`Self::resolve_window`].
    pub(crate) fn begin_window(
        &mut self,
        nameserver: SocketAddr,
        now0: u64,
        window: Duration,
    ) -> Result<Instant, StartupDnsError> {
        self.now0 = now0;
        self.start = Instant::now();
        let deadline = self
            .start
            .checked_add(window)
            .ok_or(StartupDnsError::DeadlineOverflow)?;
        self.addr = nameserver;
        self.window_open = true;
        Ok(deadline)
    }

    /// The bounded wait the shared owner folds into its single serving poll
    /// between startup selections: the earliest scheduled step among
    /// not-yet-usable names (with the one-second start guard and floor), or
    /// the maximum wait when nothing is scheduled, so the poll only sleeps to
    /// the clipped window deadline instead of deciding early.
    pub(crate) fn next_due_wait(
        &self,
        schedules: &Schedules,
        ledger: &WindowLedger,
    ) -> Result<Duration, StartupDnsError> {
        wait_until_next_step(self, schedules, ledger.names(), ledger.resolved())
    }

    /// The classification of the most recently published startup exchange, so
    /// a shared owner records a validated negative or no-eligible answer
    /// distinctly from a resolved positive (never inferred from the cache
    /// afterwards). `None` when nothing has published.
    pub(crate) fn take_published_kind(&mut self) -> Option<PublishedKind> {
        self.last_published.take()
    }

    /// The failure reason of the most recently failed startup exchange, so a
    /// shared owner records the exact counted reason instead of collapsing
    /// every non-published conclusion into one class.
    pub(crate) fn take_failed_reason(&mut self) -> Option<FailureReason> {
        self.last_failed.take()
    }

    /// The outstanding exchange ordinal and family, captured together for a
    /// shared owner settling a concluded exchange against its ledger.
    pub(crate) fn active_identity(&self) -> Option<(usize, Family)> {
        self.active.as_ref().map(|ex| (ex.ordinal, ex.family))
    }

    /// Closes the transport connection exactly once. In private mode the
    /// source is deregistered against the DNS-private poll; a `NotFound`
    /// deregister is the benign already-closed case, any other failure is
    /// surfaced as a lifecycle `Transport` error because it leaks a registry
    /// registration. In shared mode the socket belongs to the owner's registry:
    /// dropping it is the deregistration at the kernel layer (closing the fd
    /// removes it from any poll set, and mio keeps no token-keyed table), so
    /// the same token is reusable on a fresh source and `armed` clears to keep
    /// the registration state consistent with the closed stream.
    fn close_connection(&mut self) -> Result<(), StartupDnsError> {
        let deregister_error = if let Some(mut stream) = self.stream.take() {
            match &mut self.registration {
                Registration::Private => match self.poll.registry().deregister(&mut stream) {
                    Ok(()) => None,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                    Err(e) => Some(e.kind()),
                },
                Registration::Shared { armed, .. } => {
                    *armed = None;
                    None
                }
            }
        } else {
            if let Registration::Shared { armed, .. } = &mut self.registration {
                *armed = None;
            }
            None
        };
        self.filled = 0;
        self.written = 0;
        self.msglen = None;
        match deregister_error {
            None => Ok(()),
            Some(kind) => Err(StartupDnsError::Transport {
                kind,
                detail: "deregister",
            }),
        }
    }

    fn next_token(&mut self) -> Result<Token, StartupDnsError> {
        self.token_gen = self
            .token_gen
            .checked_add(1)
            .ok_or(StartupDnsError::TokenExhausted)?;
        Ok(Token(self.token_gen))
    }

    /// Closes the transport when the shared owner drove this exchange and no
    /// startup window is open, so a concluded serving-refresh exchange never
    /// leaves an idle socket registered with (or retained under) the serving
    /// poll. Private mode keeps the connection warm for reuse within the
    /// startup window, as does an open window in shared mode: the window owner
    /// calls this once at window end to close the single reused connection.
    pub(crate) fn conclude_shared_transport(&mut self) -> Result<(), StartupDnsError> {
        self.window_open = false;
        if matches!(self.registration, Registration::Shared { .. }) {
            self.close_connection()?;
        }
        Ok(())
    }

    /// Cancels the retained transport for owner shutdown: the outstanding
    /// exchange is cleared (no deadline or active-exchange predicate remains
    /// to keep the shared poll hot) and the connection closed exactly once.
    /// In shared mode closing the fd removes the source from the owner's poll
    /// set at the kernel layer; the retained transport and its heap stay owned
    /// until process exit, so the cancellation is infallible rather than
    /// surfacing a deregistration bookkeeping error on an abandoned socket
    /// that would otherwise turn a clean drain into a forced failure.
    pub(crate) fn cancel_for_shutdown(&mut self) {
        self.active = None;
        self.window_open = false;
        self.stream = None;
        if let Registration::Shared { armed, .. } = &mut self.registration {
            *armed = None;
        }
        self.filled = 0;
        self.written = 0;
        self.msglen = None;
    }

    /// Test-only readiness probe on the retained shared stream: true only once
    /// the owner-side socket has response bytes queued that the window has not
    /// yet read. Uses a nonblocking `peek` (never consumes data), so `Ok(n) if
    /// n > 0` holds exactly for queued bytes — unlike a raw `poll` readiness
    /// bit, which stays set on POLLHUP/POLLERR once the responder drops its
    /// socket after the write-ack.
    #[cfg(test)]
    pub(crate) fn test_fd_readable(&self) -> bool {
        let Some(stream) = self.stream.as_ref() else {
            return false;
        };
        let mut probe = [0u8; 1];
        matches!(stream.peek(&mut probe), Ok(n) if n > 0)
    }

    /// Test-only stage probe: whether the active exchange has sent its full
    /// query and is awaiting the response (the responder withholds answers
    /// only once a query is on the wire).
    #[cfg(test)]
    pub(crate) fn test_active_receiving(&self) -> bool {
        matches!(
            self.active.as_ref(),
            Some(ex) if ex.step == ExchangeStep::Receiving
        )
    }

    /// Performs the nonblocking connect and registers the source, leaving the
    /// connection to be completed by [`Self::step_connect`] turns. A
    /// synchronous connect error is returned so the caller can defer it to the
    /// first connecting turn, where it settles as the counted failure it is
    /// rather than aborting.
    fn begin_connect(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Option<io::ErrorKind>, StartupDnsError> {
        let watch = self.next_token()?;
        let mut stream = match TcpStream::connect(addr) {
            Ok(stream) => stream,
            Err(e) => return Ok(Some(e.kind())),
        };
        self.watch = watch;
        match &mut self.registration {
            Registration::Private => {
                self.poll
                    .registry()
                    .register(
                        &mut stream,
                        watch,
                        Interest::READABLE.add(Interest::WRITABLE),
                    )
                    .map_err(|e| StartupDnsError::Transport {
                        kind: e.kind(),
                        detail: "register",
                    })?;
            }
            Registration::Shared { armed, .. } => {
                *armed = None;
            }
        }
        self.stream = Some(stream);
        Ok(None)
    }

    /// Restricts the registered interest to reads, so the owner's single wait
    /// wakes only for response data (or EOF), never on the always-ready
    /// writable edge once the query is fully sent.
    fn set_stream_interest_readable(&mut self) -> Result<(), StartupDnsError> {
        let Some(stream) = self.stream.as_mut() else {
            return Ok(());
        };
        if matches!(self.registration, Registration::Shared { .. }) {
            return Ok(());
        }
        self.poll
            .registry()
            .reregister(stream, self.watch, Interest::READABLE)
            .map_err(|e| StartupDnsError::Transport {
                kind: e.kind(),
                detail: "reregister",
            })
    }

    /// Re-arms the writable interest when a would-block send moves the
    /// exchange to AwaitWritable. Re-arming after `EAGAIN` is the standard
    /// event-loop idiom: it makes the owner's subsequent poll deterministically
    /// wait on the writable edge even if an earlier writable event was consumed
    /// by the completed connect. Drops the readable interest because no
    /// response can arrive before the query is fully written.
    fn set_stream_interest_writable(&mut self) -> Result<(), StartupDnsError> {
        let Some(stream) = self.stream.as_mut() else {
            return Ok(());
        };
        if matches!(self.registration, Registration::Shared { .. }) {
            return Ok(());
        }
        self.poll
            .registry()
            .reregister(stream, self.watch, Interest::WRITABLE)
            .map_err(|e| StartupDnsError::Transport {
                kind: e.kind(),
                detail: "reregister",
            })
    }

    /// The absolute deadline of the outstanding exchange, or `None` when idle.
    /// An owner that waits on more than one source folds this into its single
    /// earliest-deadline wait.
    pub(crate) fn exchange_deadline(&self) -> Option<Instant> {
        self.active.as_ref().map(|ex| ex.deadline)
    }

    /// Whether an exchange is currently in progress, so a shared owner can
    /// decide whether DNS work is due without treating idle as an error.
    pub(crate) fn has_active_exchange(&self) -> bool {
        self.active.is_some()
    }

    /// The allowlist ordinal of the outstanding exchange, for the owner to
    /// recover the query name from the configuration and cache.
    pub(crate) fn active_ordinal(&self) -> Option<usize> {
        self.active.as_ref().map(|ex| ex.ordinal)
    }

    /// The stage of the outstanding exchange, for the shared owner to observe
    /// progress (e.g. that a query has been fully written and the exchange
    /// awaits a response).
    #[allow(dead_code)]
    pub(crate) fn exchange_step(&self) -> Option<ExchangeStep> {
        self.active.as_ref().map(|ex| ex.step)
    }

    /// Repoints the retained transport peer. Startup configures it through
    /// resolution; a refresh owner repoints it by policy before starting an
    /// exchange.
    #[allow(dead_code)]
    pub(crate) fn set_peer(&mut self, addr: SocketAddr) {
        self.addr = addr;
    }

    pub(crate) fn peer(&self) -> SocketAddr {
        self.addr
    }

    /// Registers the retained transport with an external single-poll owner so
    /// DNS freshness joins traffic readiness in one wait. The private poll is
    /// bypassed from here on: the shared registry is the source's only
    /// registry. The transport must hold no open connection (the startup path
    /// closes before transfer); attaching one still bound to the private poll
    /// is refused as [`StartupDnsError::SharedAttachConflict`] rather than
    /// double-registering a source.
    ///
    /// # Errors
    ///
    /// Returns `SharedAttachConflict` when the transport holds an open
    /// connection, and `Transport` when the external registration fails.
    pub(crate) fn attach_shared(
        &mut self,
        registry: &Registry,
        token: Token,
    ) -> Result<(), StartupDnsError> {
        if matches!(self.registration, Registration::Shared { .. }) {
            return Ok(());
        }
        if self.stream.is_some() {
            return Err(StartupDnsError::SharedAttachConflict);
        }
        self.registration = Registration::Shared { token, armed: None };
        self.sync_shared(registry)
    }

    /// Re-aligns the shared registration to the current exchange phase: it
    /// registers the transport the first time it is observed, re-registers it
    /// only when the phase's desired interest changes, and deregisters
    /// (or no-ops after a close) when the exchange is idle. Calling every
    /// turn is cheap: an unchanged interest performs no syscall, so an idle or
    /// quiet owner never spins a permanently-ready socket.
    ///
    /// # Errors
    ///
    /// Returns `Transport` when the external registration, re-registration, or
    /// deregistration fails.
    pub(crate) fn sync_shared(&mut self, registry: &Registry) -> Result<(), StartupDnsError> {
        if !matches!(self.registration, Registration::Shared { .. }) {
            return Ok(());
        }
        let desired = self.shared_desired_interest();
        let (token, armed) = match &mut self.registration {
            Registration::Shared { token, armed } => (*token, armed),
            Registration::Private => return Ok(()),
        };
        let Some(stream) = self.stream.as_mut() else {
            *armed = None;
            return Ok(());
        };
        if *armed == desired {
            return Ok(());
        }
        let was_armed = *armed;
        match desired {
            Some(interest) => {
                let result = if was_armed.is_some() {
                    registry.reregister(stream, token, interest)
                } else {
                    registry.register(stream, token, interest)
                };
                result.map_err(|e| StartupDnsError::Transport {
                    kind: e.kind(),
                    detail: "shared",
                })?;
            }
            None => {
                registry
                    .deregister(stream)
                    .map_err(|e| StartupDnsError::Transport {
                        kind: e.kind(),
                        detail: "deregister",
                    })?;
            }
        }
        *armed = desired;
        Ok(())
    }

    /// The interest the shared registry must currently arm for the exchange
    /// phase: `None` while idle so an owner never waits on a retained socket,
    /// the writable edge while connecting or backpressured, the readable edge
    /// while awaiting a response, and both while the next write can proceed on
    /// its own.
    fn shared_desired_interest(&self) -> Option<Interest> {
        match self.active.as_ref().map(|ex| ex.step) {
            Some(ExchangeStep::Connecting | ExchangeStep::AwaitWritable) => {
                Some(Interest::WRITABLE)
            }
            Some(ExchangeStep::Receiving) => Some(Interest::READABLE),
            Some(ExchangeStep::SendReady) => Some(Interest::READABLE | Interest::WRITABLE),
            None => None,
        }
    }

    #[cfg(test)]
    fn arm_write(&mut self, force: WriteForce) {
        self.force_write = Some(force);
    }

    #[cfg(test)]
    fn active_step(&self) -> Option<ExchangeStep> {
        self.active.as_ref().map(|ex| ex.step)
    }

    /// Whether the owner must wait for network readiness before advancing the
    /// exchange again. Connecting needs the connect-completion edge;
    /// AwaitWritable needs a writable edge after a real would-block send;
    /// Receiving needs response data. SendReady never does — the next turn's
    /// nonblocking write attempt proceeds on its own, so the owner yields
    /// instead of blocking on a stale edge; a would-block observed there
    /// transitions the exchange to AwaitWritable and arms this wait rather
    /// than spinning on an assumed write window.
    pub(crate) fn needs_wait(&self) -> bool {
        let Some(ex) = self.active.as_ref() else {
            return false;
        };
        matches!(
            ex.step,
            ExchangeStep::Connecting | ExchangeStep::AwaitWritable | ExchangeStep::Receiving
        )
    }

    /// The single owner-owned DNS wait: exactly one poll over the DNS-private
    /// registry, with the timeout clipped to `until` and to the outstanding
    /// exchange deadline so the wait never outlives the exchange. This is the
    /// discourse between turns, not part of the turn API, and performs no DNS
    /// work. Returns whether readiness for the DNS source was observed, so a
    /// caller can re-advance immediately; a timeout means re-advance to settle
    /// at the deadline. A turn that needs no readiness (a sendable exchange
    /// whose next write proceeds on its own) yields the owner immediately
    /// instead of blocking on a stale edge; a would-block send has moved the
    /// exchange to AwaitWritable, so this wait polls for the writable edge.
    pub(crate) fn wait_dns_readiness(&mut self, until: Instant) -> Result<bool, StartupDnsError> {
        if !self.needs_wait() {
            return Ok(false);
        }
        #[cfg(test)]
        {
            self.poll_ticks += 1;
        }
        let deadline = self.exchange_deadline().unwrap_or(until);
        loop {
            let now = Instant::now();
            let timeout = if now >= deadline || now >= until {
                Duration::ZERO
            } else {
                deadline.min(until).saturating_duration_since(now)
            };
            match self.poll.poll(&mut self.events, Some(timeout)) {
                Ok(()) => break,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    return Err(StartupDnsError::Transport {
                        kind: err.kind(),
                        detail: "poll",
                    });
                }
            }
        }
        Ok(self.events.iter().any(|event| event.token() == self.watch))
    }

    /// One nonblocking connect step. The socket is deemed connected only once
    /// `peer_addr` is resolvable (a completed nonblocking connect); the
    /// exchange transitions to sending on the next turn, never in the same
    /// turn that completes the connect.
    fn step_connect(
        &mut self,
        ex: &mut ActiveExchange,
        schedules: &mut Schedules,
    ) -> Result<ConnectStep, StartupDnsError> {
        if let Some(_kind) = ex.connect_err.take() {
            self.close_connection()?;
            self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Connect)?;
            return Ok(ConnectStep::Failed);
        }
        if let Some(stream) = self.stream.as_mut() {
            if let Ok(Some(_err)) = stream.take_error() {
                self.close_connection()?;
                self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Connect)?;
                return Ok(ConnectStep::Failed);
            }
            if stream.peer_addr().is_ok() {
                return Ok(ConnectStep::Transition);
            }
        }
        if Instant::now() >= ex.deadline {
            self.close_connection()?;
            self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Timeout)?;
            return Ok(ConnectStep::Failed);
        }
        Ok(ConnectStep::Waiting)
    }

    /// One nonblocking query-write step: at most one write attempt, then the
    /// deadline is checked before yielding so a completed write is honoured
    /// even at the boundary (faithful to the original `send_query` loop). A
    /// would-block is reported as `Blocked` so the stage moves to
    /// AwaitWritable; any other partial progress stays sendable.
    fn step_send(
        &mut self,
        ex: &mut ActiveExchange,
        schedules: &mut Schedules,
    ) -> Result<SendStep, StartupDnsError> {
        let mut blocked = false;
        #[cfg(test)]
        let mut forced_partial = 0usize;
        #[cfg(test)]
        {
            if let Some(force) = self.force_write.take() {
                blocked = true;
                if let (Some(stream), WriteForce::Partial(n)) = (self.stream.as_mut(), force) {
                    let end = (self.written + n).min(ex.qlen);
                    if end > self.written {
                        match stream.write(&self.query_buf[self.written..end]) {
                            Ok(0) => {
                                self.close_connection()?;
                                self.note_failure(
                                    ex.ordinal,
                                    ex.family,
                                    schedules,
                                    FailureReason::Send,
                                )?;
                                return Ok(SendStep::Failed);
                            }
                            Ok(w) => {
                                self.written += w;
                                forced_partial = w;
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                            Err(_) => {
                                self.close_connection()?;
                                self.note_failure(
                                    ex.ordinal,
                                    ex.family,
                                    schedules,
                                    FailureReason::Send,
                                )?;
                                return Ok(SendStep::Failed);
                            }
                        }
                    }
                }
            }
        }
        if !blocked && self.written < ex.qlen {
            if let Some(stream) = self.stream.as_mut() {
                match stream.write(&self.query_buf[self.written..ex.qlen]) {
                    Ok(0) => {
                        self.close_connection()?;
                        self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Send)?;
                        return Ok(SendStep::Failed);
                    }
                    Ok(n) => {
                        self.written += n;
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted =>
                    {
                        blocked = true;
                    }
                    Err(_) => {
                        self.close_connection()?;
                        self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Send)?;
                        return Ok(SendStep::Failed);
                    }
                }
            } else {
                self.close_connection()?;
                self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Send)?;
                return Ok(SendStep::Failed);
            }
        }
        if self.written >= ex.qlen {
            self.set_stream_interest_readable()?;
            return Ok(SendStep::Transition);
        }
        if Instant::now() >= ex.deadline {
            self.close_connection()?;
            self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Timeout)?;
            return Ok(SendStep::Failed);
        }
        if blocked {
            #[cfg(test)]
            {
                if forced_partial > 0 {
                    return Ok(SendStep::Waiting);
                }
            }
            self.set_stream_interest_writable()?;
            return Ok(SendStep::Blocked);
        }
        Ok(SendStep::Waiting)
    }

    /// One nonblocking response-read step: at most one read, then a complete
    /// validated message is published; an API/EOF/deadline failure settles the
    /// counted failure and closes the connection exactly once.
    fn step_recv(
        &mut self,
        ex: &mut ActiveExchange,
        fqdn: &Fqdn,
        cache: &mut Cache,
        schedules: &mut Schedules,
    ) -> Result<RecvStep, StartupDnsError> {
        if self.stream.is_none() {
            self.close_connection()?;
            self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Receive)?;
            return Ok(RecvStep::Failed);
        }
        let want = match self.msglen {
            Some(len) => len + 2,
            None => 2,
        };
        if self.filled < want
            && let Some(stream) = self.stream.as_mut()
        {
            match stream.read(&mut self.recv_buf[self.filled..]) {
                Ok(0) => {
                    self.close_connection()?;
                    self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Receive)?;
                    return Ok(RecvStep::Failed);
                }
                Ok(n) => self.filled += n,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    self.close_connection()?;
                    self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Receive)?;
                    return Ok(RecvStep::Failed);
                }
            }
        }
        if self.msglen.is_none() && self.filled >= 2 {
            let len = usize::from(u16::from_be_bytes([self.recv_buf[0], self.recv_buf[1]]));
            if len == 0 || len > DNS_MSG_LIMIT {
                self.close_connection()?;
                self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Receive)?;
                return Ok(RecvStep::Failed);
            }
            self.msglen = Some(len);
        }
        if let Some(len) = self.msglen
            && self.filled >= len + 2
        {
            let message = &self.recv_buf[2..2 + len];
            let outcome =
                dns::parse_response(&mut self.workspace, fqdn, ex.family, ex.tid, message);
            self.msglen = None;
            self.filled = 0;
            match outcome {
                Ok(outcome) => {
                    self.last_published = Some(match &outcome {
                        dns::Outcome::Positive { bindings, .. } if !bindings.is_empty() => {
                            PublishedKind::ResolvedPositive
                        }
                        dns::Outcome::Positive { .. } => PublishedKind::NoEligible,
                        dns::Outcome::NxDomain { .. } | dns::Outcome::NoData { .. } => {
                            PublishedKind::Negative
                        }
                    });
                    let name_index = cache
                        .name_index(ex.ordinal)
                        .ok_or(StartupDnsError::Cache(CacheError::NameOutOfRange))?;
                    let generation = cache.entry(name_index, ex.family)?.generation();
                    let receipt = self.now_u64();
                    dns::apply_outcome(
                        cache,
                        schedules,
                        ex.ordinal,
                        generation,
                        receipt,
                        self.now_u64(),
                        outcome,
                    )?;
                    return Ok(RecvStep::Published);
                }
                Err(_) => {
                    self.close_connection()?;
                    self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Receive)?;
                    return Ok(RecvStep::Failed);
                }
            }
        }
        if Instant::now() >= ex.deadline {
            self.close_connection()?;
            self.note_failure(ex.ordinal, ex.family, schedules, FailureReason::Timeout)?;
            return Ok(RecvStep::Failed);
        }
        Ok(RecvStep::Waiting)
    }

    /// Single-pass test-support resolution: visits each admitted name and
    /// record type once inside the fixed startup window, with no retries.
    /// This is not the startup policy path — [`Self::resolve_window`] owns the
    /// retrying window with a single clipped deadline. It exists so the
    /// in-crate transport tests can drive deterministic first-attempt
    /// behaviour without the retry schedule.
    ///
    /// # Errors
    ///
    /// Returns an error for a fatal storage, entropy, lifecycle, poll,
    /// deadline, or token-exhaustion failure; resolution aborts rather than
    /// continuing with corrupt or reused state. Counted per-exchange network
    /// failures (connect refused, write failure, socket error, deadline) are
    /// recorded in the returned report and never stop the loop.
    #[cfg(test)]
    fn resolve(
        &mut self,
        config: &Config,
        cache: &mut Cache,
        schedules: &mut Schedules,
        nameserver: SocketAddr,
        now0: u64,
    ) -> Result<StartupReport, StartupDnsError> {
        use std::os::fd::AsRawFd;
        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .map_err(|_| StartupDnsError::Transport {
                kind: std::io::ErrorKind::Other,
                detail: "test null sink",
            })?;
        let mut logs = log::LogStore::with_fd(null.as_raw_fd()).expect("null sink store");
        self.resolve_body(config, cache, schedules, nameserver, now0, &mut logs)
    }

    /// The shared test driver body used by [`Self::resolve`], parameterised over
    /// an already-constructed log store so an alloc-witness caller can hoist
    /// the one-time queue reservation (a boot cost, not a per-exchange cost)
    /// outside the measured phase.
    #[cfg(test)]
    fn resolve_body(
        &mut self,
        config: &Config,
        cache: &mut Cache,
        schedules: &mut Schedules,
        nameserver: SocketAddr,
        now0: u64,
        logs: &mut log::LogStore,
    ) -> Result<StartupReport, StartupDnsError> {
        self.now0 = now0;
        self.start = Instant::now();
        let window_deadline = self
            .start
            .checked_add(Duration::from_secs(STARTUP_WINDOW_SECS))
            .ok_or(StartupDnsError::DeadlineOverflow)?;
        self.addr = nameserver;
        let allowlist = config.allowlist();
        let names = allowlist.len();
        let mut report = StartupReport::default();
        let mut resolved = [false; ALLOWLIST_MAX];
        let mut latest = [Latest::Unattempted; ALLOWLIST_MAX];

        for (ordinal, name) in allowlist.iter().enumerate() {
            for family in Family::ALL {
                if Instant::now() >= window_deadline {
                    report.not_attempted += 1;
                    continue;
                }
                let name_index = cache
                    .name_index(ordinal)
                    .ok_or(CacheError::NameOutOfRange)?;
                let remaining = window_deadline.duration_since(Instant::now());
                let exchange_deadline =
                    Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS).min(remaining);
                match self.exchange(
                    name,
                    family,
                    ordinal,
                    cache,
                    schedules,
                    exchange_deadline,
                    logs,
                ) {
                    Ok(ExchangeResult::Published(kind)) => {
                        report.exchanges += 1;
                        let has = !cache.entry(name_index, family)?.bindings().is_empty();
                        resolved[ordinal] |= has;
                        latest[ordinal].merge(ExchangeResult::Published(kind));
                    }
                    Ok(ExchangeResult::Failed(reason)) => {
                        report.failed += 1;
                        report.record_first_failure(ordinal, family);
                        latest[ordinal].merge(ExchangeResult::Failed(reason));
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        report.resolved_names = resolved[..names].iter().filter(|&&r| r).count() as u32;
        for ordinal in 0..names {
            report.outcomes[ordinal] = if resolved[ordinal] {
                NameOutcome::Resolved
            } else {
                latest[ordinal].to_outcome()
            };
        }
        self.close_connection()?;
        Ok(report)
    }

    /// Resolves the allowlist inside one absolute startup window whose
    /// monotonic deadline is the single deadline for every exchange. The
    /// schedule due table drives the attempts: each name and family is seeded
    /// due at the window start, a failed lookup is retried on its backoff
    /// ladder with every exchange deadline clipped to the window, and a name
    /// already usable is never re-attempted or refreshed. Returns early once
    /// every name is usable; otherwise returns at the deadline, together with
    /// the whole second count since the window opened at which the caller's
    /// readiness decision is anchored — a single owned anchor, never a second
    /// clock read. Receipts use the process-relative `now0` second scale.
    ///
    /// # Errors
    ///
    /// Returns the underlying fatal storage, entropy, lifecycle, poll, token,
    /// deadline, or schedule error; counted per-exchange network failures are
    /// carried by the report.
    pub(crate) fn resolve_window(
        &mut self,
        inputs: WindowInputs<'_>,
        logs: &mut log::LogStore,
    ) -> Result<(StartupReport, u64), StartupDnsError> {
        let WindowInputs {
            config,
            cache,
            schedules,
            nameserver,
            now0,
            window,
        } = inputs;
        self.now0 = now0;
        self.start = Instant::now();
        let window_deadline = self
            .start
            .checked_add(window)
            .ok_or(StartupDnsError::DeadlineOverflow)?;
        self.addr = nameserver;
        let allowlist = config.allowlist();
        let names = allowlist.len();
        let mut report = StartupReport::default();
        let mut resolved = [false; ALLOWLIST_MAX];
        let mut attempted = [false; ALLOWLIST_MAX * 2];
        let mut latest = [Latest::Unattempted; ALLOWLIST_MAX];

        for ordinal in 0..names {
            for family in Family::ALL {
                schedules.overwrite_due_at(ordinal, family, now0)?;
            }
        }

        loop {
            if resolved[..names].iter().all(|&r| r) {
                break;
            }
            if Instant::now() >= window_deadline {
                break;
            }
            let now = self.now_u64();
            match schedules.select_due(now) {
                Ok(Some(token)) => {
                    let ordinal = token.name();
                    let family = token.family();
                    if resolved[ordinal] {
                        schedules.release_selection(ordinal, family)?;
                        continue;
                    }
                    let Some(name) = allowlist.get(ordinal) else {
                        return Err(StartupDnsError::Cache(CacheError::NameOutOfRange));
                    };
                    let remaining = window_deadline.saturating_duration_since(Instant::now());
                    let exchange_deadline =
                        Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS).min(remaining);
                    let name_index = cache
                        .name_index(ordinal)
                        .ok_or(CacheError::NameOutOfRange)?;
                    attempted[ordinal * 2 + family_index(family)] = true;
                    match self.exchange(
                        name,
                        family,
                        ordinal,
                        cache,
                        schedules,
                        exchange_deadline,
                        logs,
                    ) {
                        Ok(ExchangeResult::Published(kind)) => {
                            report.exchanges += 1;
                            let has = !cache.entry(name_index, family)?.bindings().is_empty();
                            resolved[ordinal] |= has;
                            latest[ordinal].merge(ExchangeResult::Published(kind));
                        }
                        Ok(ExchangeResult::Failed(reason)) => {
                            report.failed += 1;
                            let first = report.first_failure.is_none();
                            report.record_first_failure(ordinal, family);
                            if first {
                                logs.startup_warning(now, name.as_str(), family);
                            }
                            latest[ordinal].merge(ExchangeResult::Failed(reason));
                        }
                        Err(err) => return Err(err),
                    }
                }
                Ok(None) => {
                    let remaining = window_deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    logs.drain_sink();
                    let dns_wait =
                        wait_until_next_step(self, schedules, names, &resolved)?.min(remaining);
                    let now_i = Instant::now();
                    let log_wait = logs
                        .next_drain(now_i)
                        .map(|retry| retry.saturating_duration_since(now_i));
                    let wait = match log_wait {
                        Some(log_wait) => dns_wait.min(log_wait),
                        None => dns_wait,
                    };
                    if wait.is_zero() {
                        continue;
                    }
                    thread::sleep(wait);
                }
                Err(err) => return Err(StartupDnsError::from(err)),
            }
        }
        self.close_connection()?;
        let attempted_count = attempted[..names * 2].iter().filter(|&&t| t).count() as u32;
        report.not_attempted = (names * 2) as u32 - attempted_count;
        report.resolved_names = resolved[..names].iter().filter(|&&r| r).count() as u32;
        for ordinal in 0..names {
            report.outcomes[ordinal] = if resolved[ordinal] {
                NameOutcome::Resolved
            } else {
                latest[ordinal].to_outcome()
            };
        }
        Ok((report, self.start.elapsed().as_secs()))
    }

    /// Starts a cooperative DNS exchange without waiting for network
    /// readiness: it opens-or-reuses the transport connection, draws a fresh
    /// transaction id, builds the fixed query, and records the exchange
    /// (name/family/absolute deadline) so subsequent
    /// [`Self::advance_exchange`] turns can conclude it. Counted per-exchange
    /// network failures never surface here; they terminate a later turn as
    /// [`TurnResult::Failed`].
    ///
    /// # Errors
    ///
    /// Returns a fatal storage, entropy, lifecycle, poll, deadline, or
    /// token-exhaustion error when the exchange cannot begin; a query build or
    /// registry failure aborts rather than continuing with corrupt state.
    /// Returns [`StartupDnsError::ExchangeActive`] when an exchange is already
    /// in progress, leaving the outstanding exchange, its schedule accounting,
    /// and its connection untouched.
    pub(crate) fn start_exchange(
        &mut self,
        fqdn: &Fqdn,
        family: Family,
        ordinal: usize,
        deadline: Instant,
    ) -> Result<(), StartupDnsError> {
        if self.active.is_some() {
            return Err(StartupDnsError::ExchangeActive);
        }
        let connect_err = if self.stream.is_none() {
            self.begin_connect(self.addr)?
        } else {
            None
        };
        let tid = self.fresh_tid()?;
        let qlen = dns::build_query(fqdn, family, tid, &mut self.query_buf[2..])?;
        let total = qlen + 2;
        self.query_buf[0] = (qlen as u16 >> 8) as u8;
        self.query_buf[1] = qlen as u8;
        self.written = 0;
        self.filled = 0;
        self.msglen = None;
        self.active = Some(ActiveExchange {
            ordinal,
            family,
            deadline,
            step: ExchangeStep::Connecting,
            qlen: total,
            connect_err,
            tid,
        });
        Ok(())
    }

    /// Advances the in-progress cooperative exchange by one turn. A turn never
    /// waits: it performs at most one nonblocking I/O attempt and at most one
    /// stage transition, re-checks the absolute exchange deadline, and
    /// otherwise returns [`TurnResult::Pending`] so the single owner keeps
    /// control of all waiting (docs/alumina-proxy.md:146).
    ///
    /// # Errors
    ///
    /// Returns a fatal storage, entropy, lifecycle, poll, deadline, or
    /// token-exhaustion error. Counted per-exchange network failures return
    /// [`TurnResult::Failed`] with the backoff already advanced; an exchange
    /// that is not in progress is a fatal caller error.
    pub(crate) fn advance_exchange(
        &mut self,
        fqdn: &Fqdn,
        cache: &mut Cache,
        schedules: &mut Schedules,
    ) -> Result<TurnResult, StartupDnsError> {
        let Some(mut ex) = self.active.take() else {
            return Err(StartupDnsError::ExchangeInactive);
        };
        let next_step = match ex.step {
            ExchangeStep::Connecting => match self.step_connect(&mut ex, schedules)? {
                ConnectStep::Waiting => None,
                ConnectStep::Transition => Some(ExchangeStep::SendReady),
                ConnectStep::Failed => {
                    self.active = None;
                    return Ok(TurnResult::Failed);
                }
            },
            ExchangeStep::SendReady => match self.step_send(&mut ex, schedules)? {
                SendStep::Waiting => None,
                SendStep::Blocked => Some(ExchangeStep::AwaitWritable),
                SendStep::Transition => Some(ExchangeStep::Receiving),
                SendStep::Failed => {
                    self.active = None;
                    return Ok(TurnResult::Failed);
                }
            },
            ExchangeStep::AwaitWritable => match self.step_send(&mut ex, schedules)? {
                SendStep::Waiting => Some(ExchangeStep::SendReady),
                SendStep::Blocked => None,
                SendStep::Transition => Some(ExchangeStep::Receiving),
                SendStep::Failed => {
                    self.active = None;
                    return Ok(TurnResult::Failed);
                }
            },
            ExchangeStep::Receiving => match self.step_recv(&mut ex, fqdn, cache, schedules)? {
                RecvStep::Waiting => None,
                RecvStep::Failed => {
                    self.active = None;
                    return Ok(TurnResult::Failed);
                }
                RecvStep::Published => {
                    self.active = None;
                    if !self.window_open {
                        self.conclude_shared_transport()?;
                    }
                    return Ok(TurnResult::Published);
                }
            },
        };
        if let Some(step) = next_step {
            ex.step = step;
        }
        self.active = Some(ex);
        Ok(TurnResult::Pending)
    }

    /// The startup-only blocking driver (nonserving): it starts the exchange
    /// and then owns every wait itself via [`Self::wait_dns_readiness`],
    /// polling the DNS registry once per turn until the exchange concludes
    /// within its single clipped deadline. The boot-owned log store is passed
    /// at this seam so logging steps and the log retry deadline participate in
    /// the same wait without restarting the 90s or 2s deadlines (704q); any
    /// other owner replaces this driver body with a fold of the DNS readiness
    /// and [`Self::exchange_deadline`] into its own combined wait.
    #[allow(clippy::too_many_arguments)]
    fn exchange(
        &mut self,
        fqdn: &Fqdn,
        family: Family,
        ordinal: usize,
        cache: &mut Cache,
        schedules: &mut Schedules,
        deadline: Instant,
        logs: &mut log::LogStore,
    ) -> Result<ExchangeResult, StartupDnsError> {
        self.start_exchange(fqdn, family, ordinal, deadline)?;
        loop {
            match self.advance_exchange(fqdn, cache, schedules)? {
                TurnResult::Pending => {
                    logs.drain_sink();
                    let now = Instant::now();
                    let wake = match logs.next_drain(now) {
                        Some(retry) => deadline.min(retry),
                        None => deadline,
                    };
                    self.wait_dns_readiness(wake)?;
                }
                TurnResult::Published => {
                    return Ok(ExchangeResult::Published(
                        self.last_published
                            .take()
                            .unwrap_or(PublishedKind::ResolvedPositive),
                    ));
                }
                TurnResult::Failed => {
                    return Ok(ExchangeResult::Failed(
                        self.last_failed.take().unwrap_or(FailureReason::Receive),
                    ));
                }
            }
        }
    }

    fn note_failure(
        &mut self,
        ordinal: usize,
        family: Family,
        schedules: &mut Schedules,
        reason: FailureReason,
    ) -> Result<(), StartupDnsError> {
        self.last_failed = Some(reason);
        let now = self.now_u64();
        schedules.note_exchange_failure(ordinal, family, now)?;
        Ok(())
    }
}

/// The fixed per-name, per-family slot index used by the attempt ledger.
fn family_index(family: Family) -> usize {
    match family {
        Family::A => 0,
        Family::Aaaa => 1,
    }
}

/// The bounded wait until the earliest scheduled startup step among
/// not-yet-usable names. The one-second per-slot start guard can hold a due
/// slot back; the floor keeps that wake window short and spin-free. The caller
/// clips the result to the absolute window deadline. A name that has no
/// scheduled step at all yields the maximum wait, so the caller sleeps to the
/// window deadline instead of deciding early.
fn wait_until_next_step(
    transport: &StartupDns,
    schedules: &Schedules,
    names: usize,
    resolved: &[bool],
) -> Result<Duration, StartupDnsError> {
    let mut min_due: Option<u64> = None;
    for (ordinal, is_resolved) in resolved[..names].iter().enumerate() {
        if *is_resolved {
            continue;
        }
        for family in Family::ALL {
            if let Some(due) = schedules.due_time(ordinal, family)? {
                min_due = Some(min_due.map_or(due, |min| min.min(due)));
            }
        }
    }
    let Some(min_due) = min_due else {
        return Ok(Duration::MAX);
    };
    let due_instant = transport
        .start
        .checked_add(Duration::from_secs(min_due.saturating_sub(transport.now0)))
        .ok_or(StartupDnsError::DeadlineOverflow)?;
    let mut wait = due_instant.saturating_duration_since(Instant::now());
    if wait.is_zero() {
        wait = Duration::from_millis(100);
    }
    Ok(wait)
}

#[cfg(test)]
mod tests;
