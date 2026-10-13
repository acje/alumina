//! The actual serving event loop: real mio sockets driving the retained
//! [`crate::serve::ServeStorage`] boundary and the pure two-barrier gate.
//!
//! The loop owns each accepted socket, parses the CONNECT head with a
//! boot-fixed parser fed incrementally (new bytes only), asks the retained
//! worker for the one decision over its own clock and the accept-owned slot
//! deadline, writes the canonical fixed refusal bodies for every
//! non-authorizing phase, and on an authorized [`ConnectPhase::Peer`] dials
//! the decided eligible destination, sends the fixed `200 Connection
//! established` response to the client, validates the client TLS ClientHello
//! against the approved hostname before forwarding, then relays in both
//! directions through bounded per-direction pending buffers without dropping
//! bytes or allocating per event.
//!
//! Barrier A (client->upstream) stays closed until the complete ClientHello
//! passes [`crate::client_hello::validate`] against the approved CONNECT
//! hostname; the gate opens in the same successful write that crosses the
//! validated hello end. Barrier B (upstream->client) stays closed until the
//! gate opens; any actual upstream data/EOF/reset observed pre-open
//! terminates the setup ([`crate::gate::Activity`], architecture D4). A setup
//! graduates to established work the moment its gate opens, releasing a
//! pending seat; absolute setup deadlines are enforced by the poll timeout and
//! an expiry sweep (504).
//!
//! Host tests cover the refusal paths end to end with real sockets
//! (400/403/502/503/504 + release-once + slot reuse + edge drain). The
//! dial/hello/relay path is unit-tested in-process, and its socket behaviour
//! remains a native-Linux production obligation, not a host claim. The slot
//! token carries a generation so events for a reused slot index are dropped,
//! never misdirected.

use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
#[cfg(test)]
use std::rc::Rc;
use std::time::{Duration, Instant};

use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Registry, Token};

use signal_hook::consts::SIGTERM;

use crate::cache::{CacheError, Family};
use crate::client_hello::{self, ChInspector, Inspect};
use crate::config::FixedHostname;
use crate::connect::{ConnectParser, Feed};
use crate::eligibility::NumericAddr;
use crate::gate::{Activity, TunnelGate, UpstreamWrite, ValidatedHello};
use crate::log::{ActivityKind, RejectReason};
use crate::serve::{ServeStorage, StartupError, StartupOutcome};
use crate::startup_dns::{
    EXCHANGE_DEADLINE_SECS, FailureReason, PublishedKind, StartupDnsError, TurnResult, WindowLedger,
};
use crate::worker::{AttemptCounts, ConnectPhase, MAX_TUNNELS, SlotIndex, TunnelIndex};

/// The listener registration token.
const LISTENER: Token = Token(0);

/// Boot-fixed per-slot client->upstream byte store: the CONNECT head plus any
/// coalesced tunnel bytes up to the ClientHello inspection cap, reused as a
/// recycling relay pending buffer. Allocated once before the postboot phase and
/// reused across connections. The mandated directional profile is two 512 KiB
/// buffers per tunnel (docs/alumina-proxy.md:161-164,:183; RF-008): 128 slots x 1 MiB =
/// 128 MiB traffic storage, not total RSS.
const HOLD_CAP: usize = crate::inventory::BUFFER_BYTES;

/// Boot-fixed per-slot upstream->client pending store (relay bytes and
/// canonical response/refusal bodies), bounded at the 512 KiB direction cap.
const DOWN_CAP: usize = crate::inventory::BUFFER_BYTES;

/// Idle deadline for an established tunnel once the gate has opened, reset on
/// every successful tunnel-byte write (docs/alumina-proxy.md:190,:147). Readiness alone
/// never extends it.
const IDLE_SECS: Duration = Duration::from_secs(300);

/// The first orderly EOF starts a drain deadline that is never reset
/// (docs/alumina-proxy.md:191; RF-003); the slot closes at both-EOF-drained or here.
const DRAIN_SECS: Duration = Duration::from_secs(5);

/// The fixed shutdown grace from the first observed SIGTERM: establish-alone
/// drains close their tunnels under this deadline, forced closure after is a
/// failure (docs/alumina-proxy.md:181,220; oracle b3nx B12/B16).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(8);

/// Bounded re-arm backoff after a transient accept failure (e.g. EMFILE).
/// No canonical capacity number is invented; this only stops a hot re-arm loop
/// (xz3f N6; alumina-refinement.md factual note).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The canonical complete-visit I/O budget (docs/alumina-proxy.md:146): at
/// most 64 KiB of I/O or 16 I/O operations per connection visit, whichever
/// comes first, combined across both directions and every arm of one visit.
/// A WouldBlock or spurious-readiness attempt counts as an I/O operation
/// (:226; oracle alumina-8d7z §4), so a stalled arm still consumes budget.
const VISIT_OPS: u16 = 16;
const VISIT_BYTES: u32 = 64 * 1024;

/// Timers rejoin the turn after at most this many ready-slot visits or I/O
/// operations within one poll dispatch (docs/alumina-proxy.md:146), so an
/// over-long batch cannot delay an expired deadline past this bound.
const TIMER_RECHECK_EVERY: usize = 256;

/// The fixed event-buffer capacity factor: the poll batch is a bounded
/// snapshot, and per-batch slot dedup (one complete visit per connection per
/// batch) means the visit budget, not this cap, bounds a slot's turn. This
/// seed predates complete-visit accounting; scheduling is owned by
/// [`VISIT_OPS`]/[`VISIT_BYTES`].
const EVENT_CAP: usize = 16;

/// Read chunk size; the relation CHUNK * EVENT_CAP = 64 KiB still bounds one
/// direction's read shape, and the complete-visit budget bounds the total.
const CHUNK: usize = 4096;

/// Client sockets occupy tokens `1..=MAX_TUNNELS`; each upstream socket uses a
/// disjoint token at `UPSTREAM_BASE + index` so no two registrations collide.
const UPSTREAM_BASE: usize = MAX_TUNNELS + 1;

/// The external DNS refresh source token: the first local id past the
/// listener (0), client (1..=MAX_TUNNELS) and upstream (`UPSTREAM_BASE..`)
/// ranges, so a single poll carrying the attached DNS transport can never
/// collide with a connection token. Dispatched as a benign readiness flag,
/// never a slot.
const DNS_LOCAL: usize = UPSTREAM_BASE + MAX_TUNNELS;

/// The SIGTERM self-pipe source token: the next free local id after the DNS
/// source, dispatched as a benign readiness flag that wakes the single poll
/// so a handler-only route could never start the shutdown grace on an idle
/// loop (oracle b3nx B18).
const SIGNAL_LOCAL: usize = DNS_LOCAL + 1;

/// Token layout: low 9 bits = local id (1..=MAX_TUNNELS client,
/// `UPSTREAM_BASE..` upstream, 0 = listener), high bits = slot generation so a
/// stale event for a reused slot index is dropped before touching a socket.
/// The local id space also carries the reserved readiness sources `DNS_LOCAL`
/// and `SIGNAL_LOCAL`, both below `LOCAL_MASK`.
const LOCAL_MASK: usize = 0x1ff;
const GEN_SHIFT: usize = 9;

/// The owner's shutdown phase. `Serving` is ordinary operation; once the
/// first SIGTERM is observed the owner stops admission, closes pending
/// setups, cancels the retained DNS transport and drains established tunnels
/// under the fixed monotonic [`SHUTDOWN_GRACE`] from that first observation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shutdown {
    Serving,
    Draining { deadline: Instant },
}

/// The typed process exit decision once shutdown settles: a clean drain of
/// every established tunnel exits 0; a deadline-forced closure of remaining
/// sockets is a failure and exits `EX_SOFTWARE` (70) (docs/alumina-proxy.md:220).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ShutdownExit {
    Drained,
    Forced,
}

impl ShutdownExit {
    pub(crate) fn code(self) -> i32 {
        match self {
            ShutdownExit::Drained => 0,
            ShutdownExit::Forced => 70,
        }
    }

    /// The typed drain outcome carried by the single shutdown record, so a
    /// deadline-forced closure is never silently lost to the exit that follows.
    pub(crate) fn status(self) -> crate::log::ShutdownStatus {
        match self {
            ShutdownExit::Drained => crate::log::ShutdownStatus::Drained,
            ShutdownExit::Forced => crate::log::ShutdownStatus::Forced,
        }
    }
}

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

const BODY_200: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const BODY_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n";
const BODY_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n";
const BODY_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n";
const BODY_503: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n";
const BODY_504: &[u8] = b"HTTP/1.1 504 Gateway Timeout\r\ncontent-length: 0\r\n\r\n";

/// A typed refusal to serve a connection: the single source of truth mapping
/// forward to both the fixed HTTP body and the fixed `RejectReason` log
/// vocabulary. The refuse path never reverse-infers a reason from a byte
/// match, so a new refusal class cannot silently default to BadRequest.
#[derive(Clone, Copy)]
enum Refusal {
    BadRequest,
    Forbidden,
    DialFailed,
    SetupTimeout,
}

impl Refusal {
    fn body(self) -> &'static [u8] {
        match self {
            Refusal::BadRequest => BODY_400,
            Refusal::Forbidden => BODY_403,
            Refusal::DialFailed => BODY_502,
            Refusal::SetupTimeout => BODY_504,
        }
    }

    fn reason(self) -> RejectReason {
        match self {
            Refusal::BadRequest => RejectReason::BadRequest,
            Refusal::Forbidden => RejectReason::Forbidden,
            Refusal::DialFailed => RejectReason::DialFailed,
            Refusal::SetupTimeout => RejectReason::SetupTimeout,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ReadOutcome {
    Activity(Activity),
    Wait,
    Retry,
    Failed,
}

fn classify_read(result: io::Result<usize>) -> ReadOutcome {
    match result {
        Ok(0) => ReadOutcome::Activity(Activity::Eof),
        Ok(_) => ReadOutcome::Activity(Activity::Data),
        Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => ReadOutcome::Wait,
        Err(ref err) if err.kind() == io::ErrorKind::Interrupted => ReadOutcome::Retry,
        Err(ref err) if err.kind() == io::ErrorKind::ConnectionReset => {
            ReadOutcome::Activity(Activity::Reset)
        }
        Err(_) => ReadOutcome::Failed,
    }
}

/// The complete-visit I/O budget of one connection: how much read+write work
/// that visit has performed, so every arm of the visit resolves into one
/// shared counter against the canonical 16-op/64 KiB bound
/// (docs/alumina-proxy.md:146; oracle alumina-8d7z A1). `Idle` between
/// dispatches and for non-connection events, so deadline sweeps and direct
/// test calls are never accidentally budgeted against a stale visit. One
/// connection is one visit per poll batch: both of its readiness tokens merge
/// into a single `Live` budget (HIGH-1 dedup), sealed and counted once when a
/// different slot begins its visit or the batch ends.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum VisitState {
    Idle,
    Live { slot: usize, ops: u16, bytes: u32 },
}

impl VisitState {
    const fn idle() -> VisitState {
        VisitState::Idle
    }

    const fn live(slot: usize) -> VisitState {
        VisitState::Live {
            slot,
            ops: 0,
            bytes: 0,
        }
    }

    fn exhausted(self) -> bool {
        match self {
            VisitState::Live { ops, bytes, .. } => ops >= VISIT_OPS || bytes >= VISIT_BYTES,
            VisitState::Idle => false,
        }
    }

    #[cfg(test)]
    fn ops(self) -> u16 {
        match self {
            VisitState::Live { ops, .. } => ops,
            VisitState::Idle => 0,
        }
    }

    /// Records one attempted read/write syscall and the bytes it committed
    /// (0 for WouldBlock/Interrupted/failure, whose attempts still count as
    /// I/O operations). Saturates so the budget can never wrap; the byte
    /// counter is carried as `u32` via a checked cast (io_room already keeps
    /// a single syscall within 64 KiB, so this never clamps in practice).
    fn note(self, attempted: usize) -> VisitState {
        let bytes = u32::try_from(attempted).unwrap_or(u32::MAX);
        match self {
            VisitState::Live {
                slot,
                ops,
                bytes: acc,
            } => VisitState::Live {
                slot,
                ops: ops.saturating_add(1),
                bytes: acc.saturating_add(bytes),
            },
            VisitState::Idle => VisitState::Idle,
        }
    }
}

/// Counter of ready-slot visits and I/O operations since the last timer
/// recheck, so `expire_sweep` can rejoin the turn after at most
/// [`TIMER_RECHECK_EVERY`] units of work (docs/alumina-proxy.md:146), even
/// when dispatch stays hot. The recheck is decided *before* dispatching the
/// visit that would cross the bound (one visit may add `1 + VISIT_OPS`
/// units), so no threshold overshoot lands before the sweep.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct BatchProgress {
    work_since_recheck: u16,
}

impl BatchProgress {
    /// MEDIUM-2 pre-dispatch bound: the next visit would add at most
    /// `1 + VISIT_OPS` units, so the recheck is due the moment those units
    /// would carry cumulative work past [`TIMER_RECHECK_EVERY`]. Checked
    /// *before* dispatching, so the sweep never lands after work has already
    /// crossed 256.
    fn due(&self) -> bool {
        self.work_since_recheck as usize + 1 + VISIT_OPS as usize > TIMER_RECHECK_EVERY
    }

    /// Notes one ready-slot visit plus its I/O operations (saturating, so the
    /// count can never wrap).
    fn accrue(&mut self, ops: u16) {
        self.work_since_recheck = self
            .work_since_recheck
            .saturating_add(1)
            .saturating_add(ops);
    }
}

/// The outcome of one nonblocking write attempt, kept distinct from the visit
/// bookkeeping so the byte-cursor advance, the idle reset, and the op note are
/// each applied exactly once per syscall.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WriteOutcome {
    Wrote(usize),
    Wait,
    Failed,
    None,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ConnectState {
    Connected,
    Pending,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Idle,
    ReadingConnect,
    RunningDecision,
    Dialing,
    SendingConnected,
    ValidatingHello,
    WritingHello,
    Relay,
    Refusing(&'static [u8]),
    Closing,
}

/// Per-direction orderly-EOF state for the relay/drain phase. A source side
/// reaches `Eof` when its orderly FIN is observed; the sink half-close
/// (write) is sent only once that direction's accepted bytes have fully
/// drained, so the typed state can never claim a half-close while the
/// opposite direction still has pending accepted bytes (RF-003).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SideEof {
    Open,
    Eof { half_closed: bool },
}

/// Directional end-of-stream progress in the relay phase: `up` is the
/// client->upstream flow, `down` the upstream->client flow. Encoding the two
/// directions as distinct states makes illegal combinations (e.g. a client
/// FIN treated as whole-slot destruction) unrepresentable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct DirectionalEof {
    up: SideEof,
    down: SideEof,
}

impl DirectionalEof {
    const fn relay() -> DirectionalEof {
        DirectionalEof {
            up: SideEof::Open,
            down: SideEof::Open,
        }
    }
}

#[derive(Clone, Copy)]
struct Readiness {
    readable: bool,
    writable: bool,
    error: bool,
    read_closed: bool,
    write_closed: bool,
}

#[cfg(test)]
impl Readiness {
    const fn none() -> Readiness {
        Readiness {
            readable: false,
            writable: false,
            error: false,
            read_closed: false,
            write_closed: false,
        }
    }
}

/// The per-slot serving workspace: the byte stores come from the boot-owned
/// traffic store (transferred in by value), and the parser, inspector, gate,
/// and cursors live here. Nothing per event is allocated, and every direction's
/// pending bytes are conserved with explicit cursors.
struct SlotWorkspace {
    handle: Option<SlotIndex>,
    tunnel: Option<TunnelIndex>,
    slot_gen: u64,
    /// The batch generation in which this slot last began its single complete
    /// visit (HIGH-1 per-batch dedup): a later token for the same slot in the
    /// same batch merges or re-arms instead of opening a second visit.
    batch_seen: u64,
    client: Option<TcpStream>,
    upstream: Option<TcpStream>,
    parser: ConnectParser,
    inspector: ChInspector,
    gate: TunnelGate,
    approved: Option<FixedHostname>,
    stage: Stage,
    buf: Box<[u8]>,
    buf_base: usize,
    buf_len: usize,
    fwd: usize,
    parse_rel: usize,
    insp_rel: usize,
    head_len: usize,
    hello_end: Option<usize>,
    hello_consumed: usize,
    down: Box<[u8]>,
    down_len: usize,
    down_off: usize,
    directional: DirectionalEof,
    drain_deadline: Option<Instant>,
    idle_deadline: Option<Instant>,
    #[cfg(test)]
    test_reads: std::vec::Vec<io::Result<usize>>,
}

impl SlotWorkspace {
    fn with_traffic(up: Box<[u8]>, down: Box<[u8]>) -> SlotWorkspace {
        SlotWorkspace {
            handle: None,
            tunnel: None,
            slot_gen: 0,
            batch_seen: 0,
            client: None,
            upstream: None,
            parser: ConnectParser::new(),
            inspector: ChInspector::new(),
            gate: TunnelGate::new(),
            approved: None,
            stage: Stage::Idle,
            buf: up,
            buf_base: 0,
            buf_len: 0,
            fwd: 0,
            parse_rel: 0,
            insp_rel: 0,
            head_len: 0,
            hello_end: None,
            hello_consumed: 0,
            down,
            down_len: 0,
            down_off: 0,
            directional: DirectionalEof::relay(),
            drain_deadline: None,
            idle_deadline: None,
            #[cfg(test)]
            test_reads: std::vec::Vec::new(),
        }
    }

    /// Reclaims consumed upstream-forwarded bytes at the front of `buf`,
    /// keeping the absolute stream base in lockstep. Never called before the
    /// relay phase (pre-open `fwd` is 0), so unvalidated head/hello bytes are
    /// never dropped.
    fn compact(&mut self) {
        if self.fwd == 0 {
            return;
        }
        let live = self.buf_len - self.fwd;
        self.buf.copy_within(self.fwd..self.buf_len, 0);
        self.buf_len = live;
        self.buf_base += self.fwd;
        self.fwd = 0;
    }

    fn reset(&mut self) {
        self.parser = ConnectParser::new();
        self.inspector = ChInspector::new();
        self.gate = TunnelGate::new();
        self.approved = None;
        self.stage = Stage::Idle;
        self.buf_len = 0;
        self.buf_base = 0;
        self.fwd = 0;
        self.parse_rel = 0;
        self.insp_rel = 0;
        self.head_len = 0;
        self.hello_end = None;
        self.hello_consumed = 0;
        self.down_len = 0;
        self.down_off = 0;
        self.directional = DirectionalEof::relay();
        self.drain_deadline = None;
        self.idle_deadline = None;
    }
}

#[derive(Debug)]
pub struct ServeError {
    kind: io::ErrorKind,
}

impl From<io::Error> for ServeError {
    fn from(err: io::Error) -> ServeError {
        ServeError { kind: err.kind() }
    }
}

impl From<StartupDnsError> for ServeError {
    fn from(err: StartupDnsError) -> ServeError {
        let kind = match err {
            StartupDnsError::Transport { kind, .. } | StartupDnsError::Exchange { kind, .. } => {
                kind
            }
            _ => io::ErrorKind::Other,
        };
        ServeError { kind }
    }
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "serving error: {}", self.kind)
    }
}

impl std::error::Error for ServeError {}

pub struct Serving {
    poll: Poll,
    storage: ServeStorage,
    listener: Option<TcpListener>,
    slots: Vec<SlotWorkspace>,
    events: Events,
    listener_pause_until: Option<Instant>,
    dns_event: bool,
    visit: VisitState,
    /// Poll-batch generation stamp for per-connection visit dedup: each
    /// connection owns at most one complete visit per batch, and runs outside
    /// `run_once` (direct test/driver dispatches) each open their own batch.
    batch_gen: u64,
    /// True while `run_once` dispatches one poll batch, so connection tokens
    /// for the same slot merge into that batch's single visit instead of
    /// opening fresh budgets.
    in_batch: bool,
    /// Work-since-recheck counter (MEDIUM-2): the timer/DNS recheck rejoins
    /// the turn before the next visit would push the count past 256.
    progress: BatchProgress,
    /// Test-only high-water of `work_since_recheck` observed at a timer/DNS
    /// recheck boundary, so owner-turn fixtures assert the canonical ≤256
    /// bound actually fires between hot visits rather than being inferred.
    #[cfg(test)]
    pub(crate) max_work_since_recheck: u16,
    shutdown: Shutdown,
    signal_rx: Option<UnixStream>,
    _signal_registration: Option<signal_hook::SigId>,
    signal_read_error: Option<io::ErrorKind>,
    #[cfg(test)]
    test_signal_wake: Option<UnixStream>,
    #[cfg(test)]
    pre_settlement: Option<Box<dyn FnOnce()>>,
    #[cfg(test)]
    pre_poll: Option<PrePollHook>,
}

#[cfg(test)]
type PrePollHook = Rc<dyn Fn(&Serving)>;

impl Serving {
    /// Builds the loop's retained serving workspaces over boot-completed
    /// storage and the boot-owned traffic store, moving the retained per-slot
    /// buffer pairs into the fixed slot workspaces without a second traffic
    /// allocation and without registering the startup listener yet.
    ///
    /// This is the storage-init phase: the poll, the 128 slot workspaces
    /// (CONNECT parser, ClientHello inspector, gate, cursors) and the event
    /// buffer all exist here, so main can call it before the startup DNS
    /// window opens ([`Self::attach_listener`] registers the listener that
    /// later opens).
    ///
    /// The SIGTERM lifecycle source is armed here too, before the startup DNS
    /// window: [`signal_hook::low_level::pipe::register`] installs the safe
    /// self-pipe write action and the read end joins the single serving poll,
    /// so a signal can never be lost to a boot step that runs after serving
    /// construction. The `SigId` and read end are retained for the owner's
    /// lifetime and dropped only at (or after) process exit.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the poll cannot be created or the SIGTERM
    /// self-pipe source cannot be set up or registered.
    pub(crate) fn preallocate(
        storage: ServeStorage,
        traffic: crate::inventory::TrafficStorage,
    ) -> Result<Serving, ServeError> {
        let poll = Poll::new()?;
        let slots = traffic
            .into_slots()
            .into_iter()
            .map(|slot| {
                let (up, down) = slot.into_parts();
                SlotWorkspace::with_traffic(up, down)
            })
            .collect();
        let (signal_rx, _signal_registration, _test_wake) = Self::create_signal_source()?;
        let mut serving = Serving {
            poll,
            storage,
            listener: None,
            slots,
            events: Events::with_capacity(EVENT_CAP * 4),
            listener_pause_until: None,
            dns_event: false,
            visit: VisitState::idle(),
            batch_gen: 0,
            in_batch: false,
            progress: BatchProgress::default(),
            #[cfg(test)]
            max_work_since_recheck: 0,
            shutdown: Shutdown::Serving,
            signal_rx: Some(signal_rx),
            _signal_registration: Some(_signal_registration),
            signal_read_error: None,
            #[cfg(test)]
            test_signal_wake: _test_wake,
            #[cfg(test)]
            pre_settlement: None,
            #[cfg(test)]
            pre_poll: None,
        };
        serving.register_signal_source()?;
        Ok(serving)
    }

    /// Creates the retained SIGTERM self-pipe: a connected socket pair whose
    /// write end is registered with the safe signal-hook action and whose read
    /// end is returned for registration on the single serving poll. The write
    /// action and the read end are both retained until process exit. A test
    /// build additionally retains a clone of the write end ([`Self`]'s
    /// `test_signal_wake`) so an alloc-witness can drive the exact pipe event
    /// the signal handler would write, without delivering a process-wide
    /// SIGTERM to parallel-running host tests (the native E2E gates exercise
    /// real OS signal delivery against the binary).
    ///
    /// # Errors
    ///
    /// Returns a serve error when the socket pair cannot be created, made
    /// nonblocking, or the signal action cannot be registered.
    fn create_signal_source()
    -> Result<(UnixStream, signal_hook::SigId, Option<UnixStream>), ServeError> {
        let (rx, tx) = UnixStream::pair()?;
        rx.set_nonblocking(true)?;
        #[cfg(test)]
        let test_wake = tx.try_clone().ok();
        let sigid = signal_hook::low_level::pipe::register(SIGTERM, tx)?;
        Ok((rx, sigid, {
            #[cfg(test)]
            {
                test_wake
            }
            #[cfg(not(test))]
            {
                None
            }
        }))
    }

    /// Registers the retained SIGTERM read end on the single serving poll so
    /// the idle wait wakes on a signal, mirroring the DNS readiness source.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the external fd registration fails.
    fn register_signal_source(&mut self) -> Result<(), ServeError> {
        let Some(rx) = self.signal_rx.as_ref() else {
            return Ok(());
        };
        let fd = rx.as_raw_fd();
        let mut source = mio::unix::SourceFd(&fd);
        self.poll
            .registry()
            .register(&mut source, Self::signal_token(), Interest::READABLE)?;
        Ok(())
    }

    /// Registers the startup-bound listener on the serving poll, completing
    /// the loop after the startup window opened it for a serving decision.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the listener registration fails.
    pub(crate) fn attach_listener(&mut self, listener: TcpListener) -> Result<(), ServeError> {
        let mut listener = listener;
        self.poll
            .registry()
            .register(&mut listener, LISTENER, Interest::READABLE)?;
        self.listener = Some(listener);
        Ok(())
    }

    /// Builds the loop over an already-bound listener, boot-completed storage,
    /// and the boot-owned traffic store: preallocates the retained serving
    /// workspaces, then registers the listener. Host/test convenience over the
    /// two-phase [`Self::preallocate`] + [`Self::attach_listener`] owner seam.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the poll registry or listener registration
    /// fails.
    pub fn new(
        storage: ServeStorage,
        listener: TcpListener,
        traffic: crate::inventory::TrafficStorage,
    ) -> Result<Serving, ServeError> {
        let mut serving = Self::preallocate(storage, traffic)?;
        serving.attach_listener(listener)?;
        Ok(serving)
    }

    /// The retained storage, for host tests inspecting slot occupancy.
    pub fn storage(&self) -> &ServeStorage {
        &self.storage
    }

    /// The retained storage, mutable so the owner drives shared DNS turns.
    pub(crate) fn storage_mut(&mut self) -> &mut ServeStorage {
        &mut self.storage
    }

    /// The single poll registry, exposed so the retained DNS transport is
    /// attached to the same readiness wait as the listener and connections.
    pub fn registry(&self) -> &Registry {
        self.poll.registry()
    }

    /// The fixed token the retained DNS source is attached under on this
    /// registry.
    pub const fn dns_token() -> Token {
        Token(DNS_LOCAL)
    }

    /// The fixed token the retained SIGTERM self-pipe read end is attached
    /// under on this registry.
    pub const fn signal_token() -> Token {
        Token(SIGNAL_LOCAL)
    }

    /// The owner's shutdown phase, for host tests inspecting lifecycle state.
    pub fn shutdown(&self) -> Shutdown {
        self.shutdown
    }

    /// Whether the owner has entered shutdown: admission is stopped, pending
    /// setups are closed and established tunnels drain under the fixed grace.
    pub(crate) fn is_shutdown(&self) -> bool {
        matches!(self.shutdown, Shutdown::Draining { .. })
    }

    /// Whether a DNS freshness event was observed since the last query, so the
    /// shared owner decides when to advance the cooperative exchange.
    pub fn take_dns_event(&mut self) -> bool {
        let seen = self.dns_event;
        self.dns_event = false;
        seen
    }

    /// Attaches the retained DNS transport to this poll's registry so DNS
    /// freshness joins traffic readiness under the single wait. No-op at
    /// construction (no transport open yet); the owner re-attaches after a
    /// refresh opens a fresh transport.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the external registration fails.
    pub(crate) fn attach_dns_shared(&mut self) -> Result<(), ServeError> {
        let registry = self.poll.registry();
        self.storage
            .dns_mut()
            .attach_shared(registry, Self::dns_token())
            .map_err(ServeError::from)
    }

    /// Re-aligns the shared DNS registration to the current exchange phase
    /// after cooperative turns moved it. No-op while idle or unattached.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the external re-registration fails.
    pub(crate) fn sync_dns_shared(&mut self) -> Result<(), ServeError> {
        let registry = self.poll.registry();
        self.storage
            .dns_mut()
            .sync_shared(registry)
            .map_err(ServeError::from)
    }

    /// Runs one poll iteration, dispatching every ready event and enforcing
    /// the earliest pending deadline (setup, relay idle, or FIN drain).
    ///
    /// # Errors
    ///
    /// Returns a serve error when the poll call itself or a listener re-arm
    /// after a paused accept fails.
    pub fn run_once(&mut self, timeout: Option<Duration>) -> Result<(), ServeError> {
        self.resume_listener(Instant::now())?;
        let mut batch = std::mem::replace(&mut self.events, Events::with_capacity(0));
        loop {
            let effective = match (self.poll_timeout(), timeout) {
                (Some(d), Some(t)) => Some(d.min(t)),
                (Some(d), None) => Some(d),
                (None, t) => t,
            };
            match self.poll.poll(&mut batch, effective) {
                Ok(()) => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err.into()),
            }
        }
        let now = Instant::now();
        if batch
            .iter()
            .any(|event| event.token().0 & LOCAL_MASK == SIGNAL_LOCAL)
        {
            self.on_sigterm()?;
        }
        self.expire_sweep(now);
        self.batch_gen = self.batch_gen.wrapping_add(1);
        self.in_batch = true;
        for event in batch.iter() {
            if event.token().0 & LOCAL_MASK == SIGNAL_LOCAL {
                continue;
            }

            if self.recheck_due() {
                self.recheck_now();
            }
            self.dispatch(event)?;
        }
        if let VisitState::Live { ops, .. } = self.visit {
            self.note_visit(ops);
        }
        self.visit = VisitState::idle();
        self.in_batch = false;
        self.events = batch;
        Ok(())
    }

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

    /// Re-arms an accept-paused listener once its backoff has elapsed, so a
    /// transient accept failure is retried on a bounded cadence, never an
    /// immediate readiness hot loop.
    fn resume_listener(&mut self, now: Instant) -> Result<(), ServeError> {
        if let Some(pause) = self.listener_pause_until
            && now >= pause
        {
            self.listener_pause_until = None;
            self.reregister_listener()?;
        }
        Ok(())
    }

    fn dispatch(&mut self, event: &Event) -> Result<(), ServeError> {
        self.dispatch_readiness(
            event.token(),
            Readiness {
                readable: event.is_readable(),
                writable: event.is_writable(),
                error: event.is_error(),
                read_closed: event.is_read_closed(),
                write_closed: event.is_write_closed(),
            },
        )
    }

    fn dispatch_readiness(&mut self, token: Token, ready: Readiness) -> Result<(), ServeError> {
        if !self.in_batch {
            self.batch_gen = self.batch_gen.wrapping_add(1);
        }
        let raw = token.0;
        let local = raw & LOCAL_MASK;
        if raw == 0 {
            return self.accept_all();
        }
        if local == DNS_LOCAL {
            self.dns_event = true;
            return Ok(());
        }
        if local == SIGNAL_LOCAL {
            return self.on_sigterm();
        }
        let event_gen = (raw >> GEN_SHIFT) as u64;
        let upstream = local >= UPSTREAM_BASE;
        let index = if upstream {
            local - UPSTREAM_BASE
        } else {
            local - 1
        };
        if index >= self.slots.len() {
            return Ok(());
        }
        if event_gen != self.slots[index].slot_gen {
            return Ok(());
        }
        if ready.error {
            let connecting_dial = upstream && self.slots[index].stage == Stage::Dialing;
            if connecting_dial {
                match self.upstream_connectedness(index) {
                    ConnectState::Pending => return Ok(()),
                    ConnectState::Failed => {
                        self.refuse(index, Refusal::DialFailed);
                        return Ok(());
                    }
                    ConnectState::Connected => return self.upstream_writable(index),
                }
            }
            self.close_slot(index);
            return Ok(());
        }

        let first = self.slots[index].batch_seen != self.batch_gen;
        self.slots[index].batch_seen = self.batch_gen;
        if first {
            if let VisitState::Live { ops, .. } = self.visit {
                self.note_visit(ops);
            }
            self.visit = VisitState::live(index);
        } else {
            let live_here = matches!(
                self.visit,
                VisitState::Live { slot, .. } if slot == index
            );
            if !live_here || self.visit.exhausted() {
                self.reschedule(index);
                return Ok(());
            }
        }
        if upstream {
            if ready.readable || ready.read_closed || ready.write_closed {
                self.upstream_readable(index)?;
            }
            if ready.writable {
                self.upstream_writable(index)?;
            }
        } else {
            if ready.readable || ready.read_closed {
                self.client_readable(index)?;
            }
            if ready.writable {
                self.client_writable(index)?;
            }
        }
        Ok(())
    }

    /// Processes one SIGTERM observation: drains the retained self-pipe
    /// (bounded nonblocking reads), and on the first observation permanently
    /// stops admission, closes pending setups, cancels the retained DNS
    /// transport and fixes the monotonic shutdown deadline; every later
    /// observation only re-wakes the poll and never moves the deadline.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the listener deregistration fails.
    pub(crate) fn on_sigterm(&mut self) -> Result<(), ServeError> {
        self.drain_signal_pipe();
        if !matches!(self.shutdown, Shutdown::Serving) {
            return Ok(());
        }
        let now = Instant::now();
        self.shutdown = Shutdown::Draining {
            deadline: now + SHUTDOWN_GRACE,
        };
        self.stop_admission()?;
        self.close_pending_setups();
        self.cancel_dns_transport();
        Ok(())
    }

    /// Test-only writable handle to the SIGTERM self-pipe: writing one byte
    /// produces the identical readable edge on `signal_rx` that a real SIGTERM
    /// handler write would, so host tests drive the actual signal-observation
    /// path without a process-wide raise.
    #[cfg(test)]
    pub(crate) fn signal_wake_mut(&mut self) -> Option<&mut UnixStream> {
        self.test_signal_wake.as_mut()
    }

    /// Test-only synchronisation point inside the shared startup window: arms
    /// a one-shot closure that fires exactly before the post-all-resolved
    /// zero-wait settlement recheck ([`Self::run_startup_window`]), so a test
    /// can deterministically deliver a SIGTERM byte to the self-pipe after the
    /// window has resolved every name but before the settlement turn decides
    /// Serve-vs-Terminated. Not a public control interface: `#[cfg(test)]`
    /// only, never set in a production build.
    #[cfg(test)]
    pub(crate) fn arm_pre_settlement_hook(&mut self, f: Box<dyn FnOnce()>) {
        self.pre_settlement = Some(f);
    }

    #[cfg(test)]
    pub(crate) fn arm_pre_poll_hook(&mut self, f: PrePollHook) {
        self.pre_poll = Some(f);
    }

    #[cfg(test)]
    pub(crate) fn test_dns_fd_readable(&self) -> bool {
        self.storage.dns().test_fd_readable()
    }

    #[cfg(test)]
    pub(crate) fn test_active_ordinal(&self) -> Option<usize> {
        self.storage.dns().active_ordinal()
    }

    #[cfg(test)]
    pub(crate) fn test_active_receiving(&self) -> bool {
        self.storage.dns().test_active_receiving()
    }

    /// Bounded nonblocking drain of the SIGTERM self-pipe: at most 64 bytes
    /// per observation, so a signal storm can never monopolize the shared poll
    /// turn while kernel coalescing keeps every drained byte at least one
    /// SIGTERM. A would-block or interrupted read is the benign empty/retry
    /// case; a real read error (e.g. `EBADF`) is *named* on [`Self`]
    /// ([`Self::signal_read_error`]) instead of being swallowed, so a broken
    /// self-pipe is visible rather than misread as "no signal pending".
    fn drain_signal_pipe(&mut self) {
        const DRAIN_CAP: usize = 64;
        let Some(rx) = self.signal_rx.as_mut() else {
            return;
        };
        let mut buf = [0u8; 16];
        let mut remaining = DRAIN_CAP;
        while remaining > 0 {
            let len = remaining.min(buf.len());
            match rx.read(&mut buf[..len]) {
                Ok(n) if n > 0 => remaining = remaining.saturating_sub(n),
                Ok(_) => break,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(e) => {
                    self.signal_read_error = Some(e.kind());
                    break;
                }
            }
        }
    }

    /// The first real (non-benign) error observed draining the SIGTERM
    /// self-pipe, for host tests proving the drain names read errors exactly.
    #[cfg(test)]
    fn signal_read_error(&self) -> Option<io::ErrorKind> {
        self.signal_read_error
    }

    /// Permanently stops admission: the listener socket is deregistered and
    /// dropped (owned sockets close once), so no new connection can be
    /// accepted for the rest of the process lifetime.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the listener deregistration fails.
    fn stop_admission(&mut self) -> Result<(), ServeError> {
        if let Some(mut listener) = self.listener.take() {
            match self.poll.registry().deregister(&mut listener) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    /// Closes every non-established slot at the first SIGTERM: pending setups
    /// (pre-Relay stages) have their sockets closed exactly once, established
    /// relay tunnels keep draining under unchanged deadlines, idle slots stay
    /// idle (nothing to release), and a slot already Closing is left to its
    /// own teardown rather than double-closed.
    fn close_pending_setups(&mut self) {
        for index in 0..self.slots.len() {
            match self.slots[index].stage {
                Stage::Idle | Stage::Relay | Stage::Closing => {}
                Stage::ReadingConnect
                | Stage::RunningDecision
                | Stage::Dialing
                | Stage::SendingConnected
                | Stage::ValidatingHello
                | Stage::WritingHello
                | Stage::Refusing(_) => self.close_slot(index),
            }
        }
    }

    /// Cancels the retained DNS transport: the active exchange and the open
    /// connection are cleared so no DNS deadline or refresh admission outlives
    /// the first SIGTERM, while the retained transport heap stays owned until
    /// process exit.
    fn cancel_dns_transport(&mut self) {
        self.storage.dns_mut().cancel_for_shutdown();
    }

    /// The typed exit decision while draining: a clean drain with no occupied
    /// slot exits 0 immediately; once the fixed shutdown deadline passes the
    /// remaining sockets are closed exactly once and the drain is declared a
    /// forced failure (exit 70).
    pub(crate) fn shutdown_exit(&mut self) -> Option<ShutdownExit> {
        let phase = self.shutdown;
        match phase {
            Shutdown::Serving => None,
            Shutdown::Draining { deadline } => {
                if Instant::now() >= deadline {
                    self.force_close_remaining_sockets();
                    Some(ShutdownExit::Forced)
                } else if self.storage.occupied() == 0 {
                    Some(ShutdownExit::Drained)
                } else {
                    None
                }
            }
        }
    }

    /// Closes every remaining owned socket in one sweep at the forced
    /// deadline: no established tunnel may outlive the shutdown grace.
    fn force_close_remaining_sockets(&mut self) {
        for index in 0..self.slots.len() {
            if self.slots[index].stage != Stage::Idle {
                self.close_slot(index);
            }
        }
    }

    /// Test-only seam: rewrites an already-draining shutdown deadline so the
    /// forced-closure decision can be exercised without waiting the grace.
    #[cfg(test)]
    pub(crate) fn set_shutdown_deadline(&mut self, deadline: Instant) {
        if let Shutdown::Draining { deadline: stored } = &mut self.shutdown {
            *stored = deadline;
        }
    }

    /// Test-only seam: installs an established open-gate relay in `index` over
    /// real ready sockets, so runtime-level owner-turn composition fixtures
    /// can drive actual relay work through [`crate::runtime::Runtime::turn`]
    /// without reaching through this module's private slot fields. Mirrors the
    /// `open_relay` test helper for callers outside the serving tests module.
    #[cfg(all(test, feature = "alloc-witness"))]
    pub(crate) fn test_setup_relay(
        &mut self,
        index: usize,
        up: TcpStream,
        client: TcpStream,
    ) -> Result<(), ServeError> {
        {
            let ws = &mut self.slots[index];
            ws.upstream = Some(up);
            ws.client = Some(client);
            ws.stage = Stage::Relay;
            ws.head_len = 4;
            ws.buf_base = 0;
            ws.gate.on_connect_head(4);
            ws.gate.on_authorized();
            ws.gate.on_upstream_connected();
            ws.gate.on_response_ok();
            ws.gate.on_hello_validated(ValidatedHello::test_new(10));
            ws.gate.upstream_write(6);
        }
        self.register_upstream(index)?;
        self.register_client(index)
    }

    /// Test-only way for owner-turn fixtures to arm an expired idle deadline
    /// on `index` without reaching through this module's private slot fields.
    #[cfg(all(test, feature = "alloc-witness"))]
    pub(crate) fn test_mark_idle_expired(&mut self, index: usize) {
        self.slots[index].idle_deadline = Some(Instant::now() - Duration::from_millis(1));
    }

    /// Test-only visibility into whether a seeded slot was swept closed.
    #[cfg(all(test, feature = "alloc-witness"))]
    pub(crate) fn test_slot_closed(&self, index: usize) -> bool {
        self.slots[index].client.is_none()
    }

    fn accept_all(&mut self) -> Result<(), ServeError> {
        loop {
            if self.recheck_due() {
                self.reregister_listener()?;
                return Ok(());
            }
            let Some(listener) = &self.listener else {
                return Ok(());
            };
            match listener.accept() {
                Ok((stream, _addr)) => {
                    self.progress.accrue(1);
                    self.admit(stream)?;
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.progress.accrue(1);
                    return Ok(());
                }
                Err(_) => {
                    self.progress.accrue(1);
                    self.listener_pause_until = Some(Instant::now() + ACCEPT_BACKOFF);
                    return Ok(());
                }
            }
        }
    }

    fn admit(&mut self, stream: TcpStream) -> Result<(), ServeError> {
        let now = Instant::now();
        match self.storage.accept(now) {
            Err(_) => {
                let client = stream.peer_addr().ok();
                let secs = self.storage.cache_secs(now);
                let mut s = stream;
                write_all_bounded(&mut s, BODY_503);
                self.storage
                    .logs_mut()
                    .reject(secs, RejectReason::Capacity, client, None);
                self.note_occupancy(now);
                Ok(())
            }
            Ok(slot) => {
                let index = self.storage.slot_index(&slot);
                let ws = &mut self.slots[index];
                ws.slot_gen = ws.slot_gen.wrapping_add(1);
                ws.handle = Some(slot);
                ws.client = Some(stream);
                ws.stage = Stage::ReadingConnect;
                if self.register_client(index).is_err() {
                    self.close_slot(index);
                }
                self.note_occupancy(now);
                Ok(())
            }
        }
    }

    /// Evaluates the slot/setup capacity thresholds after an occupancy
    /// transition at `now`.
    fn note_occupancy(&mut self, now: Instant) {
        let secs = self.storage.cache_secs(now);
        let occupied = self.storage.occupied();
        let pending = self.storage.pending();
        self.storage
            .logs_mut()
            .note_capacity(secs, occupied, pending);
    }

    fn register_client(&mut self, index: usize) -> Result<(), ServeError> {
        let token = client_token(self.slots[index].slot_gen, index);
        match self.slots[index].client.as_mut() {
            Some(client) => self
                .poll
                .registry()
                .register(client, token, Interest::READABLE | Interest::WRITABLE)
                .map(|_| ())
                .map_err(Into::into),
            None => Ok(()),
        }
    }

    fn register_upstream(&mut self, index: usize) -> Result<(), ServeError> {
        let token = upstream_token(self.slots[index].slot_gen, index);
        match self.slots[index].upstream.as_mut() {
            Some(up) => self
                .poll
                .registry()
                .register(up, token, Interest::READABLE | Interest::WRITABLE)
                .map(|_| ())
                .map_err(Into::into),
            None => Ok(()),
        }
    }

    fn reregister_listener(&mut self) -> Result<(), ServeError> {
        if let Some(listener) = self.listener.as_mut() {
            self.poll
                .registry()
                .reregister(listener, LISTENER, Interest::READABLE)?;
        }
        Ok(())
    }

    fn reregister_client(&mut self, index: usize) -> Result<(), ServeError> {
        let token = client_token(self.slots[index].slot_gen, index);
        match self.slots[index].client.as_mut() {
            Some(client) => self
                .poll
                .registry()
                .reregister(client, token, Interest::READABLE | Interest::WRITABLE)
                .map(|_| ())
                .map_err(Into::into),
            None => Ok(()),
        }
    }

    fn reregister_upstream(&mut self, index: usize) -> Result<(), ServeError> {
        let token = upstream_token(self.slots[index].slot_gen, index);
        match self.slots[index].upstream.as_mut() {
            Some(up) => self
                .poll
                .registry()
                .reregister(up, token, Interest::READABLE | Interest::WRITABLE)
                .map(|_| ())
                .map_err(Into::into),
            None => Ok(()),
        }
    }

    fn buf_room(&mut self, index: usize) -> usize {
        let ws = &mut self.slots[index];
        if ws.fwd > 0 && HOLD_CAP - ws.buf_len < CHUNK {
            ws.compact();
        }
        HOLD_CAP - ws.buf_len
    }

    /// Whether `index`'s visit is live and has consumed its complete budget.
    fn visit_exhausted(&self, index: usize) -> bool {
        matches!(
            self.visit,
            VisitState::Live { slot, .. } if slot == index && self.visit.exhausted()
        )
    }

    /// Records one attempted read/write syscall on `index` into its visit, if
    /// that visit is live. Deadline sweeps and non-connection dispatches (no
    /// live visit) are unbudgeted.
    fn note_op(&mut self, index: usize, bytes: usize) {
        if matches!(
            self.visit,
            VisitState::Live { slot, .. } if slot == index
        ) {
            self.visit = self.visit.note(bytes);
        }
    }

    /// The byte room left in `index`'s live visit; `default` when the visit is
    /// not live, so a single read/write slice can never push a live visit past
    /// the canonical 64 KiB bound.
    fn io_room(&self, index: usize, default: usize) -> usize {
        if let VisitState::Live { slot, bytes, .. } = self.visit
            && slot == index
        {
            (VISIT_BYTES as usize)
                .saturating_sub(bytes as usize)
                .min(default)
        } else {
            default
        }
    }

    /// MEDIUM-2 pre-dispatch bound: the timer/DNS recheck must rejoin the turn
    /// before the next visit would push cumulative work past the canonical
    /// [`TIMER_RECHECK_EVERY`] units, where one visit adds at most
    /// `1 + VISIT_OPS` units. Checked *before* dispatching, so the sweep never
    /// lands after work has already crossed 256.
    fn recheck_due(&self) -> bool {
        self.progress.due()
    }

    /// Runs the deadline sweep and resets the work-since-recheck counter.
    fn recheck_now(&mut self) {
        #[cfg(test)]
        {
            self.max_work_since_recheck = self
                .max_work_since_recheck
                .max(self.progress.work_since_recheck);
        }
        self.expire_sweep(Instant::now());
        self.progress.work_since_recheck = 0;
    }

    /// Counts one ready-slot visit plus its I/O operations into the running
    /// work-since-recheck total (MEDIUM-2). Called on the seal of a visit —
    /// when a different slot opens its own, or at end of batch — so each slot
    /// counts exactly once per poll batch.
    fn note_visit(&mut self, ops: u16) {
        self.progress.accrue(ops);
    }

    /// Re-arms poll interest on a budget-exhausted or re-queued slot so its
    /// unfinished work reschedules without waiting for a fresh readiness edge
    /// (docs/alumina-proxy.md:146). A re-registration failure leaves the slot
    /// without interest and is unclosable-only-once: the client re-arm runs
    /// first and, on error, closes and returns; only then is the upstream arm
    /// attempted, so a first-arm failure never double-closes via the second.
    fn reschedule(&mut self, index: usize) {
        if self.reregister_client(index).is_err() {
            self.close_slot(index);
            return;
        }
        if self.reregister_upstream(index).is_err() {
            self.close_slot(index);
        }
    }

    fn client_readable(&mut self, index: usize) -> Result<(), ServeError> {
        loop {
            if self.visit_exhausted(index) {
                self.reschedule(index);
                return Ok(());
            }
            let stage = self.slots[index].stage;
            if !matches!(
                stage,
                Stage::ReadingConnect | Stage::ValidatingHello | Stage::Relay
            ) {
                return Ok(());
            }
            if stage == Stage::Relay
                && matches!(self.slots[index].directional.up, SideEof::Eof { .. })
            {
                return Ok(());
            }
            if self.buf_room(index) < CHUNK {
                match self.slots[index].stage {
                    Stage::ReadingConnect => self.refuse(index, Refusal::BadRequest),
                    Stage::ValidatingHello => self.reject_hello(index)?,
                    _ => {}
                }
                return Ok(());
            }
            if stage == Stage::Relay && self.slots[index].fwd < self.slots[index].buf_len {
                self.flush_client_upstream(index)?;
                if self.slots[index].fwd < self.slots[index].buf_len {
                    return Ok(());
                }
                if self.visit_exhausted(index) {
                    self.reschedule(index);
                    return Ok(());
                }
            }
            let room = self.io_room(index, CHUNK);
            let n = {
                let ws = &mut self.slots[index];
                let len = ws.buf_len;
                match ws.client.as_mut() {
                    None => return Ok(()),
                    Some(client) => client.read(&mut ws.buf[len..len + room]),
                }
            };
            let n = match n {
                Ok(0) => {
                    self.note_op(index, 0);
                    if self.slots[index].stage == Stage::Relay {
                        return self.observe_up_eof(index);
                    }
                    self.close_slot(index);
                    return Ok(());
                }
                Ok(n) => n,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.note_op(index, 0);
                    return Ok(());
                }
                Err(_) => {
                    self.note_op(index, 0);
                    self.close_slot(index);
                    return Ok(());
                }
            };
            self.note_op(index, n);
            match self.slots[index].stage {
                Stage::ReadingConnect => self.buffer_and_parse(index, n)?,
                Stage::ValidatingHello => self.buffer_and_validate(index, n)?,
                Stage::Relay => {
                    self.commit_retained(index, n);
                    self.flush_client_upstream(index)?;
                }
                _ => return Ok(()),
            }
            if self.visit_exhausted(index) {
                self.reschedule(index);
                return Ok(());
            }
            if !matches!(
                self.slots[index].stage,
                Stage::ReadingConnect | Stage::ValidatingHello | Stage::Relay
            ) {
                return Ok(());
            }
            if self.slots[index].stage == Stage::Relay
                && self.slots[index].fwd < self.slots[index].buf_len
            {
                return Ok(());
            }
        }
    }

    fn commit_retained(&mut self, index: usize, added: usize) {
        let ws = &mut self.slots[index];
        debug_assert!(ws.buf_len + added <= HOLD_CAP);
        ws.buf_len += added;
    }

    #[cfg(test)]
    fn append_client_bytes(&mut self, index: usize, bytes: &[u8]) {
        let ws = &mut self.slots[index];
        if ws.buf_len + bytes.len() > HOLD_CAP {
            ws.compact();
            debug_assert!(ws.buf_len + bytes.len() <= HOLD_CAP);
        }
        ws.buf[ws.buf_len..ws.buf_len + bytes.len()].copy_from_slice(bytes);
        ws.buf_len += bytes.len();
    }

    fn buffer_and_parse(&mut self, index: usize, added: usize) -> Result<(), ServeError> {
        self.commit_retained(index, added);
        let head = {
            let ws = &mut self.slots[index];
            let start = ws.parse_rel;
            let end = ws.buf_len;
            if end > start {
                let res = ws.parser.feed(&ws.buf[start..end]);
                ws.parse_rel = end;
                res
            } else {
                Ok(Feed::Incomplete)
            }
        };
        match head {
            Ok(Feed::Complete { head_len }) => {
                let slot = &mut self.slots[index];
                slot.head_len = head_len;
                slot.insp_rel = head_len;
                slot.hello_end = None;
                slot.hello_consumed = 0;
                slot.gate.on_connect_head(head_len);
                slot.stage = Stage::RunningDecision;
                self.run_decision(index)
            }
            Ok(Feed::Incomplete) => Ok(()),
            Err(_) => {
                self.refuse(index, Refusal::BadRequest);
                Ok(())
            }
        }
    }

    fn run_decision(&mut self, index: usize) -> Result<(), ServeError> {
        let Some(slot) = self.slots[index].handle.as_ref() else {
            return Ok(());
        };
        let Some(request) = self.slots[index]
            .parser
            .result()
            .copied()
            .and_then(Result::ok)
        else {
            self.refuse(index, Refusal::BadRequest);
            return Ok(());
        };
        let now = Instant::now();
        let phase = self
            .storage
            .decide(slot, &request, now, AttemptCounts::new(), None);
        match phase {
            Err(_) => {
                self.refuse(index, Refusal::DialFailed);
                Ok(())
            }
            Ok(ConnectPhase::Forbidden) => {
                self.refuse(index, Refusal::Forbidden);
                Ok(())
            }
            Ok(ConnectPhase::NoBinding) | Ok(ConnectPhase::CandidatesExhausted) => {
                self.refuse(index, Refusal::DialFailed);
                Ok(())
            }
            Ok(ConnectPhase::DeadlineExhausted) => {
                self.refuse(index, Refusal::SetupTimeout);
                Ok(())
            }
            Ok(ConnectPhase::Peer { addr, .. }) => {
                let slot = &mut self.slots[index];
                slot.approved = Some(*request.fixed_hostname());
                slot.gate.on_authorized();
                slot.stage = Stage::Dialing;
                self.dial(index, addr)
            }
        }
    }

    fn dial(&mut self, index: usize, addr: NumericAddr) -> Result<(), ServeError> {
        let ip = match addr {
            NumericAddr::V4(a) => IpAddr::V4(a),
            NumericAddr::V6(a) => IpAddr::V6(a),
        };
        let sock = SocketAddr::new(ip, crate::connect::DEST_PORT);
        match TcpStream::connect(sock) {
            Ok(stream) => {
                self.slots[index].upstream = Some(stream);
                if self.register_upstream(index).is_err() {
                    self.close_slot(index);
                }
                Ok(())
            }
            Err(_) => {
                self.refuse(index, Refusal::DialFailed);
                Ok(())
            }
        }
    }

    fn upstream_writable(&mut self, index: usize) -> Result<(), ServeError> {
        match self.slots[index].stage {
            Stage::Dialing => match self.upstream_connectedness(index) {
                ConnectState::Pending => Ok(()),
                ConnectState::Failed => {
                    self.refuse(index, Refusal::DialFailed);
                    Ok(())
                }
                ConnectState::Connected => {
                    self.slots[index].gate.on_upstream_connected();
                    let ws = &mut self.slots[index];
                    ws.down_off = 0;
                    ws.down[..BODY_200.len()].copy_from_slice(BODY_200);
                    ws.down_len = BODY_200.len();
                    ws.stage = Stage::SendingConnected;
                    self.flush_down(index);
                    let sent = {
                        let ws = &self.slots[index];
                        ws.stage == Stage::SendingConnected && ws.down_len == 0
                    };
                    if sent {
                        let ws = &mut self.slots[index];
                        ws.gate.on_response_ok();
                        ws.stage = Stage::ValidatingHello;
                        return self.enter_validating_hello(index);
                    }
                    Ok(())
                }
            },
            Stage::WritingHello => self.flush_client_upstream(index),
            Stage::Relay => {
                self.flush_client_upstream(index)?;
                self.finish_drain(index);
                self.maybe_close_drained(index);
                if self.slots[index].stage == Stage::Relay
                    && self.slots[index].fwd >= self.slots[index].buf_len
                {
                    return self.client_readable(index);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn upstream_readable(&mut self, index: usize) -> Result<(), ServeError> {
        if self.slots[index].gate.is_open() {
            return self.relay_upstream_to_client(index);
        }
        match self.slots[index].stage {
            Stage::Dialing => match self.upstream_connectedness(index) {
                ConnectState::Pending => Ok(()),
                ConnectState::Failed => {
                    self.refuse(index, Refusal::DialFailed);
                    Ok(())
                }
                ConnectState::Connected => self.observe_upstream_read(index),
            },
            _ => self.observe_upstream_read(index),
        }
    }

    fn upstream_connectedness(&self, index: usize) -> ConnectState {
        match self.slots[index].upstream.as_ref() {
            None => ConnectState::Failed,
            Some(up) => match up.take_error() {
                Ok(None) => match up.peer_addr() {
                    Ok(_) => ConnectState::Connected,
                    Err(ref err) if err.kind() == io::ErrorKind::NotConnected => {
                        ConnectState::Pending
                    }
                    Err(_) => ConnectState::Failed,
                },
                Ok(Some(_)) | Err(_) => ConnectState::Failed,
            },
        }
    }

    fn observe_upstream_read(&mut self, index: usize) -> Result<(), ServeError> {
        let mut scratch = [0u8; CHUNK];
        loop {
            if self.visit_exhausted(index) {
                self.reschedule(index);
                return Ok(());
            }
            let outcome = classify_read(self.read_upstream(index, &mut scratch));
            self.note_op(index, 0);
            match outcome {
                ReadOutcome::Activity(activity) => {
                    let ws = &mut self.slots[index];
                    ws.gate.observe_upstream_activity(activity);
                    let activity_kind = match activity {
                        Activity::Data => ActivityKind::Data,
                        Activity::Eof => ActivityKind::Eof,
                        Activity::Reset => ActivityKind::Reset,
                    };
                    let approved = ws.approved;
                    let peer = ws.upstream.as_ref().and_then(|u| u.peer_addr().ok());
                    let secs = self.storage.cache_secs(Instant::now());
                    let hostname = approved.as_ref().map(|h| h.as_str());
                    self.storage
                        .logs_mut()
                        .early_activity(secs, hostname, peer, activity_kind);
                    self.close_slot(index);
                    return Ok(());
                }
                ReadOutcome::Failed => {
                    if self.slots[index].stage == Stage::Dialing {
                        self.refuse(index, Refusal::DialFailed);
                        return Ok(());
                    }
                    self.close_slot(index);
                    return Ok(());
                }
                ReadOutcome::Wait => return Ok(()),
                ReadOutcome::Retry => {}
            }
        }
    }

    fn read_upstream(&mut self, index: usize, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(test)]
        if !self.slots[index].test_reads.is_empty() {
            return self.slots[index].test_reads.pop().expect("read injected");
        }
        match self.slots[index].upstream.as_mut() {
            Some(up) => up.read(buf),
            None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn buffer_and_validate(&mut self, index: usize, added: usize) -> Result<(), ServeError> {
        if added > 0 {
            self.commit_retained(index, added);
        }
        let inspection = {
            let ws = &mut self.slots[index];
            let start = ws.insp_rel;
            let end = ws.buf_len;
            if end > start {
                let res = ws.inspector.feed(&ws.buf[start..end]);
                ws.insp_rel = end;
                res
            } else {
                Ok(Inspect::NeedMore)
            }
        };
        match inspection {
            Err(_) => self.reject_hello(index),
            Ok(Inspect::NeedMore) => Ok(()),
            Ok(Inspect::Complete { consumed }) => {
                self.slots[index].hello_consumed = consumed;
                self.hello_complete(index)
            }
        }
    }

    fn hello_complete(&mut self, index: usize) -> Result<(), ServeError> {
        let approved = match self.slots[index].approved {
            Some(approved) => approved,
            None => return self.reject_hello(index),
        };
        let verdict = self.slots[index]
            .inspector
            .hello()
            .map(|hello| client_hello::validate(hello, &approved));
        let accepted = match verdict {
            Some(Ok(accepted)) => accepted,
            _ => return self.reject_hello(index),
        };
        let ws = &mut self.slots[index];
        let end = ws.head_len + ws.hello_consumed;
        ws.hello_end = Some(end);
        ws.gate
            .on_hello_validated(ValidatedHello::new(accepted, end));
        ws.stage = Stage::WritingHello;
        ws.fwd = ws.head_len - ws.buf_base;
        self.flush_client_upstream(index)
    }

    /// Entry into the hello-inspection stage: inspect already-buffered bytes
    /// first (a same-segment pipelined hello), then drain whatever the client
    /// already sent while readiness pointed elsewhere, so a ClientHello
    /// pipelined before the CONNECT response completes is validated without
    /// waiting for a fresh readable edge.
    fn enter_validating_hello(&mut self, index: usize) -> Result<(), ServeError> {
        self.buffer_and_validate(index, 0)?;
        if self.slots[index].stage == Stage::ValidatingHello {
            self.client_readable(index)?;
        }
        Ok(())
    }

    fn drain_to_upstream(&mut self, index: usize) -> (bool, bool) {
        let mut wrote = false;
        let mut failed = false;
        loop {
            if self.visit_exhausted(index) {
                break;
            }
            let room = self.io_room(index, usize::MAX);
            let outcome = {
                let ws = &mut self.slots[index];
                if ws.fwd >= ws.buf_len {
                    WriteOutcome::None
                } else {
                    let end = ws.buf_len.min(ws.fwd.saturating_add(room));
                    match ws.upstream.as_mut() {
                        Some(up) => match up.write(&ws.buf[ws.fwd..end]) {
                            Ok(n) => {
                                ws.fwd += n;
                                if ws.gate.is_open() {
                                    ws.idle_deadline = Some(Instant::now() + IDLE_SECS);
                                }
                                WriteOutcome::Wrote(n)
                            }
                            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                                WriteOutcome::Wait
                            }
                            Err(_) => WriteOutcome::Failed,
                        },
                        None => WriteOutcome::None,
                    }
                }
            };
            match outcome {
                WriteOutcome::Wrote(n) => {
                    wrote = true;
                    self.note_op(index, n);
                }
                WriteOutcome::Wait => {
                    self.note_op(index, 0);
                    break;
                }
                WriteOutcome::Failed => {
                    failed = true;
                    self.note_op(index, 0);
                    break;
                }
                WriteOutcome::None => break,
            }
        }
        (wrote, failed)
    }

    fn flush_client_upstream(&mut self, index: usize) -> Result<(), ServeError> {
        let (wrote_any, failed) = self.drain_to_upstream(index);
        if failed {
            self.close_slot(index);
            return Ok(());
        }
        let was_open = self.slots[index].gate.is_open();
        if !wrote_any || was_open {
            if self.visit_exhausted(index) {
                self.reschedule(index);
            }
            return Ok(());
        }
        let committed = {
            let ws = &self.slots[index];
            ws.buf_base + ws.fwd - ws.head_len
        };
        let outcome = self.slots[index].gate.upstream_write(committed);
        if matches!(
            outcome,
            UpstreamWrite::GateOpened { .. } | UpstreamWrite::Open
        ) {
            if self.slots[index].tunnel.is_none() {
                let slot = self.slots[index].handle.take();
                if let Some(slot) = slot {
                    let tunnel = self.storage.finish_setup(slot);
                    self.slots[index].tunnel = Some(tunnel);
                    self.note_occupancy(Instant::now());
                }
            }
            self.slots[index].stage = Stage::Relay;
            self.slots[index].idle_deadline = Some(Instant::now() + IDLE_SECS);
            let (_more, failed2) = self.drain_to_upstream(index);
            if failed2 {
                self.close_slot(index);
                return Ok(());
            }
            let committed2 = {
                let ws = &self.slots[index];
                ws.buf_base + ws.fwd - ws.head_len
            };
            if committed2 != committed {
                self.slots[index].gate.upstream_write(committed2);
            }
        }
        if self.visit_exhausted(index) {
            self.reschedule(index);
        }
        Ok(())
    }

    fn flush_down(&mut self, index: usize) {
        let mut failed = false;
        loop {
            if self.visit_exhausted(index) {
                break;
            }
            let (stalled, err, note) = {
                let room = self.io_room(index, usize::MAX);
                let ws = &mut self.slots[index];
                if ws.down_off >= ws.down_len {
                    (true, false, None)
                } else {
                    let end = ws.down_len.min(ws.down_off.saturating_add(room));
                    match ws.client.as_mut() {
                        Some(client) => match client.write(&ws.down[ws.down_off..end]) {
                            Ok(n) => {
                                ws.down_off += n;
                                if ws.gate.is_open() {
                                    ws.idle_deadline = Some(Instant::now() + IDLE_SECS);
                                }
                                (false, false, Some(n))
                            }
                            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                                (true, false, Some(0))
                            }
                            Err(_) => (true, true, Some(0)),
                        },
                        None => (true, false, None),
                    }
                }
            };
            if let Some(bytes) = note {
                self.note_op(index, bytes);
            }
            failed = failed || err;
            if stalled {
                break;
            }
        }
        if failed {
            self.close_slot(index);
            return;
        }
        if self.visit_exhausted(index) {
            self.reschedule(index);
            return;
        }
        let ws = &mut self.slots[index];
        if ws.down_off >= ws.down_len {
            ws.down_len = 0;
            ws.down_off = 0;
        }
    }

    fn relay_upstream_to_client(&mut self, index: usize) -> Result<(), ServeError> {
        loop {
            if self.visit_exhausted(index) {
                self.reschedule(index);
                return Ok(());
            }
            if self.slots[index].down_len + CHUNK > DOWN_CAP {
                return Ok(());
            }
            let room = self.io_room(index, CHUNK);
            let n = {
                let ws = &mut self.slots[index];
                let len = ws.down_len;
                match ws.upstream.as_mut() {
                    None => return Ok(()),
                    Some(up) => up.read(&mut ws.down[len..len + room]),
                }
            };
            let n = match n {
                Ok(0) => {
                    self.note_op(index, 0);
                    return self.observe_down_eof(index);
                }
                Ok(n) => n,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.note_op(index, 0);
                    return Ok(());
                }
                Err(_) => {
                    self.note_op(index, 0);
                    self.close_slot(index);
                    return Ok(());
                }
            };
            self.note_op(index, n);
            {
                let ws = &mut self.slots[index];
                ws.down_len += n;
            }
            self.flush_down(index);
            if self.visit_exhausted(index) {
                self.reschedule(index);
                return Ok(());
            }
            if self.slots[index].down_len > 0 {
                return Ok(());
            }
        }
    }

    fn refuse(&mut self, index: usize, refusal: Refusal) {
        let body = refusal.body();
        self.emit_reject(index, refusal.reason());
        let ws = &mut self.slots[index];
        ws.down_off = 0;
        ws.down[..body.len()].copy_from_slice(body);
        ws.down_len = body.len();
        ws.stage = Stage::Refusing(body);
        self.flush_down(index);
        if self.slots[index].down_len == 0 {
            self.close_slot(index);
        }
    }

    /// Emits one warn-reject record for the rejected slot: the client address
    /// when readable and the approved hostname when a fixed one was set.
    fn emit_reject(&mut self, index: usize, reason: RejectReason) {
        let secs = self.storage.cache_secs(Instant::now());
        let client = self.slots[index]
            .client
            .as_ref()
            .and_then(|c| c.peer_addr().ok());
        let hostname = self.slots[index].approved.as_ref().map(|h| h.as_str());
        self.storage
            .logs_mut()
            .reject(secs, reason, client, hostname);
    }

    fn client_writable(&mut self, index: usize) -> Result<(), ServeError> {
        match self.slots[index].stage {
            Stage::SendingConnected => {
                self.flush_down(index);
                let sent = {
                    let ws = &self.slots[index];
                    ws.stage == Stage::SendingConnected && ws.down_len == 0
                };
                if sent {
                    let ws = &mut self.slots[index];
                    ws.gate.on_response_ok();
                    ws.stage = Stage::ValidatingHello;
                    return self.enter_validating_hello(index);
                }
                Ok(())
            }
            Stage::Refusing(_) => {
                self.flush_down(index);
                if self.slots[index].down_len == 0 {
                    self.close_slot(index);
                }
                Ok(())
            }
            Stage::Relay => {
                self.flush_down(index);
                self.finish_drain(index);
                self.maybe_close_drained(index);
                let resume = {
                    let ws = &self.slots[index];
                    matches!(ws.directional.down, SideEof::Open)
                        && ws.down_off >= ws.down_len
                        && ws.stage == Stage::Relay
                };
                if resume {
                    return self.relay_upstream_to_client(index);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Record the client's orderly EOF on the up flow and start the once-started
    /// drain deadline. The accepted up bytes already in `buf` keep draining to
    /// the upstream; the upstream write half-close happens only once that drain
    /// finishes ([`Self::finish_drain`]). Never destroys the slot (RF-003).
    fn observe_up_eof(&mut self, index: usize) -> Result<(), ServeError> {
        {
            let ws = &mut self.slots[index];
            if matches!(ws.directional.up, SideEof::Open) {
                ws.directional.up = SideEof::Eof { half_closed: false };
                if ws.drain_deadline.is_none() {
                    ws.drain_deadline = Some(Instant::now() + DRAIN_SECS);
                }
            }
        }
        self.finish_drain(index);
        self.maybe_close_drained(index);
        Ok(())
    }

    /// Record the upstream's orderly EOF on the down flow (mirror of
    /// [`Self::observe_up_eof`]); the down pending drains to the client and the
    /// client write half-close happens once that drain finishes.
    fn observe_down_eof(&mut self, index: usize) -> Result<(), ServeError> {
        {
            let ws = &mut self.slots[index];
            if matches!(ws.directional.down, SideEof::Open) {
                ws.directional.down = SideEof::Eof { half_closed: false };
                if ws.drain_deadline.is_none() {
                    ws.drain_deadline = Some(Instant::now() + DRAIN_SECS);
                }
            }
        }
        self.finish_drain(index);
        self.maybe_close_drained(index);
        Ok(())
    }

    /// Send a directional write half-close once that direction's accepted bytes
    /// have fully drained: the client EOF drains the up buffer then
    /// `shutdown(Write)`s the upstream; the upstream EOF drains the down buffer
    /// then `shutdown(Write)`s the client. The typed state guarantees a
    /// half-close is never claimed while pending accepted bytes remain (RF-003).
    fn finish_drain(&mut self, index: usize) {
        let up_drained = {
            let ws = &self.slots[index];
            matches!(ws.directional.up, SideEof::Eof { half_closed: false }) && ws.fwd >= ws.buf_len
        };
        if up_drained {
            let ws = &mut self.slots[index];
            if let Some(up) = ws.upstream.as_mut() {
                half_close_best_effort(up);
            }
            ws.directional.up = SideEof::Eof { half_closed: true };
        }
        let down_drained = {
            let ws = &self.slots[index];
            matches!(ws.directional.down, SideEof::Eof { half_closed: false })
                && ws.down_off >= ws.down_len
        };
        if down_drained {
            let ws = &mut self.slots[index];
            if let Some(client) = ws.client.as_mut() {
                half_close_best_effort(client);
            }
            ws.directional.down = SideEof::Eof { half_closed: true };
        }
    }

    /// Close once both directions have EOF'd and drained (each write side
    /// half-closed): the slot releases exactly once ([`Self::close_slot`]).
    fn maybe_close_drained(&mut self, index: usize) {
        let both = {
            let ws = &self.slots[index];
            matches!(ws.directional.up, SideEof::Eof { half_closed: true })
                && matches!(ws.directional.down, SideEof::Eof { half_closed: true })
        };
        if both {
            self.close_slot(index);
        }
    }

    fn reject_hello(&mut self, index: usize) -> Result<(), ServeError> {
        self.slots[index].gate.on_hello_rejected();
        self.emit_reject(index, RejectReason::TlsValidation);
        self.close_slot(index);
        Ok(())
    }

    fn close_slot(&mut self, index: usize) {
        let now = Instant::now();
        let ws = &mut self.slots[index];
        ws.stage = Stage::Closing;
        let slot = ws.handle.take();
        let tunnel = ws.tunnel.take();
        ws.client.take();
        ws.upstream.take();
        ws.reset();
        if let Some(tunnel) = tunnel {
            self.storage.release_tunnel(tunnel);
        } else if let Some(slot) = slot {
            self.storage.release(slot);
        }
        self.note_occupancy(now);
    }

    fn poll_timeout(&self) -> Option<Duration> {
        let mut earliest: Option<Instant> = None;
        for i in 0..self.slots.len() {
            let mut candidate = self.slots[i]
                .handle
                .as_ref()
                .and_then(|h| self.storage.setup_deadline(h))
                .map(|d| d.limit());
            if let Some(idle) = self.slots[i].idle_deadline {
                candidate = Some(candidate.map_or(idle, |c| c.min(idle)));
            }
            if let Some(drain) = self.slots[i].drain_deadline {
                candidate = Some(candidate.map_or(drain, |c| c.min(drain)));
            }
            if let Some(c) = candidate
                && earliest.is_none_or(|e| c < e)
            {
                earliest = Some(c);
            }
        }
        if let Some(dns) = self.storage.dns().exchange_deadline()
            && earliest.is_none_or(|e| dns < e)
        {
            earliest = Some(dns);
        }
        if let Shutdown::Draining { deadline } = self.shutdown
            && earliest.is_none_or(|e| deadline < e)
        {
            earliest = Some(deadline);
        }
        let now = Instant::now();
        if let Some(log_wake) = self.storage.logs().next_drain(now)
            && earliest.is_none_or(|e| log_wake < e)
        {
            earliest = Some(log_wake);
        }
        if !self.storage.dns().has_active_exchange()
            && let Some(due) = self
                .storage
                .schedules()
                .next_selectable_due(self.storage.cache_secs(now))
        {
            let wake = self.storage.schedule_due_instant(due);
            if wake <= now {
                let floor = now + Duration::from_millis(100);
                earliest = Some(earliest.map_or(floor, |e| e.min(floor)));
            } else if earliest.is_none_or(|e| wake < e) {
                earliest = Some(wake);
            }
        }
        let deadline = earliest?;
        if deadline <= now {
            Some(Duration::ZERO)
        } else {
            Some(deadline - now)
        }
    }

    /// Enforce every passed absolute deadline in one sweep: the per-setup
    /// deadline (refuse 504 pre-200, close-only once the 200 has begun), the
    /// established-tunnel idle deadline, and the once-started FIN-drain
    /// deadline. Never rewrites or splices a begun response (xz3f N5).
    fn expire_sweep(&mut self, now: Instant) {
        for i in 0..self.slots.len() {
            let setup_expired = self.slots[i]
                .handle
                .as_ref()
                .and_then(|h| self.storage.setup_deadline(h))
                .is_some_and(|d| d.is_expired(now));
            if setup_expired {
                self.expire_setup(i);
                continue;
            }
            if self.slots[i].idle_deadline.is_some_and(|d| now >= d) {
                self.close_slot(i);
                continue;
            }
            if self.slots[i].drain_deadline.is_some_and(|d| now >= d) {
                self.close_slot(i);
            }
        }
    }

    /// Expire one pre-gate setup. Pre-200 stages receive the fixed 504 refusal;
    /// once the 200 has begun the slot closes with the in-flight body flushed
    /// best-effort but never replaced (D1, xz3f N5). A refusal that cannot yet
    /// flush is closed on the next sweep, so the passed deadline cannot spin.
    fn expire_setup(&mut self, i: usize) {
        match self.slots[i].stage {
            Stage::ReadingConnect | Stage::RunningDecision | Stage::Dialing => {
                self.refuse(i, Refusal::SetupTimeout);
            }
            Stage::SendingConnected | Stage::ValidatingHello | Stage::WritingHello => {
                self.flush_down(i);
                self.close_slot(i);
            }
            Stage::Refusing(_) | Stage::Relay | Stage::Closing | Stage::Idle => {
                self.close_slot(i);
            }
        }
    }
}

fn client_token(generation: u64, index: usize) -> Token {
    Token(((generation as usize) << GEN_SHIFT) | (index + 1))
}

fn upstream_token(generation: u64, index: usize) -> Token {
    Token(((generation as usize) << GEN_SHIFT) | (UPSTREAM_BASE + index))
}

fn half_close_best_effort(stream: &mut TcpStream) {
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

fn write_all_bounded(stream: &mut TcpStream, body: &[u8]) {
    let mut pos = 0;
    while pos < body.len() {
        match stream.write(&body[pos..]) {
            Ok(n) => pos += n,
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

#[cfg(test)]
pub(crate) fn test_offset_pattern(len: usize, seed: u32) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let salt = (i as u32).wrapping_mul(2_654_435_761).wrapping_add(seed);
            salt as u8
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener as StdListener, TcpStream};
    use std::time::{Duration, Instant};

    use crate::worker::{MAX_PENDING_SETUPS, SETUP_DEADLINE_SECS};

    fn config(port: u16) -> crate::config::Config {
        let doc = format!(
            "allowlist = [\"sub.example.org\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\n"
        );
        crate::config::parse_config_document(&doc).expect("valid test config")
    }

    fn ephemeral_port() -> u16 {
        let probe = StdListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        port
    }

    fn with_serving_stack(port: u16, body: impl FnOnce(&mut Serving) + Send + 'static) {
        let t = std::thread::Builder::new()
            .name("serving-test".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let mut serving = serve_on(port);
                body(&mut serving);
            })
            .expect("spawn serving thread");
        t.join().expect("serving thread");
    }

    fn serve_on(port: u16) -> Serving {
        let storage = ServeStorage::boot(&config(port)).expect("boot storage");
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port))
            .expect("bind listener");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        Serving::new(storage, listener, traffic).expect("serving")
    }

    #[test]
    fn serving_poll_timeout_folds_queued_log_drain_into_earliest_wait() {
        with_serving_stack(ephemeral_port(), |serving| {
            assert_eq!(
                serving.poll_timeout(),
                None,
                "no slots, no dns deadline, empty log queue: idle serving has no wait"
            );
            serving.storage_mut().logs_mut().startup_warning(
                1,
                "sub.example.org",
                crate::cache::Family::A,
            );
            assert_eq!(
                serving.poll_timeout(),
                Some(Duration::ZERO),
                "a queued runnable log folds to an immediate wake with no traffic (T3)"
            );
        });
    }

    #[test]
    fn serving_poll_timeout_folds_bounded_floor_for_idle_selectable_now_due() {
        with_serving_stack(ephemeral_port(), |serving| {
            let secs = serving.storage().dns().now_u64();
            serving
                .storage_mut()
                .schedules_mut()
                .overwrite_due_at(0, crate::cache::Family::A, secs)
                .expect("due the A family now");
            let wait = serving.poll_timeout();
            assert!(
                matches!(wait, Some(d) if d >= Duration::from_millis(50) && d <= Duration::from_millis(200)),
                "an idle transport with a selectable-now due slot folds a bounded floor wake so \
                 an indefinite production poll initiates the refresh without busy-spinning: \
                 {wait:?}"
            );
        });
    }

    #[test]
    fn serving_consumes_boot_traffic_buffers_by_value_not_reallocation() {
        std::thread::Builder::new()
            .name("serving-transfer-test".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(transfer_body)
            .expect("spawn transfer test")
            .join()
            .expect("transfer test thread");
    }

    fn transfer_body() {
        use crate::inventory::TrafficStorage;
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config(port)).expect("boot storage");
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port))
            .expect("bind listener");
        let traffic = TrafficStorage::allocate().expect("boot traffic");
        let first_up = traffic.slots()[0].up.as_ptr();
        let last_down = traffic.slots()[MAX_TUNNELS - 1].down.as_ptr();
        let serving = Serving::new(storage, listener, traffic).expect("serving");
        assert_eq!(
            serving.slots[0].buf.as_ptr(),
            first_up,
            "slot 0 hold buffer must transfer by value without a second allocation"
        );
        assert_eq!(
            serving.slots[MAX_TUNNELS - 1].down.as_ptr(),
            last_down,
            "slot 127 down buffer must transfer by value without a second allocation"
        );
    }

    fn pump(serving: &mut Serving, times: usize) {
        for _ in 0..times {
            serving
                .run_once(Some(Duration::from_millis(2)))
                .expect("pump poll");
        }
    }

    #[cfg(all(test, feature = "alloc-witness"))]
    fn turn_pump(runtime: &mut crate::runtime::Runtime, times: usize) {
        for _ in 0..times {
            runtime.turn(Some(Duration::from_millis(2))).expect(
                "an owner turn inside the witnessed shutdown may not error and stay silent",
            );
        }
    }

    fn connect(port: u16) -> TcpStream {
        TcpStream::connect(SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port))
            .expect("client connect")
    }

    fn wait_upstream_connected(up: &mio::net::TcpStream) {
        for _ in 0..10_000 {
            if up.peer_addr().is_ok() {
                return;
            }
            std::thread::yield_now();
        }
        panic!("the nonblocking upstream connect never resolved");
    }

    fn read_until(stream: &mut TcpStream, marker: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.windows(marker.len()).any(|w| w == marker) {
                        break;
                    }
                }
            }
        }
        out
    }

    /// Puts the slot into an open-gate relay with a typed head/hello boundary,
    /// so focused relay tests can drive real sockets through the actual owner.
    fn open_relay(serving: &mut Serving, index: usize) {
        let ws = &mut serving.slots[index];
        ws.stage = Stage::Relay;
        ws.gate.on_connect_head(4);
        ws.gate.on_authorized();
        ws.gate.on_upstream_connected();
        ws.gate.on_response_ok();
        ws.gate.on_hello_validated(ValidatedHello::test_new(10));
        ws.gate.upstream_write(6);
    }

    #[test]
    fn read_outcome_distinguishes_activity_from_retry_wait_and_failure() {
        use std::io::ErrorKind::{
            ConnectionReset, Interrupted, NotConnected, Unsupported, WouldBlock,
        };
        assert_eq!(classify_read(Ok(7)), ReadOutcome::Activity(Activity::Data));
        assert_eq!(classify_read(Ok(0)), ReadOutcome::Activity(Activity::Eof));
        assert_eq!(
            classify_read(Err(io::Error::from(ConnectionReset))),
            ReadOutcome::Activity(Activity::Reset),
            "an actual connection-reset read is the only error classified as early reset"
        );
        assert_eq!(
            classify_read(Err(io::Error::from(WouldBlock))),
            ReadOutcome::Wait,
            "WouldBlock/readiness is not activity"
        );
        assert_eq!(
            classify_read(Err(io::Error::from(Interrupted))),
            ReadOutcome::Retry,
            "an interrupted read is retried, never reported as a remote reset"
        );
        assert_eq!(
            classify_read(Err(io::Error::from(NotConnected))),
            ReadOutcome::Failed,
            "a not-yet-connected read is a setup failure, never silent waiting"
        );
        assert_eq!(
            classify_read(Err(io::Error::from(Unsupported))),
            ReadOutcome::Failed,
            "an unknown non-reset failure keeps its identity; it is never labelled early reset"
        );
    }

    fn hello_wire(sni: &[u8], ech_only: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x2a; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        if ech_only {
            ext.extend_from_slice(&[0xfe, 0x0d, 0x00, 0x00]);
        } else {
            let list_len = 3 + sni.len();
            ext.extend_from_slice(&[0x00, 0x00]);
            let len = 2 + list_len;
            ext.push((len >> 8) as u8);
            ext.push((len & 0xff) as u8);
            ext.push((list_len >> 8) as u8);
            ext.push((list_len & 0xff) as u8);
            ext.push(0x00);
            ext.push((sni.len() >> 8) as u8);
            ext.push((sni.len() & 0xff) as u8);
            ext.extend_from_slice(sni);
        }
        body.push((ext.len() >> 8) as u8);
        body.push((ext.len() & 0xff) as u8);
        body.extend_from_slice(&ext);

        let mut hs = vec![
            0x01,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            (body.len() & 0xff) as u8,
        ];
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x03]);
        record.push((hs.len() >> 8) as u8);
        record.push((hs.len() & 0xff) as u8);
        record.extend_from_slice(&hs);
        record
    }

    fn drive_hello(serving: &mut Serving, wire: &[u8], approved: &str) {
        let index = 0;
        let ws = &mut serving.slots[index];
        ws.buf_base = 0;
        ws.buf_len = wire.len();
        ws.buf[..wire.len()].copy_from_slice(wire);
        ws.parse_rel = 0;
        ws.insp_rel = 0;
        ws.head_len = 0;
        ws.hello_end = None;
        ws.hello_consumed = 0;
        ws.fwd = 0;
        ws.approved = FixedHostname::normalize(approved.as_bytes());
        ws.stage = Stage::ValidatingHello;
        ws.gate.on_connect_head(0);
        ws.gate.on_authorized();
        ws.gate.on_upstream_connected();
        ws.gate.on_response_ok();
        serving
            .buffer_and_validate(index, 0)
            .expect("drive hello validation");
    }

    #[test]
    fn forbidden_connect_gets_403_and_releases_the_slot() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let mut client = connect(port);
            client
                .write_all(b"CONNECT evil.example.net:443 HTTP/1.1\r\n\r\n")
                .expect("write head");
            pump(serving, 80);
            let body = read_until(&mut client, b"\r\n\r\n");
            assert!(
                body.starts_with(b"HTTP/1.1 403"),
                "forbidden CONNECT must receive 403, got {:?}",
                body
            );
            assert_eq!(
                serving.storage().occupied(),
                0,
                "the refused slot must be released"
            );
        });
    }

    #[test]
    fn refused_slot_is_reusable_after_release() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let mut c1 = connect(port);
            c1.write_all(b"CONNECT nope.example.net:443 HTTP/1.1\r\n\r\n")
                .expect("write head");
            pump(serving, 80);
            let b1 = read_until(&mut c1, b"\r\n\r\n");
            assert!(b1.starts_with(b"HTTP/1.1 403"));

            let mut c2 = connect(port);
            c2.write_all(b"CONNECT also-not.example.net:443 HTTP/1.1\r\n\r\n")
                .expect("write head");
            pump(serving, 80);
            let b2 = read_until(&mut c2, b"\r\n\r\n");
            assert!(b2.starts_with(b"HTTP/1.1 403"));
            assert_eq!(
                serving.storage().occupied(),
                0,
                "both refused slots must be released"
            );
        });
    }

    #[test]
    fn client_fin_during_reading_connect_releases_the_setup_slot() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let mut client = connect(port);
            client
                .write_all(b"CONNECT sub.example.org:443 HTTP/1.1\r\n")
                .expect("write partial head");
            client
                .shutdown(std::net::Shutdown::Write)
                .expect("client fin during reading connect");
            pump(serving, 80);
            assert_eq!(
                serving.storage().occupied(),
                0,
                "a client FIN during ReadingConnect must release the setup seat immediately"
            );
        });
    }

    #[test]
    fn hello_with_sni_mismatch_is_rejected_without_forwarding() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let wire = hello_wire(b"evil.example.net", false);
            let mut insp = ChInspector::new();
            assert!(matches!(insp.feed(&wire), Ok(Inspect::Complete { .. })));
            let approved = FixedHostname::normalize(b"sub.example.org");
            assert_eq!(
                client_hello::validate(insp.hello().expect("parsed hello"), &approved.unwrap()),
                Err(client_hello::ChError::ServerNameMismatch),
                "the fixture must fail validation only on the SNI, not on parsing"
            );
            drive_hello(serving, &wire, "sub.example.org");
            assert_eq!(
                serving.slots[0].fwd, 0,
                "no client byte may be forwarded upstream"
            );
            assert_eq!(
                serving.storage().occupied(),
                0,
                "the rejected connection is closed and its seat released"
            );
        });
    }

    #[test]
    fn hello_with_ech_is_rejected_without_forwarding() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let wire = hello_wire(b"sub.example.org", true);
            let mut insp = ChInspector::new();
            assert!(matches!(insp.feed(&wire), Ok(Inspect::Complete { .. })));
            let approved = FixedHostname::normalize(b"sub.example.org");
            assert_eq!(
                client_hello::validate(insp.hello().expect("parsed hello"), &approved.unwrap()),
                Err(client_hello::ChError::EchPresent),
                "the fixture must fail validation on ECH"
            );
            drive_hello(serving, &wire, "sub.example.org");
            assert_eq!(serving.slots[0].fwd, 0);
            assert_eq!(
                serving.storage().occupied(),
                0,
                "the ECH connection is closed without forwarding"
            );
        });
    }

    #[test]
    fn matching_hello_is_accepted_and_enters_the_hello_write() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let wire = hello_wire(b"sub.example.org", false);
            drive_hello(serving, &wire, "sub.example.org");
            let ws = &serving.slots[0];
            assert!(matches!(ws.stage, Stage::WritingHello));
            assert_eq!(ws.hello_end, Some(wire.len()));
            assert_eq!(ws.fwd, 0, "no upstream socket yet; nothing forwarded");
        });
    }

    #[test]
    fn pipelined_clienthello_pre200_is_drained_on_validating_hello_entry() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;
            wait_upstream_connected(&client);
            let _ = peer_stream.set_nodelay(true);

            let wire = hello_wire(b"sub.example.org", false);
            peer_stream
                .write_all(&wire)
                .expect("clienthello pipelined before the CONNECT response completes");
            let mut delivered = [0u8; 128];
            let hello_delivered = loop {
                match client.peek(&mut delivered) {
                    Ok(n) if n == wire.len() => break true,
                    Ok(_) => break false,
                    Err(_) => std::thread::yield_now(),
                }
            };
            assert!(
                hello_delivered,
                "the pipelined hello must be receivable (into the kernel buffer) before the phase entry"
            );

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.client = Some(client);
                ws.approved = FixedHostname::normalize(b"sub.example.org");
                ws.stage = Stage::SendingConnected;
                ws.head_len = 0;
                ws.buf_base = 0;
                ws.buf_len = 0;
                ws.fwd = 0;
                ws.insp_rel = 0;
                ws.hello_consumed = 0;
                ws.gate.on_connect_head(0);
                ws.gate.on_authorized();
                ws.gate.on_upstream_connected();
            }
            serving
                .client_writable(index)
                .expect("200 sent and the validating-hello entry runs");

            assert!(
                serving.slots[index].gate.hello_end().is_some(),
                "a ClientHello pipelined before the CONNECT response must be validated on the phase entry without a new readable edge"
            );
            assert!(
                matches!(serving.slots[index].stage, Stage::WritingHello),
                "the validated hello advances into the hello write"
            );
        });
    }

    #[test]
    fn head_spanning_multiple_reads_reaches_403() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let mut client = connect(port);
            let mut head = Vec::new();
            head.extend_from_slice(b"CONNECT evil.example.net:443 HTTP/1.1\r\n");
            head.extend_from_slice(b"Padding: ");
            while head.len() < 6000 {
                head.push(b'x');
            }
            head.extend_from_slice(b"\r\n\r\n");
            client
                .write_all(&head)
                .expect("write 6 KiB head in one write");
            pump(serving, 120);
            let body = read_until(&mut client, b"\r\n\r\n");
            assert!(
                body.starts_with(b"HTTP/1.1 403"),
                "multi-read head must drain to the 403 decision, got {:?} (len {})",
                &body[..body.len().min(24)],
                body.len()
            );
        });
    }

    #[test]
    fn malformed_head_gets_400() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let mut client = connect(port);
            client.write_all(b"\r\n\r\n").expect("write malformed head");
            pump(serving, 80);
            let body = read_until(&mut client, b"\r\n\r\n");
            assert!(
                body.starts_with(b"HTTP/1.1 400"),
                "malformed CONNECT must receive 400, got {:?}",
                body
            );
        });
    }

    #[test]
    fn pending_capacity_refuses_with_503() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let mut socks = Vec::new();
            for _ in 0..=MAX_PENDING_SETUPS {
                socks.push(connect(port));
            }
            pump(serving, 80);
            let mut last = socks[MAX_PENDING_SETUPS].try_clone().expect("clone");
            let body = read_until(&mut last, b"\r\n\r\n");
            assert!(
                body.starts_with(b"HTTP/1.1 503"),
                "33rd silent connect must receive 503, got {:?}",
                body
            );
            assert_eq!(
                serving.storage().occupied(),
                MAX_PENDING_SETUPS,
                "the first 32 silent setups occupy their seats"
            );
        });
    }

    #[test]
    fn setup_deadline_frees_silent_seats_with_504() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let mut socks = Vec::new();
            for _ in 0..=MAX_PENDING_SETUPS {
                socks.push(connect(port));
            }
            pump(serving, 40);
            let mut probe = socks[MAX_PENDING_SETUPS].try_clone().expect("clone");
            let body = read_until(&mut probe, b"\r\n\r\n");
            assert!(body.starts_with(b"HTTP/1.1 503"));
            let start = Instant::now();
            while serving.storage().occupied() > 0 {
                serving
                    .run_once(None)
                    .expect("block past the next setup deadline");
                assert!(
                    start.elapsed() <= Duration::from_secs(SETUP_DEADLINE_SECS + 5),
                    "setups were admitted with individually spread absolute deadlines; a single poll turn only ever reaches the earliest one (fdtt H2), and the sweep must keep blocking until every deadline has expired, not assert the spread covers all slots in one wake"
                );
            }
            for (i, sock) in socks[..MAX_PENDING_SETUPS].iter().enumerate() {
                let mut clone = sock.try_clone().expect("clone");
                let expired = read_until(&mut clone, b"\r\n\r\n");
                assert!(
                    expired.starts_with(b"HTTP/1.1 504"),
                    "a silent setup must receive 504 after its deadline, slot {i} got {:?}",
                    expired
                );
            }
            assert_eq!(
                serving.storage().occupied(),
                0,
                "all silent setups must be released after the deadline"
            );
        });
    }

    #[test]
    fn stale_event_for_a_reused_slot_index_is_dropped() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let client = mio::net::TcpStream::connect(SocketAddr::new(
                IpAddr::V4([127, 0, 0, 1].into()),
                port,
            ))
            .expect("client connect");
            serving.admit(client).expect("admit directly");
            assert_eq!(serving.storage().occupied(), 1);
            let current = serving.slots[0].slot_gen;
            let stale_gen = current.wrapping_sub(1);
            let stale = Token(((stale_gen as usize) << GEN_SHIFT) | 1);
            serving
                .dispatch_readiness(
                    stale,
                    Readiness {
                        readable: true,
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("dispatch stale event");
            assert_eq!(
                serving.storage().occupied(),
                1,
                "a stale event for the reused slot index must not close the new connection"
            );
        });
    }

    #[test]
    fn dialing_combined_readable_writable_rejects_early_origin_data() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
            let origin_addr = origin.local_addr().expect("origin addr");
            let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
            let mut origin_stream = origin.accept().expect("accept origin side").0;

            let _client = connect(port);
            pump(serving, 40);
            assert_eq!(
                serving.storage().occupied(),
                1,
                "the connecting client must be admitted"
            );

            let index = 0;
            let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
            {
                let ws = &mut serving.slots[index];
                ws.approved = FixedHostname::normalize(b"sub.example.org");
                ws.gate.on_connect_head(head_len);
                ws.gate.on_authorized();
                ws.stage = Stage::Dialing;
            }
            origin_stream
                .write_all(b"X")
                .expect("origin writes early data");
            let mut probe = [0u8; 1];
            let mut waits = 0;
            loop {
                match up.peek(&mut probe) {
                    Ok(1) => break,
                    Ok(_) => {}
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    Err(err) => panic!("peek origin early data: {err}"),
                }
                waits += 1;
                assert!(
                    waits < 2000,
                    "origin early data never became readable on the upstream socket"
                );
                std::thread::yield_now();
            }
            serving.slots[index].upstream = Some(up);

            let token = upstream_token(serving.slots[index].slot_gen, index);
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        readable: true,
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("combined dialing event");

            assert_eq!(
                serving.storage().occupied(),
                0,
                "early origin data during Dialing must release the admitted seat before any 200/forward"
            );
            let ws = &serving.slots[0];
            assert!(
                ws.stage == Stage::Idle,
                "the terminated setup must leave the workspace idle, never advanced to a 200-sending stage"
            );
            assert!(
                ws.client.is_none(),
                "the client socket must be closed so no 200/forward can be delivered"
            );
            assert!(
                ws.upstream.is_none(),
                "the upstream socket must be closed once early activity is observed"
            );
        });
    }

    #[test]
    fn dialing_readiness_without_origin_data_is_not_early_activity() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
            let origin_addr = origin.local_addr().expect("origin addr");
            let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
            let mut _origin_stream = origin.accept().expect("accept origin side").0;

            let _client = connect(port);
            pump(serving, 40);
            assert_eq!(
                serving.storage().occupied(),
                1,
                "the connecting client must be admitted"
            );

            let index = 0;
            let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
            {
                let ws = &mut serving.slots[index];
                ws.approved = FixedHostname::normalize(b"sub.example.org");
                ws.gate.on_connect_head(head_len);
                ws.gate.on_authorized();
                ws.stage = Stage::Dialing;
                ws.upstream = Some(up);
            }

            let token = upstream_token(serving.slots[index].slot_gen, index);
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        readable: true,
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("combined dialing event");

            assert_eq!(
                serving.storage().occupied(),
                1,
                "a WouldBlock readiness with no origin data must not terminate the setup"
            );
            assert!(
                serving.slots[0].stage == Stage::ValidatingHello,
                "with no origin data the combined event must only advance the connection (200 sent, hello pending)"
            );
        });
    }

    #[test]
    fn upstream_read_interrupted_exhaustion_rewires_and_terminates_on_pending_data() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
            let origin_addr = origin.local_addr().expect("origin addr");
            let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
            let mut origin_stream = origin.accept().expect("accept origin side").0;
            wait_upstream_connected(&up);

            let mut client = connect(port);
            client
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("client read timeout");
            pump(serving, 40);
            assert_eq!(
                serving.storage().occupied(),
                1,
                "the connecting client must be admitted"
            );

            let index = 0;
            let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
            {
                let ws = &mut serving.slots[index];
                ws.approved = FixedHostname::normalize(b"sub.example.org");
                ws.gate.on_connect_head(head_len);
                ws.gate.on_authorized();
                ws.stage = Stage::Dialing;
                ws.upstream = Some(up);
            }
            serving.register_upstream(index).expect("register upstream");

            let mut reads = vec![Ok(1)];
            reads.extend((0..EVENT_CAP).map(|_| Err(io::Error::from(io::ErrorKind::Interrupted))));
            serving.slots[index].test_reads = reads;

            let token = upstream_token(serving.slots[index].slot_gen, index);
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("interrupted burst");

            assert_eq!(
                serving.storage().occupied(),
                1,
                "an interrupted read burst must neither release the seat nor wait silently"
            );
            assert!(
                serving.slots[index].stage == Stage::Dialing,
                "an interrupted burst must not advance or terminate the setup"
            );
            let early = read_until(&mut client, b"\r\n\r\n");
            assert!(
                early.is_empty(),
                "no 200/502/504 may be sent while the interrupted burst is still draining"
            );

            origin_stream.write_all(b"X").expect("origin writes data");
            let start = Instant::now();
            while serving.storage().occupied() > 0 {
                assert!(
                    start.elapsed() <= Duration::from_millis(2000),
                    "the rearmed upstream readable event was never delivered"
                );
                serving
                    .run_once(Some(Duration::from_millis(10)))
                    .expect("poll redelivers readiness");
            }

            assert_eq!(
                serving.storage().occupied(),
                0,
                "early data still pending after the interrupted burst must terminate on the rearmed event"
            );
        });
    }

    #[test]
    fn not_connected_upstream_read_after_200_closes_without_injected_502() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
            let origin_addr = origin.local_addr().expect("origin addr");
            let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
            let _origin_stream = origin.accept().expect("accept origin side").0;
            wait_upstream_connected(&up);

            let mut client = connect(port);
            client
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("client read timeout");
            pump(serving, 40);
            assert_eq!(
                serving.storage().occupied(),
                1,
                "the connecting client must be admitted"
            );

            let index = 0;
            let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
            {
                let ws = &mut serving.slots[index];
                ws.approved = FixedHostname::normalize(b"sub.example.org");
                ws.gate.on_connect_head(head_len);
                ws.gate.on_authorized();
                ws.stage = Stage::Dialing;
                ws.upstream = Some(up);
            }
            serving.register_upstream(index).expect("register upstream");

            let token = upstream_token(serving.slots[index].slot_gen, index);
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        readable: true,
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("connect the upstream and send 200");

            assert!(
                serving.slots[index].stage == Stage::ValidatingHello,
                "a connected, silent upstream advances past the 200 and waits for hello"
            );

            serving.slots[index].test_reads =
                vec![Err(io::Error::from(io::ErrorKind::NotConnected))];
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("not-connected read");

            assert_eq!(
                serving.storage().occupied(),
                0,
                "a not-yet-connected read is a confirmed setup failure once connectedness advanced"
            );
            let body = read_until(&mut client, b"\r\n\r\n");
            assert!(
                body.starts_with(b"HTTP/1.1 200"),
                "the completed connect already sent 200 and the failure must not inject a 502, got {:?}",
                body
            );
        });
    }

    #[test]
    fn upstream_error_readiness_during_dialing_refuses_502_not_silent_close() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let mut client = connect(port);
            client
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("client read timeout");
            pump(serving, 40);
            assert_eq!(
                serving.storage().occupied(),
                1,
                "the connecting client must be admitted"
            );

            let index = 0;
            let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
            {
                let ws = &mut serving.slots[index];
                ws.approved = FixedHostname::normalize(b"sub.example.org");
                ws.gate.on_connect_head(head_len);
                ws.gate.on_authorized();
                ws.stage = Stage::Dialing;
            }
            serving.register_upstream(index).expect("register upstream");

            let token = upstream_token(serving.slots[index].slot_gen, index);
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        error: true,
                        ..Readiness::none()
                    },
                )
                .expect("upstream error readiness");

            assert_eq!(
                serving.storage().occupied(),
                0,
                "a refused dial must release the admitted seat with a 502, not a silent close"
            );
            let body = read_until(&mut client, b"\r\n\r\n");
            assert!(
                body.starts_with(b"HTTP/1.1 502"),
                "refused dialing upstream must refuse the pre-200 502, got {:?}",
                body
            );
        });
    }

    #[test]
    fn dialing_upstream_read_failure_refuses_502_before_any_200() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let origin = StdListener::bind("127.0.0.1:0").expect("origin bind");
            let origin_addr = origin.local_addr().expect("origin addr");
            let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
            let _origin_stream = origin.accept().expect("accept origin side").0;
            wait_upstream_connected(&up);

            let mut client = connect(port);
            client
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("client read timeout");
            pump(serving, 40);
            assert_eq!(
                serving.storage().occupied(),
                1,
                "the connecting client must be admitted"
            );

            let index = 0;
            let head_len = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n".len();
            {
                let ws = &mut serving.slots[index];
                ws.approved = FixedHostname::normalize(b"sub.example.org");
                ws.gate.on_connect_head(head_len);
                ws.gate.on_authorized();
                ws.stage = Stage::Dialing;
                ws.upstream = Some(up);
            }
            serving.register_upstream(index).expect("register upstream");

            serving.slots[index].test_reads =
                vec![Err(io::Error::from(io::ErrorKind::Unsupported))];
            let token = upstream_token(serving.slots[index].slot_gen, index);
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        readable: true,
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("dialing read failure");

            assert_eq!(
                serving.storage().occupied(),
                0,
                "a dialing read failure must release the admitted seat"
            );
            let body = read_until(&mut client, b"\r\n\r\n");
            assert!(
                body.starts_with(b"HTTP/1.1 502"),
                "a non-200-stage setup failure must produce a pre-200 502, got {:?}",
                body
            );
        });
    }

    #[test]
    fn relay_pending_tail_then_fresh_bytes_preserve_order_and_count() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;
            let index = 0;
            let ws = &mut serving.slots[index];
            ws.upstream = Some(up);
            ws.head_len = 4;
            ws.hello_end = Some(10);
            ws.buf_base = 0;
            ws.buf_len = 20;
            ws.fwd = 4;
            ws.buf[..20].copy_from_slice(b"HEADHELLO!0123456789");
            ws.stage = Stage::Relay;
            ws.gate.on_connect_head(4);
            ws.gate.on_authorized();
            ws.gate.on_upstream_connected();
            ws.gate.on_response_ok();
            ws.gate.on_hello_validated(ValidatedHello::test_new(10));

            serving
                .flush_client_upstream(index)
                .expect("flush pending tail");
            serving.append_client_bytes(index, b"FRESH");
            serving
                .flush_client_upstream(index)
                .expect("flush fresh bytes");

            let mut got = Vec::new();
            let mut tmp = [0u8; 64];
            while got.len() < 21 {
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            assert_eq!(
                got,
                b"HELLO!0123456789FRESH".to_vec(),
                "pending tail then fresh bytes must reach the upstream in order, unduplicated"
            );
        });
    }

    #[test]
    fn forced_compaction_preserves_absolute_cursor_and_retained_suffix() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;
            sink_stream.set_nonblocking(true).expect("sink nonblocking");

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.head_len = 4;
                ws.hello_end = Some(10);
                ws.buf_base = 0;
                ws.fwd = 4;
                ws.stage = Stage::Relay;
                ws.gate.on_connect_head(4);
                ws.gate.on_authorized();
                ws.gate.on_upstream_connected();
                ws.gate.on_response_ok();
                ws.gate.on_hello_validated(ValidatedHello::test_new(10));
                ws.buf[..4].copy_from_slice(b"HEAD");
                ws.buf[4..10].copy_from_slice(b"HELLO!");
                let payload_start = 10usize;
                let payload = b"0123456789abcdef";
                let mut filled = payload_start;
                while filled + payload.len() <= HOLD_CAP - 3 {
                    ws.buf[filled..filled + payload.len()].copy_from_slice(payload);
                    filled += payload.len();
                }
                ws.buf_len = HOLD_CAP - 3;
                assert!(
                    filled <= ws.buf_len,
                    "padded payload must fit within the pre-fill workspace"
                );
                ws.buf[filled..ws.buf_len]
                    .copy_from_slice(&test_offset_pattern(ws.buf_len - filled, 8));
            }
            serving.register_upstream(index).expect("register up");

            let committed_before = {
                let ws = &mut serving.slots[index];
                ws.buf_base + ws.fwd - ws.head_len
            };
            let hello_end_before = {
                let ws = &mut serving.slots[index];
                ws.hello_end
            };
            let suffix_before: Vec<u8> = {
                let ws = &mut serving.slots[index];
                ws.buf[ws.fwd..ws.buf_len].to_vec()
            };

            serving.append_client_bytes(index, b"FRESH");

            let ws = &mut serving.slots[index];
            assert_eq!(
                ws.buf_base + ws.fwd - ws.head_len,
                committed_before,
                "compaction must preserve the absolute committed cursor (base + fwd - head_len)"
            );
            assert_eq!(
                ws.hello_end, hello_end_before,
                "the absolute hello end must not shift when the base moves"
            );
            assert_eq!(
                &ws.buf[0..suffix_before.len()][..],
                &suffix_before[..],
                "the retained suffix must be preserved byte-for-byte across compaction"
            );

            serving
                .flush_client_upstream(index)
                .expect("flush compacted buffer");
            let expected_len = suffix_before.len() + 5;
            let mut got = Vec::new();
            let mut tmp = [0u8; 65536];
            let deadline = Instant::now() + Duration::from_secs(3);
            while got.len() < expected_len {
                assert!(
                    Instant::now() < deadline,
                    "compacted stream never fully drained: got {} / {}",
                    got.len(),
                    expected_len
                );
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&tmp[..n]),
                    Err(_) => {}
                }
                serving
                    .run_once(Some(Duration::from_millis(1)))
                    .expect("compaction-drain poll");
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&tmp[..n]),
                    Err(_) => {}
                }
            }
            let mut expected = Vec::with_capacity(expected_len);
            expected.extend_from_slice(&suffix_before);
            expected.extend_from_slice(b"FRESH");
            assert_eq!(
                got, expected,
                "post-compaction delivery must match the pre-compaction suffix plus fresh bytes"
            );
        });
    }

    #[test]
    fn relay_client_fin_drains_pending_bytes_then_half_closes_and_releases() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
                ws.buf_len = 10;
                ws.fwd = 4;
                ws.buf[..10].copy_from_slice(b"HEAD!ABCDE");
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");
            let _ = peer_stream.set_read_timeout(Some(Duration::from_millis(50)));
            let _ = sink_stream.set_read_timeout(Some(Duration::from_millis(50)));

            peer_stream
                .write_all(b"Z")
                .expect("write final client byte");
            peer_stream
                .shutdown(std::net::Shutdown::Write)
                .expect("client fin");

            let mut pending = Vec::new();
            let mut tmp = [0u8; 64];
            let mut eof_seen = false;
            let fin_start = Instant::now();
            while !eof_seen {
                assert!(
                    fin_start.elapsed() < Duration::from_secs(3),
                    "pending drain/half-close never reached sink EOF"
                );
                match sink_stream.read(&mut tmp) {
                    Ok(0) => eof_seen = true,
                    Ok(n) => pending.extend_from_slice(&tmp[..n]),
                    Err(_) => {
                        serving
                            .run_once(Some(Duration::from_millis(5)))
                            .expect("poll drain");
                        std::thread::yield_now();
                    }
                }
            }
            assert_eq!(
                pending,
                b"!ABCDEZ".to_vec(),
                "a client FIN must conserve the accepted bytes through the half-close, not drop them"
            );
            assert!(
                matches!(serving.slots[index].stage, Stage::Relay),
                "the reverse direction stays open after the client EOF"
            );
            assert!(
                serving.slots[index].client.is_some(),
                "a half-close must not fully drop the client socket"
            );

            sink_stream.write_all(b"down!").expect("origin writes down");
            sink_stream
                .shutdown(std::net::Shutdown::Write)
                .expect("origin fin");
            let close_start = Instant::now();
            while serving.slots[index].stage != Stage::Idle {
                assert!(
                    close_start.elapsed() < Duration::from_secs(3),
                    "both-EOF drain never closed the slot"
                );
                serving
                    .run_once(Some(Duration::from_millis(5)))
                    .expect("poll drain2");
            }
            let mut down = Vec::new();
            let down_start = Instant::now();
            while !down.ends_with(b"down!") {
                assert!(
                    down_start.elapsed() < Duration::from_secs(2),
                    "peer never received the down bytes"
                );
                match peer_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => down.extend_from_slice(&tmp[..n]),
                    Err(_) => std::thread::yield_now(),
                }
            }
            assert_eq!(
                down,
                b"down!".to_vec(),
                "origin bytes must reach the client intact across the drain"
            );
            assert!(
                serving.slots[index].client.is_none(),
                "both directions drained must drop the client exactly once"
            );
            assert!(
                serving.slots[index].upstream.is_none(),
                "both directions drained must drop the upstream exactly once"
            );
        });
    }

    #[test]
    fn sink_drain_of_client_upstream_resumes_paused_client_source() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
                ws.buf_len = 6;
                ws.fwd = 4;
                ws.buf[..6].copy_from_slice(b"HEAD!A");
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");

            peer_stream.write_all(b"Z").expect("client byte pending");

            let mut tmp = [0u8; 64];
            let mut got = Vec::new();
            let start = Instant::now();
            let _ = sink_stream.set_read_timeout(Some(Duration::from_millis(50)));
            while got.len() < 3 {
                assert!(
                    start.elapsed() < Duration::from_secs(3),
                    "a paused client source was never resumed after the upstream sink drained"
                );
                serving
                    .upstream_writable(index)
                    .expect("drain + resume visit");
                if let Ok(n) = sink_stream.read(&mut tmp) {
                    got.extend_from_slice(&tmp[..n]);
                }
                std::thread::yield_now();
            }
            assert_eq!(
                got,
                b"!AZ".to_vec(),
                "an upstream sink drain must resume the paused client read without a new edge"
            );
        });
    }

    #[test]
    fn direct_tail_up_read_commits_read_count_once_at_tail_offset() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;
            let _ = sink_stream.set_nonblocking(true);

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            let payload = test_offset_pattern(137, 17);
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
                ws.fwd = 0;
                ws.buf[..CHUNK].fill(0xA5);
                ws.buf_len = 0;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");

            peer_stream
                .write_all(&payload)
                .expect("write direct-read payload");
            let avail = Instant::now() + Duration::from_secs(2);
            while serving.slots[index]
                .client
                .as_ref()
                .expect("client present")
                .peek(&mut [0u8; 1])
                .is_err()
            {
                assert!(
                    Instant::now() < avail,
                    "the direct-read payload never became readable"
                );
                std::thread::yield_now();
            }

            serving
                .client_readable(index)
                .expect("direct up read visit");

            let n = {
                let ws = &serving.slots[index];
                let n = ws.buf_len;
                assert!(
                    (1..=payload.len()).contains(&n),
                    "the retained up tail must advance by exactly the returned read count, got {n}"
                );
                assert_eq!(
                    &ws.buf[..n],
                    &payload[..n],
                    "the payload must reside at the retained ustream tail offset, once, \
                     unduplicated"
                );
                assert_eq!(
                    ws.buf[n], 0xA5,
                    "the byte immediately after the committed read count must be untouched: \
                     a second commit would overwrite it"
                );
                n
            };

            let mut got = Vec::new();
            let mut tmp = [0u8; 64];
            let deadline = Instant::now() + Duration::from_secs(2);
            while got.len() < n && Instant::now() < deadline {
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(m) => got.extend_from_slice(&tmp[..m]),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::yield_now();
                    }
                    Err(_) => break,
                }
            }
            assert_eq!(
                got,
                payload[..n],
                "the directly-read payload must reach the upstream sink byte-exact"
            );
        });
    }

    #[test]
    fn direct_tail_down_read_commits_read_count_once_at_tail_offset() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let origin_l = StdListener::bind("127.0.0.1:0").expect("origin bind");
            let origin_addr = origin_l.local_addr().expect("origin addr");
            let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
            let mut origin = origin_l.accept().expect("accept origin side").0;
            origin.set_nonblocking(true).expect("origin nonblocking");

            let index = 0;
            let payload = test_offset_pattern(137, 29);
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
                ws.fwd = 0;
                ws.client = None;
                ws.down[..CHUNK].fill(0xA5);
                ws.down_len = 0;
                ws.down_off = 0;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            origin.write_all(&payload).expect("write down payload");
            let avail = Instant::now() + Duration::from_secs(2);
            while serving.slots[index]
                .upstream
                .as_ref()
                .expect("upstream present")
                .peek(&mut [0u8; 1])
                .is_err()
            {
                assert!(
                    Instant::now() < avail,
                    "the down payload never became readable"
                );
                std::thread::yield_now();
            }

            serving
                .relay_upstream_to_client(index)
                .expect("direct down read visit");

            let ws = &serving.slots[index];
            let n = ws.down_len;
            assert!(
                (1..=payload.len()).contains(&n),
                "the retained down tail must advance by exactly the returned read count, got {n}"
            );
            assert_eq!(
                &ws.down[..n],
                &payload[..n],
                "the payload must reside at the retained down tail offset, once, unduplicated"
            );
            assert_eq!(
                ws.down[n], 0xA5,
                "the byte immediately after the committed down count must be untouched: a \
                 second commit would overwrite it"
            );
            assert!(
                serving.slots[index].upstream.is_some(),
                "a stalled down flush must keep the upstream socket and the tunnel open"
            );
        });
    }

    #[test]
    fn visit_budget_exhausts_on_ops_or_bytes_whichever_first() {
        let mut v = VisitState::live(0);
        assert!(!v.exhausted());
        for _ in 0..15 {
            v = v.note(1);
        }
        assert!(!v.exhausted(), "15 ops at 1 byte stay within the budget");
        v = v.note(1);
        assert!(
            v.exhausted(),
            "the 16th op exhausts the visit before the byte cap"
        );
        assert_eq!(
            v,
            VisitState::Live {
                slot: 0,
                ops: 16,
                bytes: 16,
            }
        );

        let mut v = VisitState::live(0);
        v = v.note(32 * 1024);
        assert!(!v.exhausted());
        v = v.note(32 * 1024);
        assert!(v.exhausted(), "64 KiB combined exhausts before 16 ops");
        assert_eq!(
            v,
            VisitState::Live {
                slot: 0,
                ops: 2,
                bytes: 64 * 1024,
            }
        );

        let mut v = VisitState::live(0);
        for _ in 0..15 {
            v = v.note(0);
        }
        assert!(!v.exhausted());
        v = v.note(0);
        assert!(
            v.exhausted(),
            "a WouldBlock/spurious attempt counts as an I/O operation (:146,:226)"
        );

        let idle = VisitState::idle();
        assert!(!idle.exhausted(), "an idle (non-visit) budget never trips");
        assert_eq!(idle.ops(), 0, "an idle visit owns no ops");
    }

    #[test]
    fn batch_progress_rechecks_timers_before_the_visit_that_would_cross() {
        let mut p = BatchProgress::default();
        for _ in 0..15 {
            assert!(
                !p.due(),
                "the visit about to run stays inside 256, no recheck before dispatch"
            );
            p.accrue(16);
        }
        assert_eq!(p.work_since_recheck, 255);
        assert!(
            p.due(),
            "255 units + the next visit's 17 units = 272 > 256, the recheck must precede it"
        );
        p.work_since_recheck = 0;
        assert!(!p.due());
        p.accrue(16);
        assert_eq!(
            p.work_since_recheck, 17,
            "the boundary visit runs fully within the swept budget"
        );

        let p = BatchProgress {
            work_since_recheck: 239,
        };
        assert!(
            !p.due(),
            "239 + 17 = 256 lands exactly on the bound, so no early recheck"
        );
        let p = BatchProgress {
            work_since_recheck: 240,
        };
        assert!(
            p.due(),
            "240 + 17 crosses the bound, the recheck fires before the visit"
        );
    }

    #[test]
    fn one_batch_two_tokens_one_slot_share_a_single_complete_visit() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");

            let got = std::sync::Arc::new(std::sync::Mutex::new(0usize));
            let got_reader = std::sync::Arc::clone(&got);
            let sink_reader = std::thread::spawn(move || {
                let mut tmp = [0u8; 65536];
                loop {
                    match sink_stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => *got_reader.lock().unwrap() += n,
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });

            let payload = test_offset_pattern(192 * 1024, 7);
            peer_stream.write_all(&payload).expect("write burst");
            let avail_start = Instant::now();
            while serving.slots[index]
                .client
                .as_ref()
                .expect("client present")
                .peek(&mut [0u8; 1])
                .is_err()
            {
                assert!(
                    avail_start.elapsed() < Duration::from_secs(2),
                    "the client burst never became readable"
                );
                std::thread::yield_now();
            }

            let client_token = client_token(serving.slots[index].slot_gen, index);
            let up_token = upstream_token(serving.slots[index].slot_gen, index);
            let before = serving.slots[index].fwd;
            serving.in_batch = true;
            serving
                .dispatch_readiness(
                    client_token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("batch client-readable token");
            serving
                .dispatch_readiness(
                    up_token,
                    Readiness {
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("batch upstream-writable token");
            serving.in_batch = false;

            let after = serving.slots[index].fwd;
            let sink_total = *got.lock().unwrap();
            assert!(
                after - before <= 64 * 1024,
                "one batch with both arms of one slot must stay inside one 64 KiB visit, moved {}",
                after - before
            );
            assert!(
                sink_total <= 64 * 1024,
                "sink bytes across the batch must stay inside one 64 KiB visit, got {sink_total}"
            );
            match serving.visit {
                VisitState::Live { ops, bytes, .. } => {
                    assert!(
                        ops <= 16,
                        "the shared visit owns at most 16 ops, recorded {ops}"
                    );
                    assert!(
                        bytes <= 64 * 1024,
                        "the shared visit owns at most 64 KiB, recorded {bytes}"
                    );
                }
                VisitState::Idle => {}
            }

            drop(peer_stream);
            serving.close_slot(index);
            sink_reader.join().expect("sink reader");
        });
    }

    #[test]
    fn eof_read_attempts_count_toward_the_shared_visit_budget() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let sink_stream = sink.accept().expect("accept sink side").0;

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");

            peer_stream
                .shutdown(std::net::Shutdown::Write)
                .expect("client fin");
            let avail = Instant::now();
            while serving.slots[index]
                .client
                .as_ref()
                .expect("client present")
                .peek(&mut [0u8; 1])
                .is_err()
            {
                assert!(
                    avail.elapsed() < Duration::from_secs(2),
                    "client FIN never became readable"
                );
                std::thread::yield_now();
            }

            let client_token = client_token(serving.slots[index].slot_gen, index);

            serving.in_batch = true;
            serving.batch_gen = serving.batch_gen.wrapping_add(1);
            serving
                .dispatch_readiness(
                    client_token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("client-readable dispatch");

            assert_eq!(
                serving.visit.ops(),
                1,
                "the up-flow EOF read must consume exactly one visit op, recorded {:?}",
                serving.visit
            );

            let _ = sink_stream.set_write_timeout(Some(Duration::from_millis(100)));
            sink_stream
                .shutdown(std::net::Shutdown::Write)
                .expect("upstream fin");
            let avail2 = Instant::now();
            while serving.slots[index]
                .upstream
                .as_ref()
                .expect("upstream present")
                .peek(&mut [0u8; 1])
                .is_err()
            {
                assert!(
                    avail2.elapsed() < Duration::from_secs(2),
                    "upstream FIN never became readable"
                );
                std::thread::yield_now();
            }

            let up_token = upstream_token(serving.slots[index].slot_gen, index);
            serving
                .dispatch_readiness(
                    up_token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("upstream-readable dispatch");
            serving.in_batch = false;

            assert_eq!(
                serving.visit.ops(),
                2,
                "the down-flow EOF read must raise the total to exactly two visit ops \
                 (one per EOF read), recorded {:?}",
                serving.visit
            );
            assert!(
                serving.slots[index].client.is_none() && serving.slots[index].upstream.is_none(),
                "both-EOF drained must close the slot exactly once"
            );
        });
    }

    #[test]
    fn listener_yield_at_recheck_rearms_for_queued_clients_without_new_connects() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let mut clients = Vec::new();
            for _ in 0..6 {
                clients.push(connect(port));
            }
            serving.progress.work_since_recheck = 237;
            serving
                .run_once(Some(Duration::from_millis(2)))
                .expect("the first real poll consumes the listener edge");
            let first_wave = serving.storage().occupied();
            assert_eq!(
                first_wave, 2,
                "the preset ledger must make the accept turn yield mid-backlog after a bounded \
                 admit (2), not drain the queue in one poll: admitted {first_wave}"
            );
            assert!(
                serving.progress.work_since_recheck <= 256,
                "the accept turn never pushes the ledger past the canonical 256-unit bound"
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            while serving.storage().occupied() < clients.len() {
                assert!(
                    Instant::now() < deadline,
                    "pre-queued clients must be admitted on later polls via the listener re-arm \
                     alone (no new connects ever arrive): occupied {} of {}",
                    serving.storage().occupied(),
                    clients.len()
                );
                serving
                    .run_once(Some(Duration::from_millis(2)))
                    .expect("resume poll");
            }
            assert_eq!(
                serving.storage().occupied(),
                clients.len(),
                "all six pre-queued clients are admitted across later polls with no new connects"
            );
            for c in clients {
                let _ = c.shutdown(std::net::Shutdown::Both);
            }
        });
    }

    #[test]
    fn interleaved_a_b_a_mixed_readwrite_timer_preserves_shared_budgets() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let expected_a = 96 * 1024;
            let expected_b = 96 * 1024;
            let pattern_a = test_offset_pattern(expected_a, 1);
            let pattern_b = test_offset_pattern(expected_b, 2);

            let got_a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let got_b = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

            let mut readers = Vec::new();
            let mut peers = Vec::new();
            for (index, pattern) in [(0usize, &pattern_a), (1, &pattern_b)] {
                let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
                let sink_addr = sink.local_addr().expect("sink addr");
                let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
                let mut sink_stream = sink.accept().expect("accept sink side").0;
                sink_stream.set_nonblocking(true).expect("sink nonblocking");

                let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
                let peer_addr = peer_l.local_addr().expect("peer addr");
                let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
                let mut peer_stream = peer_l.accept().expect("accept peer side").0;

                {
                    let ws = &mut serving.slots[index];
                    ws.upstream = Some(up);
                    ws.client = Some(client);
                    ws.stage = Stage::Relay;
                    ws.head_len = 4;
                    ws.buf_base = 0;
                }
                open_relay(serving, index);
                serving.register_upstream(index).expect("register up");
                serving.register_client(index).expect("register client");

                peer_stream
                    .write_all(pattern)
                    .expect("preload client pattern before poll");

                let lane_got = if index == 0 {
                    std::sync::Arc::clone(&got_a)
                } else {
                    std::sync::Arc::clone(&got_b)
                };
                let lane_stop = std::sync::Arc::clone(&stop);
                let reader = std::thread::spawn(move || {
                    let mut tmp = [0u8; 65536];
                    loop {
                        if lane_stop.load(std::sync::atomic::Ordering::SeqCst) {
                            break;
                        }
                        match sink_stream.read(&mut tmp) {
                            Ok(0) => break,
                            Ok(n) => lane_got.lock().unwrap().extend_from_slice(&tmp[..n]),
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            Err(_) => break,
                        }
                    }
                });
                readers.push(reader);
                peers.push(peer_stream);
            }

            serving.batch_gen = serving.batch_gen.wrapping_add(1);
            let gen_a = serving.slots[0].slot_gen;
            let gen_b = serving.slots[1].slot_gen;
            serving.in_batch = true;
            let a_token = client_token(gen_a, 0);
            let b_token = client_token(gen_b, 1);
            let a_up_token = upstream_token(gen_a, 0);
            let a0 = serving.slots[0].fwd;
            serving
                .dispatch_readiness(
                    a_token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("A client-readable batch token");
            let a1 = serving.slots[0].fwd;
            serving
                .dispatch_readiness(
                    b_token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("B client-readable batch token");
            let b_ops_after_visit = match serving.visit {
                VisitState::Live { ops, .. } => ops,
                _ => unreachable!("B's visit is live after its first token"),
            };
            serving
                .dispatch_readiness(
                    a_up_token,
                    Readiness {
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("A upstream-writable batch token");
            let a2 = serving.slots[0].fwd;
            serving.in_batch = false;

            assert!(
                a1 - a0 <= 64 * 1024,
                "A's first batch token must stay inside one 64 KiB visit, moved {}",
                a1 - a0
            );
            assert!(
                a2 == a1,
                "A's upstream-writable token while B's visit is live must defer (reschedule), \
                 not advance A: moved {} -> {}",
                a1,
                a2
            );
            assert!(
                matches!(serving.visit, VisitState::Live { slot: 1, ops, .. } if ops == b_ops_after_visit),
                "A's deferred arm must not be charged to B's live visit; B's visit unchanged: {:?}",
                serving.visit
            );

            let mut pumps = 0;
            while pumps < 2000 {
                let done_a = got_a.lock().unwrap().len() >= expected_a;
                let done_b = got_b.lock().unwrap().len() >= expected_b;
                if done_a && done_b {
                    break;
                }
                serving
                    .run_once(Some(Duration::from_millis(2)))
                    .expect("interleaved real-poll drain poll");
                pumps += 1;
            }
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let tail_a = got_a.lock().unwrap().clone();
            let tail_b = got_b.lock().unwrap().clone();
            readers.remove(0).join().expect("sink reader A");
            readers.remove(0).join().expect("sink reader B");

            drop(peers);

            assert!(
                tail_a.len() >= expected_a && tail_b.len() >= expected_b,
                "both hot slots must be serviced repeatedly with no starvation: A {} / {} B {} / {}",
                tail_a.len(),
                expected_a,
                tail_b.len(),
                expected_b
            );
            assert_eq!(
                &tail_a[..expected_a],
                &pattern_a[..],
                "A's client bytes must arrive byte-exact at the upstream sink"
            );
            assert_eq!(
                &tail_b[..expected_b],
                &pattern_b[..],
                "B's client bytes must arrive byte-exact at the upstream sink"
            );

            serving.slots[0].idle_deadline = Some(Instant::now() - Duration::from_millis(1));
            serving
                .run_once(Some(Duration::from_millis(2)))
                .expect("sweep poll");
            assert!(
                matches!(serving.slots[0].stage, Stage::Idle),
                "one expired relay timer must be swept on the next owner turn (slot 0 was not idle)"
            );
            assert!(
                matches!(serving.slots[1].stage, Stage::Relay),
                "the timer sweep must not touch the other hot slot (slot 1 was not relay)"
            );
        });
    }

    #[test]
    fn retained_edge_reschedules_through_run_once_with_silent_peer() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");

            let got = std::sync::Arc::new(std::sync::Mutex::new(0usize));
            let got_reader = std::sync::Arc::clone(&got);
            let sink_reader = std::thread::spawn(move || {
                let mut tmp = [0u8; 65536];
                loop {
                    match sink_stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => *got_reader.lock().unwrap() += n,
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });

            let payload = test_offset_pattern(384 * 1024, 5);
            let payload_len = payload.len();
            let writer = std::thread::spawn(move || {
                peer_stream.write_all(&payload).expect("burst");
                peer_stream
                    .shutdown(std::net::Shutdown::Write)
                    .expect("peer half-close");
            });

            let start = Instant::now();
            while *got.lock().unwrap() < payload_len {
                assert!(
                    start.elapsed() < Duration::from_secs(20),
                    "the silent peer's relay tail stalled through real run_once: got {} of {}",
                    *got.lock().unwrap(),
                    payload_len
                );
                serving
                    .run_once(Some(Duration::from_millis(10)))
                    .expect("poll turns the relay forward");
            }
            writer.join().expect("peer writer");
            serving.close_slot(index);
            sink_reader.join().expect("sink reader");
            assert_eq!(
                *got.lock().unwrap(),
                payload_len,
                "bytes relayed via real run_once from a silent peer must be byte-exact"
            );
        });
    }

    #[test]
    fn one_relay_visit_never_exceeds_the_combined_io_budget() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;
            let _ = sink_stream.set_read_timeout(Some(Duration::from_millis(50)));

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.stage = Stage::Relay;
                ws.head_len = 0;
                ws.buf_base = 0;
                ws.buf_len = 128 * 1024;
                ws.fwd = 0;
                ws.buf[..128 * 1024].copy_from_slice(&test_offset_pattern(128 * 1024, 9));
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");

            let token = upstream_token(serving.slots[index].slot_gen, index);
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("one writable relay visit");

            let moved = serving.slots[index].fwd;
            assert!(
                moved <= 64 * 1024,
                "one connection visit must forward at most 64 KiB combined, forwarded {moved}"
            );
            assert!(
                moved > 0 && serving.slots[index].fwd < serving.slots[index].buf_len,
                "128 KiB pending must span more than one visit"
            );

            let mut total = moved;
            let drain_start = Instant::now();
            while serving.slots[index].fwd < serving.slots[index].buf_len {
                assert!(
                    drain_start.elapsed() < Duration::from_secs(3),
                    "the rescheduled relay visit never resumed the pending upload"
                );
                serving
                    .dispatch_readiness(
                        token,
                        Readiness {
                            writable: true,
                            ..Readiness::none()
                        },
                    )
                    .expect("resumed writable visit");
                total = serving.slots[index].fwd;
            }

            let mut got = 0usize;
            let mut tmp = [0u8; 4096];
            let recv_start = Instant::now();
            while got < total {
                assert!(
                    recv_start.elapsed() < Duration::from_secs(3),
                    "the sink never received all forwarded bytes"
                );
                match sink_stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => got += n,
                    Err(_) => std::thread::yield_now(),
                }
            }
            assert_eq!(
                got, total,
                "bytes forwarded across budget-split visits must arrive once, unduplicated"
            );
            assert!(
                serving.slots[index].stage == Stage::Relay,
                "a budget-split relay visit must not advance or close the tunnel"
            );
        });
    }

    #[test]
    fn preloaded_hold_drains_across_budget_splits_with_quiescent_sink_relying_on_rearm() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let sink_stream = sink.accept().expect("accept sink side").0;
            let _ = sink_stream.set_nonblocking(true);

            let index = 0;
            let hold = 96 * 1024;
            let pattern = test_offset_pattern(hold, 4);
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
                ws.fwd = 0;
                ws.buf[..hold].copy_from_slice(&pattern);
                ws.buf_len = hold;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");

            let mut progress_polls = 0usize;
            let mut last_fwd = 0usize;
            let deadline = Instant::now() + Duration::from_secs(5);
            while serving.slots[index].fwd < hold {
                assert!(
                    Instant::now() < deadline,
                    "the quiescent-sink drain must cross the 64 KiB budget split across real \
                     polls with no peer consumption to re-trigger it: fwd {} of {}",
                    serving.slots[index].fwd,
                    hold
                );
                serving
                    .run_once(Some(Duration::from_millis(5)))
                    .expect("real poll drives the re-armed drain");
                if serving.slots[index].fwd > last_fwd {
                    progress_polls += 1;
                    last_fwd = serving.slots[index].fwd;
                }
            }
            assert!(
                progress_polls >= 2,
                "the 96 KiB preload must cross at least one 64 KiB budget split through real \
                 polls with the sink quiescent: saw {progress_polls} progress polls"
            );
            assert!(
                serving.slots[index].stage == Stage::Relay,
                "a budget-split drain must not advance or close the tunnel"
            );
            assert_eq!(
                serving.slots[index].fwd, hold,
                "the quiescent sink must have absorbed the full preloaded hold"
            );
            let _ = sink_stream;
        });
    }

    #[test]
    fn preloaded_hold_drains_across_budget_splits_byte_exact_with_consuming_sink() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;
            let _ = sink_stream.set_nonblocking(true);

            let index = 0;
            let hold = 96 * 1024;
            let pattern = test_offset_pattern(hold, 4);
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
                ws.fwd = 0;
                ws.buf[..hold].copy_from_slice(&pattern);
                ws.buf_len = hold;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");

            let stop_reader = Arc::new(AtomicBool::new(false));
            let sink_got = Arc::new(Mutex::new(Vec::new()));
            let reader_stop = Arc::clone(&stop_reader);
            let reader_got = Arc::clone(&sink_got);
            let reader = std::thread::spawn(move || {
                let mut tmp = [0u8; 65536];
                loop {
                    if reader_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    match sink_stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => reader_got.lock().unwrap().extend_from_slice(&tmp[..n]),
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });

            let mut progress_polls = 0usize;
            let mut last_fwd = 0usize;
            let deadline = Instant::now() + Duration::from_secs(5);
            while serving.slots[index].fwd < hold || sink_got.lock().unwrap().len() < hold {
                assert!(
                    Instant::now() < deadline,
                    "preloaded hold stalled mid-drain with the sink peer consuming: fwd {} / \
                     {}, sink got {} / {}",
                    serving.slots[index].fwd,
                    hold,
                    sink_got.lock().unwrap().len(),
                    hold
                );
                serving
                    .run_once(Some(Duration::from_millis(5)))
                    .expect("real poll drives the drained hold");
                if serving.slots[index].fwd > last_fwd {
                    progress_polls += 1;
                    last_fwd = serving.slots[index].fwd;
                }
            }
            assert!(
                progress_polls >= 2,
                "the 96 KiB preload must span at least two 64 KiB budget-split polls, saw \
                 {progress_polls}"
            );
            assert!(
                serving.slots[index].stage == Stage::Relay,
                "a budget-split drain must not advance or close the tunnel"
            );
            stop_reader.store(true, Ordering::SeqCst);
            reader.join().expect("sink reader");
            let got = sink_got.lock().unwrap().clone();
            assert_eq!(
                got,
                pattern,
                "the drained hold must reach the sink byte-exact (offset-distinguishing pattern): \
                 got {}B",
                got.len()
            );
        });
    }

    #[test]
    fn read_direction_held_peer_drains_across_budget_splits_without_new_edges() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;
            let _ = sink_stream.set_nonblocking(true);

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            let hold = 96 * 1024;
            let pattern = test_offset_pattern(hold, 23);
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
                ws.fwd = 0;
                ws.buf_len = 0;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");

            peer_stream
                .write_all(&pattern)
                .expect("preload the full burst before the first real poll");

            let mut probe = vec![0u8; hold];
            let queue_deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let queued = match serving.slots[index]
                    .client
                    .as_ref()
                    .expect("client present")
                    .peek(&mut probe)
                {
                    Ok(n) => n,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => 0,
                    Err(e) => panic!("peek exact queued length: {e}"),
                };
                if queued >= hold {
                    break;
                }
                assert!(
                    Instant::now() < queue_deadline,
                    "the proxy-side client fd never queued the full {hold}-byte preload, peeked \
                     {queued}"
                );
                std::thread::sleep(Duration::from_millis(1));
            }

            let stop_reader = Arc::new(AtomicBool::new(false));
            let sink_got = Arc::new(Mutex::new(Vec::new()));
            let reader_stop = Arc::clone(&stop_reader);
            let reader_got = Arc::clone(&sink_got);
            let reader = std::thread::spawn(move || {
                let mut tmp = [0u8; 65536];
                loop {
                    if reader_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    match sink_stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => reader_got.lock().unwrap().extend_from_slice(&tmp[..n]),
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });

            let mut progress_polls = 0usize;
            let mut last_fwd = 0usize;
            let deadline = Instant::now() + Duration::from_secs(5);
            while serving.slots[index].fwd < hold {
                assert!(
                    Instant::now() < deadline,
                    "the held-peer read-direction drain stalled without a re-armed client \
                     READABLE edge: fwd {} of {}",
                    serving.slots[index].fwd,
                    hold
                );
                serving
                    .run_once(Some(Duration::from_millis(5)))
                    .expect("real poll drives the read-direction relay");
                if serving.slots[index].fwd > last_fwd {
                    progress_polls += 1;
                    last_fwd = serving.slots[index].fwd;
                }
            }
            let flush_deadline = Instant::now() + Duration::from_secs(5);
            while sink_got.lock().unwrap().len() < hold {
                assert!(
                    Instant::now() < flush_deadline,
                    "the sink reader never flushed all {hold} relayed bytes"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            stop_reader.store(true, Ordering::SeqCst);
            reader.join().expect("sink reader");
            drop(peer_stream);
            let got = sink_got.lock().unwrap().clone();
            assert_eq!(
                got,
                pattern,
                "the held-peer read-direction relay must reach the sink byte-exact: got {}B",
                got.len()
            );
            assert!(
                progress_polls >= 2,
                "the >64 KiB peer preload with a silent peer must cross at least one 64 KiB \
                 budget split through a re-armed client READABLE edge, saw {progress_polls} \
                 progress polls"
            );
            assert!(
                serving.slots[index].stage == Stage::Relay,
                "a budget-split read drain must not advance or close the tunnel"
            );
        });
    }

    #[test]
    fn client_read_visit_shares_combined_read_write_budget() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;
            let _ = sink_stream.set_nonblocking(true);

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");

            let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let received_reader = std::sync::Arc::clone(&received);
            let sink_reader = std::thread::spawn(move || {
                let mut tmp = [0u8; 16384];
                loop {
                    match sink_stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => received_reader.lock().unwrap().extend_from_slice(&tmp[..n]),
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });

            let payload = test_offset_pattern(96 * 1024, 10);
            peer_stream.write_all(&payload).expect("write burst");

            let token = client_token(serving.slots[index].slot_gen, index);
            let avail_start = Instant::now();
            while !serving.slots[index]
                .client
                .as_ref()
                .expect("client present")
                .peek(&mut [0u8; 1])
                .is_ok()
            {
                assert!(
                    avail_start.elapsed() < Duration::from_secs(2),
                    "the client burst never became readable"
                );
                std::thread::yield_now();
            }

            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("one client-readable visit");

            assert!(
                serving.visit.exhausted(),
                "a large read+write burst must exhaust the complete-visit budget in one visit"
            );

            let start = Instant::now();
            while received.lock().unwrap().len() < payload.len() {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "the rescheduled client burst never fully relayed"
                );
                serving
                    .dispatch_readiness(
                        token,
                        Readiness {
                            readable: true,
                            ..Readiness::none()
                        },
                    )
                    .expect("resume client visit");
                std::thread::sleep(Duration::from_millis(1));
            }
            drop(peer_stream);
            serving.close_slot(index);
            sink_reader.join().expect("sink reader");
            let got = received.lock().unwrap().len();
            assert_eq!(
                got,
                payload.len(),
                "bytes relayed across budget-split visits must arrive intact and once"
            );
        });
    }

    #[test]
    fn four_mib_up_stream_survives_budget_split_visits_byte_conserved() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");

            let got = std::sync::Arc::new(std::sync::Mutex::new(0usize));
            let got_reader = std::sync::Arc::clone(&got);
            let sink_reader = std::thread::spawn(move || {
                let mut tmp = [0u8; 65536];
                loop {
                    match sink_stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => *got_reader.lock().unwrap() += n,
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });

            let payload = test_offset_pattern(4 * 1024 * 1024, 3);
            let payload_len = payload.len();
            let writer = std::thread::spawn(move || {
                let payload_clone = payload.clone();
                peer_stream.write_all(&payload_clone).expect("4 MiB burst");
                peer_stream
                    .shutdown(std::net::Shutdown::Write)
                    .expect("client half-close");
            });

            let client_token = client_token(serving.slots[index].slot_gen, index);
            let up_token = upstream_token(serving.slots[index].slot_gen, index);
            let start = Instant::now();
            while *got.lock().unwrap() < payload_len {
                assert!(
                    start.elapsed() < Duration::from_secs(20),
                    "4 MiB up relay never reached the sink: got {}",
                    *got.lock().unwrap()
                );
                serving
                    .dispatch_readiness(
                        client_token,
                        Readiness {
                            readable: true,
                            ..Readiness::none()
                        },
                    )
                    .expect("client-readable visit");
                serving
                    .dispatch_readiness(
                        up_token,
                        Readiness {
                            writable: true,
                            ..Readiness::none()
                        },
                    )
                    .expect("upstream-writable visit");
                if serving.slots[index].upstream.is_none() {
                    break;
                }
            }
            writer.join().expect("peer writer");
            serving.close_slot(index);
            sink_reader.join().expect("sink reader");
            let got_total = *got.lock().unwrap();
            assert_eq!(
                got_total, payload_len,
                "bytes relayed across budget-split visits must be conserved end to end"
            );
        });
    }

    #[test]
    fn four_mib_down_stream_survives_budget_split_visits_byte_conserved() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let origin_l = StdListener::bind("127.0.0.1:0").expect("origin bind");
            let origin_addr = origin_l.local_addr().expect("origin addr");
            let up = mio::net::TcpStream::connect(origin_addr).expect("upstream connect");
            let mut origin = origin_l.accept().expect("accept origin side").0;

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");

            let payload = test_offset_pattern(4 * 1024 * 1024, 6);
            let payload_len = payload.len();
            let writer_payload = payload.clone();
            let origin_writer = std::thread::spawn(move || {
                origin.write_all(&writer_payload).expect("4 MiB down burst");
                origin
                    .shutdown(std::net::Shutdown::Write)
                    .expect("origin FIN");
            });

            let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let got_reader = std::sync::Arc::clone(&got);
            let client_reader = std::thread::spawn(move || {
                let mut tmp = [0u8; 65536];
                loop {
                    match peer_stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => got_reader.lock().unwrap().extend_from_slice(&tmp[..n]),
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });

            let up_token = upstream_token(serving.slots[index].slot_gen, index);
            let client_token2 = client_token(serving.slots[index].slot_gen, index);
            let start = Instant::now();
            while got.lock().unwrap().len() < payload_len {
                assert!(
                    start.elapsed() < Duration::from_secs(20),
                    "4 MiB down relay never reached the client: got {}",
                    got.lock().unwrap().len()
                );
                serving
                    .dispatch_readiness(
                        up_token,
                        Readiness {
                            readable: true,
                            ..Readiness::none()
                        },
                    )
                    .expect("upstream-readable visit");
                serving
                    .dispatch_readiness(
                        client_token2,
                        Readiness {
                            writable: true,
                            ..Readiness::none()
                        },
                    )
                    .expect("client-writable visit");
                if serving.slots[index].client.is_none() {
                    break;
                }
            }
            origin_writer.join().expect("origin writer");
            serving.close_slot(index);
            client_reader.join().expect("client reader");
            let got_vec = got.lock().unwrap().clone();
            assert_eq!(
                got_vec, payload,
                "down bytes relayed across budget-split visits must arrive byte-exact"
            );
        });
    }

    #[test]
    fn full_down_buffer_applies_backpressure_not_false_eof() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let upstream_peer_l = StdListener::bind("127.0.0.1:0").expect("upstream peer bind");
            let upstream_peer_addr = upstream_peer_l.local_addr().expect("upstream peer addr");
            let up = mio::net::TcpStream::connect(upstream_peer_addr).expect("upstream connect");
            let mut upstream_peer = upstream_peer_l
                .accept()
                .expect("accept upstream peer side")
                .0;

            let client_peer_l = StdListener::bind("127.0.0.1:0").expect("client peer bind");
            let client_peer_addr = client_peer_l.local_addr().expect("client peer addr");
            let client = mio::net::TcpStream::connect(client_peer_addr).expect("client connect");
            let client_peer = client_peer_l.accept().expect("accept client peer side").0;
            let _ = client_peer.set_read_timeout(Some(Duration::from_millis(100)));

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
                ws.fwd = 0;
                ws.down[..6].copy_from_slice(b"HELLOA");
                ws.down_len = DOWN_CAP - 1;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");
            upstream_peer
                .write_all(b"more")
                .expect("upstream data available with no room");

            let up_token = upstream_token(serving.slots[index].slot_gen, index);
            serving
                .dispatch_readiness(
                    up_token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("no-room upstream-readable visit");

            assert!(
                matches!(serving.slots[index].stage, Stage::Relay),
                "a full down buffer must apply backpressure, not close the tunnel"
            );
            assert_eq!(
                serving.slots[index].down_len,
                DOWN_CAP - 1,
                "no bytes may be read into a zero-room down buffer"
            );
            assert!(
                serving.slots[index].upstream.is_some(),
                "a no-room upstream-readable visit must never false-EOF the upstream"
            );
            assert!(
                serving.slots[index].client.is_some(),
                "the downstream client socket must be retained under backpressure"
            );

            assert_eq!(
                serving.slots[index].down_len,
                DOWN_CAP - 1,
                "backpressure must not consume the pending downstream payload"
            );
        });
    }

    #[test]
    fn stalled_reverse_fin_drains_exact_bytes_then_closes_once() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let client_peer_l = StdListener::bind("127.0.0.1:0").expect("client peer bind");
            let client_peer_addr = client_peer_l.local_addr().expect("client peer addr");
            let client = mio::net::TcpStream::connect(client_peer_addr).expect("client connect");
            let mut client_peer = client_peer_l.accept().expect("accept client peer side").0;
            let _ = client_peer.set_read_timeout(Some(Duration::from_millis(20)));

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
                ws.directional.down = SideEof::Open;
                let payload = b"STALLED-REVERSE-PAYLOAD-0123456789";
                ws.down[..payload.len()].copy_from_slice(payload);
                ws.down_len = payload.len();
                ws.down_off = 0;
            }
            open_relay(serving, index);
            serving.register_client(index).expect("register client");

            serving
                .observe_down_eof(index)
                .expect("observe stalled reverse FIN");
            assert!(
                matches!(
                    serving.slots[index].directional.down,
                    SideEof::Eof { half_closed: false }
                ),
                "the reverse EOF must be recorded as half-close pending while bytes remain buffered"
            );
            assert!(
                matches!(serving.slots[index].stage, Stage::Relay),
                "a stalled reverse buffer must keep the tunnel open (no premature half-close/close)"
            );

            let expected = b"STALLED-REVERSE-PAYLOAD-0123456789";
            let mut got = Vec::new();
            let mut tmp = [0u8; 64];
            let drain_start = Instant::now();
            while got.len() < expected.len() {
                assert!(
                    drain_start.elapsed() < Duration::from_secs(5),
                    "stalled reverse FIN never drained: got {} of {}",
                    got.len(),
                    expected.len()
                );
                serving
                    .run_once(Some(Duration::from_millis(5)))
                    .expect("gate-vicinity run poll");
                match client_peer.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&tmp[..n]),
                    Err(_) => {}
                }
            }
            assert_eq!(
                got, expected,
                "the stalled reverse payload must arrive byte-exact after the buffer drains"
            );

            client_peer
                .shutdown(std::net::Shutdown::Write)
                .expect("client fin");
            let close_start = Instant::now();
            while !matches!(serving.slots[index].stage, Stage::Idle) {
                assert!(
                    close_start.elapsed() < Duration::from_secs(5),
                    "the slot never closed once both directions drained"
                );
                serving
                    .run_once(Some(Duration::from_millis(5)))
                    .expect("gate-vicinity run poll");
            }
        });
    }

    #[test]
    fn second_gateopening_drain_shares_the_single_visit_budget() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let sink_stream = sink.accept().expect("accept sink side").0;
            let _ = sink_stream.set_read_timeout(Some(Duration::from_millis(50)));

            let client = mio::net::TcpStream::connect(
                StdListener::bind("127.0.0.1:0")
                    .expect("peer bind")
                    .local_addr()
                    .expect("peer addr"),
            )
            .expect("client connect");

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::WritingHello;
                ws.head_len = 4;
                ws.buf_base = 0;
                ws.fwd = 0;
                ws.gate.on_connect_head(4);
                ws.gate.on_authorized();
                ws.gate.on_upstream_connected();
                ws.gate.on_response_ok();
                ws.gate.on_hello_validated(ValidatedHello::test_new(1024));

                ws.buf[..4].copy_from_slice(b"HEAD");
                let hello_region = test_offset_pattern(1020, 11);
                ws.buf[4..1024].copy_from_slice(&hello_region);
                let payload_region = test_offset_pattern(HOLD_CAP - 1024, 12);
                let mut filled = 1024;
                while filled < ws.buf.len() {
                    let chunk = (ws.buf.len() - filled).min(1024);
                    let window = filled - 1024;
                    ws.buf[filled..filled + chunk]
                        .copy_from_slice(&payload_region[window..window + chunk]);
                    filled += chunk;
                }
                ws.buf_len = ws.buf.len();
            }
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");
            assert!(
                !serving.slots[index].gate.is_open(),
                "the gate must still be closed before the crossing visit"
            );

            let _ = sink_stream.set_nonblocking(true);

            serving.in_batch = true;
            serving.batch_gen = serving.batch_gen.wrapping_add(1);
            let token = upstream_token(serving.slots[index].slot_gen, index);
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        writable: true,
                        ..Readiness::none()
                    },
                )
                .expect("one gate-crossing upstream-writable token");
            let consumed = match serving.visit {
                VisitState::Live { ops, bytes, .. } => (ops, bytes),
                _ => unreachable!("the gate-crossing visit stays live until end of batch"),
            };
            let fwd_after = serving.slots[index].fwd;
            let gate_open = serving.slots[index].gate.is_open();
            let stage_after = serving.slots[index].stage;
            serving.in_batch = false;

            assert!(
                gate_open && matches!(stage_after, Stage::Relay),
                "the single visit must succeed in opening the gate prior to relay (gate={gate_open})"
            );
            assert!(
                consumed.0 <= 16 && consumed.1 <= 64 * 1024,
                "pre-open drain + post-open second drain must share ONE visit budget: {} ops / {} bytes",
                consumed.0,
                consumed.1
            );
            assert!(
                fwd_after > 1024,
                "the crossing visit must forward past the validated hello boundary (fwd {})",
                fwd_after
            );
            assert_eq!(
                serving.slots[index].down_len, 0,
                "the up-flow gate must open before any downstream read occurs in the visit"
            );
        });
    }

    #[test]
    fn full_up_buffer_never_reads_into_zero_room_or_false_eofs() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;
            sink_stream.set_nonblocking(true).expect("sink nonblocking");

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.buf_base = 0;
                ws.fwd = 0;
                let pattern = test_offset_pattern(HOLD_CAP - 1, 13);
                ws.buf[..HOLD_CAP - 1].copy_from_slice(&pattern);
                ws.buf_len = HOLD_CAP - 1;
            }
            open_relay(serving, index);
            serving.register_client(index).expect("register client");
            serving.register_upstream(index).expect("register upstream");
            peer_stream
                .write_all(b"more")
                .expect("client data available with no room");

            let token = client_token(serving.slots[index].slot_gen, index);
            serving
                .dispatch_readiness(
                    token,
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("no-room readable visit");

            assert!(
                matches!(serving.slots[index].stage, Stage::Relay),
                "a full buffer must apply backpressure, not close the tunnel"
            );
            assert_eq!(
                serving.slots[index].buf_len,
                HOLD_CAP - 1,
                "no bytes may be read into a zero-room buffer"
            );
            assert!(
                serving.slots[index].client.is_some(),
                "a no-room readable visit must never false-EOF the client"
            );

            let expected = test_offset_pattern(HOLD_CAP - 1, 13);
            let stop_reader = Arc::new(AtomicBool::new(false));
            let sink_got = Arc::new(Mutex::new(Vec::new()));
            let reader_stop = Arc::clone(&stop_reader);
            let reader_got = Arc::clone(&sink_got);
            let reader = std::thread::spawn(move || {
                let mut tmp = [0u8; 65536];
                loop {
                    if reader_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    match sink_stream.read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => reader_got.lock().unwrap().extend_from_slice(&tmp[..n]),
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });

            let drain_deadline = Instant::now();
            while sink_got.lock().unwrap().len() < expected.len() + 4 {
                assert!(
                    drain_deadline.elapsed() < Duration::from_secs(3),
                    "the full upstream buffer must drain to the origin once room appears: \
                     sink got {} of {}, fwd {} buf_len {} client {}",
                    sink_got.lock().unwrap().len(),
                    expected.len() + 4,
                    serving.slots[index].fwd,
                    serving.slots[index].buf_len,
                    serving.slots[index].client.is_some()
                );
                serving
                    .run_once(Some(Duration::from_millis(5)))
                    .expect("real poll drives the drain and the follow-up head");
            }
            stop_reader.store(true, Ordering::SeqCst);
            reader.join().expect("sink reader");
            let got = sink_got.lock().unwrap().clone();
            let mut expected_tail = expected.clone();
            expected_tail.extend_from_slice(b"more");
            assert_eq!(
                got, expected_tail,
                "the drained buffer plus the pending client bytes must reach the origin byte-exact"
            );
        });
    }

    #[test]
    fn sink_drain_of_client_writes_resumes_paused_upstream_source() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
            let sink_addr = sink.local_addr().expect("sink addr");
            let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
            let mut sink_stream = sink.accept().expect("accept sink side").0;

            let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
            let peer_addr = peer_l.local_addr().expect("peer addr");
            let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
            let mut peer_stream = peer_l.accept().expect("accept peer side").0;

            let index = 0;
            {
                let ws = &mut serving.slots[index];
                ws.upstream = Some(up);
                ws.client = Some(client);
                ws.stage = Stage::Relay;
                ws.head_len = 4;
                ws.down[..4].copy_from_slice(b"DOWN");
                ws.down_len = 4;
                ws.down_off = 0;
            }
            open_relay(serving, index);
            serving.register_upstream(index).expect("register up");
            serving.register_client(index).expect("register client");

            sink_stream.write_all(b"+").expect("origin byte pending");

            let mut tmp = [0u8; 64];
            let mut got = Vec::new();
            let start = Instant::now();
            let _ = peer_stream.set_read_timeout(Some(Duration::from_millis(50)));
            while got.len() < 5 {
                assert!(
                    start.elapsed() < Duration::from_secs(3),
                    "a paused upstream source was never resumed after the client sink drained"
                );
                serving
                    .client_writable(index)
                    .expect("drain + resume visit");
                if let Ok(n) = peer_stream.read(&mut tmp) {
                    got.extend_from_slice(&tmp[..n]);
                }
                std::thread::yield_now();
            }
            assert_eq!(
                got,
                b"DOWN+".to_vec(),
                "a client sink drain must resume the paused upstream read without a new edge"
            );
        });
    }

    #[test]
    fn expiry_never_reinjects_after_a_begun_response() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let mut client = connect(port);
            client
                .set_read_timeout(Some(Duration::from_millis(50)))
                .expect("client read timeout");
            pump(serving, 20);
            assert_eq!(
                serving.storage().occupied(),
                1,
                "silent client must be admitted"
            );

            {
                let ws = &mut serving.slots[0];
                ws.down[..BODY_200.len()].copy_from_slice(BODY_200);
                ws.down_len = BODY_200.len();
                ws.down_off = 0;
                ws.stage = Stage::SendingConnected;
            }
            let start = Instant::now();
            while serving.storage().occupied() > 0 {
                serving.run_once(None).expect("block to expiry");
                assert!(
                    start.elapsed() <= Duration::from_secs(crate::worker::SETUP_DEADLINE_SECS + 5),
                    "a begun-response slot must be released at its deadline"
                );
            }
            let mut tail = Vec::new();
            let tail_deadline = Instant::now();
            loop {
                if tail_deadline.elapsed() > Duration::from_secs(2) {
                    break;
                }
                let mut tmp = [0u8; 256];
                match client.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => tail.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            assert!(
                tail.starts_with(b"HTTP/1.1 200"),
                "the begun 200 must not be overwritten on expiry, got {:?}",
                &tail[..tail.len().min(24)]
            );
            assert!(
                !tail.windows(12).any(|w| w == b"HTTP/1.1 504"),
                "no 504 may be spliced after a begun response on expiry"
            );
        });
    }

    #[test]
    fn sigterm_first_observation_enters_draining_and_stops_admission() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let client = connect(port);
            pump(serving, 40);
            assert_eq!(
                serving.storage().occupied(),
                1,
                "a connecting client must be admitted before the signal"
            );
            assert!(
                serving.listener.is_some(),
                "admission is open before the first SIGTERM"
            );

            serving
                .signal_wake_mut()
                .expect("the serving owns the self-pipe write end")
                .write_all(&[1])
                .expect("write the signal byte into the self-pipe");
            pump(serving, 40);
            assert!(
                serving.is_shutdown(),
                "a self-pipe signal must reach draining through the shared poll"
            );
            assert!(
                matches!(serving.shutdown(), Shutdown::Draining { .. }),
                "the first SIGTERM must enter the draining phase"
            );
            assert_eq!(
                serving.signal_read_error(),
                None,
                "a healthy self-pipe drain must not name a real read error"
            );
            assert!(
                serving.listener.is_none(),
                "the listener must be dropped, so no later connection can be accepted"
            );
            assert_eq!(
                serving.storage().occupied(),
                0,
                "a pending setup is closed at the first signal; established tunnels drain"
            );
            assert!(
                !serving.storage().dns().has_active_exchange(),
                "the retained DNS transport is cancelled at the first signal"
            );
            drop(client);
        });
    }

    #[test]
    fn sigterm_repeat_does_not_extend_the_deadline() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            serving.on_sigterm().expect("first SIGTERM observation");
            let Shutdown::Draining { deadline: first } = serving.shutdown() else {
                panic!("first SIGTERM must enter draining");
            };
            std::thread::sleep(Duration::from_millis(5));
            serving.on_sigterm().expect("second SIGTERM observation");
            let Shutdown::Draining { deadline: second } = serving.shutdown() else {
                panic!("state must stay draining after a second SIGTERM");
            };
            assert_eq!(
                first, second,
                "a later SIGTERM never extends the fixed shutdown deadline"
            );
        });
    }

    #[test]
    fn sigterm_clean_drain_exits_zero_when_no_tunnels() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            serving.on_sigterm().expect("first SIGTERM observation");
            assert_eq!(serving.storage().occupied(), 0);
            assert_eq!(
                serving.shutdown_exit(),
                Some(ShutdownExit::Drained),
                "an empty drain after the first signal is a clean exit"
            );
            assert_eq!(ShutdownExit::Drained.code(), 0);
        });
    }

    #[test]
    fn sigterm_deadline_force_closes_remaining_sockets_and_exits_seventy() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let client = connect(port);
            pump(serving, 40);
            assert_eq!(serving.storage().occupied(), 1);
            serving.slots[0].stage = Stage::Relay;

            serving.on_sigterm().expect("first SIGTERM observation");
            assert_eq!(
                serving.storage().occupied(),
                1,
                "an established relay keeps draining and is not closed by the signal itself"
            );
            assert_eq!(
                serving.shutdown_exit(),
                None,
                "while a tunnel occupies a slot before the deadline, the owner keeps draining"
            );

            serving.set_shutdown_deadline(Instant::now() - Duration::from_millis(1));
            assert_eq!(
                serving.shutdown_exit(),
                Some(ShutdownExit::Forced),
                "once the fixed deadline passes, remaining sockets are closed as a failure"
            );
            assert_eq!(ShutdownExit::Forced.code(), 70);
            assert_eq!(
                serving.storage().occupied(),
                0,
                "the forced closure releases every remaining occupied socket"
            );
            drop(client);
        });
    }

    #[test]
    fn sigterm_folds_shutdown_deadline_into_the_idle_poll_wait() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            assert_eq!(
                serving.poll_timeout(),
                None,
                "idle serving with no traffic/DNS/log has no wait"
            );
            serving.on_sigterm().expect("first SIGTERM observation");
            let wait = serving
                .poll_timeout()
                .expect("an idle drain must still wake at the shutdown deadline");
            assert!(
                wait <= Duration::from_secs(8),
                "the drain wait is bounded by the fixed 8s grace from the first observation, got {wait:?}"
            );
        });
    }

    #[test]
    fn sigterm_dispatch_priority_no_accept_after_first_signal() {
        let port = ephemeral_port();
        with_serving_stack(port, move |serving| {
            let client = connect(port);
            pump(serving, 40);
            assert_eq!(serving.storage().occupied(), 1);

            serving.on_sigterm().expect("first SIGTERM observation");
            let raw = 0;
            serving
                .dispatch_readiness(
                    Token(raw),
                    Readiness {
                        readable: true,
                        ..Readiness::none()
                    },
                )
                .expect("stale listener readiness after the signal");
            assert_eq!(
                serving.storage().occupied(),
                0,
                "no admissions may occur after the first signal"
            );
            assert!(
                matches!(serving.shutdown(), Shutdown::Draining { .. }),
                "the owner stays in draining after a stale listener wake"
            );
            drop(client);
        });
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn sigterm_shutdown_path_spends_zero_allocations() {
        std::thread::Builder::new()
            .name("shutdown-alloc-witness".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(shutdown_alloc_witness_body)
            .expect("spawn shutdown alloc witness")
            .join()
            .expect("shutdown alloc witness thread");
    }

    #[cfg(feature = "alloc-witness")]
    fn shutdown_alloc_witness_body() {
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config(port)).expect("boot storage");
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port))
            .expect("bind listener");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut runtime = crate::runtime::Runtime::new(storage, listener, traffic)
            .expect("runtime owner (preallocate + attach)");

        let pending_client = connect(port);
        turn_pump(&mut runtime, 40);
        assert_eq!(
            runtime.serving().storage().occupied(),
            1,
            "the pending setup occupies the first storage slot before the signal"
        );

        let mut relay_client = connect(port);
        turn_pump(&mut runtime, 40);
        assert_eq!(
            runtime.serving().storage().occupied(),
            2,
            "two real admitted setups occupy storage before the signal: one pending, one promoted below"
        );

        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let upstream = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let _sink_stream = sink.accept().expect("accept sink side").0;
        wait_upstream_connected(&upstream);
        let index = 1;
        let wire = hello_wire(b"sub.example.org", false);
        relay_client
            .write_all(&wire)
            .expect("hello bytes available on the real admitted client socket");
        let drain_reader = {
            let mut drain = relay_client
                .try_clone()
                .expect("clone the relay client for the CONNECT-response drain reader");
            std::thread::Builder::new()
                .name("relay-client-drain".into())
                .spawn(move || {
                    let mut buf = [0u8; 256];
                    while matches!(drain.read(&mut buf), Ok(n) if n > 0) {}
                })
                .expect("spawn the CONNECT-response drain reader")
        };
        {
            let serving = runtime.serving_mut();
            let ws = &mut serving.slots[index];
            ws.approved = FixedHostname::normalize(b"sub.example.org");
            ws.gate.on_connect_head(0);
            ws.gate.on_authorized();
            ws.stage = Stage::Dialing;
            ws.upstream = Some(upstream);
            ws.head_len = 0;
            ws.buf_base = 0;
            ws.buf_len = 0;
            ws.fwd = 0;
            ws.insp_rel = 0;
            ws.hello_consumed = 0;
        }
        runtime
            .serving_mut()
            .register_upstream(index)
            .expect("register the real upstream socket");
        runtime
            .serving_mut()
            .upstream_writable(index)
            .expect("dial-connected promotion through the production owner path");
        turn_pump(&mut runtime, 40);
        assert!(
            runtime.serving().slots[index].tunnel.is_some(),
            "the promoted relay must graduate to a real storage tunnel handle"
        );
        assert!(
            matches!(runtime.serving().slots[index].stage, Stage::Relay),
            "an established relay holds the second slot before the signal"
        );
        assert!(
            runtime.serving().slots[index].client.is_some()
                && runtime.serving().slots[index].upstream.is_some(),
            "the relay owns live client and upstream sockets before the signal"
        );

        let (_, counts) = crate::alloc::run_phase(crate::alloc::Phase::Shutdown, || {
            runtime
                .serving_mut()
                .signal_wake_mut()
                .expect("the owner holds the self-pipe write end")
                .write_all(&[1])
                .expect("write the signal byte into the self-pipe");
            turn_pump(&mut runtime, 40);
            assert!(
                runtime.serving().is_shutdown(),
                "a real self-pipe signal must enter draining through Runtime::turn"
            );
            assert_eq!(
                runtime.serving().storage().occupied(),
                1,
                "the pending setup is closed at the first signal; the established relay keeps draining"
            );
            assert!(
                matches!(runtime.serving().slots[index].stage, Stage::Relay),
                "the established relay keeps draining past the first signal"
            );
            assert_eq!(
                runtime.serving_mut().shutdown_exit(),
                None,
                "while the relay still occupies a slot before the deadline, the drain does not settle"
            );
            runtime
                .serving_mut()
                .set_shutdown_deadline(Instant::now() - Duration::from_millis(1));
            turn_pump(&mut runtime, 40);
            let exit = runtime
                .serving_mut()
                .shutdown_exit()
                .expect("a drain past the fixed deadline must settle");
            assert_eq!(exit.code(), 70, "a forced closure exit is EX_SOFTWARE");
            assert!(
                runtime.serving().slots[index].client.is_none()
                    && runtime.serving().slots[index].upstream.is_none(),
                "forced closure releases the relay sockets exactly once"
            );
            assert_eq!(
                runtime.serving().storage().occupied(),
                0,
                "forced closure releases the real storage tunnel through release_tunnel: occupied 2 -> 1 -> 0"
            );
            runtime.emit_shutdown_record_and_drain(exit);
            assert!(
                runtime.serving().is_shutdown(),
                "the typed shutdown record and final bounded drain keep the owner draining"
            );
        });
        assert!(
            counts.all_zero(),
            "the real-signal shutdown through Runtime::turn must allocate/deallocate nothing: {counts:?}"
        );
        drain_reader
            .join()
            .expect("the CONNECT-response drain reader exits after the forced close");
        drop(relay_client);
        drop(pending_client);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn directional_buffer_profile_matches_the_128_mib_mandate() {
        assert_eq!(
            HOLD_CAP,
            512 * 1024,
            "client->upstream buffer must be 512 KiB"
        );
        assert_eq!(
            DOWN_CAP,
            512 * 1024,
            "upstream->client buffer must be 512 KiB"
        );
        assert_eq!(MAX_TUNNELS, 128, "the fixed tunnel budget is 128 slots");
        assert!(MAX_PENDING_SETUPS <= 32, "at most 32 pending setups");
        assert_eq!(
            (HOLD_CAP + DOWN_CAP) * MAX_TUNNELS,
            128 * 1024 * 1024,
            "two 512 KiB buffers per tunnel across 128 slots is the 128 MiB traffic profile"
        );
    }
}
