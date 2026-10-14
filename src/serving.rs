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

use crate::client_hello::{self, ChInspector, HelloRejectReason, Inspect};
use crate::config::FixedHostname;
use crate::connect::{ConnectHeadReason, ConnectParser, Feed};
use crate::eligibility::NumericAddr;
use crate::enforcement::action::{DomainOrdinal, FirstSlot, Scope};
use crate::enforcement::policy::{AnyIllegalCause, Effect, Violation};
use crate::gate::{Activity, TunnelGate, UpstreamWrite, ValidatedHello};
use crate::log::{ActivityKind, RejectReason};
use crate::serve::ServeStorage;
use crate::startup_dns::StartupDnsError;
use crate::worker::{AttemptCounts, ConnectPhase, MAX_TUNNELS, SlotIndex, TunnelIndex};

mod policy;
mod reject;
mod startup;

use self::policy::Refusal;

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

const BODY_200: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const BODY_503: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n";

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
    first_slot: FirstSlot,
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
    visits: u16,
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
            first_slot: FirstSlot::new(),
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
            visits: 0,
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
        self.first_slot = FirstSlot::new();
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
            #[cfg(test)]
            {
                self.slots[index].visits = self.slots[index].visits.saturating_add(1);
            }
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

    #[cfg(all(test, feature = "alloc-witness"))]
    pub(crate) fn test_slot_visits(&self, index: usize) -> u16 {
        self.slots[index].visits
    }

    fn accept_all(&mut self) -> Result<(), ServeError> {
        loop {
            if self.block_all_latched() {
                self.progress.accrue(1);
                return Ok(());
            }
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
        if self.clamp_on_latch(index) {
            return Ok(());
        }
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
                    Stage::ReadingConnect => {
                        self.any_illegal(
                            index,
                            AnyIllegalCause::ConnectParse(ConnectHeadReason::TooLong),
                        );
                        self.refuse(index, Refusal::BadRequest);
                    }
                    Stage::ValidatingHello => {
                        self.reject_hello(index, HelloRejectReason::Profile)?
                    }
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
            let mut scratch = [0u8; CHUNK];
            let room = self.io_room(index, CHUNK);
            let n = match self.slots[index].client.as_mut() {
                None => return Ok(()),
                Some(client) => match client.read(&mut scratch[..room]) {
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
                },
            };
            self.note_op(index, n);
            match self.slots[index].stage {
                Stage::ReadingConnect => self.buffer_and_parse(index, &scratch[..n])?,
                Stage::ValidatingHello => self.buffer_and_validate(index, &scratch[..n])?,
                Stage::Relay => {
                    self.append_client_bytes(index, &scratch[..n]);
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

    fn append_client_bytes(&mut self, index: usize, bytes: &[u8]) {
        let ws = &mut self.slots[index];
        if ws.buf_len + bytes.len() > HOLD_CAP {
            ws.compact();
            debug_assert!(ws.buf_len + bytes.len() <= HOLD_CAP);
        }
        ws.buf[ws.buf_len..ws.buf_len + bytes.len()].copy_from_slice(bytes);
        ws.buf_len += bytes.len();
    }

    fn buffer_and_parse(&mut self, index: usize, bytes: &[u8]) -> Result<(), ServeError> {
        self.append_client_bytes(index, bytes);
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
            Err(err) => {
                self.any_illegal(
                    index,
                    AnyIllegalCause::ConnectParse(ConnectHeadReason::from_connect_error(&err)),
                );
                self.refuse(index, Refusal::BadRequest);
                Ok(())
            }
        }
    }

    fn block_all_latched(&self) -> bool {
        self.storage.enforcement().block_all()
    }

    fn clamp_on_latch(&mut self, index: usize) -> bool {
        if !self.block_all_latched() {
            return false;
        }
        if self.slots[index].stage != Stage::Idle && self.slots[index].stage != Stage::Closing {
            self.close_slot(index);
        }
        true
    }

    fn stop_block_all(&mut self) {
        if !self.block_all_latched() {
            return;
        }
        self.stop_admission_latched();
        for index in 0..self.slots.len() {
            if self.slots[index].stage != Stage::Idle && self.slots[index].stage != Stage::Closing {
                self.close_slot(index);
            }
        }
    }

    fn stop_admission_latched(&mut self) {
        let _ = self.stop_admission();
    }

    fn stop_domain_block(&mut self, ordinal: DomainOrdinal, except: usize) {
        for index in 0..self.slots.len() {
            if index != except
                && self.slots[index].stage != Stage::Idle
                && self.slots[index].stage != Stage::Closing
                && self.slot_ordinal(index) == Some(ordinal)
            {
                self.close_slot(index);
            }
        }
    }

    fn slot_ordinal(&self, index: usize) -> Option<DomainOrdinal> {
        self.slots[index]
            .approved
            .as_ref()
            .and_then(|host| self.storage.ordinal_for(host))
    }

    fn any_illegal(&mut self, index: usize, cause: AnyIllegalCause) -> Effect {
        let violation = Violation::AnyIllegal { cause };
        let effect = {
            let slot = &mut self.slots[index];
            let en = self.storage.enforcement_mut();
            en.decide(&mut slot.first_slot, violation)
        };
        if matches!(effect, Effect::Block { scope: Scope::All }) {
            self.stop_block_all();
        }
        effect
    }

    fn project_tripwire(&mut self, index: usize, violation: Violation) -> Effect {
        let effect = {
            let slot = &mut self.slots[index];
            let en = self.storage.enforcement_mut();
            en.decide(&mut slot.first_slot, violation)
        };
        match effect {
            Effect::Block { scope: Scope::All } => self.stop_block_all(),
            Effect::Block {
                scope: Scope::Domain,
            } => {
                if let Violation::EarlyUpstreamData { ordinal } = violation {
                    self.stop_domain_block(ordinal, index);
                }
            }
            _ => {}
        }
        effect
    }

    fn run_decision(&mut self, index: usize) -> Result<(), ServeError> {
        let Some(slot) = self.slots[index].handle.as_ref() else {
            return Ok(());
        };
        let request = match self.slots[index].parser.result().copied() {
            Some(Ok(request)) => request,
            Some(Err(err)) => {
                self.any_illegal(
                    index,
                    AnyIllegalCause::ConnectParse(ConnectHeadReason::from_connect_error(&err)),
                );
                self.refuse(index, Refusal::BadRequest);
                return Ok(());
            }
            None => {
                self.project_tripwire(index, Violation::MissingParseResult);
                self.close_slot(index);
                return Ok(());
            }
        };
        let approved = *request.fixed_hostname();
        if let Some(ordinal) = self.storage.ordinal_for(&approved)
            && self.storage.enforcement().is_blocked(ordinal)
        {
            self.storage.enforcement_mut().note_domain_block(ordinal);
            self.refuse(index, Refusal::Forbidden);
            return Ok(());
        }
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
                self.any_illegal(index, AnyIllegalCause::HostNotAllowlisted);
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
                slot.approved = Some(approved);
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
        if self.clamp_on_latch(index) {
            return Ok(());
        }
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
        if self.clamp_on_latch(index) {
            return Ok(());
        }
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
                    let activity_kind = match activity {
                        Activity::Data => ActivityKind::Data,
                        Activity::Eof => ActivityKind::Eof,
                        Activity::Reset => ActivityKind::Reset,
                    };
                    let approved = self.slots[index].approved;
                    let validated = self.slots[index].hello_end.is_some();
                    {
                        let ws = &mut self.slots[index];
                        ws.gate.observe_upstream_activity(activity);
                    }
                    if activity == Activity::Data {
                        let violation = if validated {
                            match approved {
                                Some(host) => match self.storage.ordinal_for(&host) {
                                    Some(ordinal) => Violation::EarlyUpstreamData { ordinal },
                                    None => Violation::Unattributed,
                                },
                                None => Violation::Unattributed,
                            }
                        } else {
                            Violation::EvidenceInsufficient
                        };
                        self.project_tripwire(index, violation);
                    }
                    let peer = self.slots[index]
                        .upstream
                        .as_ref()
                        .and_then(|u| u.peer_addr().ok());
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

    fn buffer_and_validate(&mut self, index: usize, bytes: &[u8]) -> Result<(), ServeError> {
        if !bytes.is_empty() {
            self.append_client_bytes(index, bytes);
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
            Err(err) => self.reject_hello(index, HelloRejectReason::from_ch_error(&err)),
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
            None => {
                self.project_tripwire(index, Violation::MissingParseResult);
                self.close_slot(index);
                return Ok(());
            }
        };
        let verdict = self.slots[index]
            .inspector
            .hello()
            .map(|hello| client_hello::validate(hello, &approved));
        let accepted = match verdict {
            Some(Ok(accepted)) => accepted,
            Some(Err(err)) => {
                return self.reject_hello(index, HelloRejectReason::from_ch_error(&err));
            }
            None => {
                self.project_tripwire(index, Violation::MissingParseResult);
                self.close_slot(index);
                return Ok(());
            }
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
        self.buffer_and_validate(index, &[])?;
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
            let mut scratch = [0u8; CHUNK];
            let room = self.io_room(index, CHUNK);
            let n = match self.slots[index].upstream.as_mut() {
                None => return Ok(()),
                Some(up) => match up.read(&mut scratch[..room]) {
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
                },
            };
            self.note_op(index, n);
            {
                let ws = &mut self.slots[index];
                ws.down[ws.down_len..ws.down_len + n].copy_from_slice(&scratch[..n]);
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

    fn client_writable(&mut self, index: usize) -> Result<(), ServeError> {
        if self.clamp_on_latch(index) {
            return Ok(());
        }
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
mod tests;
