//! Worker-policy core for the serving integration: current-cache CONNECT
//! authorization, canonical per-tunnel upstream address selection, the fixed
//! slot lifecycle the single worker owns, and precise typed deadlines, as a
//! pure nonalloc typed substrate.
//!
//! This is the decision substrate of the single-owner worker (oracle gap G1,
//! G6): it owns no sockets and performs no I/O, so every path is deterministic
//! and unit-testable. The mio event loop, the ClientHello two-barrier gate,
//! and the byte-conserving relay are later increments and make no serving
//! claim here; the boot-owned traffic buffers this core will hand out live in
//! [`crate::inventory::TrafficStorage`].
//!
//! Setup (10 s) and per-attempt connect (2 s) deadlines are anchored on the
//! precise monotonic clock ([`Deadline`]) so a fractional-second initiation is
//! never truncated toward an earlier whole second (alumina.md:169,189;
//! 1cws M2r). The DNS cache clock is whole seconds, derived from the same
//! anchor only through the explicit [`WorkerClock::cache_secs`] conversion.
//!
//! The config/cache pair reachable by a decision is constructed only by the
//! storage that owns both ([`crate::serve::ServeStorage::work_view`]; 1cws
//! M4r), and the fixed slot table is owned by [`Worker`] as a typed enum
//! lifecycle — the table, not a detached permit or a Copy accounting object,
//! owns the counts, so one owner can never release capacity on behalf of
//! another (9pac H1; 1cws H1r).
//!
//! Family alternation (alumina.md:82) is driven by the *Connecting lifecycle*
//! previous-family transition input, never by a family bit stored in
//! [`AttemptCounts`]: the tunnel still stores exactly its two per-family
//! attempt counters (oracle alumina-ufrw; docs D5a). Each per-attempt connect
//! deadline is freshly clipped to the absolute setup deadline at the attempt
//! it initiates (alumina.md:189).

use std::time::{Duration, Instant};

use crate::cache::{Cache, CacheError, Entry, EntryState, Family, NameIndex};
use crate::config::Config;
use crate::connect::{CONNECT_LIMIT, ConnectRequest};
use crate::eligibility::NumericAddr;
use crate::inventory::{BUFFER_BYTES, TUNNEL_SLOTS};

/// Maximum concurrent tunnels, including pending setups (alumina.md:160).
pub const MAX_TUNNELS: usize = TUNNEL_SLOTS;

/// Maximum concurrent pending (in-setup) tunnels; never 160 (alumina.md:160).
pub const MAX_PENDING_SETUPS: usize = 32;

/// Sequential upstream connection attempts per tunnel (alumina.md:82).
pub const MAX_UPSTREAM_ATTEMPTS: usize = 4;

/// Absolute setup deadline after accept, never reset (alumina.md:169,189).
pub const SETUP_DEADLINE_SECS: u64 = 10;

/// Per-attempt upstream connect deadline, clipped to the setup deadline
/// (alumina.md:169,82).
pub const CONNECT_DEADLINE_SECS: u64 = 2;

/// CONNECT request-head bound reused from the parser (alumina.md:163).
pub const CONNECT_HEAD_LIMIT: usize = CONNECT_LIMIT;

/// One directional traffic buffer handed to a tunnel from boot storage
/// (alumina.md:183). Sized here so the worker owns the storage contract;
/// instances live in the boot pool, never on this core's stack.
pub type TrafficBuffer = [u8; BUFFER_BYTES];

/// The service's single clock authority: a precise monotonic boot anchor for
/// setup/connect deadlines plus the DNS whole-second epoch (`dns0`) whose
/// scale the cache is written on. Cache seconds are mounted on `dns0`, so a
/// serving evaluation is comparable against the startup receipts' own scale
/// (startup_dns.rs `now0 + elapsed`) instead of a fresh zero anchor that keeps
/// every entry permanently fresh (1cws M2r; w6xo). Constructed only by the
/// storage that owns the cache and worker (crate-internal), so no caller can
/// pair a free clock with a decision.
#[derive(Clone, Copy, Debug)]
pub struct WorkerClock {
    epoch: Instant,
    dns0: u64,
}

impl WorkerClock {
    /// One authority over both clocks: `epoch` is the precise monotonic boot
    /// anchor, `dns0` the DNS whole-second epoch the startup window wrote
    /// receipts on. The storage that owns the cache, schedules, and the single
    /// worker constructs this pairing exactly once.
    pub(crate) const fn new(epoch: Instant, dns0: u64) -> WorkerClock {
        WorkerClock { epoch, dns0 }
    }

    /// The precise monotonic boot anchor, shared by all precise deadlines.
    #[allow(dead_code)]
    pub(crate) const fn epoch(self) -> Instant {
        self.epoch
    }

    /// The whole-second DNS/cache value for `now`, mounted on `dns0`: `dns0`
    /// plus whole seconds since the boot anchor. This is the only conversion
    /// from wall time to the cache clock, and it must agree with startup's
    /// `now0 + elapsed` scale.
    pub fn cache_secs(&self, now: Instant) -> u64 {
        self.dns0
            .saturating_add(now.saturating_duration_since(self.epoch).as_secs())
    }
}

/// Per-family upstream connection attempt counts for one tunnel (alumina.md:82).
///
/// The tunnel stores only these two counts, never addresses or cache
/// references, so a cache replacement between attempts takes effect at the
/// next attempt. No family bit is stored here: the family of the just-failed
/// Connecting attempt arrives as the previous-family transition input on each
/// retry (oracle alumina-ufrw), keeping these exactly two counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttemptCounts {
    a: u8,
    aaaa: u8,
}

impl AttemptCounts {
    pub const fn new() -> AttemptCounts {
        AttemptCounts { a: 0, aaaa: 0 }
    }

    pub const fn a(self) -> u8 {
        self.a
    }

    pub const fn aaaa(self) -> u8 {
        self.aaaa
    }

    /// Total attempts across both families.
    pub const fn total(self) -> u8 {
        self.a.saturating_add(self.aaaa)
    }

    /// Returns the counts advanced by one attempt in `family`.
    pub const fn record(self, family: Family) -> AttemptCounts {
        match family {
            Family::A => AttemptCounts {
                a: self.a.saturating_add(1),
                ..self
            },
            Family::Aaaa => AttemptCounts {
                aaaa: self.aaaa.saturating_add(1),
                ..self
            },
        }
    }
}

/// A fixed, saturating deadline on the precise monotonic clock. Computed once
/// from its `Instant` anchor; expiry is evaluated against `now` exactly, so
/// delayed timer processing can never extend an authorization window
/// (alumina.md:82,189) and a connect deadline initiated mid-second expires a
/// full 2.0 s later, never after 1.x s of whole-second truncation (1cws M2r).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline {
    limit: Instant,
}

impl Deadline {
    /// The absolute setup deadline: 10 s after successful accept, never reset
    /// (alumina.md:169,189). Saturates to the accept instant on clock
    /// overflow, leaving an unrepresentable deadline already expired.
    pub fn setup(accepted: Instant) -> Deadline {
        match accepted.checked_add(Duration::from_secs(SETUP_DEADLINE_SECS)) {
            Some(limit) => Deadline { limit },
            None => Deadline { limit: accepted },
        }
    }

    /// A fresh per-attempt upstream connect deadline: 2 s from `now`, clipped
    /// to the setup deadline (alumina.md:169,189). Created at the initiation of
    /// the attempt it bounds, so an earlier attempt's expired deadline is never
    /// carried into this one and cannot be mistaken for the setup deadline
    /// (9pac M1).
    pub fn connect_attempt(now: Instant, setup: Deadline) -> Deadline {
        let fresh = match now.checked_add(Duration::from_secs(CONNECT_DEADLINE_SECS)) {
            Some(fresh) => fresh,
            None => now,
        };
        Deadline {
            limit: if fresh < setup.limit {
                fresh
            } else {
                setup.limit
            },
        }
    }

    pub fn limit(self) -> Instant {
        self.limit
    }

    pub fn is_expired(self, now: Instant) -> bool {
        now >= self.limit
    }
}

/// Destination-selection outcome for one connection attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerDecision {
    /// Attempt a TCP connection to this eligible destination for `family`.
    Peer { addr: NumericAddr, family: Family },
    /// No family remains with an unused, non-retired, eligible binding.
    NoFamily,
}

/// The terminal CONNECT-phase decision for one tunnel, computed from the
/// current cache only. Everything that can refuse before an upstream socket
/// is opened is decided here, so a refusal outcome guarantees no upstream peer
/// is ever attempted (effect non-reachability).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectPhase {
    /// The CONNECT hostname is not allowlisted (HTTP 403).
    Forbidden,
    /// Allowlisted but the name currently has no eligible non-retired binding
    /// at any outstanding per-family cursor: never resolved, or all remaining
    /// addresses are retired (HTTP 502, "no resolved addresses"; alumina.md:43).
    NoBinding,
    /// The absolute setup deadline has passed before the forwarding gate
    /// opened (HTTP 504; alumina.md:43,189).
    DeadlineExhausted,
    /// All allowed upstream attempts were consumed (HTTP 502, "upstream
    /// connection failed"; alumina.md:43). Distinct from [`ConnectPhase::NoBinding`]
    /// so the two 502 reasons and bodies are never conflated (9pac M5).
    CandidatesExhausted,
    /// Proceed: dial this eligible destination for this family within the
    /// fresh clipped per-attempt `connect_deadline`. The peer stays fixed once
    /// committed; retries only ever follow failed establishment.
    Peer {
        addr: NumericAddr,
        family: Family,
        connect_deadline: Deadline,
    },
}

impl ConnectPhase {
    /// The canonical fixed status for this phase (alumina.md:43,
    /// architecture.md:65): 403 not-allowlisted, 502 for both
    /// no-binding and candidates-exhausted, 504 setup deadline, 200 for an
    /// authorized `Peer`. HTTP 503 is capacity-only and lives in
    /// [`AdmissionError`]; HTTP 400 malformed is parser-owned and never reaches
    /// the worker. Pinned by `refusal_statuses_follow_the_canonical_fixed_matrix`.
    pub const fn status(self) -> u16 {
        match self {
            ConnectPhase::Forbidden => 403,
            ConnectPhase::NoBinding | ConnectPhase::CandidatesExhausted => 502,
            ConnectPhase::DeadlineExhausted => 504,
            ConnectPhase::Peer { .. } => 200,
        }
    }
}

/// A setup-phase slot identifier granted by [`Worker::admit`]. It is moved
/// (never copied) between the worker's lifecycle transitions and consumed by
/// [`Worker::release`], so a stale handle can never free a slot that a later
/// admit reused for another owner (9pac H1; 1cws H1r). The table, not a permit
/// object, owns the accounting.
#[derive(Debug, PartialEq, Eq)]
pub struct SlotIndex(u8);

impl SlotIndex {
    pub(crate) const fn index(&self) -> usize {
        self.0 as usize
    }
}

/// The established-phase handle produced by graduating a setup with
/// [`Worker::finish_setup`]: the same physical slot, now in a distinct type so
/// a setup handle can never graduate or release an established tunnel and an
/// established handle can never corrupt pending accounting (9mq9 H1r, typed
/// transition).
#[derive(Debug, PartialEq, Eq)]
pub struct TunnelIndex(u8);

impl TunnelIndex {
    #[allow(dead_code)]
    pub(crate) const fn index(&self) -> usize {
        self.0 as usize
    }
}

/// The lifecycle of one fixed tunnel slot: exactly one of free, in setup, or
/// established. Encoding the lifecycle as an enum makes a slot's state
/// unambiguous and makes every transition mutate exactly that slot, so
/// graduating or releasing a tunnel can never decrement another tunnel's
/// pending count (9pac H1; 1cws H1r).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Free,
    InSetup { setup_deadline: Deadline },
    Established { setup_deadline: Deadline },
}

/// Reasons the single worker can refuse a new setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    SlotCapacity,
    PendingCapacity,
}

/// The single-owner slot table for the fixed tunnel budget: at most
/// [`MAX_TUNNELS`] occupied slots including at most [`MAX_PENDING_SETUPS`]
/// pending setups; established work is never evicted (alumina.md:160,193).
/// The worker owns the table (not a detachable counter object) and the single
/// clock authority; busy/pending are derived from the slot states, so the
/// accounting can never be copied out or underflow. It owns no sockets and no
/// I/O; the actual accept/connect/close event processing holds its granted
/// handles and drives the transitions.
pub struct Worker {
    slots: [SlotState; MAX_TUNNELS],
    clock: WorkerClock,
}

impl Worker {
    /// Constructs the empty slot table with the owning storage's clock
    /// authority. All state is preallocated (a fixed array); nothing is
    /// allocated per connection. Crate-internal: the single constructor site is
    /// the storage that owns cache, schedules, and this worker.
    pub(crate) fn boot(clock: WorkerClock) -> Worker {
        Worker {
            slots: [SlotState::Free; MAX_TUNNELS],
            clock,
        }
    }

    /// Re-anchors this worker's clock to the one authority after the startup
    /// DNS window mounts `now0` and its exact elapsed origin. Crate-internal:
    /// called once by the owning storage after `resolve_window`.
    pub(crate) fn set_clock(&mut self, clock: WorkerClock) {
        self.clock = clock;
    }

    /// The single clock authority for this worker's decisions.
    pub(crate) fn clock(&self) -> WorkerClock {
        self.clock
    }

    /// The number of slots currently in setup (pending).
    pub fn pending(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| matches!(s, SlotState::InSetup { .. }))
            .count()
    }

    /// The number of occupied slots (in setup or established).
    pub fn occupied(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| !matches!(s, SlotState::Free))
            .count()
    }

    /// Admits a new setup into a free slot, capturing the absolute setup
    /// deadline at the accept instant, and returns the granted in-setup
    /// handle [`SlotIndex`]. The handle is moved through the lifecycle and
    /// consumed by [`Worker::release`] or [`Worker::finish_setup`], so a stale
    /// handle can never free a slot reused for another owner (9mq9 H1r).
    ///
    /// # Errors
    ///
    /// Returns `SlotCapacity` at [`MAX_TUNNELS`] occupied slots and
    /// `PendingCapacity` at [`MAX_PENDING_SETUPS`] pending setups; both are
    /// HTTP 503 + close (alumina.md:193).
    pub(crate) fn admit(&mut self, now: Instant) -> Result<SlotIndex, AdmissionError> {
        if self.occupied() >= MAX_TUNNELS {
            return Err(AdmissionError::SlotCapacity);
        }
        if self.pending() >= MAX_PENDING_SETUPS {
            return Err(AdmissionError::PendingCapacity);
        }
        let Some((index, free_slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| matches!(s, SlotState::Free))
        else {
            return Err(AdmissionError::SlotCapacity);
        };
        let Ok(index) = u8::try_from(index) else {
            return Err(AdmissionError::SlotCapacity);
        };
        *free_slot = SlotState::InSetup {
            setup_deadline: Deadline::setup(now),
        };
        Ok(SlotIndex(index))
    }

    /// The one owned decision for an in-setup tunnel: authorization and peer
    /// selection against the current cache, with the setup deadline read from
    /// the granted slot (never supplied by a caller) and cache seconds from
    /// this worker's clock authority (never a free clock) (9mq9 M2r/M3).
    ///
    /// # Errors
    ///
    /// Returns `NotInSetup` when the handle no longer names a live setup (a
    /// caller-level misuse the handle discipline prevents) and propagates the
    /// underlying current-cache lookup error.
    pub(crate) fn decide(
        &self,
        view: &WorkerView,
        slot: &SlotIndex,
        request: &ConnectRequest,
        now: Instant,
        counts: AttemptCounts,
        previous: Option<Family>,
    ) -> Result<ConnectPhase, DecideError> {
        let setup = self.setup_deadline(slot).ok_or(DecideError::NotInSetup)?;
        next_phase(request, view, now, counts, previous, setup).map_err(DecideError::Cache)
    }

    /// Graduates the setup named by `slot` to established work, returning the
    /// established-phase handle: it stays occupied but no longer counts
    /// pending, and the setup handle is consumed so it cannot later free or
    /// re-graduate this tunnel. A no-op when the slot is not in setup (the
    /// grant flow guarantees that), so a misplaced call can never corrupt a
    /// different slot.
    #[allow(dead_code)]
    pub(crate) fn finish_setup(&mut self, slot: SlotIndex) -> TunnelIndex {
        if let SlotState::InSetup { setup_deadline } = self.slots[slot.index()] {
            self.slots[slot.index()] = SlotState::Established { setup_deadline };
        }
        TunnelIndex(slot.0)
    }
    /// Frees the granted in-setup slot for reuse, consuming the handle.
    /// Operates on the granted slot only, so closing a setup can never release
    /// another tunnel's pending or established seat (9mq9 H1r).
    pub(crate) fn release(&mut self, slot: SlotIndex) {
        self.slots[slot.index()] = SlotState::Free;
    }

    /// Frees an established tunnel for reuse, consuming the established handle.
    #[allow(dead_code)]
    pub(crate) fn release_tunnel(&mut self, tunnel: TunnelIndex) {
        self.slots[tunnel.index()] = SlotState::Free;
    }

    /// The absolute setup deadline of the granted in-setup slot, or `None`
    /// when the slot is free.
    pub(crate) fn setup_deadline(&self, slot: &SlotIndex) -> Option<Deadline> {
        match self.slots[slot.index()] {
            SlotState::InSetup { setup_deadline } | SlotState::Established { setup_deadline } => {
                Some(setup_deadline)
            }
            SlotState::Free => None,
        }
    }

    /// The absolute setup deadline of an established tunnel's slot, or `None`
    /// when the slot is free.
    #[allow(dead_code)]
    pub(crate) fn tunnel_setup_deadline(&self, tunnel: &TunnelIndex) -> Option<Deadline> {
        match self.slots[tunnel.index()] {
            SlotState::InSetup { setup_deadline } | SlotState::Established { setup_deadline } => {
                Some(setup_deadline)
            }
            SlotState::Free => None,
        }
    }

    /// The occupied slot index for the granted in-setup handle, for the actual
    /// event processor to key its per-slot socket/parser/buffer state.
    pub(crate) fn slot_index(&self, slot: &SlotIndex) -> usize {
        slot.index()
    }

    /// The occupied slot index for the established handle.
    #[allow(dead_code)]
    pub(crate) fn tunnel_index(&self, tunnel: &TunnelIndex) -> usize {
        tunnel.index()
    }
}

/// A setup-phase decision failure: either the granted handle no longer names a
/// live setup (a caller misuse the handle discipline prevents) or an
/// underlying current-cache lookup error.
#[derive(Debug, PartialEq, Eq)]
pub enum DecideError {
    /// The granted slot handle does not currently name an in-setup slot; the
    /// handle was released or already graduated. Unreachable in the serving
    /// path by construction (handles are consumed by the transitions).
    NotInSetup,
    /// The current-cache lookup failed for an allowlisted ordinal.
    Cache(CacheError),
}

/// The single-owner worker's boot-paired inputs to one CONNECT decision: the
/// validated allowlist config, the current cache derived from that same
/// allowlist, and the single clock authority that owns both the precise
/// deadlines and the DNS-scale cache seconds. The decision core accepts this
/// view, never a free (config, cache, clock) triple, so an allowlist ordinal
/// can never index a different name in a mismatched cache and a decision can
/// never evaluate the cache on a foreign clock (1cws M4r + M2r;
/// destination-binding, alumina.md:145). The only construction seam is
/// crate-internal, so no public route can pair unrelated fields.
#[derive(Clone, Copy)]
pub struct WorkerView<'a> {
    config: &'a Config,
    cache: &'a Cache,
    clock: WorkerClock,
}

impl<'a> WorkerView<'a> {
    /// Binds a config, the cache derived from that same config, and the clock
    /// authority owned by the storage that built both. Crate-internal: the
    /// production caller is the owning storage, which passes its own aligned
    /// fields ([`crate::serve::ServeStorage::work_view`]); the worker's unit
    /// tests use it to pin decision behaviour over known in-cache state.
    pub(crate) fn new(config: &'a Config, cache: &'a Cache, clock: WorkerClock) -> WorkerView<'a> {
        WorkerView {
            config,
            cache,
            clock,
        }
    }

    /// The single clock authority bound to this config/cache pair.
    #[allow(dead_code)]
    pub(crate) const fn clock(&self) -> WorkerClock {
        self.clock
    }
}

/// The ordinal of `request` in `view.config.allowlist()`, or `None` when the
/// CONNECT hostname is not allowlisted.
fn allowlist_ordinal(request: &ConnectRequest, config: &Config) -> Option<usize> {
    config
        .allowlist()
        .iter()
        .position(|entry| entry.as_str().as_bytes() == request.hostname().as_bytes())
}

/// Decides the next CONNECT-phase action for a tunnel from the current cache.
///
/// Authorization is allowlist membership of the already-validated CONNECT
/// hostname (port 443 and non-literal forms are enforced upstream in the
/// parser). After authorization, the fixed setup deadline and the attempt
/// budget are checked before any address is selected, so a refusal never
/// reaches the peer-selection step and no upstream socket is opened. The
/// per-attempt connect deadline is freshly clipped inside the returned
/// `Peer`, never passed in (9pac M1); deadlines use the precise `now` instant
/// while cache freshness uses the view's own clock authority
/// ([`WorkerView::clock`] → [`WorkerClock::cache_secs`], 1cws M2r).
///
/// Crate-internal: the owning storage supplies `setup_deadline` from the
/// granted slot via [`Worker::decide`], never from a caller (9mq9 M3).
///
/// # Errors
///
/// Propagates `NameOutOfRange` from the current-cache lookup; because the
/// cache is owned and sized by the same validated allowlist, an allowlisted
/// ordinal is always admitted.
pub(crate) fn next_phase(
    request: &ConnectRequest,
    view: &WorkerView,
    now: Instant,
    counts: AttemptCounts,
    previous: Option<Family>,
    setup_deadline: Deadline,
) -> Result<ConnectPhase, CacheError> {
    let Some(ordinal) = allowlist_ordinal(request, view.config) else {
        return Ok(ConnectPhase::Forbidden);
    };
    let name = view
        .cache
        .name_index(ordinal)
        .ok_or(CacheError::NameOutOfRange)?;
    if setup_deadline.is_expired(now) {
        return Ok(ConnectPhase::DeadlineExhausted);
    }
    if usize::from(counts.total()) >= MAX_UPSTREAM_ATTEMPTS {
        return Ok(ConnectPhase::CandidatesExhausted);
    }
    let cache_now = view.clock.cache_secs(now);
    match select_peer(view.cache, name, cache_now, counts, previous)? {
        PeerDecision::Peer { addr, family } => Ok(ConnectPhase::Peer {
            addr,
            family,
            connect_deadline: Deadline::connect_attempt(now, setup_deadline),
        }),
        PeerDecision::NoFamily => Ok(ConnectPhase::NoBinding),
    }
}

/// Selects the next upstream peer from the current cache (alumina.md:82).
///
/// Reads the current A and AAAA entries afresh and ignores any that are empty,
/// retired, exhausted at their current per-family attempt count, or whose
/// candidate at the attempt cursor is ineligible. When only one family
/// remains it is used; when both remain, the first attempt uses IPv4 and each
/// later attempt uses the family NOT used by the previous attempt (the
/// `previous` Connecting-lifecycle transition input, oracle alumina-ufrw).
/// Within a family the address at index `n` is used, where `n` is the number
/// of earlier attempts in that family; the family is exhausted when `n`
/// reaches the entry's current address count. `now` is the whole-second
/// DNS/cache clock ([`WorkerClock::cache_secs`]), never a precise deadline.
///
/// # Errors
///
/// Propagates `NameOutOfRange` from the current-cache lookup.
pub(crate) fn select_peer(
    cache: &Cache,
    name: NameIndex,
    now: u64,
    counts: AttemptCounts,
    previous: Option<Family>,
) -> Result<PeerDecision, CacheError> {
    let a = cache.entry(name, Family::A)?;
    let aaaa = cache.entry(name, Family::Aaaa)?;
    match (
        usable_peer(&a, Family::A, counts.a(), now),
        usable_peer(&aaaa, Family::Aaaa, counts.aaaa(), now),
    ) {
        (None, None) => Ok(PeerDecision::NoFamily),
        (Some((addr, family)), None) | (None, Some((addr, family))) => {
            Ok(PeerDecision::Peer { addr, family })
        }
        (Some(a_peer), Some(aaaa_peer)) => {
            let (addr, family) = match previous {
                None => a_peer,
                Some(Family::A) => aaaa_peer,
                Some(Family::Aaaa) => a_peer,
            };
            Ok(PeerDecision::Peer { addr, family })
        }
    }
}

/// The usable candidate for `family` at its current attempt cursor: `Some`
/// only when the family still holds a binding at index `attempted`, that entry
/// is not empty or retired, and the specific candidate passes destination
/// eligibility. An ineligible candidate makes THIS family unavailable at the
/// cursor — it never erases a usable other family (9pac M3). In the running
/// path bindings are already eligible because publishing filters them
/// (cache.rs `publish_positive`), so this eligibility check is defense.
fn usable_peer(
    entry: &Entry,
    family: Family,
    attempted: u8,
    now: u64,
) -> Option<(NumericAddr, Family)> {
    if usize::from(attempted) >= entry.bindings().len() {
        return None;
    }
    if !matches!(entry.state(now), EntryState::Fresh | EntryState::Stale) {
        return None;
    }
    let addr = entry.bindings()[usize::from(attempted)];
    if !addr.is_eligible() {
        return None;
    }
    Some((addr, family))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{Generation, StagedPositive};
    use crate::config::parse_config_document;
    use crate::connect::ConnectParser;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const CONFIG: &str = "allowlist = [\"sub.example.org\", \"second.example.org\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n";

    fn config() -> Config {
        parse_config_document(CONFIG).expect("valid config")
    }

    fn v4(octets: [u8; 4]) -> NumericAddr {
        NumericAddr::V4(Ipv4Addr::from(octets))
    }

    fn v6(octets: [u8; 16]) -> NumericAddr {
        NumericAddr::V6(Ipv6Addr::from(octets))
    }

    fn pub_v4() -> NumericAddr {
        v4([8, 8, 8, 8])
    }

    fn pub_v4_b() -> NumericAddr {
        v4([1, 1, 1, 1])
    }

    fn pub_v6() -> NumericAddr {
        v6([0x26, 0x00, 0x1f, 0x39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    fn second_v6() -> NumericAddr {
        v6([0x24, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    }

    fn cache_with(name_count: usize) -> Cache {
        Cache::new(name_count).expect("cache")
    }

    fn view_of<'a>(cfg: &'a Config, cache: &'a Cache) -> WorkerView<'a> {
        WorkerView::new(cfg, cache, clock(Instant::now()))
    }

    fn view_of_clocked<'a>(
        cfg: &'a Config,
        cache: &'a Cache,
        clock: WorkerClock,
    ) -> WorkerView<'a> {
        WorkerView::new(cfg, cache, clock)
    }

    /// The decision-core anchor instant; deadlines and the cache clock derive
    /// from it. Each test uses one anchor so `now`, `setup` and the cache
    /// clock share a single origin.
    fn anchor() -> Instant {
        Instant::now()
    }

    fn clock(anchor: Instant) -> WorkerClock {
        WorkerClock::new(anchor, 0)
    }

    const DNS_EPOCH: u64 = 1_700_000_000;

    /// `secs` whole seconds after the anchor.
    fn later(anchor: Instant, secs: u64) -> Instant {
        anchor + Duration::from_secs(secs)
    }

    fn setup_at(anchor: Instant) -> Deadline {
        Deadline::setup(anchor)
    }

    fn publish(
        cache: &mut Cache,
        name: NameIndex,
        family: Family,
        addrs: &[NumericAddr],
        receipt: u64,
        ttl: u64,
    ) {
        let staged = StagedPositive::stage(name, family, Generation::INITIAL, addrs, receipt, ttl)
            .expect("staged valid");
        cache.publish_positive(&staged).expect("published");
    }

    fn name(cache: &Cache, ordinal: usize) -> NameIndex {
        cache.name_index(ordinal).expect("admitted name")
    }

    fn parse_head(head: &[u8]) -> ConnectRequest {
        let mut parser = ConnectParser::new();
        match parser.feed(head).expect("head feed") {
            crate::connect::Feed::Complete { .. } => parser.result().copied().expect("result"),
            crate::connect::Feed::Incomplete => panic!("head incomplete"),
        }
        .expect("valid connect")
    }

    fn auth_request(host: &str) -> ConnectRequest {
        let head = format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n");
        parse_head(head.as_bytes())
    }

    #[test]
    fn forbidden_host_is_effect_nonreachable_even_with_usable_cache() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let req = auth_request("evil.example.net");
        let t0 = anchor();
        let phase = next_phase(
            &req,
            &view,
            later(t0, 1),
            AttemptCounts::new(),
            None,
            setup_at(t0),
        )
        .expect("decision");
        assert_eq!(phase, ConnectPhase::Forbidden);
    }

    #[test]
    fn allowlisted_authorizes_and_selects_ipv4_first_when_both_families_remain() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
        publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let req = auth_request("sub.example.org");
        let t0 = anchor();
        let now = later(t0, 1);
        let setup = setup_at(t0);
        let phase =
            next_phase(&req, &view, now, AttemptCounts::new(), None, setup).expect("decision");
        assert_eq!(
            phase,
            ConnectPhase::Peer {
                addr: pub_v4(),
                family: Family::A,
                connect_deadline: Deadline::connect_attempt(now, setup),
            }
        );
    }

    #[test]
    fn alternates_to_aaaa_after_a_first_attempt() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
        publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let counts = AttemptCounts::new().record(Family::A);
        let req = auth_request("sub.example.org");
        let t0 = anchor();
        let now = later(t0, 1);
        let setup = setup_at(t0);
        let phase = next_phase(&req, &view, now, counts, Some(Family::A), setup).expect("decision");
        assert_eq!(
            phase,
            ConnectPhase::Peer {
                addr: pub_v6(),
                family: Family::Aaaa,
                connect_deadline: Deadline::connect_attempt(now, setup),
            }
        );
    }

    #[test]
    fn address_index_equals_earlier_attempts_in_family() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4(), pub_v4_b()], 100, 3600);
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let counts = AttemptCounts::new().record(Family::A);
        let req = auth_request("sub.example.org");
        let t0 = anchor();
        let now = later(t0, 1);
        let setup = setup_at(t0);
        let phase = next_phase(&req, &view, now, counts, None, setup).expect("decision");
        assert_eq!(
            phase,
            ConnectPhase::Peer {
                addr: pub_v4_b(),
                family: Family::A,
                connect_deadline: Deadline::connect_attempt(now, setup),
            }
        );
    }

    #[test]
    fn single_family_remains_uses_it() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let req = auth_request("sub.example.org");
        let t0 = anchor();
        let now = later(t0, 1);
        let setup = setup_at(t0);
        let phase =
            next_phase(&req, &view, now, AttemptCounts::new(), None, setup).expect("decision");
        assert_eq!(
            phase,
            ConnectPhase::Peer {
                addr: pub_v6(),
                family: Family::Aaaa,
                connect_deadline: Deadline::connect_attempt(now, setup),
            }
        );
    }

    #[test]
    fn retired_binding_is_not_usable() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4()], 1, 1);
        let decision =
            select_peer(&cache, n, 300_000, AttemptCounts::new(), None).expect("selection");
        assert_eq!(decision, PeerDecision::NoFamily);
    }

    #[test]
    fn family_exhausted_at_current_address_count_uses_other_family() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
        publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let counts = AttemptCounts::new().record(Family::A).record(Family::A);
        let req = auth_request("sub.example.org");
        let t0 = anchor();
        let now = later(t0, 1);
        let setup = setup_at(t0);
        let phase = next_phase(&req, &view, now, counts, Some(Family::A), setup).expect("decision");
        assert_eq!(
            phase,
            ConnectPhase::Peer {
                addr: pub_v6(),
                family: Family::Aaaa,
                connect_deadline: Deadline::connect_attempt(now, setup),
            }
        );
    }

    #[test]
    fn setup_deadline_expiry_returns_deadline_exhausted() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let req = auth_request("sub.example.org");
        let t0 = anchor();
        let phase = next_phase(
            &req,
            &view,
            later(t0, 10),
            AttemptCounts::new(),
            None,
            setup_at(t0),
        )
        .expect("decision");
        assert_eq!(phase, ConnectPhase::DeadlineExhausted);
    }

    #[test]
    fn expired_prior_connect_deadline_retries_while_setup_is_live() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let req = auth_request("sub.example.org");
        let t0 = anchor();
        let now = later(t0, 9);
        let setup = setup_at(t0);
        let phase =
            next_phase(&req, &view, now, AttemptCounts::new(), None, setup).expect("decision");
        let ConnectPhase::Peer {
            addr,
            family,
            connect_deadline,
        } = phase
        else {
            panic!("setup is live: expected a retried Peer, got {phase:?}");
        };
        assert_eq!(addr, pub_v4());
        assert_eq!(family, Family::A);
        assert_eq!(connect_deadline.limit(), setup.limit());
    }

    #[test]
    fn attempt_budget_exhausted_returns_candidates_exhausted() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let req = auth_request("sub.example.org");
        let counts = AttemptCounts::new()
            .record(Family::A)
            .record(Family::Aaaa)
            .record(Family::A)
            .record(Family::Aaaa);
        let t0 = anchor();
        let phase =
            next_phase(&req, &view, later(t0, 1), counts, None, setup_at(t0)).expect("decision");
        assert_eq!(phase, ConnectPhase::CandidatesExhausted);
    }

    #[test]
    fn worker_admits_up_to_32_pending_setups_and_rejects_the_33rd() {
        let t0 = anchor();
        let mut worker = Worker::boot(clock(t0));
        for _ in 0..MAX_PENDING_SETUPS {
            worker
                .admit(t0)
                .expect("admitted within the pending budget");
        }
        assert_eq!(worker.pending(), MAX_PENDING_SETUPS);
        assert_eq!(worker.admit(t0), Err(AdmissionError::PendingCapacity));
    }

    #[test]
    fn releasing_a_setup_slot_frees_pending_capacity() {
        let t0 = anchor();
        let mut worker = Worker::boot(clock(t0));
        for _ in 0..MAX_PENDING_SETUPS - 1 {
            worker.admit(t0).expect("admitted");
        }
        let last = worker.admit(t0).expect("admitted at the pending cap");
        worker.release(last);
        worker.admit(t0).expect("seat freed by release");
        assert_eq!(worker.pending(), MAX_PENDING_SETUPS);
    }

    #[test]
    fn worker_binds_slot_capacity_at_128_occupied_tunnels() {
        let t0 = anchor();
        let mut worker = Worker::boot(clock(t0));
        let mut tunnels = Vec::new();
        for _ in 0..MAX_TUNNELS {
            let slot = worker.admit(t0).expect("admitted to a free slot");
            tunnels.push(worker.finish_setup(slot));
        }
        assert_eq!(worker.admit(t0), Err(AdmissionError::SlotCapacity));
        assert_eq!(worker.pending(), 0);
        assert_eq!(worker.occupied(), MAX_TUNNELS);
        for tunnel in tunnels {
            worker.release_tunnel(tunnel);
        }
        assert_eq!(worker.occupied(), 0);
        assert_eq!(worker.pending(), 0);
    }

    #[test]
    fn graduating_or_releasing_one_slot_never_touches_another_slots_pending() {
        let t0 = anchor();
        let mut worker = Worker::boot(clock(t0));
        let a = worker.admit(t0).expect("slot a");
        let b = worker.admit(t0).expect("slot b");
        assert_eq!(worker.pending(), 2);
        let a_tunnel = worker.finish_setup(a);
        assert_eq!(
            worker.pending(),
            1,
            "graduating slot a must drop only a's pending seat"
        );
        assert_eq!(worker.occupied(), 2);
        worker.release_tunnel(a_tunnel);
        assert_eq!(
            worker.pending(),
            1,
            "releasing established a must not touch b's pending seat"
        );
        assert_eq!(worker.occupied(), 1);
        worker.release(b);
        assert_eq!(worker.pending(), 0);
        assert_eq!(worker.occupied(), 0);
    }

    #[test]
    fn admitted_slot_carries_its_absolute_setup_deadline() {
        let t0 = anchor();
        let mut worker = Worker::boot(clock(t0));
        let slot = worker.admit(t0).expect("admitted");
        assert_eq!(worker.setup_deadline(&slot), Some(Deadline::setup(t0)));
        let tunnel = worker.finish_setup(slot);
        assert_eq!(
            worker.tunnel_setup_deadline(&tunnel),
            Some(Deadline::setup(t0)),
            "the setup deadline starts at accept and is never reset by graduation"
        );
        assert_eq!(worker.pending(), 0);
        worker.release_tunnel(tunnel);
        assert_eq!(worker.occupied(), 0);
    }

    #[test]
    fn setup_deadline_is_exactly_ten_seconds_after_accept() {
        let t0 = anchor();
        assert_eq!(
            Deadline::setup(t0).limit(),
            t0 + Duration::from_secs(SETUP_DEADLINE_SECS)
        );
    }

    #[test]
    fn connect_deadline_expires_full_two_seconds_after_a_fractional_initiation() {
        let t0 = anchor();
        let setup = Deadline::setup(t0);
        let initiated = t0 + Duration::from_millis(1900);
        let attempt = Deadline::connect_attempt(initiated, setup);
        assert_eq!(
            attempt.limit(),
            initiated + Duration::from_secs(CONNECT_DEADLINE_SECS),
            "a 2 s connect deadline initiated at x.9 s must expire at exactly \
             x.9 + 2.0 s, never earlier through whole-second truncation"
        );
    }

    #[test]
    fn connect_deadline_clips_to_the_setup_deadline_when_fresh_would_exceed_it() {
        let t0 = anchor();
        let setup = Deadline::setup(t0);
        let late = t0 + Duration::from_secs(9);
        assert_eq!(
            Deadline::connect_attempt(late, setup).limit(),
            setup.limit(),
            "a connect initiated 1 s before setup end must clip to the setup deadline"
        );
    }

    #[test]
    fn selecting_after_a_a_aaaa_uses_a_not_aaaa() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(
            &mut cache,
            n,
            Family::A,
            &[pub_v4(), pub_v4_b(), v4([9, 9, 9, 9])],
            100,
            3600,
        );
        publish(
            &mut cache,
            n,
            Family::Aaaa,
            &[pub_v6(), second_v6()],
            100,
            3600,
        );
        let counts = AttemptCounts::new()
            .record(Family::A)
            .record(Family::A)
            .record(Family::Aaaa);
        let decision = select_peer(&cache, n, 1000, counts, Some(Family::Aaaa)).expect("selection");
        assert_eq!(
            decision,
            PeerDecision::Peer {
                addr: v4([9, 9, 9, 9]),
                family: Family::A
            }
        );
    }

    #[test]
    fn selecting_after_a_aaaa_a_uses_aaaa_not_a() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(
            &mut cache,
            n,
            Family::A,
            &[pub_v4(), pub_v4_b(), v4([9, 9, 9, 9])],
            100,
            3600,
        );
        publish(
            &mut cache,
            n,
            Family::Aaaa,
            &[pub_v6(), second_v6()],
            100,
            3600,
        );
        let counts = AttemptCounts::new()
            .record(Family::A)
            .record(Family::A)
            .record(Family::Aaaa);
        let decision = select_peer(&cache, n, 1000, counts, Some(Family::A)).expect("selection");
        assert_eq!(
            decision,
            PeerDecision::Peer {
                addr: second_v6(),
                family: Family::Aaaa
            }
        );
    }

    #[test]
    fn all_ineligible_family_publishes_empty_and_other_family_is_used() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[v4([127, 0, 0, 1])], 100, 3600);
        publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
        let decision = select_peer(&cache, n, 1000, AttemptCounts::new(), None).expect("selection");
        assert_eq!(
            decision,
            PeerDecision::Peer {
                addr: pub_v6(),
                family: Family::Aaaa
            }
        );
    }

    #[test]
    fn cache_for_config_matches_the_allowlist_for_every_ordinal() {
        let cfg = config();
        let cache = Cache::for_config(&cfg).expect("cache for config");
        assert_eq!(cache.name_count(), cfg.allowlist().len());
        for ordinal in 0..cfg.allowlist().len() {
            assert!(
                cache.name_index(ordinal).is_some(),
                "allowlist ordinal {ordinal} is admitted by the cache"
            );
        }
    }

    #[test]
    fn refusal_statuses_follow_the_canonical_fixed_matrix() {
        let t0 = anchor();
        assert_eq!(ConnectPhase::Forbidden.status(), 403);
        assert_eq!(ConnectPhase::NoBinding.status(), 502);
        assert_eq!(ConnectPhase::CandidatesExhausted.status(), 502);
        assert_eq!(ConnectPhase::DeadlineExhausted.status(), 504);
        assert_eq!(
            ConnectPhase::Peer {
                addr: pub_v4(),
                family: Family::A,
                connect_deadline: setup_at(t0)
            }
            .status(),
            200
        );
    }

    #[test]
    fn never_resolved_and_exhausted_attempts_are_distinct_502_verdicts() {
        let cache = cache_with(2);
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let req = auth_request("sub.example.org");
        let t0 = anchor();
        let never_resolved = next_phase(
            &req,
            &view,
            later(t0, 1),
            AttemptCounts::new(),
            None,
            setup_at(t0),
        )
        .expect("decision");
        assert_eq!(never_resolved, ConnectPhase::NoBinding);

        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let counts = AttemptCounts::new()
            .record(Family::A)
            .record(Family::Aaaa)
            .record(Family::A)
            .record(Family::Aaaa);
        let exhausted =
            next_phase(&req, &view, later(t0, 1), counts, None, setup_at(t0)).expect("decision");
        assert_eq!(exhausted, ConnectPhase::CandidatesExhausted);
    }

    #[test]
    fn chunked_connect_feed_still_authorizes() {
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4()], 100, 3600);
        let head = b"CONNECT sub.example.org:443 HTTP/1.1\r\n\r\n";
        let mut parser = ConnectParser::new();
        for chunk in head.chunks(3) {
            match parser.feed(chunk).expect("head feed") {
                crate::connect::Feed::Incomplete => {}
                crate::connect::Feed::Complete { .. } => break,
            }
        }
        let req = parser.result().copied().expect("result").expect("valid");
        let cfg = config();
        let view = view_of(&cfg, &cache);
        let t0 = anchor();
        let now = later(t0, 1);
        let setup = setup_at(t0);
        let phase =
            next_phase(&req, &view, now, AttemptCounts::new(), None, setup).expect("decision");
        assert_eq!(
            phase,
            ConnectPhase::Peer {
                addr: pub_v4(),
                family: Family::A,
                connect_deadline: Deadline::connect_attempt(now, setup),
            }
        );
    }

    #[test]
    fn traffic_buffer_matches_boot_storage_unit() {
        assert_eq!(std::mem::size_of::<TrafficBuffer>(), BUFFER_BYTES);
    }

    #[test]
    fn cache_secs_is_mounted_on_the_dns_epoch_not_zero() {
        let t0 = anchor();
        let clock = WorkerClock::new(t0, DNS_EPOCH);
        assert_eq!(
            clock.cache_secs(later(t0, 5)),
            DNS_EPOCH + 5,
            "serving cache seconds must count from the DNS epoch the startup \
             receipts were written on, otherwise a goal-scale entry is \
             evaluated at ~0..N seconds and stays permanently Fresh (1cws M2r)"
        );
    }

    #[test]
    fn worker_decide_reads_the_slot_deadline_instead_of_a_free_setup() {
        let t0 = anchor();
        let clock = WorkerClock::new(t0, DNS_EPOCH);
        let cfg = config();
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4()], DNS_EPOCH, 3600);
        let view = view_of_clocked(&cfg, &cache, clock);
        let mut worker = Worker::boot(clock);
        let slot = worker.admit(t0).expect("admitted");
        let req = auth_request("sub.example.org");
        let phase = worker
            .decide(&view, &slot, &req, later(t0, 1), AttemptCounts::new(), None)
            .expect("decision from the slot-bound deadline");
        assert!(
            matches!(
                phase,
                ConnectPhase::Peer {
                    family: Family::A,
                    ..
                }
            ),
            "slot-bound setup must authorize this owned cache: {phase:?}"
        );
        let ConnectPhase::Peer {
            connect_deadline, ..
        } = phase
        else {
            panic!("expected Peer");
        };
        assert_eq!(
            connect_deadline.limit(),
            later(t0, 1) + Duration::from_secs(CONNECT_DEADLINE_SECS),
            "the per-attempt deadline is freshly clipped from the slot's setup deadline"
        );
        worker.release(slot);
        assert_eq!(worker.occupied(), 0);
    }

    #[test]
    fn releasing_a_slot_consumes_the_handle_and_frees_capacity_for_reuse() {
        let t0 = anchor();
        let clock = WorkerClock::new(t0, DNS_EPOCH);
        let mut worker = Worker::boot(clock);
        let a = worker.admit(t0).expect("slot a");
        assert_eq!(worker.occupied(), 1);
        worker.release(a);
        assert_eq!(worker.occupied(), 0, "release consumes the granted handle");
        let b = worker.admit(t0).expect("the freed seat is reusable");
        assert_eq!(worker.occupied(), 1);
        let b_tunnel = worker.finish_setup(b);
        assert_eq!(worker.pending(), 0);
        worker.release_tunnel(b_tunnel);
        assert_eq!(worker.occupied(), 0);
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn serving_decision_path_does_not_allocate_or_deallocate() {
        use crate::alloc::{Phase, run_phase};
        let cfg = config();
        let mut cache = cache_with(2);
        let n = name(&cache, 0);
        publish(&mut cache, n, Family::A, &[pub_v4(), pub_v4_b()], 100, 3600);
        publish(&mut cache, n, Family::Aaaa, &[pub_v6()], 100, 3600);
        let view = view_of(&cfg, &cache);
        let req = auth_request("sub.example.org");
        let t0 = anchor();
        let clock = clock(t0);
        let setup = setup_at(t0);
        let now = later(t0, 1);
        let (_, control) = run_phase(Phase::Serving, || 0usize);
        assert!(control.all_zero(), "baseline should be quiet: {control:?}");
        let (outcome, counts) = run_phase(Phase::Serving, || {
            let mut counts = AttemptCounts::new();
            for _ in 0..=MAX_UPSTREAM_ATTEMPTS {
                let _phase = next_phase(&req, &view, now, counts, None, setup);
                counts = counts.record(Family::A);
            }
            counts.total()
        });
        assert!(
            counts.all_zero(),
            "serving decision path allocated: {counts:?}"
        );
        assert_eq!(outcome, (MAX_UPSTREAM_ATTEMPTS + 1) as u8);
        let (select, select_counts) = run_phase(Phase::Serving, || {
            select_peer(&cache, n, clock.cache_secs(now), AttemptCounts::new(), None).unwrap()
        });
        assert_eq!(
            select,
            PeerDecision::Peer {
                addr: pub_v4(),
                family: Family::A
            }
        );
        assert!(
            select_counts.all_zero(),
            "select_peer allocated: {select_counts:?}"
        );
    }
}
