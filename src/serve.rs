//! Boot-owned serving storage and the canonical startup-readiness rule.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use mio::net::TcpListener;

use crate::cache::{Cache, CacheError, EntryState, Family, NameIndex};
use crate::config::Config;
use crate::connect::ConnectRequest;
use crate::schedule::Schedules;
use crate::startup_dns::{STARTUP_WINDOW_SECS, StartupDns, StartupDnsError, StartupReport};
use crate::worker::{
    AdmissionError, AttemptCounts, ConnectPhase, Deadline, DecideError, SlotIndex, TunnelIndex,
    Worker, WorkerClock, WorkerView,
};

/// The retained serving storage initialized once before the postboot phase.
/// One worker owns the cache, refresh schedules, and the single DNS transport
/// with its fixed response workspace, plus the fixed tunnel-slot lifecycle and
/// the single clock authority (precise deadline anchor + DNS whole-second
/// epoch) — none of it is constructed per connection or per tunnel. Traffic
/// buffers are boot-owned separately. [`ServeStorage::boot`] is the only
/// construction path, binding the cache size and allowance to one validated
/// allowlist, and [`Self::work_view`] is the only seam that pairs that config
/// and cache for a CONNECT decision.
pub struct ServeStorage {
    cache: Cache,
    schedules: Schedules,
    dns: StartupDns,
    config: Config,
    worker: Worker,
    origin: Instant,
    now0: u64,
}

/// How serving begins when the startup window closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingMode {
    /// Every configured name is usable.
    Full,
    /// At least one name is unresolved and within the configured allowance.
    Degraded,
}

/// The terminal startup-readiness decision from the canonical rule
/// (alumina.md:65): open the listener when the unresolved count is at most the
/// configured allowance, else exit with status 75.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupDecision {
    Serve(ServingMode),
    Exit75 { unresolved: u32 },
}

/// The outcome of the boot-owned startup window: the readiness decision, the
/// single DNS-window exchange report, and the listener opened exactly when a
/// serving decision is taken.
pub struct StartupOutcome {
    /// The terminal decision, or the early [`ServingMode::Full`] decision when
    /// every name was usable and the listener opened immediately.
    pub decision: StartupDecision,
    /// The single 90-second DNS-window exchange report.
    pub report: StartupReport,
    /// The bound CONNECT listener for a serving decision; `None` for exit 75.
    pub listener: Option<TcpListener>,
}

/// A fatal startup failure: a DNS transport/storage error, a readiness
/// evaluation error, or a listener bind failure. Counted per-exchange network
/// failures never abort resolution and are carried by [`StartupReport`]
/// instead.
#[derive(Debug)]
pub enum StartupError {
    Dns(StartupDnsError),
    Cache(CacheError),
    Listener {
        kind: io::ErrorKind,
        detail: &'static str,
    },
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupError::Dns(err) => write!(f, "startup: {err}"),
            StartupError::Cache(err) => write!(f, "startup readiness: {err}"),
            StartupError::Listener { kind, detail } => {
                write!(f, "startup listener ({detail}): {kind}")
            }
        }
    }
}

impl From<StartupDnsError> for StartupError {
    fn from(err: StartupDnsError) -> Self {
        StartupError::Dns(err)
    }
}

impl From<CacheError> for StartupError {
    fn from(err: CacheError) -> Self {
        StartupError::Cache(err)
    }
}

impl ServeStorage {
    /// Constructs the boot-owned cache, schedules, worker, and DNS transport
    /// over a parsed allowlist, capturing the single process-clock origin at
    /// boot. All retained serving state is allocated here, before the startup
    /// DNS window opens; the config is the sole allowance and listener
    /// authority for the life of the storage, and the worker's clock is
    /// re-anchored to the DNS window's exact origin and epoch when the window
    /// runs ([`Self::run_startup`]).
    ///
    /// # Errors
    ///
    /// Returns the underlying storage error when the cache, schedules, or DNS
    /// poll registry cannot be created.
    pub fn boot(config: &Config) -> Result<ServeStorage, StartupDnsError> {
        let name_count = config.allowlist().len();
        let cache = Cache::new(name_count).map_err(StartupDnsError::from)?;
        let schedules = Schedules::new(name_count).map_err(StartupDnsError::from)?;
        let dns = StartupDns::new()?;
        let origin = Instant::now();
        let worker = Worker::boot(WorkerClock::new(origin, 0));
        Ok(ServeStorage {
            cache,
            schedules,
            dns,
            config: config.clone(),
            worker,
            origin,
            now0: 0,
        })
    }

    /// The single owned config/cache/clock view used for CONNECT decisions: a
    /// [`crate::worker::WorkerView`] bound to this storage's own config, cache,
    /// and clock authority, so no code can pair an unrelated config or clock
    /// with this cache (1cws M4r/M2r; destination-binding, alumina.md:145).
    pub fn work_view(&self) -> WorkerView<'_> {
        WorkerView::new(&self.config, &self.cache, self.worker.clock())
    }

    /// The whole-second DNS/cache serving clock, mounted on the same origin
    /// and epoch the startup window wrote receipts on: `now0` plus whole
    /// seconds since the window origin. The single origin+offset continuity
    /// that keeps cache freshness comparable in serving (1cws M2r).
    #[allow(dead_code)]
    pub(crate) fn cache_secs(&self, now: Instant) -> u64 {
        self.now0
            .saturating_add(now.saturating_duration_since(self.origin).as_secs())
    }

    /// Re-anchors the retained worker and cache-seconds authority to the exact
    /// origin and DNS epoch a startup window (or a test) establishes. Called
    /// by [`Self::run_startup_within`] after `resolve_window` so serving
    /// keeps the window's own elapsed base.
    pub(crate) fn mount_clock(&mut self, origin: Instant, now0: u64) {
        self.origin = origin;
        self.now0 = now0;
        self.worker.set_clock(WorkerClock::new(origin, now0));
    }

    /// The retained cache, read-only.
    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    /// The retained refresh schedules, read-only.
    pub fn schedules(&self) -> &Schedules {
        &self.schedules
    }

    /// The retained DNS transport with its fixed response workspace.
    pub fn dns(&self) -> &StartupDns {
        &self.dns
    }

    /// Admits a new actual connection into a retained slot at the accept
    /// instant, capturing its absolute setup deadline. Slot lifecycle actions
    /// are private to actual accept/connect/close event processing.
    ///
    /// # Errors
    ///
    /// `SlotCapacity` or `PendingCapacity`, mapped to HTTP 503 + close
    /// (alumina.md:193).
    pub(crate) fn accept(&mut self, now: Instant) -> Result<SlotIndex, AdmissionError> {
        self.worker.admit(now)
    }

    /// The one owned CONNECT decision for an admitted slot: reads the setup
    /// deadline from the slot and cache seconds from this storage's clock
    /// authority. Does not consume the handle; the event processor still needs
    /// it to graduate or release.
    ///
    /// # Errors
    ///
    /// `NotInSetup` for a stale handle (unreachable by the handle discipline)
    /// or the underlying current-cache lookup error.
    pub(crate) fn decide(
        &self,
        slot: &SlotIndex,
        request: &ConnectRequest,
        now: Instant,
        counts: AttemptCounts,
        previous: Option<Family>,
    ) -> Result<ConnectPhase, DecideError> {
        self.worker
            .decide(&self.work_view(), slot, request, now, counts, previous)
    }

    /// Graduates an admitted slot to established work once the successful
    /// CONNECT response completed, returning the established handle.
    #[allow(dead_code)]
    pub(crate) fn finish_setup(&mut self, slot: SlotIndex) -> TunnelIndex {
        self.worker.finish_setup(slot)
    }

    /// Releases an in-setup slot, consuming its handle.
    pub(crate) fn release(&mut self, slot: SlotIndex) {
        self.worker.release(slot);
    }

    /// Releases an established tunnel, consuming its handle.
    #[allow(dead_code)]
    pub(crate) fn release_tunnel(&mut self, tunnel: TunnelIndex) {
        self.worker.release_tunnel(tunnel);
    }

    /// The absolute setup deadline of an admitted slot.
    #[allow(dead_code)]
    pub(crate) fn setup_deadline(&self, slot: &SlotIndex) -> Option<Deadline> {
        self.worker.setup_deadline(slot)
    }

    /// The absolute setup deadline of an established tunnel.
    #[allow(dead_code)]
    pub(crate) fn tunnel_setup_deadline(&self, tunnel: &TunnelIndex) -> Option<Deadline> {
        self.worker.tunnel_setup_deadline(tunnel)
    }

    /// The fixed slot index underlying an admitted handle, for the actual
    /// event processor to key its per-slot state.
    pub(crate) fn slot_index(&self, slot: &SlotIndex) -> usize {
        self.worker.slot_index(slot)
    }

    /// The fixed slot index underlying an established handle.
    #[allow(dead_code)]
    pub(crate) fn tunnel_index(&self, tunnel: &TunnelIndex) -> usize {
        self.worker.tunnel_index(tunnel)
    }

    /// Counts currently in setup, from the retained worker's slot states.
    #[allow(dead_code)]
    pub(crate) fn pending(&self) -> usize {
        self.worker.pending()
    }

    /// Counts currently occupied, from the retained worker's slot states.
    #[allow(dead_code)]
    pub(crate) fn occupied(&self) -> usize {
        self.worker.occupied()
    }

    /// Applies the canonical startup-readiness rule over the resolved cache:
    /// every admitted name is counted once as usable or unresolved; all usable
    /// is [`ServingMode::Full`], unresolved within the configured allowance is
    /// [`ServingMode::Degraded`], otherwise exit with status 75.
    ///
    /// # Errors
    ///
    /// Propagates `NameOutOfRange` from an entry lookup; names derived from
    /// `cache.name_index` within `cache.name_count()` are always admitted.
    pub fn startup_decision(&self, now: u64) -> Result<StartupDecision, CacheError> {
        let mut unresolved = 0u32;
        for ordinal in 0..self.cache.name_count() {
            let name = self
                .cache
                .name_index(ordinal)
                .ok_or(CacheError::NameOutOfRange)?;
            if !usable_name(&self.cache, name, now)? {
                unresolved += 1;
            }
        }
        if unresolved == 0 {
            Ok(StartupDecision::Serve(ServingMode::Full))
        } else if u64::from(unresolved) <= u64::from(self.config.startup_unresolved_allowance()) {
            Ok(StartupDecision::Serve(ServingMode::Degraded))
        } else {
            Ok(StartupDecision::Exit75 { unresolved })
        }
    }

    /// Runs the boot-owned startup DNS window with the production-fixed
    /// 90-second deadline and evaluates the canonical readiness rule once when
    /// it returns: every name usable (or a late retry succeeding) opens the
    /// listener early as [`ServingMode::Full`]; a return at the deadline with
    /// unresolved names decides [`ServingMode::Degraded`] or exit 75 from the
    /// final cache. The window is fixed here and never a public parameter;
    /// [`Self::run_startup_within`] is the only shortened-window path and it is
    /// crate-private for the loopback test seam.
    ///
    /// # Errors
    ///
    /// Returns the underlying fatal DNS/readiness error, or `Listener` when
    /// the configured listen socket cannot be bound.
    pub fn run_startup(
        &mut self,
        nameserver: SocketAddr,
        now0: u64,
    ) -> Result<StartupOutcome, StartupError> {
        self.run_startup_within(nameserver, now0, Duration::from_secs(STARTUP_WINDOW_SECS))
    }

    /// The startup-window core shared by [`Self::run_startup`] and the
    /// crate's shortened-window loopback tests. The readiness decision is
    /// taken at the single window deadline this core owns, expressed in `now0`
    /// seconds plus the elapsed whole seconds since the window opened, so no
    /// second clock anchor decides the outcome.
    ///
    /// # Errors
    ///
    /// Returns the underlying fatal DNS/readiness error, or `Listener` when
    /// the configured listen socket cannot be bound.
    pub(crate) fn run_startup_within(
        &mut self,
        nameserver: SocketAddr,
        now0: u64,
        window: Duration,
    ) -> Result<StartupOutcome, StartupError> {
        let (report, decision_seconds) = self.dns.resolve_window(
            &self.config,
            &mut self.cache,
            &mut self.schedules,
            nameserver,
            now0,
            window,
        )?;
        self.mount_clock(self.dns.window_start(), now0);
        let decision = self.startup_decision(now0 + decision_seconds)?;
        let listener = match decision {
            StartupDecision::Serve(_) => Some(self.bind_listener()?),
            StartupDecision::Exit75 { .. } => None,
        };
        Ok(StartupOutcome {
            decision,
            report,
            listener,
        })
    }

    fn bind_listener(&mut self) -> Result<TcpListener, StartupError> {
        let addr = SocketAddr::new(self.config.listen().ip(), self.config.listen().port());
        TcpListener::bind(addr).map_err(|err| StartupError::Listener {
            kind: err.kind(),
            detail: "connect listener bind",
        })
    }
}

/// A name is usable when either family holds an eligible non-retired positive
/// binding (canonical alumina.md:65); validated negatives and unattempted
/// names are unresolved.
fn usable_name(cache: &Cache, name: NameIndex, now: u64) -> Result<bool, CacheError> {
    for family in Family::ALL {
        let entry = cache.entry(name, family)?;
        if matches!(entry.state(now), EntryState::Fresh | EntryState::Stale) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{Generation, StagedPositive};
    use crate::eligibility::NumericAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const FRESH: u64 = 1000;
    const TTL: u64 = 10;
    const RETIREMENT: u64 = FRESH + TTL + crate::cache::STALE_GRACE;

    fn idx(cache: &Cache, ordinal: usize) -> NameIndex {
        cache.name_index(ordinal).expect("admitted name ordinal")
    }

    fn v4(octets: [u8; 4]) -> NumericAddr {
        NumericAddr::V4(Ipv4Addr::from(octets))
    }

    fn v6(octets: [u8; 16]) -> NumericAddr {
        NumericAddr::V6(Ipv6Addr::from(octets))
    }

    fn config_with_allowance(count: usize, allowance: u8) -> Config {
        let names = match count {
            1 => "\"alpha.example.org\"",
            2 => "\"alpha.example.org\", \"beta.example.org\"",
            3 => "\"alpha.example.org\", \"beta.example.org\", \"gamma.example.org\"",
            _ => panic!("test allowlist helper supports 1..=3 names"),
        };
        let doc = format!(
            "allowlist = [{names}]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = {allowance}\n"
        );
        crate::config::parse_config_document(&doc).expect("valid test config")
    }

    fn booted(count: usize, allowance: u8) -> ServeStorage {
        ServeStorage::boot(&config_with_allowance(count, allowance)).expect("boot serving storage")
    }

    fn publish_a(cache: &mut Cache, ordinal: usize, receipt: u64, ttl: u64) {
        let name = cache.name_index(ordinal).expect("admitted name ordinal");
        let addrs = [v4([1, 1, 1, 1])];
        let staged =
            StagedPositive::stage(name, Family::A, Generation::INITIAL, &addrs, receipt, ttl)
                .expect("stage A binding");
        cache.publish_positive(&staged).expect("publish A binding");
    }

    fn publish_aaaa(cache: &mut Cache, ordinal: usize, receipt: u64, ttl: u64) {
        let name = cache.name_index(ordinal).expect("admitted name ordinal");
        let addrs = [v6([
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x11, 0x11,
        ])];
        let staged = StagedPositive::stage(
            name,
            Family::Aaaa,
            Generation::INITIAL,
            &addrs,
            receipt,
            ttl,
        )
        .expect("stage AAAA binding");
        cache
            .publish_positive(&staged)
            .expect("publish AAAA binding");
    }

    #[test]
    fn empty_cache_names_are_unresolved() {
        let cache = Cache::new(1).unwrap();
        assert_eq!(usable_name(&cache, idx(&cache, 0), 0), Ok(false));
    }

    #[test]
    fn fresh_positive_binding_makes_name_usable() {
        let mut cache = Cache::new(1).unwrap();
        publish_a(&mut cache, 0, FRESH, TTL);
        assert_eq!(usable_name(&cache, idx(&cache, 0), FRESH), Ok(true));
    }

    #[test]
    fn stale_positive_binding_remains_usable() {
        let mut cache = Cache::new(1).unwrap();
        publish_a(&mut cache, 0, FRESH, TTL);
        let stale = FRESH + TTL + 1;
        assert!(stale < RETIREMENT);
        assert_eq!(usable_name(&cache, idx(&cache, 0), stale), Ok(true));
    }

    #[test]
    fn retired_binding_is_unresolved() {
        let mut cache = Cache::new(1).unwrap();
        publish_a(&mut cache, 0, FRESH, TTL);
        assert_eq!(usable_name(&cache, idx(&cache, 0), RETIREMENT), Ok(false));
    }

    #[test]
    fn either_family_positive_makes_name_usable() {
        let mut cache = Cache::new(1).unwrap();
        publish_aaaa(&mut cache, 0, FRESH, TTL);
        assert_eq!(usable_name(&cache, idx(&cache, 0), FRESH + 5), Ok(true));
    }

    #[test]
    fn nxdomain_eviction_makes_name_unresolved() {
        let mut cache = Cache::new(1).unwrap();
        publish_a(&mut cache, 0, FRESH, TTL);
        cache.evict_nxdomain(idx(&cache, 0)).unwrap();
        assert_eq!(usable_name(&cache, idx(&cache, 0), FRESH + 5), Ok(false));
    }

    #[test]
    fn all_names_usable_decides_full_serve() {
        let mut storage = booted(2, 0);
        publish_a(&mut storage.cache, 0, FRESH, TTL);
        publish_a(&mut storage.cache, 1, FRESH, TTL);
        assert_eq!(
            storage.startup_decision(FRESH + 5),
            Ok(StartupDecision::Serve(ServingMode::Full))
        );
    }

    #[test]
    fn unresolved_within_allowance_serves_degraded() {
        let mut storage = booted(2, 1);
        publish_a(&mut storage.cache, 0, FRESH, TTL);
        let decision = storage.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Serve(ServingMode::Degraded));
    }

    #[test]
    fn allowance_zero_requires_every_name_usable() {
        let mut storage = booted(2, 0);
        publish_a(&mut storage.cache, 0, FRESH, TTL);
        let decision = storage.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Exit75 { unresolved: 1 });
    }

    #[test]
    fn trailing_unresolved_name_counts_against_allowance() {
        let mut strict = booted(2, 0);
        publish_a(&mut strict.cache, 0, FRESH, TTL);
        let decision = strict.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Exit75 { unresolved: 1 });
        let mut tolerant = booted(2, 1);
        publish_a(&mut tolerant.cache, 0, FRESH, TTL);
        let decision = tolerant.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Serve(ServingMode::Degraded));
    }

    #[test]
    fn trailing_last_name_unresolved_is_counted() {
        let mut strict = booted(3, 0);
        publish_a(&mut strict.cache, 0, FRESH, TTL);
        publish_a(&mut strict.cache, 1, FRESH, TTL);
        let decision = strict.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Exit75 { unresolved: 1 });
        let mut tolerant = booted(3, 1);
        publish_a(&mut tolerant.cache, 0, FRESH, TTL);
        publish_a(&mut tolerant.cache, 1, FRESH, TTL);
        let decision = tolerant.startup_decision(FRESH + 5).unwrap();
        assert_eq!(decision, StartupDecision::Serve(ServingMode::Degraded));
    }

    #[test]
    fn retired_everywhere_is_exit75_with_exact_unresolved_count() {
        let mut storage = booted(2, 1);
        publish_a(&mut storage.cache, 0, FRESH, TTL);
        publish_a(&mut storage.cache, 1, FRESH, TTL);
        let decision = storage.startup_decision(RETIREMENT).unwrap();
        assert_eq!(decision, StartupDecision::Exit75 { unresolved: 2 });
    }

    #[test]
    fn binding_published_strictly_before_deadline_counts_at_the_snapshot() {
        let mut storage = booted(1, 0);
        publish_a(&mut storage.cache, 0, 1089, 1);
        assert_eq!(
            storage.startup_decision(1090).unwrap(),
            StartupDecision::Serve(ServingMode::Full)
        );
    }

    #[test]
    fn serve_storage_boot_corresponds_allowlist_at_boundary() {
        let config = config_with_allowance(2, 1);
        let storage = ServeStorage::boot(&config).expect("boot serving storage");
        assert_eq!(storage.cache().name_count(), config.allowlist().len());
        assert_eq!(storage.schedules().name_count(), config.allowlist().len());
        assert_eq!(
            storage.cache().name_count(),
            storage.schedules().name_count()
        );
    }

    #[test]
    fn work_view_is_bound_to_the_owning_storages_state() {
        use crate::connect::{ConnectParser, Feed};
        use crate::worker::{ConnectPhase, Deadline};
        use std::time::Instant;
        let mut storage = booted(1, 0);
        publish_a(&mut storage.cache, 0, FRESH + 5, TTL);
        let t0 = Instant::now();
        let now = t0 + Duration::from_secs(1);
        let mut parser = ConnectParser::new();
        let head = b"CONNECT alpha.example.org:443 HTTP/1.1\r\n\r\n";
        match parser.feed(head).expect("valid connect head") {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        let req = *parser
            .result()
            .copied()
            .expect("connect result present")
            .as_ref()
            .expect("valid connect request");
        let slot = storage.accept(t0).expect("admitted via the owned seam");
        let phase = storage
            .decide(&slot, &req, now, crate::worker::AttemptCounts::new(), None)
            .expect("decision via the owned seam");
        assert!(
            matches!(
                phase,
                ConnectPhase::Peer {
                    family: Family::A,
                    ..
                }
            ),
            "the owned seam must authorize this storage's own cache: {phase:?}"
        );
        assert_eq!(phase.status(), 200);
        assert_eq!(
            storage.setup_deadline(&slot),
            Some(Deadline::setup(t0)),
            "the accepted slot carries its own setup deadline"
        );
        storage.release(slot);
        assert_eq!(storage.occupied(), 0);
    }

    #[test]
    fn storage_cache_secs_is_mounted_on_the_dns_epoch() {
        use std::time::Instant;
        let mut storage = booted(1, 0);
        let origin = Instant::now();
        const DNS_EPOCH: u64 = 1_700_000_000;
        storage.mount_clock(origin, DNS_EPOCH);
        let later = origin + Duration::from_secs(7);
        assert_eq!(
            storage.cache_secs(later),
            DNS_EPOCH + 7,
            "serving cache seconds must continue from the mounted DNS epoch"
        );
        assert_eq!(
            storage.cache_secs(origin),
            DNS_EPOCH,
            "the mounted origin evaluates to the epoch itself, not zero"
        );
    }

    #[test]
    fn storage_decide_reads_slot_deadline_and_epoch_scale() {
        use crate::connect::{ConnectParser, Feed};
        use crate::worker::ConnectPhase;
        use std::time::Instant;
        let mut storage = booted(1, 0);
        const DNS_EPOCH: u64 = 1_700_000_000;
        storage.mount_clock(Instant::now(), DNS_EPOCH);
        // Entry is Fresh on the DNS scale at the accept instant and Stale a
        // second later (TTL 1); a zero-anchored clock would see it as
        // permanently Fresh forever (1cws M2r/w6xo witness).
        publish_a(&mut storage.cache, 0, DNS_EPOCH + 1, 1);
        let t0 = Instant::now();
        let slot = storage.accept(t0).expect("admitted");
        let mut parser = ConnectParser::new();
        let head = b"CONNECT alpha.example.org:443 HTTP/1.1\r\n\r\n";
        match parser.feed(head).expect("valid connect head") {
            Feed::Complete { .. } => {}
            Feed::Incomplete => panic!("head should parse to completion"),
        }
        let req = *parser
            .result()
            .copied()
            .expect("connect result present")
            .as_ref()
            .expect("valid connect request");
        let phase = storage
            .decide(&slot, &req, t0, crate::worker::AttemptCounts::new(), None)
            .expect("decision");
        assert!(
            matches!(
                phase,
                ConnectPhase::Peer {
                    family: Family::A,
                    ..
                }
            ),
            "fresh on the DNS scale must authorize the peer: {phase:?}"
        );
        let ConnectPhase::Peer {
            connect_deadline, ..
        } = phase
        else {
            panic!("expected Peer");
        };
        assert_eq!(
            connect_deadline.limit(),
            t0 + Duration::from_secs(crate::worker::CONNECT_DEADLINE_SECS),
            "the per-attempt deadline clips to the slot's setup deadline from its own fresh span"
        );
        storage.release(slot);
        assert_eq!(storage.occupied(), 0);
    }
}

#[cfg(test)]
mod startup_integration {
    use super::ServeStorage;
    use super::ServingMode;
    use super::StartupDecision;
    use crate::cache::Family;
    use crate::config::{Config, parse_config_document};
    use std::io::{ErrorKind, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    const NOW0: u64 = 1000;

    fn config_with(names: &str, allowance: u8, listen_port: u16) -> Config {
        let doc = format!(
            "allowlist = [{names}]\nlisten = \"127.0.0.1:{listen_port}\"\nstartup_unresolved_allowance = {allowance}\n"
        );
        parse_config_document(&doc).expect("valid test config")
    }

    fn ephemeral_port() -> u16 {
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind port probe");
        let port = probe.local_addr().expect("probe address").port();
        drop(probe);
        port
    }

    fn read_query(sock: &mut TcpStream) -> Option<Vec<u8>> {
        let mut lenb = [0u8; 2];
        if sock.read_exact(&mut lenb).is_err() {
            return None;
        }
        let qlen = usize::from(u16::from_be_bytes(lenb));
        if qlen == 0 || qlen > 2048 {
            return None;
        }
        let mut q = vec![0u8; qlen];
        if sock.read_exact(&mut q).is_err() {
            return None;
        }
        Some(q)
    }

    fn write_message(sock: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
        let mut out = Vec::with_capacity(msg.len() + 2);
        out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        out.extend_from_slice(msg);
        sock.write_all(&out)?;
        sock.flush()
    }

    struct DnsResponder {
        addr: SocketAddr,
    }

    impl DnsResponder {
        fn spawn<F>(mut on_query: F) -> DnsResponder
        where
            F: FnMut(Vec<u8>) -> Option<Vec<u8>> + Send + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
            let addr = listener.local_addr().expect("responder address");
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut sock) = stream else {
                        break;
                    };
                    while let Some(query) = read_query(&mut sock) {
                        let Some(reply) = on_query(query) else {
                            break;
                        };
                        if write_message(&mut sock, &reply).is_err() {
                            break;
                        }
                    }
                }
            });
            DnsResponder { addr }
        }
    }

    fn build_positive(query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 16 {
            return None;
        }
        let tid = u16::from_be_bytes([query[0], query[1]]);
        let qname = &query[12..query.len() - 4];
        let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
        let rdata: &[u8] = match qtype {
            1 => &[1, 1, 1, 1],
            28 => &[
                0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
            ],
            _ => return None,
        };
        let mut msg = Vec::with_capacity(query.len() + 22);
        msg.extend_from_slice(&tid.to_be_bytes());
        msg.extend_from_slice(&0x8000u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&query[12..]);
        msg.extend_from_slice(qname);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(rdata);
        Some(msg)
    }

    fn qname_contains(query: &[u8], label: &[u8]) -> bool {
        query.windows(label.len()).any(|w| w == label)
    }

    #[test]
    fn full_serve_opens_listener_early_before_the_window_elapses() {
        let window = Duration::from_secs(2);
        let port = ephemeral_port();
        let config = config_with("\"alpha.example.org\", \"beta.example.org\"", 0, port);
        let responder = DnsResponder::spawn(|q| build_positive(&q));
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let start = Instant::now();
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        let elapsed = start.elapsed();
        assert_eq!(outcome.decision, StartupDecision::Serve(ServingMode::Full));
        assert_eq!(outcome.report.resolved_names, 2);
        let listener = outcome.listener.expect("listener bound for full serve");
        assert_eq!(
            listener.local_addr().expect("listener address").port(),
            port
        );
        assert!(
            elapsed < window,
            "all-usable startup must return early, not wait the window"
        );
        let conn = TcpStream::connect(("127.0.0.1", port));
        assert!(conn.is_ok(), "bound listener must accept connections");
    }

    #[test]
    fn exit75_is_decided_only_at_the_actual_window_deadline() {
        let window = Duration::from_millis(300);
        let port = ephemeral_port();
        let config = config_with("\"alpha.example.org\", \"beta.example.org\"", 0, port);
        let responder = DnsResponder::spawn(|query| {
            if qname_contains(&query, b"\x04beta") {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let start = Instant::now();
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        let elapsed = start.elapsed();
        assert_eq!(outcome.decision, StartupDecision::Exit75 { unresolved: 1 });
        assert!(
            outcome.listener.is_none(),
            "exit 75 must not bind a listener"
        );
        assert!(
            elapsed >= window,
            "unresolved startup must not be decided before the deadline (early snapshot)"
        );
        let conn = TcpStream::connect(("127.0.0.1", port));
        assert!(
            matches!(conn, Err(ref err) if err.kind() == ErrorKind::ConnectionRefused),
            "exit 75 must leave the listen port unreachable"
        );
    }

    #[test]
    fn degraded_is_decided_only_at_the_actual_window_deadline() {
        let window = Duration::from_millis(300);
        let port = ephemeral_port();
        let config = config_with("\"alpha.example.org\", \"beta.example.org\"", 1, port);
        let responder = DnsResponder::spawn(|query| {
            if qname_contains(&query, b"\x04beta") {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let start = Instant::now();
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        let elapsed = start.elapsed();
        assert_eq!(
            outcome.decision,
            StartupDecision::Serve(ServingMode::Degraded)
        );
        assert!(
            outcome.listener.is_some(),
            "degraded serve must bind a listener"
        );
        assert!(
            elapsed >= window,
            "degraded startup must not be decided before the deadline (early snapshot)"
        );
    }

    #[test]
    fn failed_lookup_retries_within_the_window_and_recovers_to_full() {
        let window = Duration::from_secs(2);
        let port = ephemeral_port();
        let config = config_with("\"alpha.example.org\"", 0, port);
        let mut queries = 0u32;
        let responder = DnsResponder::spawn(move |query| {
            queries += 1;
            if queries <= 2 {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let start = Instant::now();
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        let elapsed = start.elapsed();
        assert_eq!(
            outcome.decision,
            StartupDecision::Serve(ServingMode::Full),
            "the windowed retry must recover the failed lookup"
        );
        assert_eq!(outcome.report.resolved_names, 1);
        assert_eq!(outcome.report.failed, 2);
        assert!(outcome.listener.is_some());
        assert!(
            elapsed < window,
            "recovered startup must return early, not wait for the deadline"
        );
    }

    #[test]
    fn retried_failures_and_never_attempted_sibling_report_truthful_not_attempted() {
        let window = Duration::from_millis(1600);
        let port = ephemeral_port();
        let config = config_with("\"alpha.example.org\", \"beta.example.org\"", 1, port);
        let responder = DnsResponder::spawn(|query| {
            if qname_contains(&query, b"\x04beta") {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        assert_eq!(outcome.report.resolved_names, 1, "alpha usable");
        assert!(
            outcome.report.failed >= 4,
            "beta retried at least once after its first failed exchange: {}",
            outcome.report.failed
        );
        assert_eq!(
            outcome.report.not_attempted, 1,
            "only alpha's sibling family went un-attempted; retried failures must \
             not erase the never-attempted slots (exchanges {}, failed {}, resolved {}):",
            outcome.report.exchanges, outcome.report.failed, outcome.report.resolved_names,
        );
    }

    #[test]
    fn resolved_names_family_schedule_survives_for_serving_refresh() {
        let window = Duration::from_millis(1600);
        let port = ephemeral_port();
        let config = config_with("\"alpha.example.org\", \"beta.example.org\"", 1, port);
        let responder = DnsResponder::spawn(|query| {
            if qname_contains(&query, b"\x04beta") {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        assert_eq!(outcome.report.resolved_names, 1, "alpha usable");
        assert_eq!(
            storage.schedules().due_time(0, Family::Aaaa).unwrap(),
            Some(NOW0),
            "a resolved name's sibling family must keep its seeded due for the \
             serving refresh, never be re-clobbered to a later now"
        );
    }

    #[test]
    fn resolved_name_sibling_stays_selectable_after_startup_for_serving() {
        let window = Duration::from_millis(1600);
        let port = ephemeral_port();
        let config = config_with("\"alpha.example.org\", \"beta.example.org\"", 1, port);
        let responder = DnsResponder::spawn(|query| {
            if qname_contains(&query, b"\x04beta") {
                None
            } else {
                build_positive(&query)
            }
        });
        let mut storage = ServeStorage::boot(&config).expect("boot serving storage");
        let outcome = storage
            .run_startup_within(responder.addr, NOW0, window)
            .expect("startup");
        assert_eq!(outcome.report.resolved_names, 1, "alpha usable");
        assert_eq!(
            storage.schedules.due_time(0, Family::Aaaa).unwrap(),
            Some(NOW0),
            "sibling due must be preserved for the serving refresh"
        );
        let selected = storage
            .schedules
            .select_due(NOW0 + 2)
            .expect("a future serving refresh must be selectable")
            .expect("alpha AAAA must not be stuck in-flight after the window");
        assert_eq!(selected.name(), 0);
        assert_eq!(selected.family(), Family::Aaaa);
    }
}
