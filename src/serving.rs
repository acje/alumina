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
use std::time::{Duration, Instant};

use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};

use crate::client_hello::{self, ChInspector, Inspect};
use crate::config::FixedHostname;
use crate::connect::{ConnectParser, Feed};
use crate::eligibility::NumericAddr;
use crate::gate::{Activity, TunnelGate, UpstreamWrite, ValidatedHello};
use crate::serve::ServeStorage;
use crate::worker::{AttemptCounts, ConnectPhase, MAX_TUNNELS, SlotIndex, TunnelIndex};

/// The listener registration token.
const LISTENER: Token = Token(0);

/// Boot-fixed per-slot client->upstream byte store: the CONNECT head plus any
/// coalesced tunnel bytes up to the ClientHello inspection cap, reused as a
/// recycling relay pending buffer. Allocated once before the postboot phase and
/// reused across connections. The mandated directional profile is two 512 KiB
/// buffers per tunnel (alumina.md:161-164,:183; RF-008): 128 slots x 1 MiB =
/// 128 MiB traffic storage, not total RSS.
const HOLD_CAP: usize = 512 * 1024;

/// Boot-fixed per-slot upstream->client pending store (relay bytes and
/// canonical response/refusal bodies), bounded at the 512 KiB direction cap.
const DOWN_CAP: usize = 512 * 1024;

/// Idle deadline for an established tunnel once the gate has opened, reset on
/// every successful tunnel-byte write (alumina.md:190,:147). Readiness alone
/// never extends it.
const IDLE_SECS: Duration = Duration::from_secs(300);

/// The first orderly EOF starts a drain deadline that is never reset
/// (alumina.md:191; RF-003); the slot closes at both-EOF-drained or here.
const DRAIN_SECS: Duration = Duration::from_secs(5);

/// Bounded re-arm backoff after a transient accept failure (e.g. EMFILE).
/// No canonical capacity number is invented; this only stops a hot re-arm loop
/// (xz3f N6; alumina-refinement.md factual note).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The per-event read/write operation budget for one direction: bounded IO,
/// with a pending-ready sink re-armed rather than relying on a new edge.
const MAX_OPS: usize = 16;

/// Read chunk size; the relation CHUNK * MAX_OPS = 64 KiB bounds one drain to
/// the direction cap.
const CHUNK: usize = 4096;

/// Client sockets occupy tokens `1..=MAX_TUNNELS`; each upstream socket uses a
/// disjoint token at `UPSTREAM_BASE + index` so no two registrations collide.
const UPSTREAM_BASE: usize = MAX_TUNNELS + 1;

/// Token layout: low 9 bits = local id (1..=MAX_TUNNELS client,
/// `UPSTREAM_BASE..` upstream, 0 = listener), high bits = slot generation so a
/// stale event for a reused slot index is dropped before touching a socket.
const LOCAL_MASK: usize = 0x1ff;
const GEN_SHIFT: usize = 9;

const BODY_200: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";
const BODY_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n";
const BODY_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n";
const BODY_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n";
const BODY_503: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n";
const BODY_504: &[u8] = b"HTTP/1.1 504 Gateway Timeout\r\ncontent-length: 0\r\n\r\n";

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

/// The per-slot serving workspace, allocated once at boot and reused across
/// connections. The byte stores, parser, inspector, and gate all live here;
/// nothing per event is allocated, and every direction's pending bytes are
/// conserved with explicit cursors.
fn fixed_buffer<const CAP: usize>() -> Box<[u8; CAP]> {
    vec![0u8; CAP]
        .into_boxed_slice()
        .try_into()
        .expect("fixed buffer has exactly CAP bytes")
}

struct SlotWorkspace {
    handle: Option<SlotIndex>,
    tunnel: Option<TunnelIndex>,
    slot_gen: u64,
    client: Option<TcpStream>,
    upstream: Option<TcpStream>,
    parser: ConnectParser,
    inspector: ChInspector,
    gate: TunnelGate,
    approved: Option<FixedHostname>,
    stage: Stage,
    buf: Box<[u8; HOLD_CAP]>,
    buf_base: usize,
    buf_len: usize,
    fwd: usize,
    parse_rel: usize,
    insp_rel: usize,
    head_len: usize,
    hello_end: Option<usize>,
    hello_consumed: usize,
    down: Box<[u8; DOWN_CAP]>,
    down_len: usize,
    down_off: usize,
    directional: DirectionalEof,
    drain_deadline: Option<Instant>,
    idle_deadline: Option<Instant>,
    #[cfg(test)]
    test_reads: std::vec::Vec<io::Result<usize>>,
}

impl SlotWorkspace {
    fn new() -> SlotWorkspace {
        SlotWorkspace {
            handle: None,
            tunnel: None,
            slot_gen: 0,
            client: None,
            upstream: None,
            parser: ConnectParser::new(),
            inspector: ChInspector::new(),
            gate: TunnelGate::new(),
            approved: None,
            stage: Stage::Idle,
            buf: fixed_buffer::<HOLD_CAP>(),
            buf_base: 0,
            buf_len: 0,
            fwd: 0,
            parse_rel: 0,
            insp_rel: 0,
            head_len: 0,
            hello_end: None,
            hello_consumed: 0,
            down: fixed_buffer::<DOWN_CAP>(),
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
}

impl Serving {
    /// Builds the loop over an already-bound listener and boot-completed
    /// storage, registering the listener and allocating the fixed workspace.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the poll registry or listener registration
    /// fails.
    pub fn new(storage: ServeStorage, mut listener: TcpListener) -> Result<Serving, ServeError> {
        let poll = Poll::new()?;
        poll.registry()
            .register(&mut listener, LISTENER, Interest::READABLE)?;
        let slots = (0..MAX_TUNNELS).map(|_| SlotWorkspace::new()).collect();
        Ok(Serving {
            poll,
            storage,
            listener: Some(listener),
            slots,
            events: Events::with_capacity(MAX_OPS * 4),
            listener_pause_until: None,
        })
    }

    /// The retained storage, for host tests inspecting slot occupancy.
    pub fn storage(&self) -> &ServeStorage {
        &self.storage
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
        let effective = match (self.poll_timeout(), timeout) {
            (Some(d), Some(t)) => Some(d.min(t)),
            (Some(d), None) => Some(d),
            (None, t) => t,
        };
        let mut batch = std::mem::replace(&mut self.events, Events::with_capacity(0));
        self.poll.poll(&mut batch, effective)?;
        let now = Instant::now();
        self.expire_sweep(now);
        for event in batch.iter() {
            self.dispatch(event)?;
        }
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
        let raw = token.0;
        if raw == 0 {
            return self.accept_all();
        }
        let event_gen = (raw >> GEN_SHIFT) as u64;
        let local = raw & LOCAL_MASK;
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
            self.close_slot(index);
            return Ok(());
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

    fn accept_all(&mut self) -> Result<(), ServeError> {
        loop {
            let Some(listener) = &self.listener else {
                return Ok(());
            };
            match listener.accept() {
                Ok((stream, _addr)) => self.admit(stream)?,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => {
                    // A transient accept failure (e.g. EMFILE) with the
                    // connection still queued: re-arming immediately would
                    // re-fire readiness in a hot loop. Pause acceptance until
                    // the bounded backoff elapses (xz3f N6). No canonical
                    // capacity number is invented; the backoff only bounds the
                    // acceptance retry cadence.
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
                let mut s = stream;
                write_all_bounded(&mut s, BODY_503);
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
                Ok(())
            }
        }
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

    fn client_readable(&mut self, index: usize) -> Result<(), ServeError> {
        let mut ops = 0;
        loop {
            if ops >= MAX_OPS {
                if self.reregister_client(index).is_err() {
                    self.close_slot(index);
                }
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
                    Stage::ReadingConnect => self.refuse(index, BODY_400),
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
            }
            ops += 1;
            let mut scratch = [0u8; CHUNK];
            let n = match self.slots[index].client.as_mut() {
                None => return Ok(()),
                Some(client) => match client.read(&mut scratch) {
                    Ok(0) => {
                        if self.slots[index].stage == Stage::Relay {
                            return self.observe_up_eof(index);
                        }
                        self.close_slot(index);
                        return Ok(());
                    }
                    Ok(n) => n,
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(_) => {
                        self.close_slot(index);
                        return Ok(());
                    }
                },
            };
            match self.slots[index].stage {
                Stage::ReadingConnect => self.buffer_and_parse(index, &scratch[..n])?,
                Stage::ValidatingHello => self.buffer_and_validate(index, &scratch[..n])?,
                Stage::Relay => {
                    self.append_client_bytes(index, &scratch[..n]);
                    self.flush_client_upstream(index)?;
                }
                _ => return Ok(()),
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
            Err(_) => {
                self.refuse(index, BODY_400);
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
            self.refuse(index, BODY_400);
            return Ok(());
        };
        let now = Instant::now();
        let phase = self
            .storage
            .decide(slot, &request, now, AttemptCounts::new(), None);
        match phase {
            Err(_) => {
                self.refuse(index, BODY_502);
                Ok(())
            }
            Ok(ConnectPhase::Forbidden) => {
                self.refuse(index, BODY_403);
                Ok(())
            }
            Ok(ConnectPhase::NoBinding) | Ok(ConnectPhase::CandidatesExhausted) => {
                self.refuse(index, BODY_502);
                Ok(())
            }
            Ok(ConnectPhase::DeadlineExhausted) => {
                self.refuse(index, BODY_504);
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
                self.refuse(index, BODY_502);
                Ok(())
            }
        }
    }

    fn upstream_writable(&mut self, index: usize) -> Result<(), ServeError> {
        match self.slots[index].stage {
            Stage::Dialing => match self.upstream_connectedness(index) {
                ConnectState::Pending => Ok(()),
                ConnectState::Failed => {
                    self.refuse(index, BODY_502);
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
                    self.refuse(index, BODY_502);
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
        let mut ops = 0;
        let mut scratch = [0u8; CHUNK];
        loop {
            let outcome = classify_read(self.read_upstream(index, &mut scratch));
            match outcome {
                ReadOutcome::Activity(activity) => {
                    let ws = &mut self.slots[index];
                    ws.gate.observe_upstream_activity(activity);
                    self.close_slot(index);
                    return Ok(());
                }
                ReadOutcome::Failed => {
                    if self.slots[index].stage == Stage::Dialing {
                        self.refuse(index, BODY_502);
                        return Ok(());
                    }
                    self.close_slot(index);
                    return Ok(());
                }
                ReadOutcome::Wait => return Ok(()),
                ReadOutcome::Retry => {
                    ops += 1;
                    if ops >= MAX_OPS {
                        if self.reregister_upstream(index).is_err() {
                            self.close_slot(index);
                        }
                        return Ok(());
                    }
                }
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
            let stalled = {
                let ws = &mut self.slots[index];
                if ws.fwd >= ws.buf_len {
                    true
                } else {
                    match ws.upstream.as_mut() {
                        Some(up) => match up.write(&ws.buf[ws.fwd..ws.buf_len]) {
                            Ok(n) => {
                                ws.fwd += n;
                                wrote = true;
                                if ws.gate.is_open() {
                                    ws.idle_deadline = Some(Instant::now() + IDLE_SECS);
                                }
                                false
                            }
                            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => true,
                            Err(_) => {
                                failed = true;
                                true
                            }
                        },
                        None => true,
                    }
                }
            };
            if stalled {
                break;
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
        Ok(())
    }

    fn flush_down(&mut self, index: usize) {
        let mut failed = false;
        loop {
            let (stalled, err) = {
                let ws = &mut self.slots[index];
                if ws.down_off >= ws.down_len {
                    (true, false)
                } else {
                    match ws.client.as_mut() {
                        Some(client) => match client.write(&ws.down[ws.down_off..ws.down_len]) {
                            Ok(n) => {
                                ws.down_off += n;
                                if ws.gate.is_open() {
                                    ws.idle_deadline = Some(Instant::now() + IDLE_SECS);
                                }
                                (false, false)
                            }
                            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                                (true, false)
                            }
                            Err(_) => (true, true),
                        },
                        None => (true, false),
                    }
                }
            };
            failed = failed || err;
            if stalled {
                break;
            }
        }
        if failed {
            self.close_slot(index);
            return;
        }
        let ws = &mut self.slots[index];
        if ws.down_off >= ws.down_len {
            ws.down_len = 0;
            ws.down_off = 0;
        }
    }

    fn relay_upstream_to_client(&mut self, index: usize) -> Result<(), ServeError> {
        let mut ops = 0;
        loop {
            if ops >= MAX_OPS {
                if self.reregister_upstream(index).is_err() {
                    self.close_slot(index);
                }
                return Ok(());
            }
            if self.slots[index].down_len + CHUNK > DOWN_CAP {
                return Ok(());
            }
            ops += 1;
            let mut scratch = [0u8; CHUNK];
            let n = match self.slots[index].upstream.as_mut() {
                None => return Ok(()),
                Some(up) => match up.read(&mut scratch) {
                    Ok(0) => {
                        return self.observe_down_eof(index);
                    }
                    Ok(n) => n,
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(_) => {
                        self.close_slot(index);
                        return Ok(());
                    }
                },
            };
            {
                let ws = &mut self.slots[index];
                ws.down[ws.down_len..ws.down_len + n].copy_from_slice(&scratch[..n]);
                ws.down_len += n;
            }
            self.flush_down(index);
            if self.slots[index].down_len > 0 {
                return Ok(());
            }
        }
    }

    fn refuse(&mut self, index: usize, body: &'static [u8]) {
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
        self.close_slot(index);
        Ok(())
    }

    fn close_slot(&mut self, index: usize) {
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
        let deadline = earliest?;
        let now = Instant::now();
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
                self.refuse(i, BODY_504);
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
        Serving::new(storage, listener).expect("serving")
    }

    fn pump(serving: &mut Serving, times: usize) {
        for _ in 0..times {
            let _ = serving.run_once(Some(Duration::from_millis(2)));
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
            .buffer_and_validate(index, &[])
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
            reads.extend((0..MAX_OPS).map(|_| Err(io::Error::from(io::ErrorKind::Interrupted))));
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
