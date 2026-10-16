//! Boot-owned bounded allocation-free logging.
//!
//! The log store is a preallocated queue of 256 fixed 8 KiB slots. Records are
//! encoded directly into a slot with a deterministic escaping grammar, never
//! truncated: a record that would exceed its 8 KiB slot (including the
//! terminating newline framing) is dropped whole and counted. Enqueue and
//! drain are allocation-free and nonblocking; a stalled stdout sink yields
//! with its partial write cursor retained and never delays traffic, DNS, or
//! deadlines (docs/alumina-proxy.md:178-179,193-194).
//!
//! Grammar: `level=<warn|info|error> kind=<kind> <key>=<value>...\n`.
//! Text values are double-quoted; `\` and `"` are backslash-escaped and every
//! control byte is emitted as a deterministic `\xNN` escape, so no record
//! ever contains a bare newline except the terminal frame. Numeric values are
//! plain decimal. The exact field set is kind-specific.
//!
//! Address fields are never escaped: `SocketAddr` Display emits only digits,
//! `.`, `:`, `[`, `]`, and `%`, none of which require quoting, and is written
//! straight into the entry without an intermediate allocation.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::time::{Duration, Instant};

use crate::cache::Family;
use crate::enforcement::action::{AnyIllegalScope, DomainOrdinal, Scope};
use crate::enforcement::monitor::{CapturedFact, Monitor};
use crate::enforcement::policy::{AnyIllegalCause, Effect, UnknownReason};
use crate::inventory;
use crate::startup_dns::NameOutcome;

pub(crate) const QUEUE_SLOTS: usize = 256;
pub(crate) const SLOT_BYTES: usize = 8 * 1024;
/// Per-turn sink budget: at most this many write calls or this many bytes,
/// whichever is exhausted first (docs/alumina-proxy.md:178,194,146).
pub(crate) const SINK_MAX_OPS: usize = 16;
pub(crate) const SINK_MAX_BYTES: usize = 64 * 1024;
/// The bounded retry deadline after a WouldBlock: the sink cannot accept more
/// right now, so the owner wakes to try again on this cadence instead of
/// busy-spinning (704q N4/T3: a stalled stdout sink never delays traffic, DNS,
/// or deadlines).
const LOG_RETRY: Duration = Duration::from_millis(100);

const QUEUE_MASK: usize = QUEUE_SLOTS - 1;
/// Threshold edges: attempt an error record when usage first exceeds 80%,
/// and again when it falls below 70% (docs/alumina-proxy.md:193).
const HIGH_PCT_NUMBER: u64 = 80;
const LOW_PCT_NUMBER: u64 = 70;

const _: () = assert!(QUEUE_SLOTS * SLOT_BYTES == inventory::LOG_QUEUE_BYTES);
const _: () = assert!(QUEUE_SLOTS.is_power_of_two());

/// The severity vocabulary carried by every record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Level {
    Info,
    Warn,
    Error,
}

/// The fixed reason vocabulary for a rejected connection (docs/alumina-proxy.md:193).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    Capacity,
    BadRequest,
    Forbidden,
    DialFailed,
    SetupTimeout,
    TlsValidation,
}

impl RejectReason {
    fn as_str(self) -> &'static str {
        match self {
            RejectReason::Capacity => "capacity",
            RejectReason::BadRequest => "bad_request",
            RejectReason::Forbidden => "forbidden",
            RejectReason::DialFailed => "dial_failed",
            RejectReason::SetupTimeout => "setup_timeout",
            RejectReason::TlsValidation => "tls_validation",
        }
    }
}

/// The fixed reason vocabulary for a tunnel closed for early upstream
/// activity (docs/alumina-proxy.md:193).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivityKind {
    Data,
    Eof,
    Reset,
}

impl ActivityKind {
    fn as_str(self) -> &'static str {
        match self {
            ActivityKind::Data => "data",
            ActivityKind::Eof => "eof",
            ActivityKind::Reset => "reset",
        }
    }
}

/// The fixed occupancy dimension a capacity threshold edge reports
/// (docs/alumina-proxy.md:193).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dimension {
    Slots,
    Setups,
    Queue,
}

impl Dimension {
    fn as_str(self) -> &'static str {
        match self {
            Dimension::Slots => "slots",
            Dimension::Setups => "setups",
            Dimension::Queue => "queue",
        }
    }
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

/// The record kinds this increment emits.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    StartupWarning,
    StartupFinal,
    Fatal,
    ShutdownFinal,
    Reject,
    EarlyActivity,
    CapacityHigh,
    CapacityLow,
    QueueHigh,
    QueueLow,
    Monitor,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::StartupWarning => "startup_warning",
            Kind::StartupFinal => "startup_final",
            Kind::Fatal => "fatal",
            Kind::ShutdownFinal => "shutdown_final",
            Kind::Reject => "reject",
            Kind::EarlyActivity => "early_activity",
            Kind::CapacityHigh => "capacity_high",
            Kind::CapacityLow => "capacity_low",
            Kind::QueueHigh => "queue_high",
            Kind::QueueLow => "queue_low",
            Kind::Monitor => "monitor",
        }
    }
}

/// The terminal startup status carried by the final startup record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupStatus {
    Full,
    Degraded,
    Failed,
    Terminated,
}

impl StartupStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            StartupStatus::Full => "full",
            StartupStatus::Degraded => "degraded",
            StartupStatus::Failed => "failure",
            StartupStatus::Terminated => "terminated",
        }
    }
}

/// The typed terminal outcome of a SIGTERM shutdown drain: a clean drain of
/// every established tunnel (or an empty drain with no tunnels) exits 0; a
/// deadline-forced closure of remaining sockets is a failure and exits
/// `EX_SOFTWARE` (70) (docs/alumina-proxy.md:220). Emitted as the single shutdown record
/// before the owner exits so a forced closure is never silently lost.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShutdownStatus {
    Drained,
    Forced,
}

impl ShutdownStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ShutdownStatus::Drained => "drained",
            ShutdownStatus::Forced => "forced",
        }
    }
}

/// A single encoded field. `OptVar` variants emit nothing when the value is
/// absent, so a caller never supplies an empty quoted value.
#[derive(Clone, Copy)]
pub(crate) enum Val<'a> {
    Str(&'a str),
    OptStr(Option<&'a str>),
    U64(u64),
    OptAddr(Option<SocketAddr>),
    Family(Family),
}

#[derive(Clone, Copy)]
pub(crate) struct Field<'a> {
    key: &'static str,
    val: Val<'a>,
}

impl<'a> Field<'a> {
    fn new(key: &'static str, val: Val<'a>) -> Self {
        Field { key, val }
    }
}

/// An unbuffered writer over a fixed slot buffer; every write that does not
/// fit returns `false` (or `fmt::Error`), so the encoder aborts on overflow.
struct Entry<'a> {
    buf: &'a mut [u8; SLOT_BYTES],
    len: usize,
}

impl Entry<'_> {
    fn push(&mut self, bytes: &[u8]) -> bool {
        if self.len + bytes.len() > self.buf.len() {
            return false;
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        true
    }
}

impl fmt::Write for Entry<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.push(s.as_bytes()) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_escaped(w: &mut Entry<'_>, text: &str) -> bool {
    for &b in text.as_bytes() {
        match b {
            b'"' => {
                if !w.push(b"\\\"") {
                    return false;
                }
            }
            b'\\' => {
                if !w.push(b"\\\\") {
                    return false;
                }
            }
            0x00..=0x1f | 0x7f => {
                let hi = HEX[(b >> 4) as usize];
                let lo = HEX[(b & 0x0f) as usize];
                if !w.push(b"\\x") || !w.push(&[hi, lo]) {
                    return false;
                }
            }
            _ => {
                if !w.push(&[b]) {
                    return false;
                }
            }
        }
    }
    true
}

/// A [`fmt::Write`] adapter that pushes every written span through the same
/// quoted escaping as a `Str` field, so a formatted message cannot inject a
/// quote, backslash, or control boundary into the framed record.
struct EscapedEntry<'a, 'e> {
    entry: &'e mut Entry<'a>,
}

impl fmt::Write for EscapedEntry<'_, '_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if push_escaped(self.entry, s) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

fn write_fmt_escaped(w: &mut Entry<'_>, args: fmt::Arguments<'_>) -> bool {
    fmt::Write::write_fmt(&mut EscapedEntry { entry: w }, args).is_ok()
}

/// Encodes one record into `slot_buf` and returns its length on success, or
/// `None` when the record would exceed the slot. On overflow the slot content
/// is garbage but the caller never commits it.
fn encode_record(
    slot_buf: &mut [u8; SLOT_BYTES],
    level: Level,
    kind: Kind,
    fields: &[Field<'_>],
) -> Option<usize> {
    let mut w = Entry {
        buf: slot_buf,
        len: 0,
    };
    if !write_header(&mut w, level, kind) || !write_fields(&mut w, fields) {
        return None;
    }
    if !w.push(b"\n") {
        return None;
    }
    Some(w.len)
}

fn write_header(w: &mut Entry<'_>, level: Level, kind: Kind) -> bool {
    w.push(b"level=")
        && w.push(level.as_str().as_bytes())
        && w.push(b" kind=")
        && w.push(kind.as_str().as_bytes())
}

fn write_fields(w: &mut Entry<'_>, fields: &[Field<'_>]) -> bool {
    for field in fields {
        if let Val::OptStr(None) | Val::OptAddr(None) = field.val {
            continue;
        }
        if !w.push(b" ") || !w.push(field.key.as_bytes()) || !w.push(b"=") {
            return false;
        }
        match field.val {
            Val::Str(s) | Val::OptStr(Some(s)) => {
                if !w.push(b"\"") || !push_escaped(w, s) || !w.push(b"\"") {
                    return false;
                }
            }
            Val::U64(value) => {
                if fmt::Write::write_fmt(w, format_args!("{value}")).is_err() {
                    return false;
                }
            }
            Val::OptAddr(Some(addr)) => {
                if !w.push(b"\"") {
                    return false;
                }
                if fmt::Write::write_fmt(w, format_args!("{addr}")).is_err() {
                    return false;
                }
                if !w.push(b"\"") {
                    return false;
                }
            }
            Val::Family(family) => {
                if fmt::Write::write_fmt(w, format_args!("{family:?}")).is_err() {
                    return false;
                }
            }
            Val::OptStr(None) | Val::OptAddr(None) => continue,
        }
    }
    true
}

fn push_indexed_quoted(w: &mut Entry<'_>, key: &[u8], index: u32, text: &str) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    if !w.push(b"=\"") || !push_escaped(w, text) || !w.push(b"\"") {
        return false;
    }
    true
}

fn push_indexed_token(w: &mut Entry<'_>, key: &[u8], index: u32, token: &str) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    if !w.push(b"=") || !w.push(token.as_bytes()) {
        return false;
    }
    true
}

/// Encodes the single startup-final record: the header fields plus, in allowlist
/// ordinal order, one inline segment per unresolved name — `nameN`, `outcomeN`,
/// and (for failed or not-attempted names) `reasonN`. The names are embedded in
/// the same fixed 8 KiB entry as the header, so the startup result is exactly
/// one record that never exceeds its slot.
fn encode_record_final(
    slot_buf: &mut [u8; SLOT_BYTES],
    level: Level,
    kind: Kind,
    fields: &[Field<'_>],
    unresolved: &[StartupUnresolved<'_>],
) -> Option<usize> {
    let mut w = Entry {
        buf: slot_buf,
        len: 0,
    };
    if !write_header(&mut w, level, kind) || !write_fields(&mut w, fields) {
        return None;
    }
    for un in unresolved {
        let index = un.ordinal;
        if !push_indexed_quoted(&mut w, b"name", index, un.name) {
            return None;
        }
        if !push_indexed_token(&mut w, b"outcome", index, un.outcome_token()) {
            return None;
        }
        if let Some(reason) = un.reason_token()
            && !push_indexed_quoted(&mut w, b"reason", index, reason)
        {
            return None;
        }
    }
    if !w.push(b"\n") {
        return None;
    }
    Some(w.len)
}

fn encode_monitor(slot_buf: &mut [u8; SLOT_BYTES], secs: u64, monitor: &Monitor) -> Option<usize> {
    let mut w = Entry {
        buf: slot_buf,
        len: 0,
    };
    if !write_header(&mut w, Level::Info, Kind::Monitor) {
        return None;
    }
    if !push_u64(&mut w, b"secs", secs) {
        return None;
    }
    let ofacts = monitor.facts_any_illegal_overflow()
        || monitor.facts_early_data_overflow()
        || monitor.facts_unknown_overflow();
    let globals: [(&[u8], u64); 13] = [
        (&b"facts_total"[..], monitor.facts_total()),
        (&b"actions_total"[..], monitor.actions_total()),
        (&b"refusals_total"[..], monitor.refusals_total()),
        (&b"ofacts"[..], ofacts as u64),
        (&b"oactions"[..], monitor.actions_overflow() as u64),
        (&b"orefusals"[..], monitor.refusals_overflow() as u64),
        (&b"report_drops"[..], monitor.report_drops() as u64),
        (
            &b"oreport_drops"[..],
            monitor.report_drops_overflow() as u64,
        ),
        (&b"capture_drops"[..], monitor.capture_drops() as u64),
        (
            &b"ocapture_drops"[..],
            monitor.capture_drops_overflow() as u64,
        ),
        (
            &b"s0"[..],
            monitor.actions_first_slot_block(AnyIllegalScope::Connection) as u64,
        ),
        (
            &b"s1"[..],
            monitor.actions_first_slot_block(AnyIllegalScope::All) as u64,
        ),
        (&b"ba"[..], monitor.actions_block_all() as u64),
    ];
    for (key, value) in globals {
        if !push_u64(&mut w, key, value) {
            return None;
        }
    }
    for index in 0..AnyIllegalCause::KIND_COUNT {
        let value = monitor.facts_any_illegal_by_index(index);
        if value > 0 && !push_indexed_u64(&mut w, b"c", index as u32, value as u64) {
            return None;
        }
    }
    for index in 0..UnknownReason::COUNT {
        let value = monitor.facts_unknown_by_index(index);
        if value > 0 && !push_indexed_u64(&mut w, b"unk", index as u32, value as u64) {
            return None;
        }
    }
    for index in 0..crate::config::ALLOWLIST_MAX {
        let Some(ordinal) = DomainOrdinal::from_index(index) else {
            break;
        };
        let facts = monitor.facts_early_data(ordinal);
        let blocks = monitor.actions_domain_block(ordinal);
        let flares = monitor.actions_flare(ordinal);
        let refusals = monitor.refusals_blocked_domain(ordinal);
        if facts > 0 && !push_indexed_key_u64(&mut w, b"d", index as u32, b"f", facts as u64) {
            return None;
        }
        if blocks > 0 && !push_indexed_key_u64(&mut w, b"d", index as u32, b"b", blocks as u64) {
            return None;
        }
        if flares > 0 && !push_indexed_key_u64(&mut w, b"d", index as u32, b"l", flares as u64) {
            return None;
        }
        if refusals > 0 && !push_indexed_key_u64(&mut w, b"d", index as u32, b"r", refusals as u64)
        {
            return None;
        }
    }
    for i in 0..monitor.capture_detail_len() {
        let Some(cap) = monitor.capture_detail(i) else {
            break;
        };
        if !push_indexed_key_u64(&mut w, b"x", i as u32, b"s", cap.slot as u64) {
            return None;
        }
        if !push_indexed_key_u64(&mut w, b"x", i as u32, b"g", cap.generation) {
            return None;
        }
        if !push_indexed_token_prefix(&mut w, b"x", i as u32, b"t")
            || !push_fact_token(&mut w, &cap.detail.fact)
        {
            return None;
        }
        if !push_indexed_token_prefix(&mut w, b"x", i as u32, b"a")
            || !push_effect_token(&mut w, &cap.detail.effect)
        {
            return None;
        }
    }
    if !w.push(b"\n") {
        return None;
    }
    Some(w.len)
}

fn push_u64(w: &mut Entry<'_>, key: &[u8], value: u64) -> bool {
    w.push(b" ")
        && w.push(key)
        && w.push(b"=")
        && fmt::Write::write_fmt(w, format_args!("{value}")).is_ok()
}

fn push_indexed_u64(w: &mut Entry<'_>, key: &[u8], index: u32, value: u64) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    if !w.push(b"=") {
        return false;
    }
    if !fmt::Write::write_fmt(w, format_args!("{value}")).is_ok() {
        return false;
    }
    true
}

fn push_indexed_key_u64(
    w: &mut Entry<'_>,
    key: &[u8],
    index: u32,
    suffix: &[u8],
    value: u64,
) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    if !w.push(suffix) || !w.push(b"=") {
        return false;
    }
    fmt::Write::write_fmt(w, format_args!("{value}")).is_ok()
}

fn push_indexed_token_prefix(w: &mut Entry<'_>, key: &[u8], index: u32, suffix: &[u8]) -> bool {
    if !w.push(b" ") || !w.push(key) {
        return false;
    }
    if fmt::Write::write_fmt(w, format_args!("{index}")).is_err() {
        return false;
    }
    w.push(suffix) && w.push(b"=")
}

fn push_fact_token(w: &mut Entry<'_>, fact: &CapturedFact) -> bool {
    match *fact {
        CapturedFact::AnyIllegal(cause) => {
            if !w.push(b"a") {
                return false;
            }
            fmt::Write::write_fmt(w, format_args!("{}", cause.kind_index())).is_ok()
        }
        CapturedFact::EarlyData(ordinal) => {
            if !w.push(b"d") {
                return false;
            }
            fmt::Write::write_fmt(w, format_args!("{}", ordinal.get())).is_ok()
        }
        CapturedFact::Unknown(reason) => {
            if !w.push(b"u") {
                return false;
            }
            fmt::Write::write_fmt(w, format_args!("{}", reason.index())).is_ok()
        }
    }
}

fn push_effect_token(w: &mut Entry<'_>, effect: &Effect) -> bool {
    match *effect {
        Effect::BaselineOnly => w.push(b"none"),
        Effect::FlareOnly { scope } => push_scope_token(w, b"flr", scope),
        Effect::Block { scope } => push_scope_token(w, b"blk", scope),
        Effect::Unknown { reason } => {
            if !w.push(b"unk") {
                return false;
            }
            fmt::Write::write_fmt(w, format_args!("{}", reason.index())).is_ok()
        }
    }
}

fn push_scope_token(w: &mut Entry<'_>, prefix: &[u8], scope: Scope) -> bool {
    if !w.push(prefix) || !w.push(b":") {
        return false;
    }
    match scope {
        Scope::Connection => w.push(b"c"),
        Scope::Domain => w.push(b"d"),
        Scope::All => w.push(b"a"),
    }
}

/// One fixed 8 KiB slot. `bytes` is the encoded record length; slots are
/// reused, so a stale `bytes` on an unconsumed slot is never committed.
struct Slot {
    buf: [u8; SLOT_BYTES],
    bytes: usize,
}

impl Slot {
    fn empty() -> Slot {
        Slot {
            buf: [0; SLOT_BYTES],
            bytes: 0,
        }
    }
}

/// A partial write is a cursor state, not a first-class value; this newtype
/// keeps the drain loop from re-sending an already-acknowledged prefix.
#[derive(Clone, Copy)]
struct Cursor {
    off: usize,
}

/// Latched threshold state: a high edge is emitted when usage first exceeds
/// 80%, and the low edge when it later falls below 70%.
#[derive(Clone, Copy)]
struct Watermark {
    crossed_high: bool,
}

impl Watermark {
    fn new() -> Watermark {
        Watermark {
            crossed_high: false,
        }
    }
}

/// A threshold transition: the store emitted, or should emit, a high edge
/// (first exceed of 80%) or the low edge (fall below 70%).
#[derive(Clone, Copy)]
enum Edge {
    High { used: u64, cap: u64 },
    Low { used: u64, cap: u64 },
}

/// The sink write target. `Stdout` is the production path (fd 1, made
/// nonblocking once at construction); `Fd` is the test seam over a real file
/// or pipe owned by the caller, written through the same unbuffered syscall
/// path so file/pipe behaviour is exercised on the actual descriptor.
enum SinkIo {
    Stdout,
    #[cfg(test)]
    Fd(RawFd),
}

struct SinkState {
    io: SinkIo,
    failed: bool,
    /// Latched while the last drain retained a partial cursor on
    /// WouldBlock/zero progress: the owner wakes on [`LOG_RETRY`] instead of
    /// polling immediately, and a successful partial write clears it so a
    /// drain that made progress stays runnable.
    blocked: bool,
    #[cfg(test)]
    ops: usize,
}

/// Failure to construct the boot-owned store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStoreError {
    /// The 2 MiB backing queue could not be reserved.
    Reserve,
    /// fd 1 could not be made nonblocking.
    StdoutNonblocking,
}

/// The boot-owned log store retained through serving. Constructed once before
/// the startup DNS window and never freed until process exit.
pub(crate) struct LogStore {
    slots: Vec<Slot>,
    front: usize,
    count: usize,
    dropped: u64,
    dropped_overflow: bool,
    cursor: Option<Cursor>,
    sink: SinkState,
    slots_wm: Watermark,
    setups_wm: Watermark,
    queue_wm: Watermark,
    secs: u64,
}

/// The startup-final result counts carried by the summary record.
#[derive(Clone, Copy, Default)]
pub(crate) struct FinalCounts {
    pub(crate) allowance: u64,
    pub(crate) usable: u64,
    pub(crate) unresolved: u64,
    pub(crate) exchanges: u64,
    pub(crate) failed: u64,
    pub(crate) not_attempted: u64,
    pub(crate) dropped: u64,
}

/// One unresolved name embedded inline in the single startup-final record: the
/// allowlist ordinal (the deterministic key suffix) plus the name and its
/// latest outcome. `Resolved` names are never passed; the segment vocabulary
/// still covers them for completeness.
#[derive(Clone, Copy)]
pub(crate) struct StartupUnresolved<'a> {
    pub(crate) ordinal: u32,
    pub(crate) name: &'a str,
    pub(crate) outcome: NameOutcome,
}

impl StartupUnresolved<'_> {
    fn outcome_token(&self) -> &'static str {
        match self.outcome {
            NameOutcome::Resolved => "resolved",
            NameOutcome::Negative => "negative",
            NameOutcome::NoEligible => "no_eligible",
            NameOutcome::Failed(_) => "failed",
            NameOutcome::NotAttempted(_) => "not_attempted",
        }
    }

    fn reason_token(&self) -> Option<&'static str> {
        match self.outcome {
            NameOutcome::Failed(reason) => Some(reason.as_str()),
            NameOutcome::NotAttempted(reason) => Some(reason.as_str()),
            NameOutcome::Resolved | NameOutcome::Negative | NameOutcome::NoEligible => None,
        }
    }
}

impl LogStore {
    /// Builds the full queue over the production stdout sink and makes fd 1
    /// nonblocking, so a full or absent stdout pipe can never stall serving.
    ///
    /// # Errors
    ///
    /// Returns [`LogStoreError`] when the 2 MiB backing queue cannot be
    /// reserved or the stdout descriptor cannot be made nonblocking.
    pub(crate) fn new() -> Result<LogStore, LogStoreError> {
        Self::with_io(SinkIo::Stdout)
    }

    /// Test construction over a caller-owned descriptor: a real file (never
    /// WouldBlock at this volume) or a nonblocking pipe writer (WouldBlock
    /// once full). The caller keeps the descriptor alive for the store's
    /// lifetime; the store never owns or closes it.
    #[cfg(test)]
    pub(crate) fn with_fd(fd: RawFd) -> Result<LogStore, LogStoreError> {
        Self::with_io(SinkIo::Fd(fd))
    }

    fn with_io(io: SinkIo) -> Result<LogStore, LogStoreError> {
        let mut slots: Vec<Slot> = Vec::new();
        slots
            .try_reserve_exact(QUEUE_SLOTS)
            .map_err(|_| LogStoreError::Reserve)?;
        slots.resize_with(QUEUE_SLOTS, Slot::empty);
        Ok(LogStore {
            slots,
            front: 0,
            count: 0,
            dropped: 0,
            dropped_overflow: false,
            cursor: None,
            sink: SinkState {
                io,
                failed: false,
                blocked: false,
                #[cfg(test)]
                ops: 0,
            },
            slots_wm: Watermark::new(),
            setups_wm: Watermark::new(),
            queue_wm: Watermark::new(),
            secs: 0,
        })
    }

    /// Arms the production stdout sink: makes fd 1 nonblocking so a full or
    /// absent stdout pipe can never stall serving. Only the process that owns
    /// stdout (the binary) calls this once after boot, so tests and the
    /// library never flip the descriptor.
    pub(crate) fn prepare_stdout(&mut self) -> Result<(), LogStoreError> {
        if matches!(self.sink.io, SinkIo::Stdout) {
            set_fd_nonblocking(1).map_err(|_| LogStoreError::StdoutNonblocking)?;
        }
        Ok(())
    }

    /// Whole-record drops so far; saturates at `u64::MAX`.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Records the current monotonic second so next capacity-edge record
    /// carries real time (review M3).
    pub(crate) fn set_now(&mut self, secs: u64) {
        self.secs = secs;
    }

    /// Whether the drop counter has been saturated (the overflow state).
    #[cfg(test)]
    pub(crate) fn dropped_overflow(&self) -> bool {
        self.dropped_overflow
    }

    /// Queued (not yet flushed) record count.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.count
    }

    /// Whether the queue holds `QUEUE_SLOTS` records.
    #[cfg(test)]
    pub(crate) fn is_full(&self) -> bool {
        self.count >= QUEUE_SLOTS
    }

    /// The next Instant at which draining the queued logs is useful (N4/T3):
    /// queued non-WouldBlock logs are immediately runnable, WouldBlock-blocked
    /// logs retry on the bounded [`LOG_RETRY`] cadence, and an empty or failed
    /// sink is quiescent (it never wakes a poll).
    pub(crate) fn next_drain(&self, now: Instant) -> Option<Instant> {
        if self.count == 0 || self.sink.failed {
            return None;
        }
        if self.sink.blocked {
            Some(now + LOG_RETRY)
        } else {
            Some(now)
        }
    }

    /// Total write calls made by the sink (test observation of the per-turn
    /// op budget).
    #[cfg(test)]
    pub(crate) fn sink_ops(&self) -> usize {
        self.sink.ops
    }

    /// Whether the sink latched failed after a non-WouldBlock write error
    /// (e.g. the stdout pipe closed).
    #[cfg(test)]
    pub(crate) fn sink_has_failed(&self) -> bool {
        self.sink.failed
    }

    /// Marks the drop counter saturated as a test hook for the overflow flag.
    #[cfg(test)]
    pub(crate) fn saturate_dropped_for_test(&mut self) {
        self.dropped = u64::MAX;
        self.dropped_overflow = true;
    }

    /// The startup first-failure warning: exactly one attempt across all
    /// names and record types (docs/alumina-proxy.md:67), enqueued at the time of the
    /// first counted exchange failure inside the startup window.
    pub(crate) fn startup_warning(&mut self, secs: u64, name: &str, family: Family) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("name", Val::Str(name)),
            Field::new("family", Val::Family(family)),
        ];
        self.enqueue(Level::Warn, Kind::StartupWarning, &fields);
    }

    /// The single startup-final record (corrected T2): the canonical counts,
    /// plus one inline segment per unresolved name with its latest outcome and
    /// reason. All unresolved names share this one record — the startup result
    /// is never fanned out into per-name records.
    pub(crate) fn startup_final(
        &mut self,
        secs: u64,
        status: StartupStatus,
        counts: FinalCounts,
        unresolved: &[StartupUnresolved<'_>],
    ) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("status", Val::Str(status.as_str())),
            Field::new("allowance", Val::U64(counts.allowance)),
            Field::new("usable", Val::U64(counts.usable)),
            Field::new("unresolved", Val::U64(counts.unresolved)),
            Field::new("exchanges", Val::U64(counts.exchanges)),
            Field::new("failed", Val::U64(counts.failed)),
            Field::new("not_attempted", Val::U64(counts.not_attempted)),
            Field::new("dropped", Val::U64(counts.dropped)),
        ];
        if self.count >= QUEUE_SLOTS {
            self.drop_one();
        } else {
            let index = self.write_index();
            let len = encode_record_final(
                &mut self.slots[index].buf,
                Level::Info,
                Kind::StartupFinal,
                &fields,
                unresolved,
            );
            match len {
                Some(len) => {
                    self.slots[index].bytes = len;
                    self.count += 1;
                }
                None => self.drop_one(),
            }
        }
        self.note_queue_usage();
    }

    /// One error record for a process-fatal post-sink failure: emitted on the
    /// boot-owned stdout store before the owner exits, so an attach/serve/
    /// listener failure never writes to a stderr that could block a separate
    /// blocked descriptor (docs/alumina-proxy.md:149, B1). The message is formatted
    /// directly into the fixed slot (no heap String) and escaped by the same
    /// deterministic grammar as a `Str` field; an oversize record is dropped
    /// whole and counted.
    pub(crate) fn fatal(&mut self, secs: u64, args: fmt::Arguments<'_>) {
        self.set_now(secs);
        if self.count >= QUEUE_SLOTS {
            self.drop_one();
        } else {
            let index = self.write_index();
            let len = {
                let slot = &mut self.slots[index].buf;
                let mut w = Entry { buf: slot, len: 0 };
                let fits = write_header(&mut w, Level::Error, Kind::Fatal)
                    && w.push(b" secs=")
                    && fmt::Write::write_fmt(&mut w, format_args!("{secs}")).is_ok()
                    && w.push(b" message=\"")
                    && write_fmt_escaped(&mut w, args)
                    && w.push(b"\"")
                    && w.push(b"\n");
                if fits { Some(w.len) } else { None }
            };
            match len {
                Some(len) => self.commit_record(index, len),
                None => self.drop_one(),
            }
        }
        self.note_queue_usage();
    }

    /// One warn per rejected connection (docs/alumina-proxy.md:193): `reason` selects the
    /// fixed vocabulary; the hostname is included only when valid.
    pub(crate) fn reject(
        &mut self,
        secs: u64,
        reason: RejectReason,
        client: Option<SocketAddr>,
        hostname: Option<&str>,
    ) {
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("reason", Val::Str(reason.as_str())),
            Field::new("client", Val::OptAddr(client)),
            Field::new("hostname", Val::OptStr(hostname)),
        ];
        self.set_now(secs);
        self.enqueue(Level::Warn, Kind::Reject, &fields);
    }

    /// One warn per tunnel closed for early upstream activity (docs/alumina-proxy.md:193):
    /// the peer address and whether data, EOF, or reset was observed.
    pub(crate) fn early_activity(
        &mut self,
        secs: u64,
        hostname: Option<&str>,
        peer: Option<SocketAddr>,
        activity: ActivityKind,
    ) {
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("hostname", Val::OptStr(hostname)),
            Field::new("peer", Val::OptAddr(peer)),
            Field::new("activity", Val::Str(activity.as_str())),
        ];
        self.set_now(secs);
        self.enqueue(Level::Warn, Kind::EarlyActivity, &fields);
    }

    /// The single typed shutdown record emitted before the owner exits on a
    /// SIGTERM: `status` names whether the drain finished clean or was
    /// deadline-forced, so a forced closure is never silently lost to the
    /// immediate `process::exit` that follows (docs/alumina-proxy.md:220). The caller
    /// drains once after this, and the drain is bounded/nonblocking so a
    /// stalled stdout can never delay the exit verdict.
    pub(crate) fn shutdown_final(&mut self, secs: u64, status: ShutdownStatus) {
        self.set_now(secs);
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("status", Val::Str(status.as_str())),
        ];
        self.enqueue(Level::Info, Kind::ShutdownFinal, &fields);
    }

    pub(crate) fn monitor_summary(&mut self, secs: u64, monitor: &Monitor) -> bool {
        self.set_now(secs);
        if self.count >= QUEUE_SLOTS {
            return false;
        }
        let index = self.write_index();
        let len = encode_monitor(&mut self.slots[index].buf, secs, monitor);
        match len {
            Some(len) => {
                self.commit_record(index, len);
                self.note_queue_usage();
                true
            }
            None => false,
        }
    }

    /// Evaluates the 80%/70% capacity thresholds for tunnel slots and pending
    /// setups (docs/alumina-proxy.md:193). Call after any occupancy transition.
    pub(crate) fn note_capacity(&mut self, secs: u64, occupied: usize, pending: usize) {
        self.secs = secs;
        if let Some(edge) = note_usage(&mut self.slots_wm, occupied, crate::worker::MAX_TUNNELS) {
            self.capacity_edge(Dimension::Slots, edge);
        }
        if let Some(edge) = note_usage(
            &mut self.setups_wm,
            pending,
            crate::worker::MAX_PENDING_SETUPS,
        ) {
            self.capacity_edge(Dimension::Setups, edge);
        }
    }

    fn capacity_edge(&mut self, dimension: Dimension, edge: Edge) {
        let (kind, level, used, cap) = match (dimension, edge) {
            (Dimension::Queue, Edge::High { used, cap }) => {
                (Kind::QueueHigh, Level::Error, used, cap)
            }
            (Dimension::Queue, Edge::Low { used, cap }) => (Kind::QueueLow, Level::Info, used, cap),
            (Dimension::Slots, Edge::High { used, cap }) => {
                (Kind::CapacityHigh, Level::Error, used, cap)
            }
            (Dimension::Slots, Edge::Low { used, cap }) => {
                (Kind::CapacityLow, Level::Info, used, cap)
            }
            (Dimension::Setups, Edge::High { used, cap }) => {
                (Kind::CapacityHigh, Level::Error, used, cap)
            }
            (Dimension::Setups, Edge::Low { used, cap }) => {
                (Kind::CapacityLow, Level::Info, used, cap)
            }
        };
        let secs = self.secs;
        let fields = [
            Field::new("secs", Val::U64(secs)),
            Field::new("dimension", Val::Str(dimension.as_str())),
            Field::new("used", Val::U64(used)),
            Field::new("cap", Val::U64(cap)),
        ];
        self.enqueue(level, kind, &fields);
    }

    /// Evaluates the queue watermark on enqueue and again on each drain step
    /// (real-time threshold transitions per review M3).
    fn note_queue_usage(&mut self) {
        if let Some(edge) = note_usage(&mut self.queue_wm, self.count, QUEUE_SLOTS) {
            self.capacity_edge(Dimension::Queue, edge);
        }
    }

    /// Drains the queue through the nonblocking stdout sink under the
    /// per-turn work budget: at most [`SINK_MAX_OPS`] write calls or
    /// [`SINK_MAX_BYTES`] bytes. A WouldBlock retains the partial cursor and
    /// yields immediately; a write/close failure latches the sink failed so
    /// no later drain spins or blocks.
    pub(crate) fn drain_sink(&mut self) {
        if self.sink.failed {
            return;
        }
        let mut ops = 0usize;
        let mut bytes_out = 0usize;
        loop {
            if ops >= SINK_MAX_OPS || bytes_out >= SINK_MAX_BYTES {
                return;
            }
            let (index, off) = match self.cursor {
                Some(cursor) => (self.front, cursor.off),
                None => {
                    if self.count == 0 {
                        return;
                    }
                    (self.front, 0)
                }
            };
            let rec_len = self.slots[index].bytes;
            if off >= rec_len {
                self.advance_front();
                continue;
            }
            let chunk = (rec_len - off).min(SINK_MAX_BYTES - bytes_out);
            let fd = self.sink_fd();
            let written = {
                let slot = &self.slots[index];
                write_bytes(fd, &slot.buf[off..off + chunk])
            };
            match written {
                Err(ref err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::Interrupted =>
                {
                    self.sink.blocked = true;
                    self.cursor = Some(Cursor { off });
                    return;
                }
                Err(_) => {
                    self.sink.failed = true;
                    return;
                }
                Ok(0) => {
                    self.sink.blocked = true;
                    self.cursor = Some(Cursor { off });
                    return;
                }
                Ok(n) => {
                    ops += 1;
                    #[cfg(test)]
                    {
                        self.sink.ops += 1;
                    }
                    bytes_out += n;
                    self.sink.blocked = false;
                    let new_off = off + n;
                    if new_off >= rec_len {
                        self.advance_front();
                    } else {
                        self.cursor = Some(Cursor { off: new_off });
                        if n < chunk {
                            return;
                        }
                    }
                }
            }
        }
    }

    fn advance_front(&mut self) {
        self.cursor = None;
        if self.count > 0 {
            self.count -= 1;
            self.front = (self.front + 1) & QUEUE_MASK;
            self.note_queue_usage();
        }
    }

    fn write_index(&self) -> usize {
        (self.front + self.count) & QUEUE_MASK
    }

    fn sink_fd(&self) -> RawFd {
        match self.sink.io {
            SinkIo::Stdout => 1,
            #[cfg(test)]
            SinkIo::Fd(fd) => fd,
        }
    }

    fn enqueue(&mut self, level: Level, kind: Kind, fields: &[Field<'_>]) {
        if self.count >= QUEUE_SLOTS {
            self.drop_one();
        } else {
            let index = self.write_index();
            match encode_record(&mut self.slots[index].buf, level, kind, fields) {
                Some(len) => self.commit_record(index, len),
                None => self.drop_one(),
            }
        }
        self.note_queue_usage();
    }

    fn commit_record(&mut self, index: usize, len: usize) {
        self.slots[index].bytes = len;
        self.count += 1;
    }

    fn drop_one(&mut self) {
        self.dropped = self.dropped.saturating_add(1);
        if self.dropped == u64::MAX {
            self.dropped_overflow = true;
        }
    }
}

/// Evaluates the 80%/70% threshold on a single watermark and latches the
/// transition. Returns the edge to emit, or `None` when no transition occurred.
fn note_usage(wm: &mut Watermark, used: usize, cap: usize) -> Option<Edge> {
    let used = used as u64;
    let cap = cap as u64;
    let exceeds_high = used.saturating_mul(100) > HIGH_PCT_NUMBER.saturating_mul(cap);
    let below_low = used.saturating_mul(100) < LOW_PCT_NUMBER.saturating_mul(cap);
    if exceeds_high && !wm.crossed_high {
        wm.crossed_high = true;
        Some(Edge::High { used, cap })
    } else if below_low && wm.crossed_high {
        wm.crossed_high = false;
        Some(Edge::Low { used, cap })
    } else {
        None
    }
}

fn set_fd_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn write_bytes(fd: RawFd, bytes: &[u8]) -> io::Result<usize> {
    let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::ALLOWLIST_MAX;
    use crate::config::CONFIG_DOC_LIMIT;

    fn push_compact_group(doc: &mut String, count: usize) {
        let kinds = vec!["\"block\""; count].join(", ");
        let scopes = vec!["\"all\""; count].join(", ");
        doc.push_str(&format!(
            "[any_illegal]\nscope = \"all\"\n[actions]\nkind = [{kinds}]\nscope = [{scopes}]\n"
        ));
    }

    const _: () = assert!(SLOT_BYTES > CONFIG_DOC_LIMIT + ALLOWLIST_MAX * 64 + 512);

    use std::fs::File;
    use std::io::{Read, Seek};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_file() -> File {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "alumina-log-{}-{}.log",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("create temp file")
    }

    fn file_logstore() -> (LogStore, File) {
        let file = temp_file();
        let fd = file.as_raw_fd();
        let store = LogStore::with_fd(fd).expect("file sink store");
        (store, file)
    }

    fn read_all(file: &mut File) -> Vec<u8> {
        let mut buf = Vec::new();
        file.rewind().expect("rewind");
        file.read_to_end(&mut buf).expect("read file");
        buf
    }

    fn flush_all(store: &mut LogStore) {
        for _ in 0..(QUEUE_SLOTS + 8) {
            store.drain_sink();
            if store.len() == 0 {
                break;
            }
        }
    }

    #[test]
    fn logging_encoder_frames_and_escapes_deterministically() {
        let (mut store, mut file) = file_logstore();
        store.reject(
            7,
            RejectReason::Capacity,
            Some("127.0.0.1:40000".parse().unwrap()),
            Some("sub.example.org"),
        );
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("ascii record");
        let line = text.lines().next().expect("one record");
        assert!(
            line.starts_with(
                "level=warn kind=reject secs=7 reason=\"capacity\" client=\"127.0.0.1:40000\" hostname=\"sub.example.org\""
            ),
            "got: {line}"
        );
        assert!(text.ends_with('\n'), "newline framing ends the record");
    }

    #[test]
    fn logging_encoder_escapes_quote_backslash_and_control_bytes() {
        let mut name = String::new();
        name.push_str("a\"b");
        name.push('\\');
        name.push('\n');
        name.push('\x01');
        name.push_str(".example.org");
        let (mut store, mut file) = file_logstore();
        store.startup_warning(1, &name, Family::A);
        flush_all(&mut store);
        let out = read_all(&mut file);
        let text = String::from_utf8(out).expect("escaped ascii");
        assert!(
            text.contains("name=\"a\\\"b\\\\\\x0a\\x01.example.org\""),
            "deterministic escape of quote/backslash/control: {text:?}"
        );
        assert_eq!(
            text.matches('\\').count(),
            5,
            "five escapes, no raw controls"
        );
        assert!(!text.as_bytes().contains(&b'\n') || text.ends_with('\n'));
    }

    #[test]
    fn logging_startup_final_single_record_fits_real_config_bound() {
        use crate::config::{ALLOWLIST_MAX, CONFIG_DOC_LIMIT, parse_config_document};
        use crate::startup_dns::FailureReason;
        let first = b"abcdefghijklmnopqrstuvwxyz0123456789-";
        let d = "b".repeat(62);
        let e = "c".repeat(31);
        let mut doc = String::new();
        doc.push_str("allowlist = [\n");
        let mut names: Vec<String> = Vec::new();
        for &c in first.iter().take(ALLOWLIST_MAX) {
            let c = c as char;
            let name = format!("{c}.{d}.{e}");
            doc.push_str(&format!("  \"{name}:443\",\n"));
            names.push(name);
        }
        doc.push_str("]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n");
        push_compact_group(&mut doc, ALLOWLIST_MAX);
        assert!(
            doc.len() <= CONFIG_DOC_LIMIT,
            "worst-case config fits the documented 4096-byte bound: {}",
            doc.len()
        );
        let config = parse_config_document(&doc).expect("valid worst-case config");
        assert_eq!(config.allowlist().len(), ALLOWLIST_MAX);
        let unresolved: Vec<StartupUnresolved<'_>> = names
            .iter()
            .enumerate()
            .map(|(i, n)| StartupUnresolved {
                ordinal: i as u32,
                name: n,
                outcome: NameOutcome::Failed(FailureReason::Timeout),
            })
            .collect();
        let (mut store, mut file) = file_logstore();
        store.startup_final(
            9,
            StartupStatus::Failed,
            FinalCounts {
                allowance: 0,
                usable: 0,
                unresolved: ALLOWLIST_MAX as u64,
                exchanges: 64,
                failed: 64,
                not_attempted: 0,
                dropped: 0,
            },
            &unresolved,
        );
        assert_eq!(
            store.dropped(),
            0,
            "no size-drop for the actual worst valid config"
        );
        flush_all(&mut store);
        assert_eq!(store.dropped(), 0, "no drop once flushed");
        let out = read_all(&mut file);
        let records: Vec<&[u8]> = out
            .split(|&b| b == b'\n')
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(records.len(), 1, "single final record, no per-name fan-out");
        assert!(
            records[0].len() < SLOT_BYTES,
            "the startup-final record incl framing fits the 8 KiB entry: {}",
            records[0].len()
        );
    }

    #[test]
    fn logging_fatal_record_exact_grammar() {
        let (mut store, mut file) = file_logstore();
        store.fatal(7, format_args!("serving failed"));
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text, "level=error kind=fatal secs=7 message=\"serving failed\"\n",
            "the fatal record is one error record carrying the bounded message field"
        );
    }

    #[test]
    fn logging_startup_final_embeds_outcomes_inline_with_reasons() {
        use crate::startup_dns::{FailureReason, NameOutcome, NotAttemptedReason};
        let (mut store, mut file) = file_logstore();
        store.startup_final(
            9,
            StartupStatus::Failed,
            FinalCounts::default(),
            &[
                StartupUnresolved {
                    ordinal: 0,
                    name: "neg.example.org",
                    outcome: NameOutcome::Negative,
                },
                StartupUnresolved {
                    ordinal: 1,
                    name: "fail.example.org",
                    outcome: NameOutcome::Failed(FailureReason::Timeout),
                },
                StartupUnresolved {
                    ordinal: 2,
                    name: "skip.example.org",
                    outcome: NameOutcome::NotAttempted(NotAttemptedReason::WindowClosed),
                },
            ],
        );
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text,
            "level=info kind=startup_final secs=9 status=\"failure\" allowance=0 usable=0 unresolved=0 exchanges=0 failed=0 not_attempted=0 dropped=0 name0=\"neg.example.org\" outcome0=negative name1=\"fail.example.org\" outcome1=failed reason1=\"timeout\" name2=\"skip.example.org\" outcome2=not_attempted reason2=\"window_closed\"\n",
            "single final record embeds name/outcome/reason inline, no fan-out (corrected T2)"
        );
    }

    #[test]
    fn logging_oversize_record_is_dropped_whole_and_counted() {
        let long = "z".repeat(SLOT_BYTES * 2);
        let (mut store, _file) = file_logstore();
        store.startup_warning(1, &long, Family::A);
        assert_eq!(store.dropped(), 1, "oversize record dropped whole");
        assert_eq!(store.len(), 0, "nothing queued for the oversize record");
    }

    #[test]
    fn logging_queue_drops_when_full_and_counts() {
        let (mut store, _file) = file_logstore();
        for _ in 0..(QUEUE_SLOTS + 40) {
            store.startup_warning(1, "sub.example.org", Family::A);
        }
        assert!(store.is_full(), "queue must be full after overfilling");
        assert_eq!(store.len(), QUEUE_SLOTS, "capacity never exceeds the bound");
        assert_eq!(
            store.dropped(),
            41,
            "296 warnings + 1 high edge on a 256-slot queue: whole-record drops are counted exactly (review M6)"
        );
        assert!(!store.dropped_overflow());
    }

    #[test]
    fn logging_drop_counter_saturation_sets_overflow_state() {
        let (mut store, _file) = file_logstore();
        store.saturate_dropped_for_test();
        store.startup_warning(1, "sub.example.org", Family::A);
        assert_eq!(
            store.dropped(),
            u64::MAX,
            "drop count saturates, never wraps"
        );
        assert!(store.dropped_overflow(), "overflow flag latches");
    }

    #[test]
    fn logging_sink_budget_binds_on_ops_then_bytes() {
        let (mut store, mut file) = file_logstore();
        let filler = "filler.example.org";
        for _ in 0..(SINK_MAX_BYTES / 512) {
            store.startup_warning(1, filler, Family::A);
        }
        store.drain_sink();
        assert!(
            store.sink_ops() <= SINK_MAX_OPS,
            "op cap bounds one turn: {} ops",
            store.sink_ops()
        );
        let out = read_all(&mut file);
        assert!(
            out.len() <= SINK_MAX_BYTES,
            "byte cap bounds one turn: {}",
            out.len()
        );
        assert!(
            store.len() > 0,
            "unspent records stay queued for a later turn"
        );
        flush_all(&mut store);
        assert_eq!(store.len(), 0, "later turns flush the remainder");
    }

    #[test]
    fn logging_threshold_high_then_low_edges() {
        let (mut store, mut file) = file_logstore();
        for used in 0..=410usize {
            store.note_capacity(1, used, 0);
        }
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=capacity_high secs=1 dimension=\"slots\" used=410 cap=512"),
            "high edge at first exceed of 80%: {text}"
        );
        assert!(
            !text.contains("kind=capacity_low"),
            "no low edge before any high edge"
        );
        store.note_capacity(2, 358, 0);
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=capacity_low secs=2 dimension=\"slots\" used=358 cap=512"),
            "low edge after crossing below 70%: {text}"
        );
    }

    #[test]
    fn logging_early_activity_exact_record_unique_keys() {
        let (mut store, mut file) = file_logstore();
        store.early_activity(
            4,
            Some("sub.example.org"),
            Some("127.0.0.1:40000".parse().unwrap()),
            ActivityKind::Data,
        );
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text,
            "level=warn kind=early_activity secs=4 hostname=\"sub.example.org\" peer=\"127.0.0.1:40000\" activity=\"data\"\n",
            "exact early-activity record, no duplicate kind key (review R3/M1)"
        );
        assert_eq!(
            text.matches("kind=").count(),
            1,
            "the record key kind appears exactly once"
        );
    }

    #[test]
    fn logging_queue_threshold_edges_real_secs_on_enqueue_and_drain() {
        let (mut store, mut file) = file_logstore();
        for _ in 0..249 {
            store.startup_warning(100, "sub.example.org", Family::A);
        }
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=queue_high secs=100 dimension=\"queue\" used=205 cap=256"),
            "high edge at first exceed of 80% with the enqueue secs: {text}"
        );
        assert_eq!(
            store.dropped(),
            0,
            "204.8 threshold crossing must not drop records"
        );
        assert!(
            text.contains("kind=queue_low"),
            "low edge present after drain: {text}"
        );
        let low_line = text.lines().find(|l| l.contains("kind=queue_low")).unwrap();
        let exp = "kind=queue_low secs=";
        let idx = low_line.find(exp).expect("low edge has real secs");
        assert!(
            low_line[idx..].starts_with(exp) && !low_line[idx + exp.len()..].starts_with('0'),
            "low edge carries the real monotonic sec (review M3), got: {low_line}"
        );
    }

    #[test]
    fn logging_monitor_summary_exact_grammar_and_zero_suppression() {
        use crate::enforcement::action::{AnyIllegalScope, DomainOrdinal};
        use crate::enforcement::monitor::Monitor;
        use crate::enforcement::policy::UnknownReason;
        let mut m = Monitor::new();
        m.note_fact_any_illegal(crate::enforcement::policy::AnyIllegalCause::HostNotAllowlisted);
        m.note_fact_any_illegal(crate::enforcement::policy::AnyIllegalCause::HostNotAllowlisted);
        m.note_fact_unknown(UnknownReason::Unattributed);
        let ordinal = DomainOrdinal::from_index(0).expect("bound-level ordinal");
        m.note_fact_early_data(ordinal);
        m.note_action_first_slot_block(AnyIllegalScope::Connection);
        m.note_action_domain_block(ordinal);
        m.note_action_flare(ordinal);
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert_eq!(
            text,
            "level=info kind=monitor secs=7 facts_total=4 actions_total=3 refusals_total=0 \
             ofacts=0 oactions=0 orefusals=0 report_drops=0 oreport_drops=0 capture_drops=0 \
             ocapture_drops=0 s0=1 s1=0 ba=0 \
             c10=2 unk3=1 d0f=1 d0b=1 d0l=1\n",
            "exact monitor grammar: always-emit globals, then zero-suppressed scoped segments"
        );
        assert!(
            text.contains(" c10=2"),
            "the AnyIllegal cause index 10 (HostNotAllowlisted) carries its fold: {text}"
        );
        assert!(
            text.contains("unk3=1"),
            "the Unattributed unknown reason index 3 carries its fold: {text}"
        );
        assert!(
            !text.contains("c0="),
            "zero causes stay suppressed (no c0 key)"
        );
        assert!(!text.contains(" d0="), "M4: no empty-valued d0 marker key");
        assert!(
            !text.contains(" r=1"),
            "M4: per-field zero-suppression drops the zero refusal field"
        );
    }

    #[cfg(test)]
    #[test]
    fn logging_monitor_all_saturated_record_fits_the_8k_slot() {
        use crate::enforcement::monitor::Monitor;
        let mut m = Monitor::new();
        m.saturate_all_for_test();
        assert!(
            m.capture_detail_len() == crate::enforcement::monitor::CAPTURE_DETAIL_LEN,
            "the worst-case fixture fills the whole correlated-detail ring"
        );
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.len() < SLOT_BYTES,
            "the all-saturated monitor record stays inside the 8 KiB slot: {} bytes",
            text.len()
        );
        assert!(
            text.contains("ofacts=1"),
            "saturation latches the aggregate overflow flags: {text}"
        );
        assert!(
            text.contains("ocapture_drops=1"),
            "correlated-detail loss latches its own overflow: {text}"
        );
        assert!(
            text.contains("x0g="),
            "the correlated-detail section is emitted once captures exist: {text}"
        );
        assert!(
            text.contains("x0s=511"),
            "the all-saturated capture ring carries its worst legal slot identity: {text}"
        );
    }

    #[cfg(test)]
    #[test]
    fn logging_monitor_emits_distinct_slot_identity_for_equal_generation_slots() {
        use crate::enforcement::monitor::{CapturedDetail, SlotCapture};
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        let cap = |slot, generation| SlotCapture {
            slot,
            generation,
            detail: Some(CapturedDetail {
                fact: CapturedFact::AnyIllegal(cause),
                effect,
            }),
        };
        let mut m = Monitor::new();
        m.note_consumed_capture(cap(0, 1));
        m.note_consumed_capture(cap(1, 1));
        let (mut store, mut file) = file_logstore();
        assert!(store.monitor_summary(7, &m), "summary committed");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("x0s=0") && text.contains("x1s=1"),
            "H1': the encoded identity carries each capture's actual slot: {text}"
        );
        assert!(
            text.contains("x0g=1") && text.contains("x1g=1"),
            "H1': both slots share the equal per-slot generation: {text}"
        );
        assert!(
            text.contains("x0t=a10") && text.contains("x1t=a10"),
            "H1': both captures emit their typed fact: {text}"
        );
        assert!(
            text.contains("x0a=blk:c") && text.contains("x1a=blk:c"),
            "H1': both captures emit their applied effect: {text}"
        );
    }

    #[cfg(test)]
    #[test]
    fn logging_monitor_summary_on_full_ring_refuses_without_displacing_held_records() {
        use crate::enforcement::monitor::Monitor;
        use crate::enforcement::policy::UnknownReason;
        let (mut store, mut file) = file_logstore();
        let mut guard = 0;
        while store.len() < QUEUE_SLOTS - 1 && guard < 8 * QUEUE_SLOTS {
            store.startup_warning(100, "sub.example.org", Family::A);
            guard += 1;
        }
        assert_eq!(store.len(), QUEUE_SLOTS - 1, "fill leaves one free slot");
        store.shutdown_final(101, ShutdownStatus::Drained);
        assert_eq!(
            store.len(),
            QUEUE_SLOTS,
            "the shutdown verdict holds the last free ring slot"
        );
        let dropped_before = store.dropped();
        let mut m = Monitor::new();
        m.note_fact_unknown(UnknownReason::Unattributed);
        assert!(
            !store.monitor_summary(101, &m),
            "a full-ring monitor summary is refused, not enqueued"
        );
        assert_eq!(
            store.dropped(),
            dropped_before,
            "H2: the refused summary does not displace or count away any held record"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "all held records survive intact");
        flush_all(&mut store);
        let text = String::from_utf8(read_all(&mut file)).unwrap();
        assert!(
            text.contains("kind=shutdown_final"),
            "the shutdown verdict remains emitted despite the refused monitor: {text}"
        );
    }

    #[test]
    fn logging_stalled_pipe_yields_retains_cursor_and_counts_drops() {
        let (reader, writer) = UnixStream::pair().expect("socketpair");
        writer.set_nonblocking(true).expect("writer nonblocking");
        let mut store = LogStore::with_fd(writer.as_raw_fd()).expect("pipe sink store");
        let big = "p".repeat(4000);
        let mut turns = 0;
        while turns < 8 * QUEUE_SLOTS && store.len() < QUEUE_SLOTS {
            store.startup_warning(1, &big, Family::A);
            store.drain_sink();
            turns += 1;
        }
        assert_eq!(
            store.len(),
            QUEUE_SLOTS,
            "stalled sink retains the full queue"
        );
        assert!(
            !store.sink_has_failed(),
            "a full pipe is WouldBlock, not a sink failure"
        );
        let dropped_before = store.dropped();
        for _ in 0..16 {
            store.startup_warning(1, &big, Family::A);
        }
        assert_eq!(
            store.dropped(),
            dropped_before + 16,
            "enqueue keeps dropping whole records while the sink is stalled"
        );
        assert_eq!(store.len(), QUEUE_SLOTS, "queued records stay put");
        let _ = reader;
        let _ = writer;
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn logging_enqueue_drop_drain_paths_spend_zero_allocations() {
        use crate::alloc::{Phase, run_phase};
        use crate::startup_dns::{FailureReason, NameOutcome};
        let v4: SocketAddr = "192.0.2.10:40000".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
        let long = "z".repeat(SLOT_BYTES * 2);
        let unresolved = [
            StartupUnresolved {
                ordinal: 0,
                name: "sub.example.org",
                outcome: NameOutcome::Failed(FailureReason::Receive),
            },
            StartupUnresolved {
                ordinal: 1,
                name: "sub.example.org",
                outcome: NameOutcome::Negative,
            },
        ];
        let (_, control) = run_phase(Phase::Logging, || 0usize);
        assert!(control.all_zero(), "baseline should be quiet: {control:?}");
        let (mut store, _file) = file_logstore();
        let mut stdout_store = LogStore::new().expect("stdout sink store");
        let (_, counts) = run_phase(Phase::Logging, || {
            store.startup_warning(1, "sub.example.org", Family::A);
            store.startup_final(
                2,
                StartupStatus::Failed,
                FinalCounts::default(),
                &unresolved,
            );
            store.early_activity(3, Some("sub.example.org"), Some(v4), ActivityKind::Data);
            store.reject(4, RejectReason::Capacity, Some(v4), Some("sub.example.org"));
            store.reject(
                5,
                RejectReason::DialFailed,
                Some(v6),
                Some("sub.example.org"),
            );
            store.reject(6, RejectReason::TlsValidation, None, None);
            store.note_capacity(7, 410, 0);
            store.note_capacity(8, 410, 103);
            for _ in 0..20 {
                store.startup_warning(9, &long, Family::A);
            }
            for _ in 0..(QUEUE_SLOTS + 4) {
                store.startup_warning(10, "sub.example.org", Family::A);
            }
            for _ in 0..(SINK_MAX_OPS + 4) {
                store.drain_sink();
            }
            for _ in 0..(QUEUE_SLOTS + 4) {
                stdout_store.startup_warning(11, "sub.example.org", Family::A);
            }
            for _ in 0..(SINK_MAX_OPS + 4) {
                stdout_store.drain_sink();
            }
        });
        assert!(
            counts.all_zero(),
            "enqueue/drop/drain paths (file and stdout sink variants) must not allocate or deallocate after boot: {counts:?}"
        );
    }

    #[test]
    fn logging_sink_failure_latches_and_never_blocks() {
        let (reader, writer) = UnixStream::pair().expect("socketpair");
        let writer_fd = writer.as_raw_fd();
        drop(reader);
        let mut store = LogStore::with_fd(writer_fd).expect("pipe sink store");
        store.startup_warning(1, "sub.example.org", Family::A);
        store.drain_sink();
        assert!(
            store.sink_has_failed(),
            "EPIPE latches the sink failed (SIGPIPE ignored by std per oracle B17)"
        );
        assert!(store.len() >= 1, "the record is never silently lost");
        store.drain_sink();
        assert!(store.sink_has_failed());
        let _ = writer;
    }

    #[test]
    fn logging_next_drain_contract_runnable_blocked_and_quiescent() {
        let now = Instant::now();
        let (empty, _empty_file) = file_logstore();
        assert_eq!(
            empty.next_drain(now),
            None,
            "an empty queue is quiescent and never wakes a poll"
        );

        {
            use std::os::fd::AsRawFd;
            let (reader, writer) = UnixStream::pair().expect("socketpair");
            let writer_fd = writer.as_raw_fd();
            drop(reader);
            let mut epipe = LogStore::with_fd(writer_fd).expect("pipe sink store");
            epipe.startup_warning(1, "sub.example.org", Family::A);
            epipe.drain_sink();
            assert!(epipe.sink_has_failed());
            assert_eq!(
                epipe.next_drain(now),
                None,
                "a failed sink is quiescent and never wakes a poll"
            );
            let _ = writer;
        }

        let (reader, writer) = UnixStream::pair().expect("socketpair");
        writer.set_nonblocking(true).expect("writer nonblocking");
        let mut store = LogStore::with_fd(writer.as_raw_fd()).expect("pipe sink store");
        let big = "p".repeat(4000);
        for _ in 0..QUEUE_SLOTS {
            store.startup_warning(1, &big, Family::A);
        }
        let mut turns = 0;
        while store.len() > 0 && turns < 8 * QUEUE_SLOTS {
            store.drain_sink();
            turns += 1;
        }
        assert!(store.len() > 0, "the pipe fills and records stay queued");
        assert_eq!(
            store.next_drain(now),
            Some(now + LOG_RETRY),
            "a WouldBlock-stalled sink retries on the bounded monotonic LOG_RETRY deadline, never busy-spinning"
        );

        let (mut runnable, _file) = file_logstore();
        runnable.startup_warning(1, "sub.example.org", Family::A);
        assert_eq!(
            runnable.next_drain(now),
            Some(now),
            "queued non-blocked records are immediately runnable"
        );
        let _ = reader;
    }
}
