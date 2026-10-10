//! Startup DNS-over-TCP transport (alumina.md:62-68, 82, 171, 180): a single
//! reusable connection with one outstanding query, transaction ids drawn from
//! the OS CSPRNG, and publication of only fully validated outcomes into the
//! cache and schedule.
//!
//! The exchange deadline is 2 seconds, clipped to the caller's absolute
//! startup window deadline. On timeout, malformed, mismatched, truncated or
//! oversized responses the connection is closed, nothing is published, and the
//! exchange counts as failed. Startup readiness evaluation from the published
//! cache remains a caller concern.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};

use crate::cache::{Cache, CacheError, Family};
use crate::config::{ALLOWLIST_MAX, Config, Fqdn};
use crate::dns::{self, DNS_MSG_LIMIT, DnsError, Outcome, ResponseWorkspace};
use crate::schedule::{ScheduleError, Schedules};

pub const EXCHANGE_DEADLINE_SECS: u64 = 2;
pub const STARTUP_WINDOW_SECS: u64 = 90;
const QUERY_BUF_LEN: usize = 512;
const RECV_BUF_LEN: usize = DNS_MSG_LIMIT + 2;

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
    /// The OS entropy source failed while drawing a transaction id.
    Entropy,
    /// The monotonic poll-token generation is exhausted; no token is reused.
    TokenExhausted,
    /// The monotonic clock cannot represent the startup window deadline; the
    /// window is not extended, shortened, or clamped.
    DeadlineOverflow,
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
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExchangeResult {
    Published,
    Failed,
}

/// Terminal classification of one exchange at the resolve-loop boundary.
/// `Network` is a counted per-exchange failure whose schedule backoff has
/// already been advanced; `Fatal` aborts the whole resolve with a storage,
/// entropy, lifecycle, poll, or token-exhaustion error.
enum ExchangeError {
    Network,
    Fatal(StartupDnsError),
}

impl From<StartupDnsError> for ExchangeError {
    fn from(err: StartupDnsError) -> Self {
        ExchangeError::Fatal(err)
    }
}

impl From<DnsError> for ExchangeError {
    fn from(err: DnsError) -> Self {
        ExchangeError::Fatal(StartupDnsError::Dns(err))
    }
}

impl From<CacheError> for ExchangeError {
    fn from(err: CacheError) -> Self {
        ExchangeError::Fatal(StartupDnsError::Cache(err))
    }
}

impl From<ScheduleError> for ExchangeError {
    fn from(err: ScheduleError) -> Self {
        ExchangeError::Fatal(StartupDnsError::Schedule(err))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StartupReport {
    pub exchanges: u32,
    pub failed: u32,
    pub cancelled: u32,
    pub not_attempted: u32,
    pub resolved_names: u32,
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
    tid: u16,
    now0: u64,
    start: Instant,
    addr: SocketAddr,
    watch: Token,
    token_gen: usize,
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
            tid: 0,
            now0: 0,
            start: Instant::now(),
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            watch: Token(0),
            token_gen: 0,
        })
    }

    fn fresh_tid(&mut self) -> Result<u16, StartupDnsError> {
        let mut bytes = [0u8; 2];
        getrandom::fill(&mut bytes).map_err(|_| StartupDnsError::Entropy)?;
        self.tid = u16::from_be_bytes(bytes);
        Ok(self.tid)
    }

    fn now_u64(&self) -> u64 {
        self.now0.saturating_add(self.start.elapsed().as_secs())
    }

    /// The exact monotonic origin of the most recent `resolve_window` run —
    /// the single elapsed base startup receipts were written on. The owning
    /// storage re-anchors its serving clock to this origin so cache seconds
    /// continue seamlessly from startup into serving (one anchor, 1cws M2r).
    pub(crate) fn window_start(&self) -> Instant {
        self.start
    }

    /// Closes the transport connection exactly once: deregisters the source,
    /// drops the socket, and resets the read/write message state. A `NotFound`
    /// deregister is the benign already-closed case; any other deregister
    /// failure is surfaced as a lifecycle `Transport` error because it leaks a
    /// registry registration.
    fn close_connection(&mut self) -> Result<(), StartupDnsError> {
        let deregister_error = if let Some(mut stream) = self.stream.take() {
            match self.poll.registry().deregister(&mut stream) {
                Ok(()) => None,
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                Err(e) => Some(e.kind()),
            }
        } else {
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

    fn open(&mut self, addr: SocketAddr, deadline: Instant) -> Result<(), StartupDnsError> {
        let watch = self.next_token()?;
        let mut stream = TcpStream::connect(addr).map_err(|e| StartupDnsError::Exchange {
            kind: e.kind(),
            detail: "connect",
        })?;
        self.watch = watch;
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
        self.stream = Some(stream);
        self.wait_connected(deadline)
    }

    fn wait_connected(&mut self, deadline: Instant) -> Result<(), StartupDnsError> {
        loop {
            if let Some(stream) = self.stream.as_mut() {
                if let Ok(Some(err)) = stream.take_error() {
                    self.close_connection()?;
                    return Err(StartupDnsError::Exchange {
                        kind: err.kind(),
                        detail: "socket",
                    });
                }
                if stream.peer_addr().is_ok() {
                    return Ok(());
                }
            }
            let (_, writable, error, closed) = self.poll_once(deadline)?;
            if error || closed {
                self.close_connection()?;
                return Err(StartupDnsError::Exchange {
                    kind: io::ErrorKind::ConnectionAborted,
                    detail: "connect failed",
                });
            }
            if writable
                && self
                    .stream
                    .as_ref()
                    .is_some_and(|stream| stream.peer_addr().is_ok())
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.close_connection()?;
                return Err(StartupDnsError::Exchange {
                    kind: io::ErrorKind::TimedOut,
                    detail: "connect deadline expired",
                });
            }
        }
    }

    fn poll_once(
        &mut self,
        deadline: Instant,
    ) -> Result<(bool, bool, bool, bool), StartupDnsError> {
        let now = Instant::now();
        let timeout = if now >= deadline {
            Duration::ZERO
        } else {
            deadline.duration_since(now)
        };
        self.poll
            .poll(&mut self.events, Some(timeout))
            .map_err(|e| StartupDnsError::Transport {
                kind: e.kind(),
                detail: "poll",
            })?;
        let mut readable = false;
        let mut writable = false;
        let mut error = false;
        let mut closed = false;
        for event in self.events.iter() {
            if event.token() != self.watch {
                continue;
            }
            readable |= event.is_readable();
            writable |= event.is_writable();
            error |= event.is_error();
            closed |= event.is_read_closed() || event.is_write_closed();
        }
        Ok((readable, writable, error, closed))
    }

    fn send_query(&mut self, qlen: usize, deadline: Instant) -> Result<bool, StartupDnsError> {
        loop {
            if self.written < qlen {
                if let Some(stream) = self.stream.as_mut() {
                    match stream.write(&self.query_buf[self.written..qlen]) {
                        Ok(0) => {
                            self.close_connection()?;
                            return Err(StartupDnsError::Exchange {
                                kind: io::ErrorKind::WriteZero,
                                detail: "write zero",
                            });
                        }
                        Ok(n) => {
                            self.written += n;
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => {
                            self.close_connection()?;
                            return Err(StartupDnsError::Exchange {
                                kind: e.kind(),
                                detail: "write",
                            });
                        }
                    }
                } else {
                    self.close_connection()?;
                    return Err(StartupDnsError::Exchange {
                        kind: io::ErrorKind::NotConnected,
                        detail: "write on closed stream",
                    });
                }
            }
            if self.written >= qlen {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                self.close_connection()?;
                return Err(StartupDnsError::Exchange {
                    kind: io::ErrorKind::TimedOut,
                    detail: "write deadline expired",
                });
            }
            let (_, _, error, closed) = self.poll_once(deadline)?;
            if error || closed {
                self.close_connection()?;
                return Err(StartupDnsError::Exchange {
                    kind: io::ErrorKind::ConnectionAborted,
                    detail: "write failed",
                });
            }
        }
    }

    fn recv_message(
        &mut self,
        fqdn: &Fqdn,
        family: Family,
        deadline: Instant,
    ) -> Result<Option<Outcome>, StartupDnsError> {
        loop {
            if self.stream.is_none() {
                return Ok(None);
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
                        return Ok(None);
                    }
                    Ok(n) => self.filled += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        self.close_connection()?;
                        return Ok(None);
                    }
                }
            }
            if self.msglen.is_none() && self.filled >= 2 {
                let len = usize::from(u16::from_be_bytes([self.recv_buf[0], self.recv_buf[1]]));
                if len == 0 || len > DNS_MSG_LIMIT {
                    self.close_connection()?;
                    return Ok(None);
                }
                self.msglen = Some(len);
            }
            if let Some(len) = self.msglen
                && self.filled >= len + 2
            {
                let message = &self.recv_buf[2..2 + len];
                let outcome =
                    dns::parse_response(&mut self.workspace, fqdn, family, self.tid, message);
                self.msglen = None;
                self.filled = 0;
                match outcome {
                    Ok(outcome) => return Ok(Some(outcome)),
                    Err(_) => {
                        self.close_connection()?;
                        return Ok(None);
                    }
                }
            }
            if Instant::now() >= deadline {
                self.close_connection()?;
                return Ok(None);
            }
            let (_, _, error, closed) = self.poll_once(deadline)?;
            if error {
                self.close_connection()?;
                return Ok(None);
            }
            if closed {
                if let Some(stream) = self.stream.as_mut() {
                    match stream.read(&mut self.recv_buf[self.filled..]) {
                        Ok(n) if n > 0 => self.filled += n,
                        _ => {
                            self.close_connection()?;
                            return Ok(None);
                        }
                    }
                } else {
                    self.close_connection()?;
                    return Ok(None);
                }
            }
        }
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
                match self.exchange(name, family, ordinal, cache, schedules, exchange_deadline) {
                    Ok(ExchangeResult::Published) => {
                        report.exchanges += 1;
                        let has = !cache.entry(name_index, family)?.bindings().is_empty();
                        resolved[ordinal] |= has;
                    }
                    Ok(ExchangeResult::Failed) => report.failed += 1,
                    Err(ExchangeError::Network) => report.failed += 1,
                    Err(ExchangeError::Fatal(err)) => return Err(err),
                }
            }
        }
        report.resolved_names = resolved[..names].iter().filter(|&&r| r).count() as u32;
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
        config: &Config,
        cache: &mut Cache,
        schedules: &mut Schedules,
        nameserver: SocketAddr,
        now0: u64,
        window: Duration,
    ) -> Result<(StartupReport, u64), StartupDnsError> {
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
                    match self.exchange(name, family, ordinal, cache, schedules, exchange_deadline)
                    {
                        Ok(ExchangeResult::Published) => {
                            report.exchanges += 1;
                            let has = !cache.entry(name_index, family)?.bindings().is_empty();
                            resolved[ordinal] |= has;
                        }
                        Ok(ExchangeResult::Failed) => report.failed += 1,
                        Err(ExchangeError::Network) => report.failed += 1,
                        Err(ExchangeError::Fatal(err)) => return Err(err),
                    }
                }
                Ok(None) => {
                    let remaining = window_deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    let wait =
                        wait_until_next_step(self, schedules, names, &resolved)?.min(remaining);
                    if wait.is_zero() {
                        break;
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
        Ok((report, self.start.elapsed().as_secs()))
    }

    fn exchange(
        &mut self,
        fqdn: &Fqdn,
        family: Family,
        ordinal: usize,
        cache: &mut Cache,
        schedules: &mut Schedules,
        deadline: Instant,
    ) -> Result<ExchangeResult, ExchangeError> {
        if self.stream.is_none()
            && let Err(err) = self.open(self.addr, deadline)
        {
            return Err(self.settle_or_fatal(ordinal, family, schedules, err));
        }
        self.fresh_tid()?;
        let qlen = dns::build_query(fqdn, family, self.tid, &mut self.query_buf[2..])?;
        let total = qlen + 2;
        self.query_buf[0] = (qlen as u16 >> 8) as u8;
        self.query_buf[1] = qlen as u8;
        self.written = 0;
        self.filled = 0;
        self.msglen = None;
        if let Err(err) = self.send_query(total, deadline) {
            return Err(self.settle_or_fatal(ordinal, family, schedules, err));
        }
        let received = match self.recv_message(fqdn, family, deadline) {
            Ok(received) => received,
            Err(err) => return Err(self.settle_or_fatal(ordinal, family, schedules, err)),
        };
        let Some(outcome) = received else {
            self.note_failure(ordinal, family, schedules)?;
            return Ok(ExchangeResult::Failed);
        };
        let name_index =
            cache
                .name_index(ordinal)
                .ok_or(ExchangeError::Fatal(StartupDnsError::Cache(
                    CacheError::NameOutOfRange,
                )))?;
        let generation = cache.entry(name_index, family)?.generation();
        let receipt = self.now_u64();
        dns::apply_outcome(
            cache,
            schedules,
            ordinal,
            generation,
            receipt,
            self.now_u64(),
            outcome,
        )?;
        Ok(ExchangeResult::Published)
    }

    fn settle_or_fatal(
        &mut self,
        ordinal: usize,
        family: Family,
        schedules: &mut Schedules,
        err: StartupDnsError,
    ) -> ExchangeError {
        match err {
            StartupDnsError::Exchange { .. } => {
                match self.note_failure(ordinal, family, schedules) {
                    Ok(()) => ExchangeError::Network,
                    Err(fatal) => ExchangeError::Fatal(fatal),
                }
            }
            fatal => ExchangeError::Fatal(fatal),
        }
    }

    fn note_failure(
        &mut self,
        ordinal: usize,
        family: Family,
        schedules: &mut Schedules,
    ) -> Result<(), StartupDnsError> {
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
mod tests {
    use super::*;
    use crate::config::parse_config_document;
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpListener, TcpStream};
    use std::thread;

    enum Step {
        PositiveA {
            ttl: u32,
            octets: [u8; 4],
        },
        PositiveAaaa {
            ttl: u32,
            octets: [u8; 16],
        },
        NodataWithSoa {
            ttl: u32,
            min: u32,
        },
        NxdomainWithSoa {
            ttl: u32,
            min: u32,
        },
        PositiveAMismatchedTid {
            ttl: u32,
            octets: [u8; 4],
        },
        FragmentedPositive {
            ttl: u32,
            octets: [u8; 4],
            chunk: usize,
            gap: Duration,
        },
        Stall(Duration),
        Malformed(Vec<u8>),
        Close,
    }

    struct Responder {
        addr: SocketAddr,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl Responder {
        fn port(&self) -> u16 {
            self.addr.port()
        }
    }

    impl Drop for Responder {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                handle
                    .join()
                    .expect("responder thread panicked; test result is unreliable");
            }
        }
    }

    fn qname_bytes(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn soa_rdata(apex: &str, minimum: u32) -> Vec<u8> {
        let mut rd = qname_bytes(&format!("ns1.{apex}"));
        rd.extend_from_slice(&qname_bytes(&format!("hostmaster.{apex}")));
        for v in [1u32, 3600, 600, 86400, minimum] {
            rd.extend_from_slice(&v.to_be_bytes());
        }
        rd
    }

    fn question_from(query: &[u8]) -> Vec<u8> {
        query[12..].to_vec()
    }

    fn record(owner: &[u8], ty: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut rec = owner.to_vec();
        rec.extend_from_slice(&ty.to_be_bytes());
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&ttl.to_be_bytes());
        rec.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rec.extend_from_slice(rdata);
        rec
    }

    fn respond_for(query: &[u8], step: &Step) -> Option<Vec<u8>> {
        let tid = u16::from_be_bytes([query[0], query[1]]);
        let qname = &query[12..query.len() - 4];
        let question = question_from(query);
        let mut msg = Vec::new();
        msg.extend_from_slice(&tid.to_be_bytes());
        let (rcode, an, ns, answers, authority): (u16, u16, u16, Vec<Vec<u8>>, Vec<Vec<u8>>) =
            match step {
                Step::PositiveA { ttl, octets } => {
                    (0, 1, 0, vec![record(qname, 1, *ttl, octets)], vec![])
                }
                Step::PositiveAMismatchedTid { ttl, octets } => {
                    (0, 1, 0, vec![record(qname, 1, *ttl, octets)], vec![])
                }
                Step::PositiveAaaa { ttl, octets } => {
                    (0, 1, 0, vec![record(qname, 28, *ttl, octets)], vec![])
                }
                Step::NodataWithSoa { ttl, min } => {
                    let soa = soa_rdata("example.org", *min);
                    let owner = qname_bytes("example.org");
                    (0, 0, 1, vec![], vec![record(&owner, 6, *ttl, &soa)])
                }
                Step::NxdomainWithSoa { ttl, min } => {
                    let soa = soa_rdata("example.org", *min);
                    let owner = qname_bytes("example.org");
                    (3, 0, 1, vec![], vec![record(&owner, 6, *ttl, &soa)])
                }
                Step::Stall(_)
                | Step::Malformed(_)
                | Step::FragmentedPositive { .. }
                | Step::Close => return None,
            };
        let flags = 0x8000 | rcode;
        msg.extend_from_slice(&flags.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&an.to_be_bytes());
        msg.extend_from_slice(&ns.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&question);
        for rec in answers {
            msg.extend_from_slice(&rec);
        }
        for rec in authority {
            msg.extend_from_slice(&rec);
        }
        Some(msg)
    }

    fn spawn_responder(conn_scripts: Vec<Vec<Step>>) -> Responder {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
        let addr = listener.local_addr().expect("responder addr");
        let handle = thread::spawn(move || {
            let scripts = conn_scripts.into_iter();
            for conn_steps in scripts {
                let (mut sock, _) = match listener.accept() {
                    Ok(x) => x,
                    Err(_) => break,
                };
                for step in conn_steps {
                    match step {
                        Step::Stall(d) => thread::sleep(d),
                        Step::Close => break,
                        Step::Malformed(bytes) => {
                            let mut lenb = [0u8; 2];
                            if read_exact(&mut sock, &mut lenb).is_err() {
                                break;
                            }
                            let qlen = usize::from(u16::from_be_bytes(lenb));
                            let mut q = vec![0u8; qlen];
                            if qlen == 0 || read_exact(&mut sock, &mut q).is_err() {
                                break;
                            }
                            let mut out = Vec::with_capacity(bytes.len() + 2);
                            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                            out.extend_from_slice(&bytes);
                            if sock.write_all(&out).is_err() {
                                break;
                            }
                        }
                        Step::FragmentedPositive {
                            ttl,
                            octets,
                            chunk,
                            gap,
                        } => {
                            let Some(q) = read_query(&mut sock) else {
                                break;
                            };
                            let msg = positive_a_message(&q, ttl, &octets);
                            let mut out = Vec::with_capacity(msg.len() + 2);
                            out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
                            out.extend_from_slice(&msg);
                            let mut at = 0;
                            while at < out.len() {
                                let take = (out.len() - at).min(chunk.max(1));
                                if sock.write_all(&out[at..at + take]).is_err() {
                                    break;
                                }
                                at += take;
                                if at < out.len() {
                                    thread::sleep(gap);
                                }
                            }
                        }
                        step => {
                            let Some(q) = read_query(&mut sock) else {
                                break;
                            };
                            let reply = respond_for(&q, &step);
                            if let Some(mut bytes) = reply {
                                if matches!(step, Step::PositiveAMismatchedTid { .. }) {
                                    let mismatched =
                                        u16::from_be_bytes([bytes[0], bytes[1]]).wrapping_add(1);
                                    bytes[0] = (mismatched >> 8) as u8;
                                    bytes[1] = mismatched as u8;
                                }
                                let mut out = Vec::with_capacity(bytes.len() + 2);
                                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                                out.extend_from_slice(&bytes);
                                if sock.write_all(&out).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
        Responder {
            addr,
            handle: Some(handle),
        }
    }

    fn read_query(sock: &mut TcpStream) -> Option<Vec<u8>> {
        let mut lenb = [0u8; 2];
        if read_exact(sock, &mut lenb).is_err() {
            return None;
        }
        let qlen = usize::from(u16::from_be_bytes(lenb));
        let mut q = vec![0u8; qlen];
        if qlen == 0 || read_exact(sock, &mut q).is_err() {
            return None;
        }
        Some(q)
    }

    fn positive_a_message(q: &[u8], ttl: u32, octets: &[u8; 4]) -> Vec<u8> {
        let tid = u16::from_be_bytes([q[0], q[1]]);
        let qname = &q[12..q.len() - 4];
        let mut msg = Vec::new();
        msg.extend_from_slice(&tid.to_be_bytes());
        msg.extend_from_slice(&0x8000u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&question_from(q));
        msg.extend_from_slice(&record(qname, 1, ttl, octets));
        msg
    }

    fn read_exact(sock: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = sock.read(&mut buf[filled..])?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            filled += n;
        }
        Ok(())
    }

    fn config() -> Config {
        parse_config_document(
            "allowlist = [\"alpha.example.org\", \"beta.example.org\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\n",
        )
        .expect("valid config")
    }

    fn ns(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)
    }

    fn bindings_of(
        cache: &Cache,
        ordinal: usize,
        family: Family,
    ) -> Vec<crate::eligibility::NumericAddr> {
        cache
            .entry(cache.name_index(ordinal).unwrap(), family)
            .unwrap()
            .bindings()
            .to_vec()
    }

    #[test]
    fn token_generation_exhaustion_is_rejected_not_wrapped() {
        let cfg = config();
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.token_gen = usize::MAX;
        let err = transport
            .resolve(&cfg, &mut cache, &mut schedules, ns(0), 1_000_000)
            .expect_err("token generation exhaustion must be a typed error, never a wrap");
        assert_eq!(err, StartupDnsError::TokenExhausted);
    }

    #[test]
    fn storage_failure_escapes_resolve_as_err_not_a_counted_failure() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::PositiveA {
                ttl: 120,
                octets: [93, 184, 216, 34],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(1).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let err = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .expect_err(
                "a schedule-storage refusal on a later name must escape resolve as a fatal error",
            );
        assert!(
            matches!(err, StartupDnsError::Dns(dns::DnsError::Cache(_))),
            "storage refusal surfaces as Dns(Cache): {err:?}"
        );
    }

    #[test]
    fn connect_refused_counts_failure_and_sets_schedule_due() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let dead_port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let cfg = config();
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(&cfg, &mut cache, &mut schedules, ns(dead_port), 1_000_000)
            .unwrap();
        assert_eq!(report.exchanges, 0);
        assert_eq!(report.failed, 4);
        assert_eq!(report.resolved_names, 0);
        for ordinal in 0..2 {
            for family in Family::ALL {
                assert!(
                    schedules.due_time(ordinal, family).unwrap().is_some(),
                    "a connect-refused exchange must still advance the schedule for ({ordinal}, {family:?})"
                );
            }
        }
    }

    #[test]
    fn mismatched_tid_fails_exchange_and_nothing_published_for_that_name() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::PositiveAMismatchedTid {
                ttl: 120,
                octets: [93, 184, 216, 34],
            }],
            vec![
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::PositiveA {
                    ttl: 90,
                    octets: [1, 1, 1, 1],
                },
                Step::NodataWithSoa { ttl: 300, min: 60 },
            ],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 3);
        assert_eq!(report.failed, 1);
        assert!(
            bindings_of(&cache, 0, Family::A).is_empty(),
            "a mismatched-tid response must never publish"
        );
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
    }

    #[test]
    fn fragmented_partial_read_response_is_assembled_across_reads() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::FragmentedPositive {
                ttl: 120,
                octets: [93, 184, 216, 34],
                chunk: 1,
                gap: Duration::from_millis(2),
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 4);
        assert_eq!(report.failed, 0);
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(93, 184, 216, 34)
            )]
        );
    }

    #[test]
    fn deadline_expiry_fails_exchange_without_publish_and_reconnects() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Stall(Duration::from_secs(3)), Step::Close],
            vec![
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::PositiveA {
                    ttl: 90,
                    octets: [1, 1, 1, 1],
                },
                Step::NodataWithSoa { ttl: 300, min: 60 },
            ],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 3);
        assert_eq!(report.failed, 1);
        assert!(bindings_of(&cache, 0, Family::A).is_empty());
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
    }

    #[test]
    fn resolve_publishes_positives_and_nodata_across_one_connection() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::PositiveA {
                ttl: 120,
                octets: [93, 184, 216, 34],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 4);
        assert_eq!(report.failed, 0);
        assert_eq!(report.cancelled, 0);
        assert_eq!(report.resolved_names, 2);
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(93, 184, 216, 34)
            )]
        );
        assert!(bindings_of(&cache, 0, Family::Aaaa).is_empty());
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
        let due = schedules.due_time(1, Family::A).unwrap().expect("due");
        let interval = due - 1_000_000;
        assert!(
            (90..=95).contains(&interval),
            "refresh from receipt + min(300, max(30,90)): {interval}"
        );
    }

    #[test]
    fn positive_aaaa_publishes_v6_binding_and_schedule() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::PositiveA {
                ttl: 120,
                octets: [93, 184, 216, 34],
            },
            Step::PositiveAaaa {
                ttl: 120,
                octets: [
                    0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
                ],
            },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 4);
        assert_eq!(report.failed, 0);
        assert_eq!(report.resolved_names, 2);
        assert_eq!(
            bindings_of(&cache, 0, Family::Aaaa),
            vec![crate::eligibility::NumericAddr::V6(
                std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)
            )]
        );
        let due = schedules.due_time(0, Family::Aaaa).unwrap().expect("due");
        let interval = due - 1_000_000;
        assert!(
            (120..=125).contains(&interval),
            "v6 refresh from receipt + min(300, max(30,120)): {interval}"
        );
    }

    #[test]
    fn malformed_response_fails_exchange_and_connection_is_reused_next() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Malformed(vec![1, 2, 3, 4])],
            vec![
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::PositiveA {
                    ttl: 90,
                    octets: [1, 1, 1, 1],
                },
                Step::NodataWithSoa { ttl: 300, min: 60 },
            ],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 3);
        assert_eq!(report.failed, 1);
        assert!(bindings_of(&cache, 0, Family::A).is_empty());
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
    }

    #[test]
    fn stalled_responder_times_out_exchange_and_reconnects() {
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Stall(Duration::from_secs(1)), Step::Close],
            vec![
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::PositiveA {
                    ttl: 90,
                    octets: [1, 1, 1, 1],
                },
                Step::NodataWithSoa { ttl: 300, min: 60 },
            ],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 3);
        assert_eq!(report.failed, 1);
        assert!(bindings_of(&cache, 0, Family::A).is_empty());
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn startup_dns_phase_is_allocation_free_including_reconnect() {
        use crate::alloc::{self, Phase};
        let cfg = config();
        let responder = spawn_responder(vec![
            vec![Step::Malformed(vec![0xff, 0xff, 0xff, 0xff])],
            vec![
                Step::NodataWithSoa { ttl: 300, min: 60 },
                Step::PositiveA {
                    ttl: 90,
                    octets: [1, 1, 1, 1],
                },
                Step::NodataWithSoa { ttl: 300, min: 60 },
            ],
        ]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();

        let (_, control) = alloc::run_phase(Phase::StartupDns, || {
            let bytes = Box::new([0u8; 64]);
            std::hint::black_box(bytes);
        });
        assert!(
            control.allocs > 0 && control.deallocs > 0,
            "counter must attribute a local alloc/dealloc: {control:?}"
        );

        let (report, counts) = alloc::run_phase(Phase::StartupDns, || {
            transport
                .resolve(
                    &cfg,
                    &mut cache,
                    &mut schedules,
                    ns(responder.port()),
                    1_000_000,
                )
                .unwrap()
        });
        assert!(
            counts.all_zero(),
            "startup DNS phase must be allocation-free including a reconnect: {counts:?}"
        );
        assert_eq!(report.exchanges, 3);
        assert_eq!(report.failed, 1);
    }

    #[test]
    fn nxdomain_evicts_for_the_name_via_cache() {
        let cfg = config();
        let responder = spawn_responder(vec![vec![
            Step::NxdomainWithSoa { ttl: 300, min: 60 },
            Step::NxdomainWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        let report = transport
            .resolve(
                &cfg,
                &mut cache,
                &mut schedules,
                ns(responder.port()),
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.exchanges, 4);
        assert_eq!(report.resolved_names, 1);
        assert!(bindings_of(&cache, 0, Family::A).is_empty());
        assert!(bindings_of(&cache, 0, Family::Aaaa).is_empty());
        assert_eq!(
            bindings_of(&cache, 1, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(1, 1, 1, 1)
            )]
        );
    }

    #[test]
    fn wait_until_next_step_with_no_scheduled_step_does_not_decide_early() {
        let transport = StartupDns::new().unwrap();
        let schedules = Schedules::new(2).unwrap();
        let resolved = [false, true];
        let wait = wait_until_next_step(&transport, &schedules, 2, &resolved).unwrap();
        assert!(
            wait > Duration::from_millis(100),
            "an unresolved name with no scheduled step must sleep toward the \
             window deadline, not break early: {wait:?}"
        );
    }
}
