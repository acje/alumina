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
use crate::startup_dns::{STARTUP_WINDOW_SECS, StartupDnsError, TurnResult};

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
    /// in main that must not write to stderr (alumina.md:149, B1). The
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
        if !self.serving.is_shutdown() {
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
    /// at process exit (alumina.md:150,206): a clean drain exits 0, and a
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
mod tests {
    use super::*;

    use std::io::{self, Read, Write};
    use std::net::SocketAddr;
    use std::net::{TcpListener as StdListener, TcpStream};
    use std::thread;

    use crate::cache::Family;

    fn config(port: u16) -> crate::config::Config {
        let doc = format!(
            "allowlist = [\"sub.example.org\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\n"
        );
        crate::config::parse_config_document(&doc).expect("valid test config")
    }

    fn config_two_names(port: u16) -> crate::config::Config {
        let doc = format!(
            "allowlist = [\"sub.example.org\", \"other.example.org\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\n"
        );
        crate::config::parse_config_document(&doc).expect("valid test config")
    }

    fn ephemeral_port() -> u16 {
        let probe = StdListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        port
    }

    /// A stale DNS peer: accepts the transport connection, reads the query,
    /// withholds any response, then finally answers just before closing so the
    /// test exits cleanly.
    fn spawn_stall_responder() -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = StdListener::bind("127.0.0.1:0").expect("bind stall responder");
        let addr = listener.local_addr().expect("responder addr");
        let handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept transport");
            let mut sink = [0u8; 64];
            let _ = sock.read(&mut sink);
            thread::sleep(Duration::from_millis(300));
            let _ = sock.write(&sink);
            let _ = sock.flush();
            thread::sleep(Duration::from_millis(50));
        });
        (addr, handle)
    }

    fn connect(port: u16) -> TcpStream {
        TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).expect("client connect")
    }

    #[test]
    fn single_poll_wait_advances_stalled_dns_and_accepts_traffic_together() {
        let t = thread::Builder::new()
            .name("runtime-falsifier".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(falsifier_body)
            .expect("spawn falsifier thread");
        t.join().expect("falsifier thread");
    }

    fn falsifier_body() {
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config(port)).expect("boot storage");
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).expect("bind listener");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut runtime = Runtime::new(storage, listener, traffic).expect("runtime");
        let (responder_addr, responder) = spawn_stall_responder();

        let exchange_deadline = Instant::now() + Duration::from_secs(10);
        runtime
            .serving
            .storage_mut()
            .start_dns_exchange(responder_addr, 0, Family::A, exchange_deadline)
            .expect("start exchange");

        let client = connect(port);
        let mut accepted = false;
        let mut dns_query_written = false;
        for _ in 0..300 {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn");
            accepted |= runtime.serving.storage().occupied() > 0;
            dns_query_written |= matches!(
                runtime.serving.storage().dns().exchange_step(),
                Some(crate::startup_dns::ExchangeStep::Receiving)
            );
            if accepted && dns_query_written {
                break;
            }
        }

        drop(client);
        drop(responder);
        assert!(
            accepted,
            "the single owner wait must observe listener accept readiness and admit the client"
        );
        assert!(
            dns_query_written,
            "the cooperative DNS exchange against a stalled peer must advance to Receiving \
             (query fully written) through the same single wait"
        );
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

    fn read_query(sock: &mut TcpStream) -> Option<Vec<u8>> {
        let mut lenb = [0u8; 2];
        read_exact(sock, &mut lenb).ok()?;
        let qlen = usize::from(u16::from_be_bytes(lenb));
        if qlen == 0 {
            return None;
        }
        let mut q = vec![0u8; qlen];
        read_exact(sock, &mut q).ok()?;
        Some(q)
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

    fn positive_response(msg: &[u8]) -> Option<Vec<u8>> {
        if msg.len() < 14 {
            return None;
        }
        let tid = u16::from_be_bytes([msg[0], msg[1]]);
        let qname = &msg[12..msg.len() - 4];
        let qtype = u16::from_be_bytes([msg[msg.len() - 4], msg[msg.len() - 3]]);
        let (rtype, rdata): (u16, Vec<u8>) = match qtype {
            1 => (1, vec![93, 184, 216, 34]),
            28 => (
                28,
                vec![
                    0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
                ],
            ),
            _ => return None,
        };
        let mut out = Vec::new();
        out.extend_from_slice(&tid.to_be_bytes());
        out.extend_from_slice(&0x8000u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&msg[12..]);
        out.extend_from_slice(&record(qname, rtype, 120, &rdata));
        Some(out)
    }

    fn write_response(sock: &mut TcpStream, reply: &[u8]) -> io::Result<()> {
        sock.write_all(&(reply.len() as u16).to_be_bytes())?;
        sock.write_all(reply)
    }

    fn spawn_responder_keep_alive() -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = StdListener::bind("127.0.0.1:0").expect("bind responder");
        let addr = listener.local_addr().expect("responder addr");
        let handle = thread::spawn(move || {
            loop {
                let (mut sock, _) = match listener.accept() {
                    Ok(x) => x,
                    Err(_) => break,
                };
                while let Some(q) = read_query(&mut sock) {
                    if let Some(reply) = positive_response(&q)
                        && write_response(&mut sock, &reply).is_err()
                    {
                        break;
                    }
                }
            }
        });
        (addr, handle)
    }

    fn spawn_responder_close_after_answer() -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = StdListener::bind("127.0.0.1:0").expect("bind responder");
        let addr = listener.local_addr().expect("responder addr");
        let handle = thread::spawn(move || {
            loop {
                let (mut sock, _) = match listener.accept() {
                    Ok(x) => x,
                    Err(_) => break,
                };
                if let Some(q) = read_query(&mut sock)
                    && let Some(reply) = positive_response(&q)
                {
                    let _ = write_response(&mut sock, &reply);
                }
            }
        });
        (addr, handle)
    }

    /// A DNS peer that answers every query on the FIRST accepted connection
    /// and stays silent on every subsequent one, mirroring the e2e
    /// `silent_after_first_session` responder. A transport that keeps the
    /// single startup connection warm across names resolves both on session 1;
    /// a transport that closes after each name reconnects onto a silent
    /// session and the later name can never publish.
    fn spawn_responder_first_session_only() -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = StdListener::bind("127.0.0.1:0").expect("bind responder");
        let addr = listener.local_addr().expect("responder addr");
        let handle = thread::spawn(move || {
            let mut sessions = 0usize;
            loop {
                let (mut sock, _) = match listener.accept() {
                    Ok(x) => x,
                    Err(_) => break,
                };
                if sessions == 0 {
                    while let Some(q) = read_query(&mut sock) {
                        if let Some(reply) = positive_response(&q)
                            && write_response(&mut sock, &reply).is_err()
                        {
                            break;
                        }
                    }
                } else {
                    let mut sink = [0u8; 64];
                    loop {
                        match sock.read(&mut sink) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                }
                sessions += 1;
            }
        });
        (addr, handle)
    }

    /// A DNS responder that withholds the final allowlist answer (the query
    /// whose qname is the first distinct name beyond the initially-answered
    /// one) until the coordinator releases it, mirroring the e2e
    /// `hold_final` mechanic: the window is provably mid-resolution with an
    /// unanswered final name when a SIGTERM lands, so a settlement race is
    /// deterministic rather than timing-dependent. Returns the responder
    /// address, a flag raised once the final answer is withheld, the release
    /// sender, a channel acking the held answer's `write_response` having
    /// returned, and the thread handle.
    #[allow(clippy::type_complexity)]
    fn spawn_responder_hold_final() -> (
        SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::sync::mpsc::Sender<()>,
        std::sync::mpsc::Receiver<()>,
        thread::JoinHandle<()>,
    ) {
        let listener = StdListener::bind("127.0.0.1:0").expect("bind responder");
        let addr = listener.local_addr().expect("responder addr");
        let held_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag_for_thread = held_flag.clone();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (wrote_tx, wrote_rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept transport");
            let mut seen: std::collections::HashSet<Vec<u8>> = Default::default();
            let mut held = false;
            while let Some(query) = read_query(&mut sock) {
                let Some(reply) = positive_response(&query) else {
                    break;
                };
                let qname = query[12..query.len() - 4].to_vec();
                let new_name = !seen.contains(&qname);
                if new_name && !seen.is_empty() && !held {
                    held = true;
                    flag_for_thread.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = release_rx.recv();
                }
                seen.insert(qname);
                if write_response(&mut sock, &reply).is_err() {
                    break;
                }
                if held {
                    let _ = wrote_tx.send(());
                    break;
                }
            }
        });
        (addr, held_flag, release_tx, wrote_rx, handle)
    }

    fn name_published(runtime: &Runtime, ordinal: usize, family: Family) -> bool {
        let cache = runtime.serving.storage().cache();
        let Some(name_index) = cache.name_index(ordinal) else {
            return false;
        };
        matches!(cache.entry(name_index, family), Ok(entry) if !entry.bindings().is_empty())
    }

    #[test]
    fn idle_after_published_does_not_spin() {
        let t = thread::Builder::new()
            .name("runtime-idle-falsifier".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(idle_falsifier_body)
            .expect("spawn idle falsifier thread");
        t.join().expect("idle falsifier thread");
    }

    fn idle_falsifier_body() {
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config(port)).expect("boot storage");
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).expect("bind listener");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut runtime = Runtime::new(storage, listener, traffic).expect("runtime");
        let (responder_addr, responder) = spawn_responder_keep_alive();

        let exchange_deadline = Instant::now() + Duration::from_secs(10);
        runtime
            .serving
            .storage_mut()
            .start_dns_exchange(responder_addr, 0, Family::A, exchange_deadline)
            .expect("start exchange");

        let mut published = false;
        for _ in 0..200 {
            runtime
                .turn(Some(Duration::from_millis(5)))
                .expect("owner turn");
            if !runtime.serving.storage().dns().has_active_exchange()
                && name_published(&runtime, 0, Family::A)
            {
                published = true;
                break;
            }
        }
        assert!(
            published,
            "the cooperative exchange must publish before the idle probe"
        );

        let probe_start = Instant::now();
        let mut wakeups = 0u32;
        for _ in 0..20 {
            runtime
                .turn(Some(Duration::from_millis(5)))
                .expect("idle owner turn");
            if runtime.serving.take_dns_event() {
                wakeups += 1;
            }
        }
        let elapsed = probe_start.elapsed();
        drop(responder);
        assert_eq!(
            wakeups, 0,
            "an exchange settled idle must produce no DNS wakeups (no retained registered socket)"
        );
        assert!(
            elapsed >= Duration::from_millis(80),
            "idle turns must wait out the serving timeout rather than spin: {elapsed:?}"
        );
    }

    #[test]
    fn peer_close_after_answer_then_reconnect_publishes() {
        let t = thread::Builder::new()
            .name("runtime-reconnect-falsifier".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(reconnect_falsifier_body)
            .expect("spawn reconnect falsifier thread");
        t.join().expect("reconnect falsifier thread");
    }

    fn reconnect_falsifier_body() {
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config(port)).expect("boot storage");
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).expect("bind listener");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut runtime = Runtime::new(storage, listener, traffic).expect("runtime");
        let (responder_addr, responder) = spawn_responder_close_after_answer();

        runtime
            .serving
            .storage_mut()
            .start_dns_exchange(
                responder_addr,
                0,
                Family::A,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("start exchange A");
        let mut first = false;
        for _ in 0..200 {
            runtime
                .turn(Some(Duration::from_millis(5)))
                .expect("owner turn");
            if name_published(&runtime, 0, Family::A) {
                first = true;
                break;
            }
        }
        assert!(
            first,
            "the first exchange must publish against a responder that closes after answering"
        );

        runtime
            .serving
            .storage_mut()
            .start_dns_exchange(
                responder_addr,
                0,
                Family::Aaaa,
                Instant::now() + Duration::from_secs(10),
            )
            .expect("start exchange Aaaa");
        let mut second = false;
        for _ in 0..200 {
            runtime
                .turn(Some(Duration::from_millis(5)))
                .expect("owner turn");
            if name_published(&runtime, 0, Family::Aaaa) {
                second = true;
                break;
            }
        }
        drop(responder);
        assert!(
            second,
            "a reconnect after the peer closed must publish through a fresh connection"
        );
    }

    use crate::serve::{ServingMode, StartupDecision};

    #[test]
    fn preallocate_then_startup_then_attach_accepts_in_main_order() {
        let t = thread::Builder::new()
            .name("runtime-main-wiring".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(main_wiring_body)
            .expect("spawn main-wiring falsifier");
        t.join().expect("main-wiring falsifier thread");
    }

    /// Mirrors main.rs exactly: the retained serving workspaces are preallocated
    /// BEFORE any DNS exchange, the startup window then runs over that complete
    /// owner, and the serving decision's listener is attached for traffic.
    fn main_wiring_body() {
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config(port)).expect("boot storage");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut owner =
            Preallocated::preallocate(storage, traffic).expect("preallocate serving workspaces");
        assert!(
            !owner.serving().storage().dns().has_active_exchange(),
            "the retained DNS transport must not start an exchange before the window"
        );

        let (responder_addr, responder) = spawn_responder_keep_alive();
        let outcome = owner
            .run_startup_within(responder_addr, 1000, Duration::from_secs(2))
            .expect("startup window");
        assert_eq!(outcome.decision, StartupDecision::Serve(ServingMode::Full));
        let listener = outcome
            .listener
            .expect("a serving decision binds the connect listener");
        let mut runtime = owner.attach(listener).expect("attach listener + dns");

        let client = connect(port);
        let mut accepted = false;
        for _ in 0..200 {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn");
            if runtime.serving().storage().occupied() > 0 {
                accepted = true;
                break;
            }
        }
        drop(client);
        drop(responder);
        assert!(
            accepted,
            "the wired owner must accept the client on the startup-bound listener"
        );
    }

    #[test]
    fn startup_queued_warning_still_observes_sigterm_and_never_binds() {
        let t = thread::Builder::new()
            .name("startup-starvation-falsifier".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(startup_starvation_falsifier_body)
            .expect("spawn startup-starvation falsifier thread");
        t.join().expect("startup-starvation falsifier thread");
    }

    /// The shared-startup window must observe a queued SIGTERM even while the
    /// first-failure warning sits queued in an unblocked runnable sink and the
    /// retry backoff offers nothing due: the zero-wait log state must not
    /// `continue` past the shared poll. The warning is enqueued before the
    /// window (the 97nx queued-runnable state), the signal byte is queued
    /// before the window, and the refused nameserver (a dead loopback port)
    /// keeps the exchange pending so the window cannot resolve early. A
    /// correct owner settles Terminated and never binds a listener; a starved
    /// owner spins to the window deadline and decides Exit75 instead.
    fn startup_starvation_falsifier_body() {
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config(port)).expect("boot storage");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut owner = Preallocated::preallocate(storage, traffic).expect("preallocate");
        owner
            .serving
            .storage_mut()
            .logs_mut()
            .startup_warning(1000, "sub.example.org", Family::A);
        let dead = ephemeral_port();
        let dead_addr = SocketAddr::from(([127, 0, 0, 1], dead));
        owner
            .wake_signal_test()
            .expect("self-pipe test write end")
            .write_all(&[1])
            .expect("queue a SIGTERM byte before the startup window");
        let outcome = owner
            .run_startup_within(dead_addr, 1000, Duration::from_secs(2))
            .expect("startup window");
        assert_eq!(
            outcome.decision,
            StartupDecision::Terminated,
            "a queued SIGTERM during a queued-runnable retry backoff must settle as the \
             terminated outcome instead of being starved by the queued runnable warning"
        );
        assert!(
            outcome.listener.is_none(),
            "the terminated startup must never bind a listener"
        );
    }

    #[test]
    fn runtime_skips_cooperative_dns_and_stays_draining_after_sigterm() {
        let t = thread::Builder::new()
            .name("runtime-shutdown-falsifier".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(shutdown_falsifier_body)
            .expect("spawn shutdown falsifier thread");
        t.join().expect("shutdown falsifier thread");
    }

    fn shutdown_falsifier_body() {
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config(port)).expect("boot storage");
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).expect("bind listener");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut runtime = Runtime::new(storage, listener, traffic).expect("runtime");
        let (responder_addr, responder) = spawn_stall_responder();

        let exchange_deadline = Instant::now() + Duration::from_secs(30);
        runtime
            .serving
            .storage_mut()
            .start_dns_exchange(responder_addr, 0, Family::A, exchange_deadline)
            .expect("start exchange");
        assert!(
            runtime.serving().storage().dns().has_active_exchange(),
            "the exchange must be active before the signal"
        );

        runtime
            .serving
            .on_sigterm()
            .expect("first observed SIGTERM");
        assert!(
            runtime.serving().is_shutdown(),
            "the runtime owner must enter shutdown after the first signal"
        );
        assert!(
            !runtime.serving().storage().dns().has_active_exchange(),
            "the retained DNS transport must be cancelled at the first signal"
        );
        assert!(
            !runtime.dns_deadline_due(),
            "no DNS deadline may remain due after the transport is cancelled"
        );

        for _ in 0..10 {
            runtime
                .turn(Some(Duration::from_millis(5)))
                .expect("owner turn during shutdown");
            assert!(
                runtime.serving().is_shutdown(),
                "a serving turn must not leave the draining phase"
            );
        }
        drop(responder);
    }

    #[test]
    fn startup_window_reuses_one_connection_across_names() {
        let t = thread::Builder::new()
            .name("reuse-window-falsifier".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(startup_reuse_window_body)
            .expect("spawn reuse-window falsifier thread");
        t.join().expect("reuse-window falsifier thread");
    }

    /// The shared startup window must resolve every allowlist name over one
    /// reusable connection, exactly as the private driver does: the window
    /// owner closes the transport once at the end, never after each published
    /// name. A first-session-only responder proves the connection stayed warm
    /// across names — a per-publish close reconnects the second name onto a
    /// silent session it can never resolve, forcing the decision down from
    /// Full to Exit75.
    fn startup_reuse_window_body() {
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config_two_names(port)).expect("boot storage");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut owner = Preallocated::preallocate(storage, traffic).expect("preallocate");

        let (responder_addr, responder) = spawn_responder_first_session_only();
        let outcome = owner
            .run_startup_within(responder_addr, 1000, Duration::from_secs(3))
            .expect("startup window");
        drop(responder);

        assert_eq!(
            outcome.decision,
            StartupDecision::Serve(ServingMode::Full),
            "both allowlist names must resolve on a single reusable startup connection"
        );
    }

    #[test]
    fn runtime_self_pipe_sigterm_cancels_active_receiving() {
        let t = thread::Builder::new()
            .name("selfpipe-receiving-cancellation-witness".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(selfpipe_receiving_cancellation_body)
            .expect("spawn self-pipe receiving-cancellation witness thread");
        t.join()
            .expect("self-pipe receiving-cancellation witness thread");
    }

    /// The retained DNS transport must reach an observable `Receiving` step
    /// against a peer that withholds its answer, and the first-observed
    /// SIGTERM — delivered through the real signal self-pipe and observed by a
    /// serving `turn`, not by calling `on_sigterm` directly — must cancel the
    /// active exchange, leave no DNS deadline due, and keep the owner draining
    /// across later turns (oracle 991u C1, dm48, U1).
    fn selfpipe_receiving_cancellation_body() {
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config(port)).expect("boot storage");
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).expect("bind listener");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut runtime = Runtime::new(storage, listener, traffic).expect("runtime");
        let (responder_addr, responder) = spawn_stall_responder();

        let exchange_deadline = Instant::now() + Duration::from_secs(30);
        runtime
            .serving
            .storage_mut()
            .start_dns_exchange(responder_addr, 0, Family::A, exchange_deadline)
            .expect("start exchange");

        let mut saw_receiving = false;
        for _ in 0..300 {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn to Receiving");
            if matches!(
                runtime.serving.storage().dns().exchange_step(),
                Some(crate::startup_dns::ExchangeStep::Receiving)
            ) {
                saw_receiving = true;
                break;
            }
        }
        assert!(
            saw_receiving,
            "the retained DNS exchange must observably reach Receiving against a silent peer"
        );
        assert!(
            runtime.serving().storage().dns().has_active_exchange(),
            "the exchange must be active when the SIGTERM self-pipe byte lands"
        );

        runtime
            .serving
            .signal_wake_mut()
            .expect("self-pipe test write end")
            .write_all(&[1])
            .expect("queue a SIGTERM byte through the real self-pipe");
        for _ in 0..10 {
            runtime
                .turn(Some(Duration::from_millis(5)))
                .expect("owner turn during shutdown");
            assert!(
                runtime.serving().is_shutdown(),
                "the first self-pipe-observed SIGTERM must enter the draining phase"
            );
            assert!(
                !runtime.serving().storage().dns().has_active_exchange(),
                "the active Receiving exchange must be cancelled at the first signal"
            );
            assert!(
                !runtime.dns_deadline_due(),
                "no DNS deadline may remain due after the transport is cancelled"
            );
        }
        drop(responder);
    }

    #[test]
    fn run_startup_post_all_resolved_sigterm_settles_terminated() {
        let t = thread::Builder::new()
            .name("post-settlement-sigterm-witness".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(post_all_resolved_settlement_body)
            .expect("spawn post-all-resolved settlement witness thread");
        t.join()
            .expect("post-all-resolved settlement witness thread");
    }

    /// Every allowlist name resolves, so the window leaves the selection loop
    /// all-resolved; only then — at the pre-settlement checkpoint, before the
    /// zero-wait recheck decides Serve-vs-Terminated — a real SIGTERM self-pipe
    /// byte becomes readable. The settlement turn must observe it and settle
    /// Terminated, never binding a listener (oracle 991u C2, dm48, U1): the
    /// pending-signal race is against the settlement boundary, not a stale DNS
    /// deadline.
    fn post_all_resolved_settlement_body() {
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config_two_names(port)).expect("boot storage");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut owner = Preallocated::preallocate(storage, traffic).expect("preallocate");
        let (responder_addr, responder) = spawn_responder_keep_alive();

        let wake = owner
            .serving
            .signal_wake_mut()
            .expect("self-pipe test write end")
            .try_clone()
            .expect("clone the self-pipe write end for the settlement hook");
        owner.serving.arm_pre_settlement_hook(Box::new(move || {
            let mut wake = wake;
            wake.write_all(&[1])
                .expect("queue a SIGTERM byte at the pre-settlement checkpoint");
        }));

        let outcome = owner
            .run_startup_within(responder_addr, 1000, Duration::from_secs(5))
            .expect("startup window");
        drop(responder);

        assert_eq!(
            outcome.decision,
            StartupDecision::Terminated,
            "a SIGTERM readable at the post-all-resolved pre-settlement checkpoint must settle \
             Terminated through the zero-wait recheck"
        );
        assert!(
            outcome.listener.is_none(),
            "the terminated startup must never bind a listener"
        );
    }

    #[test]
    fn run_startup_both_ready_sigterm_and_final_answer_settles_terminated() {
        let t = thread::Builder::new()
            .name("both-ready-same-batch-witness".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(both_ready_settlement_body)
            .expect("spawn both-ready settlement witness thread");
        t.join().expect("both-ready settlement witness thread");
    }

    /// Mirrors the e2e SIMULTANEOUS-COMPLETION case natively and proves the
    /// same-batch ownership claim: once the final allowlist exchange's query is
    /// on the wire the pre-poll hook spins until the responder reports the
    /// answer withheld, releases it, waits until the owner's DNS stream is
    /// readable but not yet read, and only then queues the SIGTERM byte, so a
    /// single in-loop poll observes DNS-ready plus the pending signal in one
    /// batch. A correct owner must settle that batch as Terminated (signal
    /// priority over a just-completed DNS readiness) and never bind a listener
    /// (oracle 991u C2), and must not count the final name as resolved or
    /// published past the signal. Both ordering defenses matter: the startup DNS
    /// transport cancellation in `on_sigterm` clears the active exchange inside
    /// the same turn, and the post-poll loop head re-checks shutdown before
    /// `advance_dns` runs — either alone keeps the final name unpublished.
    fn both_ready_settlement_body() {
        let port = ephemeral_port();
        let storage = ServeStorage::boot(&config_two_names(port)).expect("boot storage");
        let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
        let mut owner = Preallocated::preallocate(storage, traffic).expect("preallocate");

        let (responder_addr, held_flag, release_tx, wrote_rx, responder) =
            spawn_responder_hold_final();

        let wake = std::cell::RefCell::new(
            owner
                .serving
                .signal_wake_mut()
                .expect("self-pipe test write end")
                .try_clone()
                .expect("clone the self-pipe write end"),
        );

        let fired = std::cell::Cell::new(false);
        let held_for_hook = held_flag.clone();
        let release = release_tx;
        let wrote = wrote_rx;
        let hook = std::rc::Rc::new(move |serving: &Serving| {
            if fired.get() {
                return;
            }
            if serving.test_active_ordinal() == Some(1) && !serving.test_active_receiving() {
                return;
            }
            let spin_deadline = Instant::now() + Duration::from_millis(1500);
            while !held_for_hook.load(std::sync::atomic::Ordering::SeqCst) {
                if serving.test_active_ordinal() != Some(1) {
                    return;
                }
                assert!(
                    Instant::now() < spin_deadline,
                    "final allowlist answer must be withheld once the final exchange is in flight"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            fired.set(true);
            release
                .send(())
                .expect("release the held final allowlist answer");
            wrote
                .recv_timeout(Duration::from_secs(5))
                .expect("the held answer write_response must return before the signal byte");
            let deadline = Instant::now() + Duration::from_secs(5);
            while !serving.test_dns_fd_readable() {
                assert!(
                    Instant::now() < deadline,
                    "owner DNS fd must become readable after the write ack"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            wake.borrow_mut()
                .write_all(&[1])
                .expect("queue a SIGTERM byte only after DNS-ready is observed");
        });
        owner.serving.arm_pre_poll_hook(hook);

        let outcome = owner
            .run_startup_within(responder_addr, 1000, Duration::from_secs(5))
            .expect("startup window");
        drop(responder);

        assert_eq!(
            outcome.decision,
            StartupDecision::Terminated,
            "same-batch DNS-ready + pending signal must settle Terminated, never Serve"
        );
        assert!(
            outcome.listener.is_none(),
            "the terminated startup must never bind a listener"
        );
        assert_eq!(
            outcome.report.resolved_names, 1,
            "the final name's answer became readable in the same poll batch, so the \
             post-batch turn re-checks shutdown before advance_dns and never counts it resolved"
        );
    }
}
