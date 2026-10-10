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

use crate::serve::ServeStorage;
use crate::serving::{ServeError, Serving};
use crate::startup_dns::TurnResult;

/// The bounded number of cooperative DNS advances a single owner turn may make,
/// so a chatty or stalled peer can never starve traffic within a turn.
const DNS_ADVANCE_BOUND: usize = 8;

/// The shared-readiness owner: one process owner whose single wait sees both
/// DNS freshness and traffic readiness, and whose turn policy decides when DNS
/// work is due (a freshness event, a send that can proceed without waiting, or
/// the exchange deadline).
pub struct Runtime {
    serving: Serving,
    dns_token: Token,
}

impl Runtime {
    /// Builds the owner over boot-completed storage and an already-bound
    /// listener, attaching the retained DNS transport to the single serving
    /// poll.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the serving poll or the shared DNS
    /// registration fails.
    pub fn new(storage: ServeStorage, listener: TcpListener) -> Result<Runtime, ServeError> {
        let dns_token = Serving::dns_token();
        let mut serving = Serving::new(storage, listener)?;
        serving.attach_dns_shared()?;
        Ok(Runtime { serving, dns_token })
    }

    /// The serving engine, for host observation.
    pub fn serving(&self) -> &Serving {
        &self.serving
    }

    /// The token the retained DNS source is attached under on the single poll.
    pub fn dns_token(&self) -> Token {
        self.dns_token
    }

    /// One owner turn: a single wait over DNS freshness and traffic readiness
    /// (the serving poll carries both), then dispatch and a bounded
    /// cooperative DNS advance when DNS work is due, then a re-alignment of
    /// the shared DNS interest to its phase. The wait never outlives the
    /// outstanding exchange because the deadline is folded into the serving
    /// timeout.
    ///
    /// # Errors
    ///
    /// Returns a serve error when the poll, a registration, or a cooperative
    /// DNS turn fails.
    pub fn turn(&mut self, timeout: Option<Duration>) -> Result<(), ServeError> {
        self.serving.run_once(timeout)?;
        let event_seen = self.serving.take_dns_event();
        let sendable = self.dns_sendable_without_wait();
        let deadline_due = self.dns_deadline_due();
        if event_seen || sendable || deadline_due {
            self.cooperative_dns_turn()?;
        }
        self.serving.sync_dns_shared()
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
        let mut runtime = Runtime::new(storage, listener).expect("runtime");
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
        let mut runtime = Runtime::new(storage, listener).expect("runtime");
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
        let mut runtime = Runtime::new(storage, listener).expect("runtime");
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
}
