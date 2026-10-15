use super::*;

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::net::{TcpListener as StdListener, TcpStream};
use std::thread;

use crate::cache::Family;

fn config(port: u16) -> crate::config::Config {
    let doc = format!(
        "allowlist = [\"sub.example.org:443\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\"]\nscope = [\"connection\"]\n"
    );
    crate::config::parse_config_document(&doc).expect("valid test config")
}

fn config_two_names(port: u16) -> crate::config::Config {
    let doc = format!(
        "allowlist = [\"sub.example.org:443\", \"other.example.org:443\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\", \"flare_only\"]\nscope = [\"connection\", \"connection\"]\n"
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

#[test]
#[cfg(all(test, feature = "alloc-witness"))]
fn hot_relay_turns_compose_with_bounded_stalled_dns() {
    let t = std::thread::Builder::new()
        .name("runtime-hot-dns-many-slots".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(hot_relay_many_slots_body)
        .expect("spawn falsifier thread");
    t.join().expect("falsifier thread");
}

#[cfg(all(test, feature = "alloc-witness"))]
fn hot_relay_many_slots_body() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    let port = ephemeral_port();
    let storage = ServeStorage::boot(&config_two_names(port)).expect("boot storage");
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

    const HOT_SLOTS: usize = 17;
    const FIRST_HOT_INDEX: usize = 30;
    const EXPIRED_INDEX: usize = 47;
    let per_slot = 96 * 1024;
    let stop = Arc::new(AtomicBool::new(false));
    let mut readers = Vec::new();
    let mut holds = Vec::new();
    let mut got: Vec<Arc<Mutex<Vec<u8>>>> = Vec::new();
    for i in 0..HOT_SLOTS {
        let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
        let sink_addr = sink.local_addr().expect("sink addr");
        let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
        let mut sink_stream = sink.accept().expect("accept sink side").0;
        sink_stream.set_nonblocking(true).expect("sink nonblocking");

        let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
        let peer_addr = peer_l.local_addr().expect("peer addr");
        let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
        let mut peer_stream = peer_l.accept().expect("accept peer side").0;

        runtime
            .serving_mut()
            .test_setup_relay(FIRST_HOT_INDEX + i, up, client)
            .expect("install relay");

        let pattern = crate::serving::test_offset_pattern(per_slot, 30 + i as u32);
        peer_stream.write_all(&pattern).expect("preload pattern");
        holds.push(peer_stream);

        let lane_got = Arc::new(Mutex::new(Vec::new()));
        got.push(Arc::clone(&lane_got));
        let lane_stop = Arc::clone(&stop);
        readers.push(std::thread::spawn(move || {
            let mut tmp = [0u8; 65536];
            loop {
                if lane_stop.load(Ordering::SeqCst) {
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
        }));
    }

    let sink = StdListener::bind("127.0.0.1:0").expect("sink bind");
    let sink_addr = sink.local_addr().expect("sink addr");
    let up = mio::net::TcpStream::connect(sink_addr).expect("upstream connect");
    let sink_stream = sink.accept().expect("accept sink side").0;
    let _ = sink_stream;
    let peer_l = StdListener::bind("127.0.0.1:0").expect("peer bind");
    let peer_addr = peer_l.local_addr().expect("peer addr");
    let client = mio::net::TcpStream::connect(peer_addr).expect("client connect");
    let mut peer_stream = peer_l.accept().expect("accept peer side").0;
    runtime
        .serving_mut()
        .test_setup_relay(EXPIRED_INDEX, up, client)
        .expect("install expired-timer relay");
    peer_stream
        .write_all(&crate::serving::test_offset_pattern(4096, 99))
        .expect("preload expired-timer relay");
    holds.push(peer_stream);
    runtime.serving_mut().test_mark_idle_expired(EXPIRED_INDEX);

    let mut accept_backlog = Vec::new();
    for _ in 0..4 {
        accept_backlog.push(connect(port));
    }

    let mut turns = 0;
    let mut dns_receiving = false;
    let mut dns_advanced_any = false;
    let mut expired_closed = false;
    let mut backlog_admitted = false;
    let mut second_visit_turn = [0i32; HOT_SLOTS];
    while turns < 900 {
        runtime
            .turn(Some(Duration::from_millis(2)))
            .expect("owner turn");
        turns += 1;
        let advances = runtime.dns_advances_last_turn;
        assert!(
            advances <= DNS_ADVANCE_BOUND,
            "one owner turn must advance the stalled DNS exchange at most eight steps,                  observed {advances}"
        );
        dns_advanced_any |= advances >= 1;
        expired_closed |= runtime.serving.test_slot_closed(EXPIRED_INDEX);
        backlog_admitted |= runtime.serving.storage().occupied() >= accept_backlog.len();
        let mut all_complete = true;
        for i in 0..HOT_SLOTS {
            let visits = runtime.serving.test_slot_visits(FIRST_HOT_INDEX + i);
            if visits >= 2 && second_visit_turn[i] == 0 {
                second_visit_turn[i] = turns;
            }
            if got[i].lock().unwrap().len() < per_slot {
                all_complete = false;
            }
        }
        dns_receiving |= matches!(
            runtime.serving.storage().dns().exchange_step(),
            Some(crate::startup_dns::ExchangeStep::Receiving)
        );
        if dns_receiving && all_complete && expired_closed && backlog_admitted {
            break;
        }
    }
    stop.store(true, Ordering::SeqCst);
    let tails: Vec<Vec<u8>> = got
        .iter()
        .map(|lane| lane.lock().unwrap().clone())
        .collect();
    for reader in readers {
        reader.join().expect("sink reader");
    }
    drop(holds);
    drop(accept_backlog);
    drop(responder);

    let high_water = runtime.serving.max_work_since_recheck;
    assert!(
        dns_receiving,
        "while {HOT_SLOTS} hot relays keep the owner busy, the stalled DNS exchange must              advance through the same turns (query fully written -> Receiving)"
    );
    assert!(
        dns_advanced_any,
        "the stalled exchange must actually be advanced by the per-turn counter, never zero"
    );
    assert!(
        expired_closed,
        "the expired-timer slot must be swept closed on an owner turn while the hot slots              stay busy"
    );
    assert!(
        backlog_admitted,
        "a pending accept backlog must be admitted while hot relays and DNS busy the owner"
    );
    assert!(
        (200..=256).contains(&high_water),
        "the timer/DNS recheck must fire mid-batch under {HOT_SLOTS} hot slots, high-water \
         {high_water} outside [200, 256]"
    );
    for i in 0..HOT_SLOTS {
        assert!(
            (1..=HOT_SLOTS as i32).contains(&second_visit_turn[i]),
            "hot slot {i} must reach its second owner visit within one full round-robin pass \
             of the competing hot slots ({HOT_SLOTS} batches; one visit per slot per batch, \
             and 96KiB needs two visits under the 64KiB cap), so deferring the second visit \
             past a full pass is starvation; observed on turn {turn}",
            turn = second_visit_turn[i]
        );
        assert_eq!(
            tails[i].len(),
            per_slot,
            "hot relay {i} must complete under DNS + backlog load"
        );
        let pattern = crate::serving::test_offset_pattern(per_slot, 30 + i as u32);
        assert_eq!(
            &tails[i][..],
            &pattern[..],
            "hot relay {i} bytes byte-exact"
        );
    }
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

    let (responder_addr, held_flag, release_tx, wrote_rx, responder) = spawn_responder_hold_final();

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

enum SessionGate {
    Answer(Box<dyn FnMut(Vec<u8>) -> Option<Vec<u8>>>),
    Silent,
}

fn spawn_supervised_responder(
    on_session: impl FnMut(usize) -> SessionGate + Send + 'static,
) -> (
    SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread::JoinHandle<()>,
) {
    let listener = StdListener::bind("127.0.0.1:0").expect("bind responder");
    let addr = listener.local_addr().expect("responder addr");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let handle = thread::spawn(move || {
        let mut on_session = on_session;
        let mut session = 0usize;
        loop {
            let (mut sock, _) = match listener.accept() {
                Ok(conn) => conn,
                Err(_) => break,
            };
            session += 1;
            if stop_for_thread.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let gate = on_session(session);
            match gate {
                SessionGate::Answer(mut answer) => {
                    while let Some(query) = read_query(&mut sock) {
                        let Some(reply) = answer(query) else {
                            break;
                        };
                        if write_response(&mut sock, &reply).is_err() {
                            break;
                        }
                    }
                }
                SessionGate::Silent => {
                    sock.set_nonblocking(true)
                        .expect("silent session nonblocking");
                    let mut sink = [0u8; 64];
                    loop {
                        if stop_for_thread.load(std::sync::atomic::Ordering::SeqCst) {
                            break;
                        }
                        match sock.read(&mut sink) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        }
    });
    (addr, stop, handle)
}

fn spawn_supervised_positive_with_count() -> (
    SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    thread::JoinHandle<()>,
) {
    let queries = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let queries_in_responder = queries.clone();
    let (addr, stop, handle) = spawn_supervised_responder(move |_session| {
        let queries_for_query = queries_in_responder.clone();
        SessionGate::Answer(Box::new(move |query| {
            queries_for_query.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            positive_response(&query)
        }))
    });
    (addr, stop, queries, handle)
}

fn spawn_supervised_first_session_positive_with_count() -> (
    SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    thread::JoinHandle<()>,
) {
    let sessions = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sessions_for_thread = sessions.clone();
    let (addr, stop, handle) = spawn_supervised_responder(move |session| {
        sessions_for_thread.store(session, std::sync::atomic::Ordering::SeqCst);
        if session == 1 {
            SessionGate::Answer(Box::new(|query| positive_response(&query)))
        } else {
            SessionGate::Silent
        }
    });
    (addr, stop, sessions, handle)
}

fn stop_and_join_responder(
    addr: SocketAddr,
    stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: thread::JoinHandle<()>,
) {
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut last_err = None;
    while !handle.is_finished() {
        if std::time::Instant::now() >= deadline {
            panic!(
                "responder did not stop within the 2s teardown deadline; last unblock connect \
                 error: {last_err:?}"
            );
        }
        match std::net::TcpStream::connect(addr) {
            Ok(sock) => {
                sock.shutdown(std::net::Shutdown::Both).ok();
                break;
            }
            Err(err) => {
                last_err = Some(err);
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
    handle.join().expect("join responder thread");
}

#[test]
fn idle_runtime_wakes_indefinite_poll_onto_due_refresh_and_renews() {
    let t = thread::Builder::new()
        .name("runtime-idle-refresh-falsifier".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(idle_refresh_body)
        .expect("spawn idle-refresh falsifier thread");
    t.join().expect("idle-refresh falsifier thread");
}

fn idle_refresh_body() {
    let port = ephemeral_port();
    let storage = ServeStorage::boot(&config(port)).expect("boot storage");
    let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
    let mut owner = Preallocated::preallocate(storage, traffic).expect("preallocate");
    let (responder_addr, stop, queries, responder) = spawn_supervised_positive_with_count();
    let outcome = owner
        .run_startup_within(responder_addr, 1000, Duration::from_secs(3))
        .expect("startup window");
    assert_eq!(
        outcome.decision,
        StartupDecision::Serve(ServingMode::Full),
        "the startup window must resolve the allowlist name"
    );
    let mut runtime = owner
        .attach(outcome.listener.expect("serving listener"))
        .expect("attach");

    let queries_at_attach = queries.load(std::sync::atomic::Ordering::SeqCst);
    let secs = runtime.serving().storage().dns().now_u64();
    runtime
        .serving
        .storage_mut()
        .schedules_mut()
        .overwrite_due_at(0, Family::A, secs)
        .expect("due the A family now");
    assert!(
        !runtime.serving().storage().dns().has_active_exchange(),
        "the retained transport must be idle before the due probe"
    );

    let probe_start = Instant::now();
    let mut started = false;
    for _ in 0..200 {
        runtime
            .turn(None)
            .expect("owner turn on the production indefinite poll");
        if runtime.serving().storage().dns().has_active_exchange() {
            started = true;
            break;
        }
    }
    assert!(
        probe_start.elapsed() < Duration::from_secs(10),
        "the indefinite production poll must wake on its own fold to start a due refresh"
    );
    assert!(
        started,
        "an idle serving owner must auto-start a due refresh under the production \
         indefinite poll, woken by its own poll fold rather than a test-supplied timeout"
    );

    let pre_refresh_due = runtime
        .serving()
        .storage()
        .schedules()
        .due_time(0, Family::A)
        .expect("A due query")
        .expect("A scheduled");
    let mut renewed = false;
    for _ in 0..200 {
        if !runtime.serving().storage().dns().has_active_exchange()
            && let Ok(Some(due)) = runtime
                .serving()
                .storage()
                .schedules()
                .due_time(0, Family::A)
            && due > pre_refresh_due
        {
            renewed = true;
            break;
        }
        runtime
            .turn(None)
            .expect("owner turn to renewal on the indefinite poll");
    }
    let queries_after = queries.load(std::sync::atomic::Ordering::SeqCst);
    stop_and_join_responder(responder_addr, &stop, responder);
    assert!(
        renewed,
        "the auto-initiated refresh must publish a positive and reschedule the family \
         ahead of its pre-refresh due"
    );
    assert!(
        queries_after > queries_at_attach,
        "the auto-initiated refresh must issue a real query on the live responder"
    );
    assert!(
        name_published(&runtime, 0, Family::A),
        "a published renewal leaves the family usable"
    );
}

#[test]
fn due_refresh_renews_across_cycles_under_indefinite_poll() {
    let t = thread::Builder::new()
        .name("runtime-multicycle-falsifier".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(multicycle_body)
        .expect("spawn multicycle falsifier thread");
    t.join().expect("multicycle falsifier thread");
}

fn multicycle_body() {
    let port = ephemeral_port();
    let storage = ServeStorage::boot(&config(port)).expect("boot storage");
    let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
    let mut owner = Preallocated::preallocate(storage, traffic).expect("preallocate");
    let (responder_addr, stop, queries, responder) = spawn_supervised_positive_with_count();
    let outcome = owner
        .run_startup_within(responder_addr, 1000, Duration::from_secs(3))
        .expect("startup window");
    assert_eq!(
        outcome.decision,
        StartupDecision::Serve(ServingMode::Full),
        "startup must resolve the allowlist name"
    );
    let mut runtime = owner
        .attach(outcome.listener.expect("serving listener"))
        .expect("attach");

    let mut completed_cycles = 0usize;
    for _ in 0..2 {
        let queries_before = queries.load(std::sync::atomic::Ordering::SeqCst);
        let secs = runtime.serving().storage().dns().now_u64();
        runtime
            .serving
            .storage_mut()
            .schedules_mut()
            .overwrite_due_at(0, Family::A, secs)
            .expect("due the A family for a refresh cycle");
        loop {
            runtime
                .turn(None)
                .expect("owner turn on the production indefinite poll");
            if !runtime.serving().storage().dns().has_active_exchange()
                && runtime
                    .serving()
                    .storage()
                    .schedules()
                    .due_time(0, Family::A)
                    .expect("A due query")
                    .expect("A scheduled")
                    > secs
            {
                break;
            }
            assert!(
                queries.load(std::sync::atomic::Ordering::SeqCst) < queries_before + 64,
                "refresh cycle must not stall on the resolver"
            );
        }
        let queries_after = queries.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            queries_after > queries_before,
            "each refresh cycle must issue a real query on the live responder \
             (cycle {})",
            completed_cycles + 1
        );
        assert!(
            name_published(&runtime, 0, Family::A),
            "the family must stay usable across refresh cycles"
        );
        completed_cycles += 1;
    }
    stop_and_join_responder(responder_addr, &stop, responder);
    assert_eq!(
        completed_cycles, 2,
        "the production indefinite poll must drive two complete real-query refresh cycles"
    );
}

#[test]
fn idle_runtime_retries_failed_refresh_on_backoff() {
    let t = thread::Builder::new()
        .name("runtime-refresh-retry-falsifier".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(refresh_retry_body)
        .expect("spawn refresh-retry falsifier thread");
    t.join().expect("refresh-retry falsifier thread");
}

fn refresh_retry_body() {
    let port = ephemeral_port();
    let storage = ServeStorage::boot(&config(port)).expect("boot storage");
    let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
    let mut owner = Preallocated::preallocate(storage, traffic).expect("preallocate");
    let (responder_addr, stop, sessions, responder) =
        spawn_supervised_first_session_positive_with_count();
    let outcome = owner
        .run_startup_within(responder_addr, 1000, Duration::from_secs(3))
        .expect("startup window");
    assert_eq!(
        outcome.decision,
        StartupDecision::Serve(ServingMode::Full),
        "the first responder session must resolve the allowlist name"
    );
    let mut runtime = owner
        .attach(outcome.listener.expect("serving listener"))
        .expect("attach");

    let secs = runtime.serving().storage().dns().now_u64();
    runtime
        .serving
        .storage_mut()
        .schedules_mut()
        .overwrite_due_at(0, Family::A, secs)
        .expect("due the A family now");
    runtime
        .serving
        .storage_mut()
        .schedules_mut()
        .overwrite_due_at(0, Family::Aaaa, secs)
        .expect("due the Aaaa family now");

    let mut inflight = false;
    for _ in 0..200 {
        runtime
            .turn(None)
            .expect("owner turn to first refresh on the indefinite poll");
        if runtime.serving().storage().dns().has_active_exchange() {
            inflight = true;
            break;
        }
    }
    assert!(
        inflight,
        "the owner must auto-start the first due refresh under the production indefinite poll"
    );

    let mut receiving = false;
    for _ in 0..200 {
        runtime
            .turn(None)
            .expect("owner turn advancing the first refresh");
        if matches!(
            runtime.serving().storage().dns().exchange_step(),
            Some(crate::startup_dns::ExchangeStep::Receiving)
        ) {
            receiving = true;
            break;
        }
    }
    assert!(
        receiving,
        "the first refresh must reach the silent session and wait on the response"
    );
    let mut fresh_session = false;
    for _ in 0..200 {
        if sessions.load(std::sync::atomic::Ordering::SeqCst) >= 2 {
            fresh_session = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        fresh_session,
        "the first refresh must have reached a fresh session"
    );

    let probe_start = Instant::now();
    runtime.turn(None).expect("emission-free in-flight turn");
    let probe_elapsed = probe_start.elapsed();
    assert!(
        probe_elapsed >= Duration::from_secs(1),
        "the owner must wait out the real exchange deadline while an exchange is in flight \
         with a selectable-now sibling (no zero-wait busy-spin): {probe_elapsed:?}"
    );

    let mut retried_after_failure = false;
    for _ in 0..60 {
        runtime.turn(None).expect("owner turn on backoff");
        let seen = sessions.load(std::sync::atomic::Ordering::SeqCst);
        if seen >= 3 {
            retried_after_failure = true;
            break;
        }
    }
    stop_and_join_responder(responder_addr, &stop, responder);
    assert!(
        retried_after_failure,
        "after a silent refresh session fails, the owner must wake on the due/backoff and \
         re-initiate on its own (session count never reached 3)"
    );
    assert!(
        !runtime.serving().is_shutdown(),
        "the refresh owner stays serving while background retries continue"
    );
}

#[test]
fn sigterm_stops_due_refresh_flow() {
    let t = thread::Builder::new()
        .name("runtime-sigterm-suppression-falsifier".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(sigterm_suppression_body)
        .expect("spawn sigterm-suppression falsifier thread");
    t.join().expect("sigterm-suppression falsifier thread");
}

fn sigterm_suppression_body() {
    let port = ephemeral_port();
    let storage = ServeStorage::boot(&config(port)).expect("boot storage");
    let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
    let mut owner = Preallocated::preallocate(storage, traffic).expect("preallocate");
    let (responder_addr, stop, _queries, responder) = spawn_supervised_positive_with_count();
    let outcome = owner
        .run_startup_within(responder_addr, 1000, Duration::from_secs(3))
        .expect("startup window");
    assert_eq!(
        outcome.decision,
        StartupDecision::Serve(ServingMode::Full),
        "the startup window must resolve the allowlist name"
    );
    let mut runtime = owner
        .attach(outcome.listener.expect("serving listener"))
        .expect("attach");

    let secs = runtime.serving().storage().dns().now_u64();
    runtime
        .serving
        .storage_mut()
        .schedules_mut()
        .overwrite_due_at(0, Family::A, secs)
        .expect("due the A family now");

    let mut started = false;
    for _ in 0..200 {
        runtime
            .turn(None)
            .expect("owner turn to due start on the indefinite poll");
        if runtime.serving().storage().dns().has_active_exchange() {
            started = true;
            break;
        }
    }
    assert!(
        started,
        "a due refresh must start before the signal so the suppression probe is meaningful"
    );
    assert!(
        !runtime.serving().is_shutdown(),
        "the owner is still serving before the signal byte lands"
    );

    runtime
        .serving
        .signal_wake_mut()
        .expect("self-pipe test write end")
        .write_all(&[1])
        .expect("queue a SIGTERM byte through the real self-pipe");
    let secs = runtime.serving().storage().dns().now_u64();
    runtime
        .serving
        .storage_mut()
        .schedules_mut()
        .overwrite_due_at(0, Family::A, secs)
        .expect("re-arm the A family due after the signal");
    runtime
        .serving
        .storage_mut()
        .schedules_mut()
        .overwrite_due_at(0, Family::Aaaa, secs)
        .expect("re-arm the Aaaa family due after the signal");
    for _ in 0..20 {
        runtime
            .turn(Some(Duration::from_millis(5)))
            .expect("owner turn during shutdown");
        assert!(
            runtime.serving().is_shutdown(),
            "the first observed SIGTERM enters the draining phase"
        );
        assert!(
            !runtime.serving().storage().dns().has_active_exchange(),
            "no new DNS initiation may occur after the first SIGTERM even with due refresh work"
        );
    }
    stop_and_join_responder(responder_addr, &stop, responder);
}

#[cfg(feature = "alloc-witness")]
#[test]
fn due_refresh_owner_path_spends_zero_allocations() {
    std::thread::Builder::new()
        .name("refresh-alloc-witness".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(refresh_alloc_witness_body)
        .expect("spawn refresh alloc witness")
        .join()
        .expect("refresh alloc witness thread");
}

#[cfg(feature = "alloc-witness")]
fn refresh_alloc_witness_body() {
    let port = ephemeral_port();
    let storage = ServeStorage::boot(&config(port)).expect("boot storage");
    let traffic = crate::inventory::TrafficStorage::allocate().expect("boot traffic");
    let mut owner = Preallocated::preallocate(storage, traffic).expect("preallocate");
    let (responder_addr, stop, _queries, responder) = spawn_supervised_positive_with_count();
    let outcome = owner
        .run_startup_within(responder_addr, 1000, Duration::from_secs(3))
        .expect("startup window");
    assert_eq!(
        outcome.decision,
        StartupDecision::Serve(ServingMode::Full),
        "startup resolves before the witness"
    );
    let mut runtime = owner
        .attach(outcome.listener.expect("serving listener"))
        .expect("attach");
    let secs = runtime.serving().storage().dns().now_u64();
    runtime
        .serving
        .storage_mut()
        .schedules_mut()
        .overwrite_due_at(0, Family::A, secs)
        .expect("due today for the witness");

    let runtime = {
        let (runtime, counts) =
            crate::alloc::run_phase(crate::alloc::Phase::BackgroundRefresh, || {
                let mut runtime = runtime;
                let pre_due = runtime
                    .serving()
                    .storage()
                    .schedules()
                    .due_time(0, Family::A)
                    .expect("A due query")
                    .expect("A scheduled");
                let mut published = false;
                for _ in 0..200 {
                    runtime
                        .turn(Some(Duration::from_millis(5)))
                        .expect("witness owner turn");
                    if !runtime.serving().storage().dns().has_active_exchange() {
                        let Ok(Some(due)) = runtime
                            .serving()
                            .storage()
                            .schedules()
                            .due_time(0, Family::A)
                        else {
                            continue;
                        };
                        if due > pre_due {
                            published = true;
                            break;
                        }
                    }
                }
                assert!(
                    published,
                    "the due-initiated refresh must publish a positive renewal in the witness"
                );
                runtime
            });
        assert!(
            counts.all_zero(),
            "the actual refresh owner path must allocate/deallocate nothing: {counts:?}"
        );
        runtime
    };

    stop_and_join_responder(responder_addr, &stop, responder);
    std::mem::forget(runtime);
}
