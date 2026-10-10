#![cfg(feature = "alloc-witness")]

use std::hint::black_box;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
use std::net::TcpStream as StdTcpStream;
use std::time::{Duration, Instant};

use alumina::alloc::{self, Phase};
use mio::net::{TcpListener, TcpStream as MioTcpStream};
use mio::{Events, Poll};
#[cfg(target_os = "linux")]
use mio::{Interest, Token};

#[cfg(target_os = "linux")]
const READY_TIMEOUT: Duration = Duration::from_millis(500);

fn accept_ready(listener: &TcpListener) -> MioTcpStream {
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match listener.accept() {
            Ok((server, _peer_addr)) => return server,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept after loopback handshake failed: {error}"),
        }
    }
}

fn bind_accept_pair() -> (TcpListener, StdTcpStream, MioTcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .expect("listener bind");
    let addr = listener.local_addr().expect("listener local addr");
    let peer = StdTcpStream::connect(addr).expect("peer connect");
    let server = accept_ready(&listener);
    (listener, peer, server)
}

#[test]
fn boot_allocations_are_attributed_and_excluded() {
    let (_, boot) = alloc::run_phase(Phase::StartupDns, || {
        let poll = Poll::new().expect("poll");
        let events = Events::with_capacity(8);
        drop(events);
        drop(poll);
    });
    assert!(
        boot.allocs > 0,
        "boot phase must see Poll::new/Events::with_capacity allocations: {:?}",
        boot
    );
    assert!(
        boot.deallocs > 0,
        "boot phase must see their release once dropped: {:?}",
        boot
    );

    let poll = Poll::new().expect("poll");
    let events = Events::with_capacity(8);
    let (_, steady) = alloc::run_phase(Phase::Serving, || {
        let value: u64 = 7;
        black_box(value);
    });
    assert!(
        steady.all_zero(),
        "boot-held Poll/Events must not be attributed to a later steady phase: {:?}",
        steady
    );
    std::mem::forget(poll);
    std::mem::forget(events);
}

#[test]
fn events_drop_negative_control_catches_heap_free() {
    let events = Events::with_capacity(8);
    let (_, phase) = alloc::run_phase(Phase::Shutdown, || {
        drop(events);
    });
    assert!(
        phase.deallocs > 0,
        "dropping the Events heap buffer inside a named phase must be caught: {:?}",
        phase
    );
}

#[test]
fn kernel_fd_close_is_not_heap_dealloc() {
    let (listener, peer, server) = bind_accept_pair();
    let (_, shutdown) = alloc::run_phase(Phase::Shutdown, || {
        drop(server);
        drop(peer);
        drop(listener);
    });
    assert!(
        shutdown.all_zero(),
        "socket drops close kernel fds (inline OwnedFd), no Rust heap is freed: {:?}",
        shutdown
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_epoll_operation_matrix() {
    let (_, positive) = alloc::run_phase(Phase::Serving, || {
        let block = Box::new([0u8; 128]);
        black_box(&block);
        drop(block);
    });
    assert!(
        positive.allocs > 0 && positive.deallocs > 0,
        "positive allocator control must precede measured ops: {:?}",
        positive
    );

    let mut poll = Poll::new().expect("poll");
    let mut events = Events::with_capacity(64);
    let (listener, mut peer, mut server) = bind_accept_pair();
    let (listener2, peer2, mut server2) = bind_accept_pair();

    let (_, serving) =
        alloc::run_phase(Phase::Serving, || {
            poll.registry()
                .register(&mut server, Token(2), Interest::WRITABLE)
                .expect("register server");
            poll.poll(&mut events, Some(READY_TIMEOUT))
                .expect("poll writable");
            assert!(
                events
                    .iter()
                    .any(|event| event.token() == Token(2) && event.is_writable()),
                "connected loopback server must report writable"
            );

            poll.registry()
                .reregister(&mut server, Token(2), Interest::READABLE)
                .expect("reregister server");
            peer.write_all(b"ping").expect("peer write");
            poll.poll(&mut events, Some(READY_TIMEOUT))
                .expect("poll readable");
            assert!(
                events
                    .iter()
                    .any(|event| event.token() == Token(2) && event.is_readable()),
                "server must report readable after peer writes"
            );
            let mut buf = [0u8; 32];
            let n = server.read(&mut buf).expect("server read");
            assert_eq!(&buf[..n], b"ping");

            let would_block = matches!(
                server.read(&mut buf),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            );
            assert!(
                would_block,
                "drain to WouldBlock must be the distinct no-data state"
            );

            poll.poll(&mut events, Some(Duration::from_millis(20)))
                .expect("poll quiet");
            assert!(
                events.iter().all(|event| event.token() != Token(2)),
                "no readiness while nothing is pending"
            );

            poll.registry()
                .deregister(&mut server)
                .expect("deregister server");
            peer.write_all(b"x").expect("peer write");
            poll.poll(&mut events, Some(READY_TIMEOUT))
                .expect("poll quiet after deregister");
            assert!(
                events.iter().all(|event| event.token() != Token(2)),
                "deregistered server must not report readiness"
            );

            poll.registry()
                .register(&mut server, Token(2), Interest::READABLE)
                .expect("re-register server");
            poll.poll(&mut events, Some(READY_TIMEOUT))
                .expect("poll readable after re-register");
            assert!(
                events
                    .iter()
                    .any(|event| event.token() == Token(2) && event.is_readable()),
                "re-registered server must report readiness again"
            );
            let n = server
                .read(&mut buf)
                .expect("server read after re-register");
            assert_eq!(&buf[..n], b"x");

            drop(peer);
            poll.poll(&mut events, Some(READY_TIMEOUT))
                .expect("poll eof");
            assert!(
                events.iter().any(|event| event.token() == Token(2)
                    && (event.is_read_closed() || event.is_readable())),
                "peer close must surface as read-closed readiness"
            );
            assert_eq!(
                server.read(&mut buf).expect("server read eof"),
                0,
                "peer EOF reads as Ok(0), distinct from WouldBlock"
            );

            poll.registry()
                .register(&mut server2, Token(3), Interest::READABLE)
                .expect("register server2");
            server2.write_all(b"boom").expect("server2 write");
            std::thread::sleep(Duration::from_millis(10));
            drop(peer2);
            poll.poll(&mut events, Some(READY_TIMEOUT))
                .expect("poll reset");
            assert!(
                events.iter().any(|event| event.token() == Token(3)
                    && (event.is_error() || event.is_read_closed())),
                "RST must surface as error/close readiness"
            );
            let reset = matches!(
                server2.read(&mut buf),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset
            );
            assert!(
                reset,
                "RST reads as ConnectionReset, distinct from WouldBlock and EOF"
            );
        });

    assert!(
        serving.all_zero(),
        "pinned mio serving ops must be allocation-free: {:?}",
        serving
    );

    let (_, shutdown) = alloc::run_phase(Phase::Shutdown, || {
        drop(listener);
        drop(listener2);
        drop(server);
        drop(server2);
    });
    assert!(
        shutdown.all_zero(),
        "shutdown fd drops must free no Rust heap: {:?}",
        shutdown
    );

    std::mem::forget(poll);
    std::mem::forget(events);
}

#[cfg(target_os = "linux")]
fn exercise_outbound_connect_matrix(
    poll: &mut Poll,
    events: &mut Events,
    payload: &[u8],
) -> (TcpListener, MioTcpStream, MioTcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).expect("bind listener");
    let server_addr = listener.local_addr().expect("listener addr");

    let mut client = MioTcpStream::connect(server_addr).expect("nonblocking connect");
    poll.registry()
        .register(&mut client, Token(10), Interest::WRITABLE)
        .expect("register connect");
    poll.poll(events, Some(READY_TIMEOUT))
        .expect("poll connect");
    assert!(
        events
            .iter()
            .any(|event| event.token() == Token(10) && event.is_writable()),
        "outbound connect completion must surface as writable"
    );
    let connect_error = client.take_error().expect("take_error");
    assert!(
        connect_error.is_none(),
        "completed outbound connect carries no pending error"
    );
    let client_addr = client.local_addr().expect("client local addr");
    assert_eq!(client.peer_addr().expect("client peer_addr"), server_addr);

    let mut server = accept_ready(&listener);
    assert_eq!(
        server.peer_addr().expect("server peer_addr"),
        client_addr,
        "accepted stream's peer is the connecting client"
    );

    let tiny = [0x5au8; 5];
    let n = client.write(&tiny).expect("tiny write");
    assert_eq!(n, tiny.len(), "empty socket accepts the full tiny write");
    let mut read_buf = [0u8; 128];
    let n = server.read(&mut read_buf).expect("server read");
    assert!(
        n > 0 && n < read_buf.len(),
        "read partial: a short payload returns fewer bytes than the buffer"
    );
    let drained = matches!(
        server.read(&mut read_buf),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    );
    assert!(drained, "drained socket read must be WouldBlock");

    let n0 = client.write(payload).expect("bulk write");
    assert!(n0 > 0, "bulk write must accept at least one byte");
    let mut saw_partial = n0 < payload.len();
    let mut saw_would_block = false;
    let deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < deadline && !saw_would_block {
        match client.write(payload) {
            Ok(0) => break,
            Ok(n) if n < payload.len() => saw_partial = true,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => saw_would_block = true,
            Err(error) => panic!("bulk write failed: {error}"),
        }
    }
    assert!(
        saw_partial,
        "send-buffer boundary must produce a partial write before WouldBlock"
    );
    assert!(
        saw_would_block,
        "saturated send buffer must surface WouldBlock"
    );

    let mut n_read = 0usize;
    let drain_deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < drain_deadline {
        match server.read(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => {
                if n_read < 4 && n > 0 {
                    let k = n.min(4 - n_read);
                    assert_eq!(
                        &read_buf[..k],
                        &payload[n_read..n_read + k],
                        "server receives the written payload bytes intact"
                    );
                }
                n_read += n;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("server drain failed: {error}"),
        }
    }
    assert!(
        n_read >= n0,
        "server must drain at least the first accepted bulk write"
    );

    let refuse = TcpListener::bind("127.0.0.1:0".parse().unwrap()).expect("bind refuse");
    let refuse_addr = refuse.local_addr().expect("refuse addr");
    drop(refuse);
    match MioTcpStream::connect(refuse_addr) {
        Ok(mut refused) => {
            poll.registry()
                .register(&mut refused, Token(11), Interest::WRITABLE)
                .expect("register refused");
            poll.poll(events, Some(READY_TIMEOUT))
                .expect("poll refused");
            let refused_error = refused
                .take_error()
                .expect("refused take_error")
                .expect("refused connect exposes the pending error");
            assert_eq!(
                refused_error.kind(),
                std::io::ErrorKind::ConnectionRefused,
                "refused outbound connect is ConnectionRefused"
            );
        }
        Err(error) => assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "immediate refused connect is ConnectionRefused"
        ),
    }

    (listener, client, server)
}

#[cfg(target_os = "linux")]
fn exercise_registry_error_kinds(poll: &mut Poll) -> (TcpListener, MioTcpStream, MioTcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).expect("bind listener");
    let server_addr = listener.local_addr().expect("listener addr");
    let mut client = MioTcpStream::connect(server_addr).expect("nonblocking connect");
    let mut server = accept_ready(&listener);

    poll.registry()
        .register(&mut client, Token(20), Interest::READABLE)
        .expect("register client");
    let double = poll
        .registry()
        .register(&mut client, Token(20), Interest::WRITABLE)
        .expect_err("double register must fail");
    assert_eq!(
        double.kind(),
        std::io::ErrorKind::AlreadyExists,
        "registering an already registered source returns EEXIST"
    );

    let missing = poll
        .registry()
        .deregister(&mut server)
        .expect_err("deregister of unregistered source must fail");
    assert_eq!(
        missing.kind(),
        std::io::ErrorKind::NotFound,
        "deregistering an unregistered source returns ENOENT"
    );

    (listener, client, server)
}

#[cfg(target_os = "linux")]
fn assert_registry_error_profile(phase: alloc::Counts, label: &str) {
    println!("MIO-REGISTRY-OBS {label}: {phase:?}");
    #[cfg(debug_assertions)]
    assert!(
        phase.allocs > 0 && phase.deallocs > 0,
        "{label} registry error path must construct errors (debug-harness mio interception): {phase:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_registry_error_kinds_startupdns() {
    let mut poll = Poll::new().expect("poll");
    let (_, startup) = alloc::run_phase(Phase::StartupDns, || {
        exercise_registry_error_kinds(&mut poll)
    });
    assert_registry_error_profile(startup, "startupdns");
    std::mem::forget(poll);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_registry_error_kinds_backgroundrefresh() {
    let mut poll = Poll::new().expect("poll");
    let (_, refresh) = alloc::run_phase(Phase::BackgroundRefresh, || {
        exercise_registry_error_kinds(&mut poll)
    });
    assert_registry_error_profile(refresh, "backgroundrefresh");
    std::mem::forget(poll);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_outbound_connect_matrix_startupdns() {
    let mut poll = Poll::new().expect("poll");
    let mut events = Events::with_capacity(64);
    let payload = vec![0xabu8; 1 << 24];
    let (_, startup) = alloc::run_phase(Phase::StartupDns, || {
        exercise_outbound_connect_matrix(&mut poll, &mut events, &payload)
    });
    assert!(
        startup.all_zero(),
        "StartupDns outbound mio ops must be allocation-free: {:?}",
        startup
    );
    std::mem::forget(poll);
    std::mem::forget(events);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_outbound_connect_matrix_backgroundrefresh() {
    let mut poll = Poll::new().expect("poll");
    let mut events = Events::with_capacity(64);
    let payload = vec![0xabu8; 1 << 24];
    let (_, refresh) = alloc::run_phase(Phase::BackgroundRefresh, || {
        exercise_outbound_connect_matrix(&mut poll, &mut events, &payload)
    });
    assert!(
        refresh.all_zero(),
        "BackgroundRefresh outbound mio ops must be allocation-free: {:?}",
        refresh
    );
    std::mem::forget(poll);
    std::mem::forget(events);
}
