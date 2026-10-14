use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use mio::net::TcpListener as MioListener;

use alumina::config::parse_config_document;
use alumina::inventory::TrafficStorage;
use alumina::runtime::Runtime;
use alumina::serve::ServeStorage;

const BODY_403: &str = "403 Forbidden";
const LOOPS: usize = 400;
const MAX_MONITOR_RECORDS: usize = 32;

fn main() {
    let (rd, wr) = unsafe { nix_pipe().expect("pipe") };
    unsafe {
        let flags = libc::fcntl(rd, libc::F_GETFL);
        assert!(flags >= 0, "read end flags");
        assert_eq!(libc::fcntl(rd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
    }
    let dup = unsafe { libc::dup2(wr, 1) };
    assert_eq!(dup, 1, "stdout redirected onto the witness pipe");
    let _keep_write_end = wr;
    let mut rd = rd;

    let bind = "127.0.0.1:0".parse().expect("valid bind address");
    let listener = MioListener::bind(bind).expect("bind serving listener");
    let port = listener.local_addr().expect("listener local addr").port();
    let doc = format!(
        "allowlist = [\"sub.example.org\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\"]\nscope = [\"connection\"]\n"
    );
    let config = parse_config_document(&doc).expect("valid config");
    let mut storage = ServeStorage::boot(&config).expect("boot storage");
    storage
        .prepare_stdout_log_sink()
        .expect("prepare nonblocking stdout sink");
    let traffic = TrafficStorage::allocate().expect("allocate traffic storage");
    let mut runtime =
        Runtime::new(storage, listener, traffic).expect("preallocate + attach runtime");

    let mut captured: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 4096];
    let started = Instant::now();
    for i in 0..LOOPS {
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connect client");
        client
            .write_all(b"CONNECT nope.example.net:443 HTTP/1.1\r\n\r\n")
            .expect("write connect head");
        let mut seen = false;
        let mut buf = [0u8; 128];
        for _ in 0..100 {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn drives accept+decision+refuse+close");
            client.set_nonblocking(true).expect("nonblocking client");
            match client.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if String::from_utf8_lossy(&buf[..n]).contains(BODY_403) {
                        seen = true;
                    }
                    break;
                }
                _ => {}
            }
        }
        assert!(
            seen,
            "iteration {i}: the mandatory 403 stop must be served while stdout is drained"
        );
        client.set_nonblocking(false).expect("blocking client");
        drop(client);
        for _ in 0..4 {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn settles close_slot reset");
        }
        drain_stdout(&mut rd, &mut scratch, &mut captured);
        if i % 50 == 49 {
            std::thread::sleep(Duration::from_millis(30));
        }
    }
    runtime
        .turn(Some(Duration::from_millis(2)))
        .expect("final turn");
    drain_stdout(&mut rd, &mut scratch, &mut captured);

    let text = String::from_utf8_lossy(&captured);
    let monitor_lines: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("level=info kind=monitor"))
        .collect();
    assert!(
        !monitor_lines.is_empty(),
        "the runtime must emit a coalesced monitor summary on real stdout"
    );
    assert!(
        monitor_lines.len() <= MAX_MONITOR_RECORDS,
        "summaries are coalesced to whole seconds, not per detection: {} lines",
        monitor_lines.len()
    );
    for line in &monitor_lines {
        let facts = field_u64(line, "facts_total");
        let actions = field_u64(line, "actions_total");
        let refusals = field_u64(line, "refusals_total");
        assert!(
            facts >= 1 && actions >= 1 && facts == actions,
            "a refuse storm folds one fact per applied first-slot action: {line} (facts={facts} actions={actions})"
        );
        assert_eq!(
            refusals, 0,
            "Host-Not-Allowlisted refuses are detections+actions, never blocked-domain refusals: {line}"
        );
        assert!(line.contains(" ofacts=0"), "no counter saturated: {line}");
    }
    let elapsed = started.elapsed().as_secs().max(1);
    assert!(
        monitor_lines.len() as u64 <= (elapsed + 2),
        "at most one summary per whole serving second (elapsed {elapsed}s got {}): {text}",
        monitor_lines.len()
    );
    eprintln!(
        "MONITOR-STDOUT-OK loops={LOOPS} records={} refusals=0 facts==actions elapsed={elapsed}s",
        monitor_lines.len()
    );
}

fn drain_stdout(rd: &mut libc::c_int, scratch: &mut [u8], captured: &mut Vec<u8>) {
    loop {
        let n = unsafe { libc::read(*rd, scratch.as_mut_ptr().cast(), scratch.len()) };
        if n > 0 {
            captured.extend_from_slice(&scratch[..n as usize]);
        } else {
            break;
        }
    }
}

fn field_u64(line: &str, key: &str) -> u64 {
    let needle = format!(" {key}=");
    let idx = line
        .find(&needle)
        .unwrap_or_else(|| panic!("missing {key}: {line}"));
    let rest = &line[idx + needle.len()..];
    let end = rest.find(' ').unwrap_or(rest.len());
    rest[..end].parse().expect("numeric field")
}

unsafe fn nix_pipe() -> Option<(libc::c_int, libc::c_int)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == 0 {
        Some((fds[0], fds[1]))
    } else {
        None
    }
}
