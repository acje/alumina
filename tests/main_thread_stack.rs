use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use mio::net::TcpListener as MioListener;

use alumina::config::parse_config_document;
use alumina::inventory::TrafficStorage;
use alumina::runtime::Runtime;
use alumina::serve::ServeStorage;

const LOOPS: usize = 64;
const BODY_403: &str = "403 Forbidden";

fn rlimit_stack_readable() -> Option<String> {
    let contents = std::fs::read_to_string("/proc/self/limits").ok()?;
    contents
        .lines()
        .find(|l| l.contains("Max stack size"))
        .map(|l| l.trim().to_string())
}

fn main() {
    let rlimit = rlimit_stack_readable();
    match &rlimit {
        Some(line) => println!("RLIMIT_STACK {line}"),
        None => println!("RLIMIT_STACK (not readable on this platform)"),
    }

    let bind = "127.0.0.1:0".parse().expect("valid bind address");
    let listener = MioListener::bind(bind).expect("bind serving listener");
    let port = listener.local_addr().expect("listener local addr").port();
    let doc = format!(
        "allowlist = [\"sub.example.org\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\n"
    );
    let config = parse_config_document(&doc).expect("valid config");
    let storage = ServeStorage::boot(&config).expect("boot storage");
    let traffic = TrafficStorage::allocate().expect("allocate traffic storage");
    let mut runtime =
        Runtime::new(storage, listener, traffic).expect("preallocate + attach runtime");

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
                    let text = String::from_utf8_lossy(&buf[..n]);
                    if text.contains(BODY_403) {
                        seen = true;
                    }
                    break;
                }
                _ => {}
            }
        }
        assert!(
            seen,
            "iteration {i}: the server must refuse a non-allowlisted CONNECT with the 403 body"
        );
        client.set_nonblocking(false).expect("blocking client");
        drop(client);
        for _ in 0..20 {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn settles close_slot reset");
        }
    }

    println!("MAIN-THREAD-STACK-OK loops={LOOPS} accept+reset cycles on true main thread");
}
