use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use mio::net::TcpListener as MioListener;

use alumina::config::parse_config_document;
use alumina::inventory::TrafficStorage;
use alumina::runtime::Runtime;
use alumina::serve::ServeStorage;

const BODY_403: &str = "403 Forbidden";

fn main() {
    let (rd, wr) = unsafe { nix_pipe().expect("pipe") };
    let dup = unsafe { libc::dup2(wr, 1) };
    assert_eq!(
        dup, 1,
        "stdout redirected onto the never-drained stall pipe"
    );
    #[cfg(target_os = "linux")]
    unsafe {
        libc::fcntl(wr, libc::F_SETPIPE_SZ, 4096);
    }
    let _keep_read_end = rd;
    let _keep_write_end = wr;

    let bind = "127.0.0.1:0".parse().expect("valid bind address");
    let listener = MioListener::bind(bind).expect("bind serving listener");
    let port = listener.local_addr().expect("listener local addr").port();
    let doc = format!(
        "allowlist = [\"sub.example.org\"]\nlisten = \"127.0.0.1:{port}\"\nstartup_unresolved_allowance = 0\n"
    );
    let config = parse_config_document(&doc).expect("valid config");
    let mut storage = ServeStorage::boot(&config).expect("boot storage");
    storage
        .prepare_stdout_log_sink()
        .expect("prepare nonblocking stdout sink");
    let traffic = TrafficStorage::allocate().expect("allocate traffic storage");
    let mut runtime =
        Runtime::new(storage, listener, traffic).expect("preallocate + attach runtime");

    let loops = 2000usize;
    for i in 0..loops {
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
            "iteration {i}: the server must still refuse with 403 while stdout is unconsumed"
        );
        client.set_nonblocking(false).expect("blocking client");
        drop(client);
        for _ in 0..4 {
            runtime
                .turn(Some(Duration::from_millis(2)))
                .expect("owner turn settles close_slot reset");
        }
    }

    let total_emitted = loops as u64;
    let dropped = runtime.serving().storage().log_dropped();
    assert!(
        dropped > 0,
        "the stall must actually fill the pipe and drop whole records: {dropped}"
    );
    assert!(
        dropped <= total_emitted,
        "drops are whole-record and never exceed the records emitted this run: {dropped}"
    );
    eprintln!(
        "STDOUT-STALL-OK loops={loops} refused-served-while-stalled=yes drops={dropped} (<= {total_emitted})"
    );
}

unsafe fn nix_pipe() -> Option<(libc::c_int, libc::c_int)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == 0 {
        Some((fds[0], fds[1]))
    } else {
        None
    }
}
