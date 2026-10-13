#!/usr/bin/env python3
"""Native foreground SIGTERM shutdown gate against the actual alumina binary.

Runs inside one podman container (harness image = pinned rust base +
python3/setpriv/ip, --network none, NNP, no-new-privileges) after the release
static binary from the exact candidate is mounted at /app. The driver stages
/work/config.toml + /work/resolv.conf, owns a DNS-over-TCP responder on
127.0.0.1:53, launches the ACTUAL binary per case (dropped to uid 65534 via
setpriv, `cd /work && exec alumina`), sends real SIGTERM, and observes each
supervised child exit code and timing. Every case binary is spawned and reaped
FOREGROUND with a bounded deadline; a timeout is FAIL, never a pass.

Topology (all upstream addresses global-unicast IPv4 bound on lo inside the
--network none namespace, so the crate's martian/SSRF guard admits them):
    drain.example.org -> 8.8.8.8         raw echo upstream
    force.example.org -> 208.67.222.220  silent upstream (accepts, records,
                                         never replies -> a stalled established
                                         relay that cannot drain by itself)

Cases (each exercises the ACTUAL shipped shutdown path):
    IDLE-SIGTERM-EXIT0        idle owner: SIGTERM -> clean drain exit 0, fast
    NEG-NO-SELF-EXIT          no signal for 2s -> process must NOT self-exit;
                              then SIGTERM -> exit 0
    PRE-SERVING-SILENT-NOBIND SIGTERM during the startup window against a fully
                              silent resolver: observed at the first serving
                              poll, listener never bound across the interval ->
                              exit 0
    RETRY-BACKOFF-STORM       SIGTERM storm after a phase-OBSERVED counted
                              startup failure (startup_warning record): no bind
                              pre- or post-signal -> exit 0
    EARLY-DRAIN               established relay verified by upstream hello
                              receipt; client half-closes after SIGTERM -> the
                              complete hello+payload stream echoes byte-exact
                              through EOF -> exit 0 before the grace
    FORCED-REPEAT-NOADMIT     stalled established relay; SIGTERM, connect is
                              refused (no admissions), second SIGTERM does NOT
                              extend the deadline -> forced exit 70 on time
    STORM-DURING-DRAIN        stalled relay + SIGTERM storm: the fixed 8 s
                              deadline is never extended (disjoint first vs
                              reset-deadline windows) -> forced exit 70 on time
    STALLED-STDOUT            stalled relay + stdout GENUINELY FULL in a 4 KiB
                              pipe (supervised nonblocking fill reaches EAGAIN):
                              the sink must not delay shutdown -> exit 70 on time
    SILENT-DNS-REFRESH-DRAIN
                              stalled relay; the real current AAAA due-refresh
                              is served and its response TRANSMITTED
                              (responder-side transmission witness, not owner
                              consumption); a next-due serving DNS exchange
                              (sibling AAAA-family by fixed inputs) is genuinely
                              accepted, its query read, and left UNANSWERED
                              (responder silent from session 3, a dead-resolver
                              serving negative), and only then is SIGTERM
                              delivered: the forced drain closes in the
                              first-deadline window with that accepted/read/
                              unanswered observation before signal.
                              Handled-signal DNS suppression is claimed by the
                              native owner witness (src/runtime.rs
                              sigterm_stops_due_refresh_flow), not from this
                              fixture's accept roster.
    SIMULTANEOUS-COMPLETION-NOBIND
                              SIGTERM while the final allowlist answer is held:
                              completion that races a signal must never win a
                              listener bind -> exit 0, listener never bound

Exit 0 iff every case passes and every fixture thread/process is supervised to
exit; each case emits `SHUTDOWN-<NAME>: PASS|FAIL <detail>`. A timeout is a
FAIL with the runner-killed child reaped; the driver never leaves a live
binary or fixture behind. `CASE_FILTER` selects a non-empty subset and the
summary distinguishes scoped green from full-suite green; a filter matching
zero cases is rejected (nonzero, never an unqualified ALL-PASS).
"""

import fcntl
import os
import signal
import socket
import subprocess
import sys
import threading
import time

PROXY = ("127.0.0.1", 8080)
CONNECT_PORT = 443

# E2E_TARGET is exported by the shell wrapper (observed native triple).
E2E_TARGET = os.environ["E2E_TARGET"]
BINPATH = f"/app/target/{E2E_TARGET}/release/alumina"

# Headroom left un-prefilled in the 4 KiB stalled-stdout pipe for the binary's
# PRE-switch stdout diagnostics (the fixed println! lines before the nonblocking
# log-sink switch). Set from the measured pre-switch byte count; a blocking
# write past the headroom would hang startup, so the case fails (honest) rather
# than block forever. The stalled-stdout case validates this effective setting
# against the real pipe capacity (a value >= capacity would refuse the case as
# ambiguous rather than prefill zero and report a false stall).
PRESWITCH_BYTES = int(os.environ.get("SHUTDOWN_PRESWITCH_BYTES", "600"))

# The fixed first-handled SIGTERM shutdown grace is 8 s. Acceptance windows are
# DISJOINT so a repeat/reset-region signal cannot be mistaken for the first
# deadline: first-deadline window [GRACE_LO, GRACE_HI]; a storm that resets the
# grace from a repeat near t0+1.35 s would exit ~9.35 s and FAIL, and a repeat
# near t0+5 s (forced case) would exit ~13 s and FAIL. Windows are wider than
# the observed native jitter (~8.04-8.07 s) but exclude every reset extension.
GRACE_LO = 7.0
GRACE_HI = 8.8


def in_first_deadline_window(elapsed):
    return GRACE_LO <= elapsed <= GRACE_HI


FAILURES = []


def fail(name, detail):
    print(f"SHUTDOWN-{name}: FAIL {detail}", flush=True)
    FAILURES.append(name)


def pass_(name, detail):
    print(f"SHUTDOWN-{name}: PASS {detail}", flush=True)


def bounded_wait(proc, deadline, name):
    """Wait for `proc` within `deadline`; on timeout kill and return None.
    A timed-out child is reaped (killed) so no case leaks a live binary."""
    try:
        rc = proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        return rc
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        fail(name, f"case binary did not exit before its deadline; killed")
        return None


def connect_probe():
    """One sampled connect to the proxy port, classified so an observation
    boundary error can never count as listener absence:
      ("reachable", None)  connection accepted (listener reachable/bound)
      ("refused", None)    authoritative connection refusal (no listener)
      ("error", exc)       operational failure (timeout/EMFILE/EACCES/
                           ENETUNREACH/reset/...) - indeterminate, never absence.
    Only an authoritative refusal supports a sampled no-listener claim. A
    connect reset (ECONNRESET) is a peer reset on an established/connecting
    path - an operational error, never absence - because a reset can be the
    proxy actively refusing a tunnel rather than proving no listener exists."""
    try:
        s = socket.create_connection(PROXY, timeout=0.4)
        s.close()
        return ("reachable", None)
    except OSError as exc:
        if exc.errno == socket.errno.ECONNREFUSED:
            return ("refused", None)
        return ("error", exc)


def sample_no_bind(name, proc):
    """One interval-wide no-bind sample. A reachable connect or an operational
    probe error both FAIL with distinct details (reaping the binary); only an
    authoritative refusal is the expected no-listener state. Returns True when
    the sample observed refusal."""
    kind, exc = connect_probe()
    if kind == "reachable":
        proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        fail(name, "listener bound at a sampled probe point (interval-wide no-bind violated)")
        return False
    if kind == "error":
        proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        fail(name, f"operational connect error during no-bind sampling (indeterminate, not absence): {exc}")
        return False
    return True


def wait_reachable(deadline):
    """Wait until the listener is reachable. Returns ("reachable", None) on a
    successful connect, ("timeout", None) when the deadline lapses, or
    ("error", exc) on an operational probe error (never treated as absence)."""
    while time.monotonic() < deadline:
        kind, exc = connect_probe()
        if kind == "reachable":
            return ("reachable", None)
        if kind == "error":
            return ("error", exc)
        time.sleep(0.05)
    return ("timeout", None)


def require_reachable(name, proc, timeout=20.0):
    """Require the startup listener to become reachable. Reaps the binary and
    FAILs with the exact reason on timeout or an operational probe error;
    operational errors are never read as listener absence."""
    kind, exc = wait_reachable(time.monotonic() + timeout)
    if kind == "reachable":
        return True
    proc.kill()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    if kind == "error":
        fail(name, f"operational connect error while waiting for the listener (indeterminate, not absence): {exc}")
    else:
        fail(name, "listener never reached")
    return False


def probe_refused_sampled(deadline, name, proc):
    """Post-signal no-listener witness: sample until the proxy port is
    authoritatively REFUSED. A connect that succeeds (admission stayed open) or
    an operational probe error both FAIL, so a broken observation boundary can
    never green the no-bind claim. Returns True once refused."""
    while time.monotonic() < deadline:
        kind, exc = connect_probe()
        if kind == "refused":
            return True
        if not sample_no_bind(name, proc):
            return False
        time.sleep(0.05)
    fail(name, "listener never observed authoritatively refused across the sampled post-signal interval (admission stayed open or observation gap)")
    return False


def wait_log_marker(name, marker, timeout=8.0):
    """Poll the case's captured stdout file until the binary has actually
    emitted `marker` (a real phase receipt from the child's log output), so a
    schedule phase is observed rather than assumed by a fixed sleep."""
    path = f"/tmp/shutdown-{name}.log"
    logfd = None
    try:
        logfd = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    try:
        end = time.monotonic() + timeout
        buf = b""
        while time.monotonic() < end:
            try:
                chunk = os.read(logfd, 65536)
            except OSError:
                time.sleep(0.02)
                continue
            if chunk:
                buf += chunk
                if marker in buf:
                    return True
            else:
                time.sleep(0.02)
        return marker in buf
    finally:
        os.close(logfd)


# ---------------------------------------------------------------------------
# DNS-over-TCP responder (mirrors e2e_relay.py; adds per-case modes).
# ---------------------------------------------------------------------------
class DnsResponder:
    """Authority for the allowlist names. Modes:
    `delay_first`: sleep before answering the first accepted session's queries
        (keeps the startup window blocked so PRE-SERVING can signal mid-window).
    `silent_after_session`: serve session N and before; accept and never answer
        from session N+1 on (a dead, silent resolver for any later refresh).
    `silent_always`: accept every query and never answer (a fully silent
        resolver used to hold the startup window open in Receiving)."""

    def __init__(self, addr, answers, delay_first=0.0, silent_after_session=None,
                 silent_always=False, hold_final=False):
        self.addr = addr
        self.answers = answers
        self.delay_first = delay_first
        self.silent_after_session = silent_after_session
        self.silent_always = silent_always
        self.hold_final = hold_final
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(addr)
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self._stop = False
        self._lock = threading.Lock()
        self.sessions = 0
        self.queries = 0
        self.session_times = []  # (session, time.monotonic() accept instant)
        self.thread = threading.Thread(target=self._run, name="dns", daemon=True)
        self._handlers = []
        # Set once every configured allowlist name has received a positive
        # (usable) A answer, so a case can fire a SIGTERM at the same-batch
        # moment the startup window is about to settle all names resolved.
        self.completed = threading.Event()
        # Under `hold_final`, the last name's response is withheld until the
        # case releases it, so a SIGTERM can be delivered while the window is
        # provably still resolving and the settlement recheck must observe it.
        self.final_query_received = threading.Event()
        self.release_final = threading.Event()
        self._final_held = False
        self._answered = set()
        # AAAA-refresh TRANSMISSION witness: set only AFTER the responder's
        # sendall of an AAAA NODATA answer on a serving session (>= 2) returns,
        # so a cancelled/failed send can never publish it. It proves the
        # responder transmitted the answer, never that the owner consumed or
        # published the result (owner-side publication is native-witness
        # territory, src/runtime.rs sigterm_stops_due_refresh_flow).
        self.aaaa_refresh_sent = threading.Event()
        # Dead-resolver serving negative: set when a silent-zone serving
        # connection has been accepted AND its DNS query read while the
        # responder intentionally leaves it unanswered (a genuine next-due
        # exchange going unanswered, not a decorative branch in a passing path).
        self.silent_accept = threading.Event()

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def join(self, deadline):
        end = time.monotonic() + deadline
        self.thread.join(max(0.0, end - time.monotonic()))
        pending = list(self._handlers)
        for t in pending:
            t.join(max(0.0, end - time.monotonic()))
        self._handlers = [t for t in self._handlers if t.is_alive()]
        return not any(t.is_alive() for t in pending) and not self.thread.is_alive()

    def _run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self.sessions += 1
                session = self.sessions
                self.session_times.append((session, time.monotonic()))
            silent = self.silent_always or (
                self.silent_after_session is not None and session > self.silent_after_session
            )
            print(
                f"DNS-TRACE: accepted connection session={session} t={time.monotonic():.3f} "
                f"silent_after_session={self.silent_after_session} silent_always={self.silent_always}",
                flush=True,
            )
            t = threading.Thread(target=self._serve, args=(conn, session, silent), daemon=True)
            with self._lock:
                self._handlers.append(t)
            t.start()

    @staticmethod
    def _read_name(msg, pos):
        labels = []
        while True:
            ln = msg[pos]
            if ln == 0:
                pos += 1
                break
            if ln & 0xC0:
                return None, pos
            labels.append(msg[pos + 1:pos + 1 + ln])
            pos += 1 + ln
        return b".".join(labels), pos

    def _serve(self, conn, session, silent):
        try:
            conn.settimeout(5.0)
            while not self._stop:
                hdr = conn.recv(2)
                if len(hdr) != 2:
                    return
                qlen = int.from_bytes(hdr, "big")
                if qlen == 0 or qlen > 65535:
                    return
                msg = b""
                while len(msg) < qlen:
                    chunk = conn.recv(qlen - len(msg))
                    if not chunk:
                        return
                    msg += chunk
                if len(msg) < 12:
                    return
                tid = msg[0:2]
                qdcount = int.from_bytes(msg[4:6], "big")
                if qdcount != 1:
                    return
                qname, qpos = self._read_name(msg, 12)
                if qname is None:
                    return
                qtype = int.from_bytes(msg[qpos:qpos + 2], "big")
                with self._lock:
                    self.queries += 1
                    if session == 1 and self.delay_first > 0:
                        delay = self.delay_first
                        self.delay_first = 0.0
                    else:
                        delay = 0.0
                if delay:
                    time.sleep(delay)
                if silent:
                    print(f"DNS-TRACE: query {qname!r} qtype={qtype} t={time.monotonic():.3f} -> SILENT (no answer)", flush=True)
                    # never answer; keep the connection open (a stalled resolver).
                    # The query was read on a silent-zone session: published as
                    # accepted/queried-and-unanswered DNS. Observation scope only:
                    # any query on a silent session sets the event (no per-query
                    # qtype/qname assertion); the due-family expectation comes
                    # from the fixture's fixed inputs, not from this event.
                    self.silent_accept.set()
                    time.sleep(1.0)
                    continue
                question = msg[12:qpos + 4]
                ip = self.answers.get(qname.lower())
                final_answer = False
                transmitted_refresh = False
                if ip is None:
                    # unknown NAME -> NXDOMAIN for any type (whole-name
                    # nonexistence, the runtime's name-wide eviction), never a
                    # fake positive
                    rr = b""
                    ancount = 0
                    nscount = 0
                    ns_rr = b""
                    rcode = 3
                elif qtype == 1:
                    rr = qname_literal(qname) + b"\x00\x01\x00\x01"
                    rr += (120).to_bytes(4, "big")
                    rr += (4).to_bytes(2, "big")
                    rr += ip
                    ancount = 1
                    rcode = 0
                    nscount = 0
                    ns_rr = b""
                    with self._lock:
                        self._answered.add(qname.lower())
                        if all(k in self._answered for k in self.answers):
                            self.completed.set()
                            if self.hold_final and not self._final_held:
                                self._final_held = True
                                final_answer = True
                else:
                    # existing name, non-A type (the serving AAAA due-refresh:
                    # startup never attempts AAAA, its slot stays due and the
                    # owner's due-refresh re-queries it right after the
                    # listener binds). Type-specific absence: NOERROR with zero
                    # answers plus a covering SOA (RFC 2308), so only the
                    # queried family is treated absent and A survives -- never a
                    # whole-name NXDOMAIN. On a serving session (>= 2) the
                    # transmitted AAAA answer is the real current-refresh
                    # witness; the event is published below only after sendall
                    # returns (B1).
                    rr = b""
                    ancount = 0
                    rcode = 0
                    nscount = 1
                    ns_rr = soa_record(qname, 300, 60)
                    transmitted_refresh = session >= 2 and qtype == 28
                if final_answer:
                    # Withhold the final answer until the case has delivered a
                    # SIGTERM, so the startup window is provably still resolving
                    # when the signal lands and the settlement recheck must turn
                    # a would-be Full decision into Terminated (no bind).
                    print("DNS-TRACE: holding final answer until released", flush=True)
                    self.final_query_received.set()
                    self.release_final.wait(timeout=10.0)
                flags = (0x8000 | 0x0100 | (rcode & 0x0F))
                hdrw = tid + flags.to_bytes(2, "big")
                hdrw += (1).to_bytes(2, "big")
                hdrw += (ancount).to_bytes(2, "big")
                hdrw += (nscount).to_bytes(2, "big")
                hdrw += (0).to_bytes(2, "big")
                resp = hdrw + question + rr + ns_rr
                print(f"DNS-TRACE: query {qname!r} qtype={qtype} t={time.monotonic():.3f} -> TX {resp.hex()}", flush=True)
                conn.sendall(len(resp).to_bytes(2, "big") + resp)
                if transmitted_refresh:
                    self.aaaa_refresh_sent.set()
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

def soa_record(owner, ttl, minimum):
    """A synthetic single-name authoritative-zone SOA covering `owner`. The
    zone apex of the queried name is the queried name itself, so the owner
    always covers it -- exactly what the runtime's NODATA classification
    requires (src/dns.rs classify_soa/soa_covers)."""
    mname = qname_literal(b"ns1.example.org")
    rname = qname_literal(b"hostmaster.example.org")
    rdata_len = len(mname) + len(rname) + 20
    m = qname_literal(owner)
    m += b"\x00\x06\x00\x01"  # type SOA, class IN
    m += ttl.to_bytes(4, "big")
    m += rdata_len.to_bytes(2, "big")
    m += mname
    m += rname
    for v in (1, 3600, 600, 86400, minimum):  # serial refresh retry expire minimum
        m += v.to_bytes(4, "big")
    return m


def qname_literal(qname):
    out = bytearray()
    for label in qname.split(b"."):
        if not label:
            continue
        out += bytes([len(label)])
        out += label
    out += bytes([0])
    return bytes(out)


# ---------------------------------------------------------------------------
# Upstream fixtures (echo + silent), supervised like e2e_relay.py.
# ---------------------------------------------------------------------------
class _BoundServer:
    def __init__(self, addr):
        self.addr = addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(addr)
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self._stop = False
        self._lock = threading.Lock()
        self._bytes = 0
        self.conns = 0
        self.thread = threading.Thread(target=self._run, name=self.NAME, daemon=True)
        self._handlers = []

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def join(self, deadline):
        end = time.monotonic() + deadline
        self.thread.join(max(0.0, end - time.monotonic()))
        pending = list(self._handlers)
        for t in pending:
            t.join(max(0.0, end - time.monotonic()))
        self._handlers = [t for t in self._handlers if t.is_alive()]
        return not any(t.is_alive() for t in pending) and not self.thread.is_alive()

    def bytes_received(self):
        with self._lock:
            return self._bytes

    def add_bytes(self, n):
        with self._lock:
            self._bytes += n

    def _run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self.conns += 1
            t = threading.Thread(target=self._serve_one, args=(conn,), daemon=True)
            with self._lock:
                self._handlers.append(t)
            t.start()

    def _serve_one(self, conn):
        raise NotImplementedError


class EchoUpstream(_BoundServer):
    NAME = "echo"

    def _serve_one(self, conn):
        try:
            conn.settimeout(10.0)
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                self.add_bytes(len(chunk))
                conn.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class SilentUpstream(_BoundServer):
    """Accepts and records bytes, never replies: a stalled established relay
    that cannot drain by itself (soced exit 70 at the shutdown deadline)."""

    NAME = "silent"

    def _serve_one(self, conn):
        try:
            conn.settimeout(10.0)
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                self.add_bytes(len(chunk))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Wire helpers (mirror src/client_hello.rs test builder, as in e2e_relay.py).
# ---------------------------------------------------------------------------
CONTENT_HANDSHAKE = 22
HANDSHAKE_CLIENT_HELLO = 1
RANDOM_LEN = 32
SUPPORTED_VERSIONS = 43
SERVER_NAME = 0
TLS13 = 0x0304
TLS12 = 0x0303


def tls_records(payload):
    rec = bytearray([CONTENT_HANDSHAKE, 0x03, 0x01])
    rec += (len(payload)).to_bytes(2, "big")
    rec += payload
    return bytes(rec)


def client_hello(sni):
    versions_data = bytearray([2]) + TLS13.to_bytes(2, "big")
    names_data = bytearray()
    names_data += bytes([0])
    names_data += len(sni).to_bytes(2, "big")
    names_data += sni.encode()
    snis_data = len(names_data).to_bytes(2, "big") + names_data
    exts = bytearray()
    exts += SUPPORTED_VERSIONS.to_bytes(2, "big")
    exts += len(versions_data).to_bytes(2, "big")
    exts += versions_data
    exts += SERVER_NAME.to_bytes(2, "big")
    exts += len(snis_data).to_bytes(2, "big")
    exts += snis_data
    body = bytearray()
    body += TLS12.to_bytes(2, "big")
    body += bytes(RANDOM_LEN)
    body += bytes([0])
    body += (4).to_bytes(2, "big")
    body += bytes([0x13, 0x01, 0x13, 0x02])
    body += bytes([1])
    body += bytes([0])
    body += len(exts).to_bytes(2, "big")
    body += exts
    hs = bytearray([HANDSHAKE_CLIENT_HELLO])
    hs += (len(body)).to_bytes(3, "big")
    hs += body
    return tls_records(hs)


def send_connect(sock, host, port=CONNECT_PORT):
    head = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
    sock.sendall(head)


def recv_head_exact_200(sock):
    """Read a fully-delimited head and require exact HTTP/1.1 200.
    Returns (is_200, buf) where buf includes any tunnel bytes already read
    past the `\r\n\r\n` separator (they belong to the forwarded stream)."""
    sock.settimeout(6.0)
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            return False, buf
        if not chunk:
            return False, buf
        buf += chunk
    first = buf.split(b"\r\n", 1)[0]
    return first.split(b" ")[1:2] == [b"200"], buf


def recv_through_eof(s, timeout=10.0, seed=b""):
    """Read the relay stream to EOF (the proxy closed the tunnel). Returns the
    complete received byte string seeded from any bytes already read past the
    CONNECT head separator, or None on a timeout before EOF."""
    s.settimeout(timeout)
    buf = bytearray(seed)
    while True:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            return None
        if not chunk:
            return bytes(buf)
        buf += chunk

# ---------------------------------------------------------------------------
def spawn_binary(stdout_target=None, stderr_target=None, preexec_dup2=None):
    """Launch the ACTUAL binary as pid of setpriv->sh->exec (the binary),
    dropped to uid 65534 with empty caps. stdout/stderr passed through; for the
    stalled-stdout case `stdout_target` is the write end of a full pipe."""
    argv = [
        "setpriv", "--reuid", "65534", "--regid", "65534", "--clear-groups",
        "/bin/sh", "-c", f"cd /work && exec {BINPATH}",
    ]
    return subprocess.Popen(argv, stdout=stdout_target, stderr=stderr_target)


def setup_dns(answers, delay_first=0.0, silent_after_session=None, silent_always=False,
              hold_final=False):
    dns = DnsResponder(("127.0.0.1", 53), answers, delay_first,
                       silent_after_session, silent_always, hold_final).start()
    return dns


def run_case(name, body):
    """Common per-case supervision: run `body` inside try/finally so fixture
    threads are always stopped/joined after the case, pass or fail."""
    fixtures = []
    try:
        body(fixtures)
    finally:
        for fx in fixtures:
            fx.stop()
        for fx in fixtures:
            ok = fx.join(2.0)
            if not ok:
                fail(name, f"fixture {type(fx).__name__} did not supervise to exit")
                return


def open_case_log(name):
    return open(f"/tmp/shutdown-{name}.log", "wb")


def dump_case_logs(name):
    """On FAIL, surface the binary's captured output: bounded tail so a signal
    storm or busy loop cannot balloon the record. Scans /tmp/shutdown-*.log
    written in the last 180s (the case's display name differs from its case-_
    function name, which is the run_case key). Returns the tail or None."""
    import glob

    now = time.time()
    parts = []
    for path in glob.glob("/tmp/shutdown-*.log"):
        try:
            if now - os.path.getmtime(path) > 180:
                continue
            with open(path, "rb") as fh:
                data = fh.read()[-1500:]
            parts.append(f"{path}:{data!r}")
        except OSError:
            continue
    return " | ".join(parts) if parts else None


def case_idle_sigterm(fixtures):
    name = "IDLE-SIGTERM-EXIT0"
    dns = setup_dns({b"drain.example.org": bytes([8, 8, 8, 8]),
                     b"force.example.org": bytes([208, 67, 222, 220])})
    fixtures.append(dns)
    echo = EchoUpstream(("8.8.8.8", 443)).start()
    fixtures.append(echo)
    silent = SilentUpstream(("208.67.222.220", 443)).start()
    fixtures.append(silent)
    log = open_case_log(name)
    try:
        proc = spawn_binary(stdout_target=log, stderr_target=log)
        if not require_reachable(name, proc):
            return
        if proc.poll() is not None:
            fail(name, f"binary exited on its own before SIGTERM (rc {proc.returncode})"); return
        t0 = time.monotonic()
        os.kill(proc.pid, signal.SIGTERM)
        rc = bounded_wait(proc, time.monotonic() + 5.0, name)
        if rc is None:
            return
        elapsed = time.monotonic() - t0
        if rc != 0:
            fail(name, f"idle drain must exit 0, got {rc} after {elapsed:.2f}s")
        elif elapsed >= 3.0:
            fail(name, f"idle drain took too long: {elapsed:.2f}s (must exit fast)")
        else:
            pass_(name, f"idle SIGTERM -> clean exit 0 in {elapsed:.2f}s")
    finally:
        log.close()


def case_neg_no_self_exit(fixtures):
    name = "NEG-NO-SELF-EXIT"
    dns = setup_dns({b"drain.example.org": bytes([8, 8, 8, 8]),
                     b"force.example.org": bytes([208, 67, 222, 220])})
    fixtures.append(dns)
    log = open_case_log(name)
    try:
        proc = spawn_binary(stdout_target=log, stderr_target=log)
        if not require_reachable(name, proc):
            return
        time.sleep(2.0)
        if proc.poll() is not None:
            fail(name, f"process self-exited with no signal (rc {proc.returncode})"); return
        t0 = time.monotonic()
        os.kill(proc.pid, signal.SIGTERM)
        rc = bounded_wait(proc, time.monotonic() + 5.0, name)
        if rc is None:
            return
        elapsed = time.monotonic() - t0
        if rc != 0:
            fail(name, f"SIGTERM after 2s idle must exit 0, got {rc}")
        else:
            pass_(name, f"no self-exit for 2s; SIGTERM -> exit 0 in {elapsed:.2f}s")
    finally:
        log.close()


def case_pre_serving(fixtures):
    """SIGTERM while the startup DNS window is still resolving against a
    fully SILENT resolver (accepts the query, never replies, keeps the window
    in Receiving). The boot-armed shared poll must observe the signal with
    priority: the startup terminates promptly (never waits the 90s window),
    the typed terminated startup outcome never BINDS a listener, and the empty
    drain exits 0 (no forced delay)."""
    name = "PRE-SERVING-SILENT-NOBIND"
    dns = setup_dns({b"drain.example.org": bytes([8, 8, 8, 8]),
                     b"force.example.org": bytes([208, 67, 222, 220])},
                    silent_always=True)
    fixtures.append(dns)
    log = open_case_log(name)
    try:
        proc = spawn_binary(stdout_target=log, stderr_target=log)
        # Wait until the startup DNS window has begun (>=1 query observed):
        # the boot-armed handler is installed before run_startup, at that
        # moment the exchange is in Receiving against the silent resolver.
        probe_deadline = time.monotonic() + 5.0
        while time.monotonic() < probe_deadline and dns.queries == 0:
            time.sleep(0.02)
        if dns.queries == 0:
            proc.kill(); proc.wait()
            fail(name, "no DNS query observed; startup window never began")
            return
        kind, exc = connect_probe()
        if kind == "reachable":
            proc.kill(); proc.wait()
            fail(name, "listener bound before the signal: not a pre-serving probe")
            return
        if kind == "error":
            proc.kill(); proc.wait()
            fail(name, f"operational connect error before the signal (indeterminate, not absence): {exc}")
            return
        if proc.poll() is not None:
            fail(name, f"process exited before the pre-serving SIGTERM (rc {proc.returncode})"); return
        t0 = time.monotonic()
        os.kill(proc.pid, signal.SIGTERM)
        # interval-wide no-bind: from the first signal to process exit the
        # listener port must NEVER become reachable (no bind at any point
        # across the whole observation interval, not just at signal time);
        # operational probe errors fail the case rather than green an absence.
        while proc.poll() is None and time.monotonic() - t0 < 12.0:
            if not sample_no_bind(name, proc):
                return
            time.sleep(0.02)
        rc = bounded_wait(proc, time.monotonic() + 12.0, name)
        if rc is None:
            return
        elapsed = time.monotonic() - t0
        if rc != 0:
            fail(name, f"pre-serving SIGTERM must terminate the owner with exit 0, got {rc} after {elapsed:.2f}s")
        elif elapsed >= 6.0:
            fail(name, f"pre-serving shutdown took too long ({elapsed:.2f}s); the shared poll must observe the signal promptly, not at the window end")
        else:
            pass_(name, f"SIGTERM mid-window against silent resolver -> exit 0 in {elapsed:.2f}s with the listener never bound across the interval")
    finally:
        log.close()


def case_retry_backoff_storm(fixtures):
    """SIGTERM storm during the STARTUP retry-backoff phase: after a counted
    exchange failure (observed via the binary's own startup_warning record, not
    assumed by a sleep) the window arms the retry backoff; the storm must be
    observed through the shared poll and terminate promptly with interval-wide
    no listener bind pre- or post-signal (the backoff wait is shared-poll
    driven, never a blind sleep)."""
    name = "RETRY-BACKOFF-STORM"
    # no DNS responder: nothing listens on 127.0.0.1:53, so the retained
    # transport's connect is refused instantly -> a counted exchange failure
    # emits the single startup_warning record and arms the first-stage retry
    # backoff for the next due.
    log = open_case_log(name)
    try:
        proc = spawn_binary(stdout_target=log, stderr_target=log)
        # phase-observed counted failure: wait for the real startup_warning
        # record instead of sleeping to assume the backoff phase was reached.
        if not wait_log_marker(name, b"kind=startup_warning", timeout=8.0):
            proc.kill(); proc.wait()
            fail(name, "counted-failure phase never observed (no startup_warning record emitted before the signal)")
            return
        if proc.poll() is not None:
            fail(name, f"process exited on its own (rc {proc.returncode})"); return
        kind, exc = connect_probe()
        if kind == "reachable":
            proc.kill(); proc.wait()
            fail(name, "listener bound before the signal during backoff"); return
        if kind == "error":
            proc.kill(); proc.wait()
            fail(name, f"operational connect error before the signal (indeterminate, not absence): {exc}")
            return
        t0 = time.monotonic()
        # Storm with error-aware no-bind probes interleaved from the FIRST
        # signal: a bind during the backoff is observed between signals, not
        # only after all six have fired, so the interval-wide no-bind claim
        # covers the post-first-signal window and not just post-storm.
        for _ in range(6):
            if proc.poll() is not None:
                break
            os.kill(proc.pid, signal.SIGTERM)
            if not sample_no_bind(name, proc):
                return
            time.sleep(0.05)
        # post-signal no-bind, error-aware, across the whole interval to exit
        while proc.poll() is None and time.monotonic() - t0 < 10.0:
            if not sample_no_bind(name, proc):
                return
            time.sleep(0.02)
        rc = bounded_wait(proc, time.monotonic() + 10.0, name)
        if rc is None:
            return
        elapsed = time.monotonic() - t0
        if rc != 0:
            fail(name, f"SIGTERM storm during retry backoff must exit 0, got {rc} after {elapsed:.2f}s")
        elif elapsed >= 6.0:
            fail(name, f"storm during backoff took too long ({elapsed:.2f}s); the backoff wait must observe the signal")
        else:
            pass_(name, f"SIGTERM storm during phase-observed startup retry backoff -> exit 0 in {elapsed:.2f}s with no-bind probes interleaved from the first signal")
    finally:
        log.close()


def case_storm_during_drain(fixtures):
    """Established stalled relay + a SIGTERM STORM right after the first
    signal: the fixed 8s deadline must not be extended by later signals. The
    first-deadline and repeat-reset-deadline windows are disjoint, so a storm
    that moves the grace even once (exit ~9.0-9.35s) fails the case; the
    process must also remain live immediately before the first window (no
    early drop)."""
    name = "STORM-DURING-DRAIN"
    dns = setup_dns({b"drain.example.org": bytes([8, 8, 8, 8]),
                     b"force.example.org": bytes([208, 67, 222, 220])})
    fixtures.append(dns)
    silent = SilentUpstream(("208.67.222.220", 443)).start()
    fixtures.append(silent)
    log = open_case_log(name)
    s = None
    try:
        proc = spawn_binary(stdout_target=log, stderr_target=log)
        if not require_reachable(name, proc):
            return
        s = establish_relay("force.example.org")
        if s is None:
            proc.kill(); proc.wait(); fail(name, "could not establish stalled relay"); return
        time.sleep(0.3)
        if silent.bytes_received() == 0:
            proc.kill(); proc.wait(); fail(name, "no hello bytes upstream (relay not established)"); return
        t0 = time.monotonic()
        os.kill(proc.pid, signal.SIGTERM)
        # storm of repeat signals during the drain: none may move the deadline
        time.sleep(1.0)
        for _ in range(8):
            os.kill(proc.pid, signal.SIGTERM)
            time.sleep(0.05)
        if not probe_refused_sampled(t0 + 2.0, name, proc):
            return
        # live-before the first-deadline window: still draining at its edge
        hold_until = t0 + GRACE_LO - 0.3
        now = time.monotonic()
        if now < hold_until:
            time.sleep(hold_until - now)
        if proc.poll() is not None:
            fail(name, f"process exited before the first-deadline window (early drop, rc {proc.returncode})")
            return
        rc = bounded_wait(proc, t0 + 12.5, name)
        if rc is None:
            return
        elapsed = time.monotonic() - t0
        if rc != 70:
            fail(name, f"storm drain must exit 70, got {rc} after {elapsed:.2f}s")
        elif elapsed < GRACE_LO:
            fail(name, f"storm forced closure too early: {elapsed:.2f}s (< {GRACE_LO:.1f}s first-deadline window)")
        elif elapsed > GRACE_HI:
            fail(name, f"repeat SIGTERM storm extended the fixed 8s deadline: {elapsed:.2f}s (> {GRACE_HI:.1f}s first-deadline window; a storm reset near t0+1.35s would land ~9.35s)")
        else:
            pass_(name, f"SIGTERM storm did not extend the fixed 8s deadline: forced exit 70 in {elapsed:.2f}s within the disjoint first-deadline window {GRACE_LO:.1f}-{GRACE_HI:.1f}s")
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
        log.close()


def establish_relay(host, timeout=8.0):
    """CONNECT + valid matching ClientHello -> established relay to the
    allowlisted host's resolved silent upstream, whose receipt of the hello
    bytes is the establishment witness for a relay that never replies. Returns
    the client socket or None."""
    s = socket.create_connection(PROXY, timeout=6.0)
    try:
        send_connect(s, host)
        ok, _ = recv_head_exact_200(s)
        if not ok:
            s.close()
            return None
        s.sendall(client_hello(host))
        return s
    except OSError:
        s.close()
        return None


def case_early_drain(fixtures):
    """One established relay carrying a byte-exact hello+payload stream through
    EOF. A CONNECT 200 is confirmed, then the full hello+payload tunnel stream
    is sent; the upstream record-echo of that whole stream can only come back
    through a real Relay-stage tunnel, so its byte-exact return IS the relay
    establishment witness (a relay that never establishes returns nothing).
    SIGTERM then client half-close: the relay must drain the complete
    hello+payload tunnel stream byte-exact through EOF and the owner exits 0
    before the grace. Dropping pending setup or tunnel bytes fails the full
    stream equality assertion."""
    name = "EARLY-DRAIN"
    dns = setup_dns({b"drain.example.org": bytes([8, 8, 8, 8]),
                     b"force.example.org": bytes([208, 67, 222, 220])})
    fixtures.append(dns)
    echo = EchoUpstream(("8.8.8.8", 443)).start()
    fixtures.append(echo)
    log = open_case_log(name)
    s = None
    try:
        proc = spawn_binary(stdout_target=log, stderr_target=log)
        if not require_reachable(name, proc):
            return
        full = client_hello("drain.example.org")
        payload = bytes((i * 7) % 256 for i in range(512))
        full += payload
        seed = b""
        try:
            s = socket.create_connection(PROXY, timeout=6.0)
            send_connect(s, "drain.example.org")
            ok, head = recv_head_exact_200(s)
            if not ok:
                s.close()
                s = None
                proc.kill(); proc.wait()
                fail(name, "early-drain relay never got CONNECT 200")
                return
            if b"\r\n\r\n" in head:
                seed = head.split(b"\r\n\r\n", 1)[1]
            s.sendall(full)
        except OSError as exc:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
                s = None
            proc.kill(); proc.wait()
            fail(name, f"early-drain relay CONNECT/send failed: {exc}")
            return
        t0 = time.monotonic()
        os.kill(proc.pid, signal.SIGTERM)
        # client half-close right after the signal: the relay drains and closes
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        stream = recv_through_eof(s, timeout=9.0, seed=seed)
        rc = bounded_wait(proc, time.monotonic() + 9.0, name)
        if rc is None:
            return
        elapsed = time.monotonic() - t0
        if rc != 0:
            fail(name, f"early drain must exit 0 (established tunnel closed), got {rc} after {elapsed:.2f}s")
        elif stream is None:
            fail(name, f"relay stream incomplete through EOF (dropped setup or tunnel bytes): got None, expected {len(full)} bytes")
        elif stream != full:
            fail(name, f"byte-conservation violated on the drained relay: got {len(stream)} of {len(full)} expected bytes")
        elif elapsed >= GRACE_LO:
            fail(name, f"early drain took too long ({elapsed:.2f}s; must exit before the {GRACE_LO:.1f}s grace edge)")
        else:
            pass_(name, f"real relay stream (upstream echo of the full stream through a Relay-stage tunnel) drained byte-exact through EOF after SIGTERM -> exit 0 in {elapsed:.2f}s")
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
        log.close()


def case_forced_repeat_noadmit(fixtures):
    """Stalled established relay (silent upstream): deadline-forced closure is
    FAILURE (exit 70), the deadline is monotonic (repeat SIGTERM never extends),
    and no connection is admitted after the first signal."""
    name = "FORCED-REPEAT-NOADMIT"
    dns = setup_dns({b"drain.example.org": bytes([8, 8, 8, 8]),
                     b"force.example.org": bytes([208, 67, 222, 220])})
    fixtures.append(dns)
    silent = SilentUpstream(("208.67.222.220", 443)).start()
    fixtures.append(silent)
    log = open_case_log(name)
    s = None
    try:
        proc = spawn_binary(stdout_target=log, stderr_target=log)
        if not require_reachable(name, proc):
            return
        s = establish_relay("force.example.org")
        if s is None:
            proc.kill(); proc.wait(); fail(name, "could not establish stalled relay to silent upstream"); return
        time.sleep(0.3)  # let the hello bytes reach the upstream -> Relay stage
        if silent.bytes_received() == 0:
            proc.kill(); proc.wait(); fail(name, "no hello bytes observed upstream (relay not established)"); return
        t0 = time.monotonic()
        os.kill(proc.pid, signal.SIGTERM)
        # no admissions after the first signal: the listener must be dropped
        # (error-aware sampling; an operational probe error never reads as
        # absence, so it fails the case rather than greening a broken probe)
        if not probe_refused_sampled(t0 + 2.0, name, proc):
            return
        time.sleep(3.0)
        if proc.poll() is not None:
            rc_pre = proc.returncode
            fail(name, f"process exited before the forced deadline ({rc_pre}); stale listener admission or early closure")
            return
        time.sleep(2.0)  # t0+5s: a second (repeat) SIGTERM must not extend
        os.kill(proc.pid, signal.SIGTERM)
        # deadline measured from t0 (the first observation) with disjoint
        # windows: a repeat signal that extended the grace to ~13s fails the
        # first-deadline window.
        rc = bounded_wait(proc, t0 + 12.5, name)
        if rc is None:
            return
        elapsed = time.monotonic() - t0
        if rc != 70:
            fail(name, f"deadline-forced closure must exit 70, got {rc} after {elapsed:.2f}s")
        elif elapsed < GRACE_LO:
            fail(name, f"forced closure too early: {elapsed:.2f}s (< {GRACE_LO:.1f}s first-deadline window)")
        elif elapsed > GRACE_HI:
            fail(name, f"repeat SIGTERM extended the fixed deadline: {elapsed:.2f}s (> {GRACE_HI:.1f}s first-deadline window; a reset at t0+5s would land ~13s)")
        else:
            pass_(name, f"forced exit 70 on the fixed deadline in {elapsed:.2f}s within the first-deadline window; no admission after the signal; repeat SIGTERM did not extend")
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
        log.close()


def case_stalled_stdout(fixtures):
    """Stalled relay + stdout backed into a GENUINELY FULL 4 KiB pipe (the
    driver never reads it): after startup a supervised nonblocking writer fills
    the pipe to EXACT capacity - a 4096-byte EAGAIN only proves under-4096 free,
    so one-byte writes to EAGAIN prove no single-byte headroom remains - and
    the child's log-sink writes during shutdown necessarily WouldBlock, so the
    forced deadline still closes the tunnel on time. The effective
    prefill/headroom setting is validated and reported (a headroom >= capacity
    is refused as ambiguous rather than silently producing an empty pipe)."""
    name = "STALLED-STDOUT"
    dns = setup_dns({b"drain.example.org": bytes([8, 8, 8, 8]),
                     b"force.example.org": bytes([208, 67, 222, 220])})
    fixtures.append(dns)
    silent = SilentUpstream(("208.67.222.220", 443)).start()
    fixtures.append(silent)
    errlog = open(f"/tmp/shutdown-{name}.stderr.log", "wb")
    r = w = w_probe = None
    s = None
    try:
        r, w = os.pipe()
        fcntl.fcntl(w, fcntl.F_SETPIPE_SZ, 4096)
        cap = fcntl.fcntl(w, fcntl.F_GETPIPE_SZ)
        if PRESWITCH_BYTES >= cap:
            fail(name, f"SHUTDOWN_PRESWITCH_BYTES={PRESWITCH_BYTES} >= pipe capacity {cap}: headroom would make the prefill empty, refusing an ambiguous stall")
            return
        prefill = max(0, cap - PRESWITCH_BYTES)
        os.write(w, b"x" * prefill)
        # reserve a probe write end: after startup this supervised nonblocking
        # writer fills the pipe to genuine full occupancy (EAGAIN), so the
        # retained pipe stays full for the whole shutdown interval.
        w_probe = os.dup(w)
        fcntl.fcntl(w_probe, fcntl.F_SETFL, os.O_NONBLOCK)
        proc = spawn_binary(stdout_target=w, stderr_target=errlog)
        os.close(w); w = None
        if not require_reachable(name, proc):
            return
        s = establish_relay("force.example.org")
        if s is None:
            proc.kill(); proc.wait(); fail(name, "could not establish stalled relay"); return
        time.sleep(0.3)
        if silent.bytes_received() == 0:
            proc.kill(); proc.wait(); fail(name, "no hello bytes upstream (relay not established)"); return
        # fill the retained pipe to EXACT full occupancy: a 4096-byte
        # nonblocking write EAGAINs whenever fewer than 4096 bytes are free
        # (a partial pipe still accepting a small record), so the 4096-fill
        # alone only proves a headroom below 4096. Prove no single-byte
        # headroom remains by draining free space with nonblocking one-byte
        # writes to EAGAIN - the only authoritative exact-capacity signal.
        saw_eagain = False
        filled = 0
        for _ in range(128):
            try:
                filled += os.write(w_probe, b"x" * 4096)
            except BlockingIOError:
                saw_eagain = True
                break
        if not saw_eagain:
            proc.kill(); proc.wait()
            fail(name, f"retained pipe never reached the 4096-fill EAGAIN (capacity {cap}); stall not genuine ({filled} probe bytes accepted)")
            return
        one_eagain = False
        one_filled = 0
        for _ in range(PRESWITCH_BYTES + 2):
            try:
                os.write(w_probe, b"x")
                one_filled += 1
            except BlockingIOError:
                one_eagain = True
                break
        if not one_eagain:
            proc.kill(); proc.wait()
            fail(name, f"retained pipe not at exact full occupancy: a single-byte nonblocking write still succeeded after the 4096-fill EAGAIN ({filled}+{one_filled} bytes against capacity {cap}); stall not genuine")
            return
        t0 = time.monotonic()
        os.kill(proc.pid, signal.SIGTERM)
        rc = bounded_wait(proc, t0 + 12.5, name)
        if rc is None:
            return
        elapsed = time.monotonic() - t0
        if rc != 70:
            fail(name, f"stalled-stdout forced closure must exit 70, got {rc} after {elapsed:.2f}s")
        elif elapsed < GRACE_LO:
            fail(name, f"stalled-stdout forced closure too early: {elapsed:.2f}s")
        elif elapsed > GRACE_HI:
            fail(name, f"full-output stall delayed the fixed deadline: {elapsed:.2f}s (> {GRACE_HI:.1f}s first-deadline window)")
        else:
            pass_(name, f"exactly full stdout pipe (nonblocking single-byte write EAGAIN after {filled}+{one_filled} probe bytes against capacity {cap}) did not delay shutdown: forced exit 70 in {elapsed:.2f}s within the first-deadline window")
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
        if w is not None:
            os.close(w)
        if w_probe is not None:
            os.close(w_probe)
        if r is not None:
            os.close(r)
        errlog.close()


def case_silent_dns(fixtures):
    """Stalled relay + the REAL current DNS refresh profile, honestly scoped.
    Startup resolves both A families on session 1 and never attempts AAAA (their
    slots stay due), so the serving owner's due-refresh re-queries AAAA right
    after the listener binds. The harness SERVES the first such refresh on
    session 2 (the responder-side TRANSMISSION witness, set only after sendall
    returns; proves the responder sent the answer, not that the owner consumed
    it), then a next-due serving DNS exchange on a silent-zone session (>= 3,
    sibling AAAA-family by fixed inputs) is genuinely ACCEPTED, its query read,
    and left UNANSWERED (the responder goes silent from session 3); the case
    REQUIRES that responder-observed accepted/read/unanswered observation
    BEFORE delivering SIGTERM (the sticky event asserts neither qtype nor
    continued owner activity). The forced drain must then still close in the
    first-deadline window with that accepted/read/unanswered serving query
    observed before signal. Observed session counts are printed as an
    observation
    only: handled-SIGTERM DNS SUPPRESSION is NOT claimed from this fixture's
    accept roster -- it is the native owner witness (src/runtime.rs
    sigterm_stops_due_refresh_flow re-arms A+AAAA due after a real self-pipe
    SIGTERM and asserts no new DNS initiation), run separately with its
    no-signal negative control."""
    name = "SILENT-DNS-REFRESH-DRAIN"
    dns = setup_dns({b"drain.example.org": bytes([8, 8, 8, 8]),
                     b"force.example.org": bytes([208, 67, 222, 220])},
                    silent_after_session=2)
    fixtures.append(dns)
    silent = SilentUpstream(("208.67.222.220", 443)).start()
    fixtures.append(silent)
    log = open_case_log(name)
    s = None
    try:
        proc = spawn_binary(stdout_target=log, stderr_target=log)
        if not require_reachable(name, proc):
            return
        s = establish_relay("force.example.org")
        if s is None:
            proc.kill(); proc.wait(); fail(name, "could not establish stalled relay"); return
        time.sleep(0.3)
        if silent.bytes_received() == 0:
            proc.kill(); proc.wait(); fail(name, "no hello bytes upstream (relay not established)"); return
        # Current-refresh transmission witness: the first due-refresh AAAA answer
        # must actually be SENT on a serving session (event published only after
        # sendall returns), not merely admitted or assembled.
        if not dns.aaaa_refresh_sent.wait(10.0):
            proc.kill(); proc.wait()
            fail(name, "current AAAA refresh answer never transmitted on a post-startup session (fixture premise of a real refresh violated)")
            return
        # Dead-resolver serving negative: some serving DNS query must be
        # genuinely accepted, its query read, and left unanswered on a
        # silent-zone session (>= 3) BEFORE the signal -- a responder-observed
        # accepted/read/unanswered serving query (sibling AAAA-family by fixed
        # inputs; asserts neither qtype nor continued owner activity), not an
        # unreachable branch.
        if not dns.silent_accept.wait(10.0):
            proc.kill(); proc.wait()
            fail(name, "next due serving DNS query was never accepted/queried-and-left-unanswered on a silent-zone session before the signal (dead-resolver serving negative premise violated)")
            return
        t0 = time.monotonic()
        os.kill(proc.pid, signal.SIGTERM)
        rc = bounded_wait(proc, t0 + 12.5, name)
        if rc is None:
            return
        elapsed = time.monotonic() - t0
        with dns._lock:
            sess_exit = dns.sessions
            timeline = list(dns.session_times)
            queries = dns.queries
        if rc != 70:
            fail(name, f"silent-DNS forced closure must exit 70, got {rc} after {elapsed:.2f}s")
        elif elapsed < GRACE_LO:
            fail(name, f"silent-DNS forced closure too early: {elapsed:.2f}s")
        elif elapsed > GRACE_HI:
            fail(name, f"DNS left a deadline that delayed the forced closure: {elapsed:.2f}s (> {GRACE_HI:.1f}s first-deadline window)")
        else:
            pass_(name, f"current AAAA refresh answer TRANSMITTED on a post-startup serving session (responder-side witness) and a next-due serving DNS query accepted/queried-and-left-unanswered on a silent-zone serving session before the signal (dead-resolver serving negative; responder-observed, due-family scheduling from fixed inputs); {queries} queries over {sess_exit} sessions observed (timeline {[(s, f'{t:.2f}') for s, t in timeline]} rel. signal {t0:.2f}); forced exit 70 in {elapsed:.2f}s within the first-deadline window with that accepted/read/unanswered serving DNS query observed before signal (responder-observed; sibling AAAA-family by fixed inputs, asserts neither qtype nor continued owner activity). Session counts are an observation only; owner-side active-cancellation and suppression are covered natively by src/runtime.rs runtime_self_pipe_sigterm_cancels_active_receiving + sigterm_stops_due_refresh_flow (run separately), not claimed from this fixture's accept roster")
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
        log.close()


def case_simultaneous_completion(fixtures):
    """SIGTERM delivered while the final allowlist answer is HELD: the
    responder withholds the final answer until it is told to release, so the
    startup DNS window is provably still resolving when the SIGTERM lands. The
    pre-bind settlement recheck must observe the pending signal and settle
    Terminated: completion that races a signal must never win a listener bind
    across the whole interval (991u C1/C2). This cross-process case cannot
    control the owner's single poll, so it claims signal-during-held-answer;
    the true one-poll DNS-ready+signal batch membership is proven by the
    native private-owner Rust witness (run_startup_both_ready...)."""
    name = "SIMULTANEOUS-COMPLETION-NOBIND"
    dns = setup_dns({b"drain.example.org": bytes([8, 8, 8, 8]),
                     b"force.example.org": bytes([208, 67, 222, 220])},
                    hold_final=True)
    fixtures.append(dns)
    log = open_case_log(name)
    try:
        proc = spawn_binary(stdout_target=log, stderr_target=log)
        # Wait until the final allowlist answer has been withheld: the startup
        # window is mid-resolution, so a signal delivered now cannot have been
        # beaten by a bind.
        if not dns.final_query_received.wait(20.0):
            proc.kill(); proc.wait()
            fail(name, "responder never held the final allowlist answer")
            return
        t0 = time.monotonic()
        os.kill(proc.pid, signal.SIGTERM)
        # Release the withheld answer only after the signal has had a beat to
        # arrive in the self-pipe, so the settlement recheck races an
        # in-progress resolution against a pending signal. This remains a
        # signal-during-held-answer witness: it does not claim to place both
        # readinesses into a single poll of the separate process's loop.
        time.sleep(0.05)
        dns.release_final.set()
        while proc.poll() is None and time.monotonic() - t0 < 10.0:
            if not sample_no_bind(name, proc):
                return
            time.sleep(0.02)
        rc = bounded_wait(proc, time.monotonic() + 10.0, name)
        if rc is None:
            return
        elapsed = time.monotonic() - t0
        if rc != 0:
            fail(name, f"simultaneous-completion SIGTERM must terminate with exit 0, got {rc} after {elapsed:.2f}s")
        elif elapsed >= 6.0:
            fail(name, f"simultaneous-completion termination took too long ({elapsed:.2f}s)")
        else:
            pass_(name, f"signal while the final allowlist answer is held -> exit 0 in {elapsed:.2f}s, listener never bound across the interval (same-batch DNS+signal prove natively)")
    finally:
        log.close()


CASES = [
    case_idle_sigterm,
    case_neg_no_self_exit,
    case_pre_serving,
    case_retry_backoff_storm,
    case_early_drain,
    case_forced_repeat_noadmit,
    case_storm_during_drain,
    case_stalled_stdout,
    case_silent_dns,
    case_simultaneous_completion,
]


def main():
    if not os.path.exists(BINPATH):
        print(f"SHUTDOWN-BLOCKED: release binary missing: {BINPATH}", file=sys.stderr, flush=True)
        return 3
    st = os.stat(BINPATH)
    print(f"SHUTDOWN-BIN: {BINPATH} size={st.st_size}", flush=True)
    case_filter = os.environ.get("CASE_FILTER", "")
    selected = [case for case in CASES if not case_filter or case_filter in case.__name__]
    if not selected:
        print(
            f"SHUTDOWN-NO-SELECTION: CASE_FILTER={case_filter!r} matched zero of {len(CASES)} cases; refusing unqualified green",
            flush=True,
        )
        return 2
    print(
        f"SHUTDOWN-SELECTED: {len(selected)}/{len(CASES)} cases by CASE_FILTER={case_filter!r}: "
        + ", ".join(case.__name__ for case in selected),
        flush=True,
    )
    completed = []
    for case in selected:
        before = set(FAILURES)
        run_case(case.__name__, case)
        for disp in sorted(set(FAILURES) - before):
            tail = dump_case_logs(disp)
            if tail:
                print(f"SHUTDOWN-{disp}: LOG-TAIL {tail}", flush=True)
        if not (set(FAILURES) - before):
            completed.append(case.__name__)
    print(f"SHUTDOWN-COMPLETED: {len(completed)}/{len(selected)} selected cases", flush=True)
    if FAILURES:
        print(f"SHUTDOWN-FAILURES: {sorted(set(FAILURES))}", flush=True)
        return 1
    if case_filter:
        print(f"SHUTDOWN-SCOPED-PASS: {len(completed)}/{len(selected)} selected cases passed", flush=True)
    else:
        print(f"SHUTDOWN-ALL-PASS: {len(completed)}/{len(selected)} cases passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
