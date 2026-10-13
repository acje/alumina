#!/usr/bin/env python3
"""Real-IO CONNECT/SNI opaque-relay E2E against the actual alumina binary.

Runs entirely inside one podman container (harness image = pinned rust base +
openssl/python3/setpriv/ip, --network none, NNP enabled, no-new-privileges)
after the production static binary is mounted at /app. The driver stages
/work/config.toml + /work/resolv.conf, starts an in-container DNS-over-TCP
responder on 127.0.0.1:53, and the outer shell wrapper launches the actual
binary (dropped to uid 65534 via setpriv). The driver drives real TCP clients
through the proxy and asserts the observed wire behaviour.

Topology -- all upstream addresses are global-unicast IPv4 (so the crate's
martian/SSRF eligibility guard admits them) bound on lo inside the --network
none namespace, so everything stays local:
    example.com      -> 8.8.8.8         real TLS1.3 upstream (`openssl
                                       s_server -rev`: authentic handshake +
                                       app bytes echoed reversed)
    echo.example.org -> 8.8.4.4         raw TCP echo upstream (byte-exact):
                                       fragmentation / coalescing / partial
                                       writes / FIN / backpressure drivers
    down.example.org -> 208.67.222.222  nothing listening: early-upstream
                                       non-reachability must yield 502 before
                                       any hello is forwarded
    neg.example.org  -> 208.67.222.220  counting-only listener: accepts a
                                       connection, records bytes, never replies.
                                       Rejected-hello tunnels CONNECT here and
                                       must forward ZERO bytes (barrier A never
                                       opens), proven by the counter.

Cases (full-stream byte-exact, distinct soft-timeout handling, upstream-effect
assertions):
    POS-RELAY-TLS13          valid TLS1.3 ClientHello, matching SNI, app bytes
    POS-FRAGMENTED-HELLO     CONNECT head split across TCP writes + fragmented
                             validated ClientHello
    POS-COALESCED            CONNECT head + leading hello bytes in one write
    POS-PARTIAL-WRITES       odd-sized chunked writes through the relay
    POS-FIN-HALFCLOSE        client half-close observed, relay drains + echo
                             returns intact
    POS-LARGE-ECHO           4 MiB byte-exact echo (multi-chunk backpressure)
    NEG-DISALLOWED-CONNECT   non-allowlisted CONNECT -> 403, no upstream dial
    NEG-SNI-MISMATCH         allowlisted CONNECT, wrong SNI -> hello reject,
                             zero bytes forwarded, TCP close (EOF/reset) not timeout
    NEG-ECH                  allowlisted CONNECT, ECH extension -> reject,
                             zero bytes forwarded, close not timeout
    NEG-MALFORMED            allowlisted CONNECT, garbage hello -> reject,
                             zero bytes forwarded, close not timeout
    NEG-EARLY-UPSTREAM       allowlisted CONNECT, dial fails -> 502

Exit 0 iff every case passes and every fixture thread is supervised to exit;
each case emits `E2E-<NAME>: PASS|FAIL <detail>`. A receive TIMEOUT is never a
clean rejection (the proxy must close the tunnel, not leave it silently open),
and a partial-byte stream fails byte-exact against the full expected echo.
"""

import os
import socket
import subprocess
import sys
import threading
import time

PROXY = ("127.0.0.1", 8080)
CONNECT_PORT = 443

# Wire constants mirrored from src/client_hello.rs (E2E crafts ClientHelios the
# production parser must accept or reject for the stated reason, never as
# malformed).
CONTENT_HANDSHAKE = 22
HANDSHAKE_CLIENT_HELLO = 1
RANDOM_LEN = 32
SUPPORTED_VERSIONS = 43
SERVER_NAME = 0
ENCRYPTED_CLIENT_HELLO = 0xFE0D
TLS13 = 0x0304
TLS12 = 0x0303

FAILURES = []


def fail(name, detail):
    print(f"E2E-{name}: FAIL {detail}", flush=True)
    FAILURES.append(name)


def pass_(name, detail):
    print(f"E2E-{name}: PASS {detail}", flush=True)


def tls_records(payload):
    """A single TLS record containing an arbitrary handshake payload."""
    rec = bytearray([CONTENT_HANDSHAKE, 0x03, 0x01])
    rec += (len(payload)).to_bytes(2, "big")
    rec += payload
    return bytes(rec)


def client_hello(sni, ech=False, versions=(TLS13,), legacy=TLS12):
    """Byte-exact TLS1.3 ClientHello mirroring the crate's own test builder."""
    versions_data = bytearray([len(versions) * 2])
    for v in versions:
        versions_data += v.to_bytes(2, "big")
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
    if ech:
        exts += ENCRYPTED_CLIENT_HELLO.to_bytes(2, "big")
        exts += (0).to_bytes(2, "big")

    body = bytearray()
    body += legacy.to_bytes(2, "big")
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


def read_exact(sock, n):
    """Read exactly n bytes, raising EOFError on a short/empty stream.

    TCP has no message boundaries, so a length-prefixed frame (DNS-over-TCP,
    TLS record header) must be assembled across repeated recv calls; a single
    recv(2) may legally return fewer bytes than requested."""
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError(f"short read: wanted {n} got {len(out)}")
        out += chunk
    return out


def recv_http_response(sock, timeout=5.0):
    """Read a full HTTP response head. Returns (head_bytes, remainder_bytes,
    complete).

    `complete` is True only when a CRLFCRLF-delimited head was fully received
    within the timeout. A timeout, transport error or EOF before the delimiter
    yields `complete=False` with the partial bytes -- callers MUST NOT accept
    an incomplete head as a status verdict (a peer that stalls mid-head must
    fail the case, never pass on a substring). `remainder` is every byte read
    past the delimiter in the same segment; the caller must preserve it (a
    pipelined ClientHello echo over-reading the head would otherwise be lost).
    """
    sock.settimeout(timeout)
    buf = b""
    incomplete = False
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            incomplete = True
            break
        except OSError:
            incomplete = True
            break
        if not chunk:
            incomplete = True
            break
        buf += chunk
        if len(buf) > 64 * 1024:
            break
    marker = buf.find(b"\r\n\r\n")
    if marker < 0:
        return buf, b"", False
    head_end = marker + 4
    return buf[:marker], buf[head_end:], True


def http_status_code(head):
    """Exact 3-digit status code parsed from a complete response head.

    Returns an int, or None when the head has no parsable `HTTP/x.y <n>`
    status line. Callers compare against the exact expected code -- never a
    substring, so a wrong code carrying the expected digits in its reason text
    cannot pass."""
    first = head.split(b"\r\n", 1)[0] if head else b""
    parts = first.split(b" ")
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def send_connect(sock, host, port=CONNECT_PORT, head_chunks=None):
    """Send CONNECT; when head_chunks is set, split the head across those
    write sizes (fragmentation / partial writes). The full head is always
    delivered; the chunk list is a trailing optional size pattern, with any
    remainder sent as a final whole chunk."""
    head = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
    if head_chunks is None:
        sock.sendall(head)
        return
    pos = 0
    for size in head_chunks:
        part = head[pos:pos + size]
        if not part:
            continue
        sock.sendall(part)
        time.sleep(0.02)
        pos += len(part)
    if pos < len(head):
        sock.sendall(head[pos:])
        time.sleep(0.02)


def send_chunked(sock, payload, chunks):
    """Send `payload` across the given chunk sizes; remainder sent whole."""
    pos = 0
    for size in chunks:
        part = payload[pos:pos + size]
        if not part:
            continue
        sock.sendall(part)
        time.sleep(0.02)
        pos += len(part)
    if pos < len(payload):
        sock.sendall(payload[pos:])
    return len(payload)


# --------------------------------------------------------------------------
# DNS-over-TCP responder. The listen socket is bound SYNCHRONOUSLY in the
# constructor so a query from the proxy's startup window can never race a
# not-yet-bound listener (drives out the startup DNS race).
# --------------------------------------------------------------------------
class DnsResponder:
    def __init__(self, addr, answers):
        self.addr = addr
        self.answers = answers  # bytes qname -> ip_bytes (A) or None (NXDOMAIN)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(self.addr)
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self._stop = False
        self.thread = threading.Thread(target=self._run, name="dns-responder", daemon=True)
        self.conns = 0
        self._hlock = threading.Lock()
        self._handlers = []  # owned per-connection DNS handler threads (B2/B5)

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
        self.thread.join(timeout=deadline)
        return not self.thread.is_alive()

    def drain_handlers(self, deadline):
        """Join all owned per-connection DNS handler threads within deadline;
        True only when every handler completed (a live one is a leak)."""
        end = time.time() + deadline
        with self._hlock:
            pending = list(self._handlers)
        for t in pending:
            t.join(max(0.0, end - time.time()))
        with self._hlock:
            self._handlers[:] = [t for t in self._handlers if not t.is_alive()]
        return not any(t.is_alive() for t in pending)

    def bytes_received(self):
        # DNS request bytes are not accounted per-fixture; the interface exists
        # so supervise() treats every fixture uniformly.
        return 0

    def _run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.conns += 1
            print(f"E2E-DNS-CONN: #{self.conns}", file=sys.stderr, flush=True)
            t = threading.Thread(
                target=self._serve, args=(conn,), daemon=True, name="dns-serve"
            )
            with self._hlock:
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

    def _serve(self, conn):
        try:
            conn.settimeout(5.0)
            # a real TCP nameserver keeps the connection open across many
            # exchanges; the binary reuses one connection for the whole window
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
                question = msg[12:qpos + 4]
                params = f"{qname.decode(errors='replace')} type={qtype} tid={tid.hex()} qlen={qlen}"
                if os.environ.get("E2E_DNS_TS"):
                    import datetime

                    params += f" t={datetime.datetime.now().isoformat(timespec='milliseconds')}"
                print(f"E2E-DNS-QUERY: {params}", file=sys.stderr, flush=True)

                ip = self.answers.get(qname.lower())
                if ip is None:
                    # unknown NAME -> NXDOMAIN for any type (whole-name
                    # nonexistence, the runtime's name-wide eviction), never a
                    # fake positive
                    self._reply(conn, tid, question, 3)
                    continue
                if qtype == 1:  # A
                    ancount = 1
                    rcode = 0
                    nscount = 0
                    ns_rr = b""
                    rr = qname_literal(qname) + b"\x00\x01\x00\x01"
                    rr += (60).to_bytes(4, "big")
                    rr += (4).to_bytes(2, "big")
                    rr += ip
                else:
                    # existing name, non-A type (AAAA/...): validated NODATA.
                    # The name EXISTS for A, so a type-absence answer must be
                    # NOERROR with zero answers plus a covering SOA (RFC 2308),
                    # never a whole-name NXDOMAIN. NODATA lets the runtime evict
                    # only the queried family (src/dns.rs classify_soa,
                    # src/cache.rs evict_nodata), keeping the A binding, so a
                    # query of the other family cannot take an existing
                    # IPv4-only name down.
                    ancount = 0
                    rcode = 0
                    nscount = 1
                    ns_rr = soa_record(qname, 300, 60)
                    rr = b""
                flags = (0x8000 | 0x0100 | (rcode & 0x0F))
                hdrw = tid + flags.to_bytes(2, "big")
                hdrw += (1).to_bytes(2, "big")
                hdrw += (ancount).to_bytes(2, "big")
                hdrw += (nscount).to_bytes(2, "big")
                hdrw += (0).to_bytes(2, "big")
                resp = hdrw + question + rr + ns_rr
                print(f"E2E-DNS-TX: {resp.hex()}", file=sys.stderr, flush=True)
                conn.sendall(len(resp).to_bytes(2, "big") + resp)
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _reply(self, conn, tid, question, rcode):
        flags = (0x8000 | 0x0100 | 0x0080 | (rcode & 0x0F))
        hdrw = tid + flags.to_bytes(2, "big")
        hdrw += (1).to_bytes(2, "big")
        hdrw += (0).to_bytes(2, "big")
        hdrw += (0).to_bytes(2, "big")
        hdrw += (0).to_bytes(2, "big")
        resp = hdrw + question
        try:
            conn.sendall(len(resp).to_bytes(2, "big") + resp)
        except OSError:
            pass


def qname_literal(qname):
    out = bytearray()
    for label in qname.split(b"."):
        if not label:
            continue
        out += bytes([len(label)])
        out += label
    out += bytes([0])
    return bytes(out)


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


# --------------------------------------------------------------------------
# Upstream fixture servers. Every listen socket binds SYNCHRONOUSLY in the
# constructor, and each fixture counts what it receives so the driver can
# assert effect non-reachability (rejected hellos forward ZERO bytes).
# --------------------------------------------------------------------------
class _BoundServer:
    def __init__(self, addr):
        self.addr = addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(self.addr)
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self._stop = False
        self._lock = threading.Lock()
        self._bytes = 0
        self.conns = 0
        self.thread = threading.Thread(target=self._run, name=self.NAME, daemon=True)
        self._handlers = []  # owned per-connection handler threads (B2/B5)
        self._observe_errors = 0  # R4: unexpected observer errors, not success

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
        self.thread.join(timeout=deadline)
        return not self.thread.is_alive()

    def _record_observe_error(self, detail):
        with self._lock:
            self._observe_errors += 1
        print(f"E2E-OBSERVE-ERROR: {self.NAME}: {detail}", file=sys.stderr, flush=True)

    def observe_errors(self):
        with self._lock:
            return self._observe_errors

    def drain_handlers(self, deadline):
        """Join every owned connection handler within `deadline`. Returns True
        only when every handler completed WITHOUT error; a handler still alive
        after the deadline (leak) or one that ended in an unexpected observer
        error is NOT a clean zero-effect verdict (R4 -- a dead thread that
        failed its read must not become success)."""
        end = time.time() + deadline
        with self._lock:
            pending = list(self._handlers)
        for t in pending:
            t.join(max(0.0, end - time.time()))
        with self._lock:
            self._handlers[:] = [t for t in self._handlers if t.is_alive()]
        return not any(t.is_alive() for t in pending) and self.observe_errors() == 0

    def bytes_received(self):
        with self._lock:
            return self._bytes

    def add_bytes(self, n):
        with self._lock:
            self._bytes += n

    def _spawn_handler(self, conn):
        t = threading.Thread(
            target=self._serve_one, args=(conn,), daemon=True, name=self.NAME + "-serve"
        )
        with self._lock:
            self._handlers.append(t)
        t.start()

    def _run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.conns += 1
            self._spawn_handler(conn)

    def _serve_one(self, conn):
        raise NotImplementedError


class RawEchoServer(_BoundServer):
    """Byte-exact echo upstream; counts accepted connections and bytes."""

    NAME = "raw-echo"

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


class CountingListener(_BoundServer):
    """Accepts a connection, records bytes received, never replies.

    The hello-reject tunnels dial this upstream to prove barrier A stayed
    closed: the proxy must connect (a normal Dialing step) but forward ZERO
    bytes, observable as `bytes_received() == 0` with a non-zero conn count.

    R4: the observation is NOT successful merely because the worker thread
    ended. A recv failure before EOF -- any OSError other than a plain timeout
    (a stalled, still-open tunnel), or an uncaught worker exception -- is
    recorded as a counting-observer error. A zero-byte verdict is only valid
    when the handler completed with no such error, so a failed read can never
    masquerade as "zero bytes forwarded".
    """

    NAME = "counting"

    def _serve_one(self, conn):
        try:
            conn.settimeout(10.0)
            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    # stalled tunnel with the connection still open: not a
                    # clean EOF; loop until the tunnel closes or the drain
                    # deadline flags this handler as alive (leak/stall).
                    continue
                if not chunk:
                    break  # expected normal EOF
                self.add_bytes(len(chunk))
        except OSError as exc:
            self._record_observe_error(f"recv failed before EOF: {exc}")
        except Exception as exc:
            self._record_observe_error(f"uncaught counting worker error: {exc!r}")
        finally:
            try:
                conn.close()
            except OSError:
                pass


# --------------------------------------------------------------------------
# Client drivers
# --------------------------------------------------------------------------
def proxy_socket():
    s = socket.create_connection(PROXY, timeout=10.0)
    return s


def case_relay_tls13():
    """Real TLS1.3 ClientHello through the proxy to the -rev upstream.

    The upstream reverses application-layer bytes, so an authentic handshake
    succeeds and app bytes come back reversed: `hello-e2e\n` -> `\ne2e-olleh`.
    Passing is judged on the reversed app bytes arriving over the tunnel
    (proving the authentic handshake + bidirectional opaque relay); openssl
    waits for the TLS close exchange on stdin EOF, so a content match is the
    assertion rather than a clean exit (client-side orderly-EOF / half-close
    teardown is covered by POS cases against the byte-exact raw echo).
    """
    got = b""
    proc = subprocess.Popen(
        [
            "openssl", "s_client", "-proxy", "127.0.0.1:8080",
            "-connect", "example.com:443", "-servername", "example.com",
            "-tls1_3", "-quiet",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdin is not None
        assert proc.stdout is not None
        proc.stdin.write(b"hello-e2e\n")
        proc.stdin.flush()
        proc.stdin.close()
        import select

        deadline = time.time() + 20.0
        fd = proc.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.5)
            if fd in ready:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                got += chunk
                if b"\ne2e-olleh" in got or b"e2e-olleh" in got:
                    pass_(
                        "POS-RELAY-TLS13",
                        f"authentic TLS1.3 handshake + reversed app bytes relaying (got {len(got)}B)",
                    )
                    return
        err = b""
        # R3: terminate the TLS client BEFORE draining stderr. A held-open
        # upstream keeps s_client alive and its stderr pipe open, so reading to
        # EOF first would block forever and the finally kill/wait would never
        # run. Standard bounded subprocess completion: kill, then a bounded
        # wait, then read the drained pipe (guaranteed EOF after reap).
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        try:
            err = proc.stderr.read()
        except OSError:
            pass
        fail(
            "POS-RELAY-TLS13",
            f"reversed echo missing; out={got!r} err={err!r}",
        )
    finally:
        # the TLS client child is always reaped (kill-then-wait) on success AND
        # failure paths; a live child at driver completion is a leaked process.
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def case_raw_echo(host, chunks_each, total_bytes, name, coalesce_hello=False):
    """Valid matching ClientHello through the proxy to the raw echo upstream.

    Fragmented head + fragmented hello + odd-sized writes + byte-exact echo
    round-trip. The echo upstream reflects exactly what the proxy forwards
    (the validated hello first, then the payload), so the full client stream
    after the 200 head must equal `client_hello(host) + payload` byte-exact --
    a dropped-middle, dropped-tail, duplicated, or overread-dropped byte
    fails even when the tail alone would still match.
    """
    hello = client_hello(host)
    s = proxy_socket()
    rest = b""
    if coalesce_hello:
        # CONNECT head and the full hello in one write, before reading 200:
        # the proxy must validate the already-buffered pipelined hello. The
        # upstream echo of the hello can arrive in the same segment as the 200,
        # so recv_http_response returns the over-read remainder and we preserve
        # it (never lose bytes past the head).
        head = f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode()
        s.sendall(head + hello)
        resp, rest, complete = recv_http_response(s)
        if not complete or http_status_code(resp) != 200:
            fail(name, f"no completed exact-200 head for {host}: complete={complete} {resp!r}")
            s.close()
            return
    else:
        send_connect(s, host, head_chunks=chunks_each["head"])
        resp, _, complete = recv_http_response(s)
        if not complete or http_status_code(resp) != 200:
            fail(name, f"no completed exact-200 head for {host}: complete={complete} {resp!r}")
            s.close()
            return
        send_chunked(s, hello, chunks_each["hello_chunks"])
        rest = b""

    payload = bytes((i * 31) % 256 for i in range(total_bytes))
    s.sendall(payload)
    # half-close so upstream EOF returns and the relay can drain
    try:
        s.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    expected = hello + payload
    # B7 full-stream completion: read to EOF within a bounded deadline. The
    # proxy must drain the whole expected stream AND deliver the reverse
    # half-close (EOF); stopping at the exact expected length would pass a
    # stream that later duplicates bytes or never completes the tunnel.
    got = rest
    s.settimeout(20.0)
    while True:
        try:
            chunk = s.recv(1 << 20)
        except socket.timeout:
            fail(name, "stream not completed to EOF within deadline (no reverse half-close)")
            s.close()
            return
        except OSError as exc:
            fail(name, f"transport error before stream completion: {exc.errno}")
            s.close()
            return
        if not chunk:
            break  # orderly EOF == full stream delivered and drained
        got += chunk
        if len(got) > len(expected):
            fail(
                name,
                f"stream has extra bytes beyond expected {len(expected)}B (got {len(got)}B), "
                f"tail or duplication leaked: {got[len(expected):len(expected)+32]!r}",
            )
            s.close()
            return
    s.close()
    if got != expected:
        # report WHERE the stream diverges to distinguish dropped-middle from
        # tail-only and dropped-tail
        diverges = next(
            (i for i in range(min(len(got), len(expected))) if got[i] != expected[i]),
            min(len(got), len(expected)),
        )
        fail(
            name,
            f"stream not byte-exact: want {len(expected)}B got {len(got)}B, "
            f"first divergence at {diverges} (tail-only would have passed)",
        )
        return
    pass_(name, f"full validated-hello + {total_bytes}-byte opaque echo byte-exact")


def case_fin_halfclose(host):
    """Explicit FIN/half-close case: fragmented head + fragmented hello,
    payload, then client SHUT_WR; the full hello+payload echo must still come
    back byte-exact (the relay drains the accepted bytes through the
    half-close instead of dropping them)."""
    case_raw_echo(
        host,
        {"head": [3, 5, 2, 6, 1], "hello_chunks": [4, 1, 3, 2, 8, 5, 1]},
        512,
        "POS-FIN-HALFCLOSE",
    )


def read_close_after(sock, timeout):
    """After a rejected hello, the proxy must deliver EOF/reset WITHOUT any
    forwarded bytes. A read TIMEOUT (socket.timeout) is NOT a clean rejection
    -- it means the tunnel was left silently open -- and fails the case."""
    sock.settimeout(timeout)
    data = b""
    try:
        data = sock.recv(4096)
        if data:
            return "bytes", data
        # empty b"" == orderly EOF == clean close-without-forward
        return "eof", data
    except socket.timeout:
        return "timeout", b""
    except OSError as exc:
        # ConnectionReset (and any other transport error) closes without
        # forwarding; record the kind distinctly -- never conflated with EOF.
        return f"error:{exc.errno}", b""


def case_neg_dial_fail():
    """down.example.org resolves to 208.67.222.222 where nothing listens: the
    upstream dial is refused, so the relay must answer a pre-200 502 before
    any hello is exchanged, and release the seat. Requires a COMPLETED head
    whose exact status token is 502 (a peer that stalls mid-head must fail)."""
    s = proxy_socket()
    send_connect(s, "down.example.org")
    resp, _, complete = recv_http_response(s)
    if not complete or http_status_code(resp) != 502:
        fail(
            "NEG-EARLY-UPSTREAM",
            f"expected completed exact-502, got complete={complete} {resp!r}",
        )
        s.close()
        return
    pass_("NEG-EARLY-UPSTREAM", f"dial refused -> exact-502 before any hello")
    s.close()


def case_neg_disallowed(counting_conns_before, echo_conns_before):
    """non-allowlisted CONNECT -> 403 and NO upstream dial at all.

    notexample.com resolves (in this harness) to the counting listener address,
    so ANY erroneous dial for the refused host is observable as a new accept on
    the counting listener. The raw-echo accept count is the second observable
    destination (a buggy dial to the echo fixture would land there); the TLS
    upstream is log-observed only, so the python-observable no-dial scope is
    counting + echo, stated explicitly. Both are sampled AFTER a bounded
    completion window so a delayed accept cannot arrive undetected."""
    s = proxy_socket()
    send_connect(s, "notexample.com")
    resp, _, complete = recv_http_response(s)
    if not complete or http_status_code(resp) != 403:
        fail("NEG-DISALLOWED-CONNECT", f"expected completed exact-403, got complete={complete} {resp!r}")
        s.close()
        return
    s.close()
    # bounded completion window: let any delayed dial/accept land before the
    # no-dial verdict (a sampling race must not certify absence)
    time.sleep(0.5)
    if counting.conns != counting_conns_before:
        fail(
            "NEG-DISALLOWED-CONNECT",
            f"403 CONNECT dialed an observable upstream (counting conns {counting_conns_before}->{counting.conns})",
        )
        return
    if echo_fx is None or echo_fx.conns != echo_conns_before:
        conns_now = -1 if echo_fx is None else echo_fx.conns
        fail(
            "NEG-DISALLOWED-CONNECT",
            f"403 CONNECT dialed the echo upstream (echo conns {echo_conns_before}->{conns_now})",
        )
        return
    pass_(
        "NEG-DISALLOWED-CONNECT",
        f"non-allowlisted CONNECT -> exact-403; no dial to counting/echo (TLS log-observed only)",
    )


def case_neg_hello(name_label, hello, what, counting_conns_before, counting_bytes_before):
    """Allowlisted CONNECT to the counting listener (proxy dials, sends 200),
    then a rejected ClientHello: barrier A must stay closed -- ZERO bytes
    forwarded upstream (counter delta 0) and zero bytes back to the client --
    and the tunnel must be CLOSED (EOF/reset), never left open on a timeout.

    The byte verdict is taken ONLY after the counting listener's handler for
    the rejected tunnel has completed (drain_handlers), so a handler that
    reads leaked bytes later cannot race past the zero-byte assertion.
    """
    s = proxy_socket()
    send_connect(s, "neg.example.org")
    resp, _, complete = recv_http_response(s)
    if not complete or http_status_code(resp) != 200:
        fail(what, f"expected completed exact-200 before hello reject, got complete={complete} {resp!r}")
        s.close()
        return
    s.sendall(hello)
    kind, data = read_close_after(s, 6.0)
    s.close()
    if kind == "timeout" or kind.startswith("error:"):
        fail(
            what,
            f"receive timeout/transport error is NOT a clean rejection (saw {kind}, {len(data)}B); "
            f"the tunnel stayed open or errored instead of closing cleanly",
        )
        return
    if data:
        fail(what, f"expected close with no forwarded bytes, got {len(data)}B: {data[:32]!r}")
        return
    # upstream-effect proof requires the counting handler to have COMPLETED
    # before the byte total is trusted (a late recv would otherwise hide leaked
    # bytes). A handler that does not finish within the deadline is a leak, not
    # a zero-effect success.
    if not counting.drain_handlers(2.0):
        fail(what, "counting handler(s) did not complete within the deadline before byte verdict")
        return
    if counting.bytes_received() != counting_bytes_before:
        fail(
            what,
            f"rejected hello forwarded upstream bytes: counter {counting_bytes_before}->{counting.bytes_received()}",
        )
        return
    if counting.conns <= counting_conns_before:
        fail(
            what,
            f"rejected tunnel never even reached the upstream (conns {counting_conns_before}->{counting.conns})",
        )
        return
    pass_(what, "proxy closed without forwarding; upstream received zero bytes (barrier A closed)")


def main():
    # The static-ELF gate runs in the container shell via GNU readelf (the
    # authoritative binutils seam) against the exact executed binary before the
    # driver is launched; no ELF parsing happens here.

    answers = {
        b"example.com": bytes([8, 8, 8, 8]),
        b"echo.example.org": bytes([8, 8, 4, 4]),
        b"down.example.org": bytes([208, 67, 222, 222]),
        b"neg.example.org": bytes([208, 67, 222, 220]),
        # B3 observable no-dial witness: the non-allowlisted host resolves HERE
        # (counting listener), so an erroneous dial for notexample.com would
        # land on an observable accept rather than an unobserved destination.
        b"notexample.com": bytes([208, 67, 222, 220]),
    }
    dns = DnsResponder(("127.0.0.1", 53), answers).start()
    global counting, echo_fx
    echo_fx = RawEchoServer(("8.8.4.4", 443)).start()
    counting = CountingListener(("208.67.222.220", 443)).start()
    fixtures = [dns, echo_fx, counting]

    supervisor_rc = 0
    try:
        # wait for the proxy listener (startup DNS resolved + listener attached)
        deadline = time.time() + 60.0
        while time.time() < deadline:
            try:
                probe = socket.create_connection(PROXY, timeout=1.0)
                probe.close()
                break
            except OSError:
                time.sleep(0.5)
        else:
            fail("SETUP-LISTENER", "proxy listener never became reachable")
            return 1

        if os.environ.get("E2E_EARLY_ONLY"):
            # isolation probe (diagnostic only): run ONLY the dial-refused
            # early-upstream case and emit a DISTINCT non-certifying result
            # (never E2E-ALL-PASS, never exit 0) so no subset run can be read
            # as a full gate. The publication wrapper independently rejects
            # this env var (B1).
            case_neg_dial_fail()
            print("E2E-DIAGNOSTIC-ONLY: subset probe executed; NOT a gate verdict", flush=True)
            return 2
        else:
            case_relay_tls13()

            case_raw_echo(
                "echo.example.org",
                {"head": [1, 1, 2, 1, 3, 2, 1], "hello_chunks": [1, 2, 3, 5, 8, 13, 21]},
                4096,
                "POS-FRAGMENTED-HELLO",
            )
            case_raw_echo(
                "echo.example.org",
                {"head": None, "hello_chunks": [len(client_hello("echo.example.org"))]},
                4096,
                "POS-COALESCED",
                coalesce_hello=True,
            )
            case_raw_echo(
                "echo.example.org",
                {"head": [2, 9, 5, 1], "hello_chunks": [7, 11, 13, 17, 19, 23]},
                4096,
                "POS-PARTIAL-WRITES",
            )
            case_fin_halfclose("echo.example.org")
            # large multi-chunk echo: sustained bidirectional relay + backpressure
            case_raw_echo(
                "echo.example.org",
                {"head": None, "hello_chunks": [len(client_hello("echo.example.org"))]},
                4 * 1024 * 1024,
                "POS-LARGE-ECHO",
                coalesce_hello=True,
            )

            # negatives with upstream-effect assertions
            c_conns = counting.conns
            c_bytes = counting.bytes_received()

            case_neg_disallowed(c_conns, echo_fx.conns)
            # wait one accept-turn so a newly accepted negative-tunnel connection
            # is observed before the next slice's counter snapshot
            time.sleep(0.3)
            c_conns = counting.conns
            c_bytes = counting.bytes_received()
            case_neg_hello(
                "NEG-SNI-MISMATCH",
                client_hello("other.example.org"),
                "NEG-SNI-MISMATCH",
                c_conns,
                c_bytes,
            )
            time.sleep(0.3)
            c_conns = counting.conns
            c_bytes = counting.bytes_received()
            case_neg_hello("NEG-ECH", client_hello("neg.example.org", ech=True), "NEG-ECH", c_conns, c_bytes)
            time.sleep(0.3)
            c_conns = counting.conns
            c_bytes = counting.bytes_received()
            case_neg_hello("NEG-MALFORMED", b"\x16\x03\x01\x00\x03\x01\x02\x03", "NEG-MALFORMED", c_conns, c_bytes)
            case_neg_dial_fail()
    finally:
        # supervision runs on EVERY exit path: setup failure, case exception,
        # early return -- never skipped by an early `return` up the stack.
        supervisor_rc = supervise(fixtures)

    if FAILURES:
        print(f"E2E-FAILURES: {sorted(set(FAILURES))}", flush=True)
        return 1
    if supervisor_rc != 0:
        print(f"E2E-FAILURES: fixture supervision failed ({supervisor_rc})", flush=True)
        return 1
    print("E2E-ALL-PASS", flush=True)
    return 0


def supervise(fixtures):
    """Reap every fixture thread with a deadline; close each listen socket so
    its accept loop observes OSError and returns; drain owned connection/query
    handlers so no live worker survives a PASS. A thread that does not join in
    time, or any forwarding fixture whose received-byte total is non-zero at
    shutdown, is a leaked resource / leaked-effect and fails the gate (B2):
    the aggregate counting/echo zero is asserted at completed shutdown."""
    rc = 0
    for fx in fixtures:
        fx.stop()
    for fx in fixtures:
        ok = fx.join(2.0)
        drained = fx.drain_handlers(2.0) if hasattr(fx, "drain_handlers") else True
        print(
            f"E2E-SUPERVISE: {fx.thread.name} joined={ok} handlers={drained} conns={fx.conns} "
            f"bytes={fx.bytes_received()}",
            flush=True,
        )
        if not ok or not drained:
            rc = 1
    # aggregate invariant: at completed fixture shutdown, the forwarding
    # fixtures that assert zero-forward MUST hold zero (a late leaked byte
    # cannot coexist with a PASS even if individual case sampling missed it).
    if counting is not None and counting.bytes_received() != 0:
        print(
            f"E2E-SUPERVISE: counting fixture byte total {counting.bytes_received()} != 0 at shutdown "
            f"(leaked upstream effect)",
            file=sys.stderr,
            flush=True,
        )
        rc = 1
    return rc


counting = None  # global assigned in main(); referenced by negative cases
echo_fx = None  # global assigned in main(); the raw-echo upstream (B3 witness)


if __name__ == "__main__":
    sys.exit(main())
