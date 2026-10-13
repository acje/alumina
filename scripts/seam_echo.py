#!/usr/bin/env python3
"""seam_echo.py -- minimal single-owner stdlib SSLSocket measurement seam.

Open-loop paced framer + real TLS1.3 byte-exact echo validator and endpoint.
One stdlib selectors readiness loop owns every client TLS partial operation
(WANT read/write), schedule advancement, admission and measurement state
(Decision A of alumina-8tdu). No async, no third-party deps. The echo backend
is a separate peer role (thread-per-connection, admission-capped) so the
client, the immediate neighbour of the measured subject, is the single owner.

Fixed accepted workload (alumina-gjq4): 4096 B payload + 12 B header counted
separately; 8 persistent TLS1.3 connections; aggregate open-loop pacing at
100 decimal Mbps of client application payload plus echo; 5 s warmup and 60 s
measurement window; setup and drain each bounded by one absolute 5 s
deadline; fixed-frame floor rounding; 1024 frames / 4 MiB outstanding
capacity with explicit unsent on exhaustion and no catch-up after the window
end.

Measurement semantics (ownership+cutoff+cohort corrections, alumina-evj7):

- Pending TLS operations are a single per-conn slot; admission NEVER
  overwrites an interrupted operation. The exact pending send/recv is
  dispatched only when its recorded readiness direction is present in the
  selectors mask; per-state interest is re-applied so idle sockets wait on
  READ only and never spin on unconditional WRITE.
- The end-of-window cutoff is checked at the actual new-write dispatch
  boundary. A frame is distinguishable between "never attempted" and
  "interrupted TLS write with zero accepted bytes" via an attempt flag; only
  in-progress (attempted) writes may finish under drain, and never-attempted
  frames past the window are classified as untouched offered-unsent.
- Echo eligibility is validated against the per-connection ordered queue of
  fully-sent frames, so backpressure-skipped slots expect no echo, premature
  echoes are protocol-invalid, and a drain-terminated partial write is
  operational-invalid (not valid-unfulfilled).
- Completion timestamps are captured immediately AFTER the successful send
  return and after the recv that completes each full frame. When one read
  chunk contains several frames they share that single post-recv completion
  time; cohorts are attributed by that observation.
- Latency histograms contain ONLY measurement-window measurements: measure
  cohort, echo completed in-window. The measurement schedule anchors its
  first slot to warmup_end. In-window sent/echoed totals, drain totals and
  achieved Mbps are reported separately from cohort counts.
- CPU/RSS sampling is bounded by the observed measurement aperture: explicit
  start/end boundary tick observations with observed timestamps and disclosed
  boundary lag (no exact scheduled-window claim/interpolation), a CPU mean
  over that observed span, sampled current RSS (VmRSS) kept separate from the
  lifetime high-water mark (VmHWM), and typed Unknown CPU evidence that
  invalidates the run (unknown-cpu) when a required subject lacks acceptable
  evidence.

Roles (one per invocation): --role backend|client|dns-responder|selftest.

Verdict: exit 0 = trustworthy measurement (workload_fulfilled bool separates
fulfilled from trustworthy-but-unfulfilled); exit 3 = INVALID with named
reasons; exit 1 = harness/operational failure.
"""

import argparse
import collections
import hashlib
import json
import os
import platform
import selectors
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

TOOL_VERSION = "0.2.0"
TOOL_NAME = "seam_echo"

FRAME_HDR_LEN = 12            # uint32 payload_len + uint64 seq
FRAME_PAYLOAD = 4096          # fixed client application payload per frame
FRAME_SIZE = FRAME_HDR_LEN + FRAME_PAYLOAD
DEFAULT_CONNS = 8
DEFAULT_TARGET_MBPS = 100.0   # decimal Mbps of client application payload
DEFAULT_SECONDS = 60.0
DEFAULT_WARMUP = 5.0
SETUP_DEADLINE = 5.0
DRAIN_DEADLINE = 5.0
OUTSTANDING_FRAMES_CAP = 1024
OUTSTANDING_BYTES_CAP = 4194304   # 1024 * 4096 payload
STALL_LIMIT = 5.0             # conn with outstanding work idle this long -> timeout
SAMPLE_PERIOD = 0.25
RECV_VISIT = 64               # max recv chunks per conn per visit (fairness bound)
LIN_BIN_US = 100              # histogram bin width (linear)
LIN_MAX_US = 2_000_000        # observations above this land in the overflow bin
CPU_MIN_WINDOW_SAMPLES = 2    # required in-window samples for a known CPU subject
CLK_TCK = int(os.sysconf("SC_CLK_TCK")) if hasattr(os, "sysconf") else 100


def _mono():
    return time.monotonic()


def _file_sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for blk in iter(lambda: fh.read(1 << 16), b""):
                h.update(blk)
        return h.hexdigest()
    except OSError:
        return None


def _identity_block():
    return {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "tool_sha256": _file_sha256(os.path.abspath(__file__)),
        "source_head": os.environ.get("BENCH_SOURCE_HEAD"),
        "dirty_count": os.environ.get("BENCH_DIRTY_COUNT"),
        "rust_target": os.environ.get("BENCH_RUST_TARGET"),
        "retained_binary_sha256": os.environ.get("BENCH_BINARY_SHA256"),
        "executed_binary_sha256": _file_sha256("/work/alumina"),
        "image_id": os.environ.get("BENCH_IMAGE_ID"),
        "config_sha256": os.environ.get("BENCH_CONFIG_SHA"),
        "python_version": platform.python_version(),
        "openssl_version": ssl.OPENSSL_VERSION,
    }


# --------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------

def frame_payload(conn, seq, plen=FRAME_PAYLOAD):
    """Deterministic payload bytes for (conn, seq); verified byte-exact on
    echo. Built by C-speed bytes replication, not a Python byte loop."""
    block = struct.pack(">QQ", conn, seq)
    return (block * (plen // len(block) + 1))[:plen]


def build_frame(conn, seq, plen=FRAME_PAYLOAD):
    return struct.pack(">IQ", plen, seq) + frame_payload(conn, seq, plen)


class FrameAssembler:
    """Reassembles length/seq/payload frames from an arbitrary byte stream.

    A header whose payload length differs from the fixed frame size is
    rejected. EOF/timeout mid-frame leaves an incomplete tail."""

    def __init__(self):
        self._buf = b""
        self._wanted = FRAME_HDR_LEN

    def feed(self, chunk):
        if not chunk:
            return []
        self._buf += chunk
        out = []
        while True:
            if len(self._buf) < self._wanted:
                return out
            if self._wanted == FRAME_HDR_LEN:
                plen, seq = struct.unpack(">IQ", self._buf[:FRAME_HDR_LEN])
                if plen != FRAME_PAYLOAD:
                    raise ValueError(
                        "frame payload length %d != fixed %d" % (plen, FRAME_PAYLOAD))
                self._wanted = FRAME_HDR_LEN + plen
                continue
            plen, seq = struct.unpack(">IQ", self._buf[:FRAME_HDR_LEN])
            if len(self._buf) >= self._wanted:
                payload = self._buf[FRAME_HDR_LEN:self._wanted]
                out.append((plen, seq, payload))
                self._buf = self._buf[self._wanted:]
                self._wanted = FRAME_HDR_LEN
        return out

    def incomplete(self):
        return len(self._buf) > 0


def read_http_head(sock, end_deadline):
    """Read a complete CRLFCRLF-delimited head within the shared absolute
    monotonic deadline. Recomputed remaining budget on every loop turn; a
    deadline that expires, EOF or an oversized head returns None."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        left = end_deadline - _mono()
        if left <= 0:
            return None
        sock.settimeout(max(left, 1e-3))
        try:
            chunk = sock.recv(65536)
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
        if len(buf) > 64 * 1024:
            return None
    return buf[:buf.find(b"\r\n\r\n")]


def http_status_code(head):
    if not head:
        return None
    parts = head.split(b"\r\n", 1)[0].split(b" ")
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def connect_tunnel(proxy_addr, peer_host, peer_port, end_deadline):
    """Open a CONNECT tunnel within the shared absolute deadline; returns the
    connected socket or raises RuntimeError."""
    left = end_deadline - _mono()
    if left <= 0:
        raise RuntimeError("setup deadline exceeded before CONNECT")
    s = socket.create_connection(proxy_addr, timeout=max(left, 1e-3))
    try:
        s.settimeout(max(end_deadline - _mono(), 1e-3))
        req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (
            peer_host, peer_port, peer_host, peer_port)
        s.sendall(req.encode("ascii"))
        head = read_http_head(s, end_deadline)
        if head is None:
            raise RuntimeError("CONNECT head incomplete/timeout")
        if http_status_code(head) != 200:
            raise RuntimeError("CONNECT refused: %r" % head[:80])
    except Exception:
        try:
            s.close()
        except OSError:
            pass
        raise
    return s


# --------------------------------------------------------------------------
# DNS helpers (validated construction reused from scripts/e2e_relay.py)
# --------------------------------------------------------------------------

def qname_literal(qname):
    out = bytearray()
    for label in qname.split(b"."):
        if not label:
            continue
        out += bytes([len(label)]) + label
    out += bytes([0])
    return bytes(out)


def soa_record(owner, ttl, minimum):
    mname = qname_literal(b"ns1.example.org")
    rname = qname_literal(b"hostmaster.example.org")
    rlen = len(mname) + len(rname) + 20
    m = qname_literal(owner) + b"\x00\x06\x00\x01"
    m += ttl.to_bytes(4, "big") + rlen.to_bytes(2, "big") + mname + rname
    for v in (1, 3600, 600, 86400, minimum):
        m += v.to_bytes(4, "big")
    return m


class DnsResponder:
    """DNS-over-TCP responder: A answer for a known name, covering-SOA NODATA
    (RFC 2308) for non-A types of an existing name, NXDOMAIN otherwise."""

    def __init__(self, bind, answers):
        self.addr = bind
        self.answers = answers
        self.queries = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(bind)
        self.sock.listen(32)
        self.sock.settimeout(0.5)

    def _read_name(self, msg, pos):
        labels = []
        while pos < len(msg):
            ln = msg[pos]
            if ln & 0xC0 == 0xC0:
                return b".".join(labels), pos + 2
            pos += 1
            if ln == 0:
                return b".".join(labels), pos
            if pos + ln > len(msg):
                return None, pos
            labels.append(msg[pos:pos + ln])
            pos += ln
        return None, pos

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._serve(conn)

    def _serve(self, conn):
        try:
            conn.settimeout(5.0)
            length = conn.recv(2)
            if len(length) != 2:
                return
            (n,) = struct.unpack(">H", length)
            msg = b""
            while len(msg) < n:
                chunk = conn.recv(n - len(msg))
                if not chunk:
                    return
                msg += chunk
            tid = msg[:2]
            qname, qpos = self._read_name(msg, 12)
            if qname is None or qpos + 4 > len(msg):
                return
            qtype = int.from_bytes(msg[qpos:qpos + 2], "big")
            question = msg[12:qpos + 4]
            self.queries += 1
            ip = self.answers.get(qname.lower())
            if ip is None:
                self._reply(conn, tid, question, 3, b"", 0)
            elif qtype == 1:
                rr = qname_literal(qname) + b"\x00\x01\x00\x01"
                rr += (60).to_bytes(4, "big") + (4).to_bytes(2, "big") + ip
                self._reply(conn, tid, question, 0, rr, 1)
            else:
                self._reply(conn, tid, question, 0,
                            soa_record(qname, 300, 60), 0, nscount=1)
        except (OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _reply(self, conn, tid, question, rcode, rr, ancount, nscount=0):
        flags = 0x8000 | 0x0100 | (rcode & 0x0F)
        hdr = tid + flags.to_bytes(2, "big")
        hdr += (1).to_bytes(2, "big") + ancount.to_bytes(2, "big")
        hdr += nscount.to_bytes(2, "big") + (0).to_bytes(2, "big")
        resp = hdr + question + rr
        try:
            conn.sendall(len(resp).to_bytes(2, "big") + resp)
        except OSError:
            pass


# --------------------------------------------------------------------------
# latency histogram (C6-correct overflow)
# --------------------------------------------------------------------------

class Histogram:
    """Compact latency histogram with a truthful top boundary and overflow.

    Linear bins of LIN_BIN_US up to LIN_MAX_US; observations above LIN_MAX_US go
    to a counted overflow bucket with no upper bound. Quantiles never clamp a
    partial top bin below its data: a quantile whose rank falls in overflow is
    reported at the overflow lower bound with overflow=True, and the exact max
    is always recorded separately."""

    def __init__(self, bin_us=LIN_BIN_US, max_us=LIN_MAX_US):
        self.bin_us = bin_us
        self.nbins = max_us // bin_us
        self.bins = [0] * self.nbins
        self.overflow = 0
        self.count = 0
        self.exact_max_us = None

    def add(self, value_us):
        self.count += 1
        if self.exact_max_us is None or value_us > self.exact_max_us:
            self.exact_max_us = value_us
        if value_us >= LIN_MAX_US:
            self.overflow += 1
            return
        self.bins[int(value_us // self.bin_us)] += 1

    def quantile(self, q):
        if self.count == 0:
            return None
        rank = min(max(int(q * self.count), 0), self.count - 1)
        run = 0
        for i, c in enumerate(self.bins):
            run += c
            if rank < run:
                low = i * self.bin_us
                return {"us": low + self.bin_us // 2, "overflow": False,
                        "lower_us": low}
            if run >= self.count:
                break
        return {"us": LIN_MAX_US, "overflow": True, "lower_us": LIN_MAX_US}


# --------------------------------------------------------------------------
# process sampling (procfs CPU ticks + current VmRSS + lifetime VmHWM)
# --------------------------------------------------------------------------

def proc_stat_ticks(pid):
    with open("/proc/%d/stat" % pid, "rb") as fh:
        data = fh.read()
    close = data.rfind(b")")
    fields = data[close + 2:].split()
    return int(fields[11]) + int(fields[12])


def proc_vmrss_kb(pid):
    with open("/proc/%d/status" % pid, "rb") as fh:
        for line in fh:
            if line.startswith(b"VmRSS:"):
                return int(line.split()[1])
    raise OSError("VmRSS not found")


def proc_vmhwm_kb(pid):
    with open("/proc/%d/status" % pid, "rb") as fh:
        for line in fh:
            if line.startswith(b"VmHWM:"):
                return int(line.split()[1])
    raise OSError("VmHWM not found")


class ProcSampler:
    """Tick/current-RSS/lifetime-HWM sampler for named pids. A failed probe is
    recorded as unknown for that pid, never folded into a positive. Window
    summaries weight interval means by actual elapsed time and disclose the
    sampled interval."""

    def __init__(self, pids, period=SAMPLE_PERIOD):
        self.labels = list(pids)      # list of (label, pid)
        self.period = period
        self.samples = collections.defaultdict(list)
        self.unknown = {}
        self._last_ticks = {}
        self._last_wall = {}

    def sample(self, boundary=None):
        """Append a sample for every label at the observed monotonic time.
        `boundary` tags the explicit warmup->measure ("start") and window-end
        ("end") tick observations used as the measured CPU aperture; periodic
        samples pass boundary=None."""
        now = _mono()
        for label, pid in self.labels:
            try:
                ticks = proc_stat_ticks(pid)
                rss = proc_vmrss_kb(pid)
                hwm = proc_vmhwm_kb(pid)
            except Exception as exc:  # a failed probe is typed unknown
                self.unknown.setdefault(label, "%s" % exc)
                continue
            prev = self._last_ticks.get(label)
            self._last_ticks[label] = ticks
            rec = {"t": now, "ticks": ticks, "vmrss_kb": rss, "vmhwm_kb": hwm}
            if boundary is not None:
                rec["boundary"] = boundary
            if prev is not None and label in self._last_wall:
                dt = now - self._last_wall[label]
                rec["dt_s"] = dt
                rec["cores"] = (ticks - prev) / CLK_TCK / max(dt, 1e-9)
            else:
                rec["dt_s"] = None
                rec["cores"] = None
            self.samples[label].append(rec)
            self._last_wall[label] = now

    def _boundary(self, label, kind):
        for r in self.samples.get(label, []):
            if r.get("boundary") == kind:
                return r
        return None

    def window_summary(self, label, start, end, min_samples=CPU_MIN_WINDOW_SAMPLES):
        """CPU over the OBSERVED span between the explicit start and end
        boundary tick observations (observed timestamps, boundary lag vs the
        scheduled window disclosed); sampled current RSS over that same
        observed span; VmHWM reported separately as the process lifetime
        high-water mark. No warmup-straddling or drain periodic delta is
        counted as measurement CPU and the observed end delta is included.
        A missing boundary probe, fewer than min_samples contained periodic
        intervals, or any failed probe -> unknown."""
        all_s = self.samples.get(label, [])
        unknown = {"unknown": True,
                   "reason": self.unknown.get(label, "no boundary samples"),
                   "samples": len(all_s), "core_samples": 0, "cores_mean": None,
                   "cores_peak": None, "rss_current_mean_kb": None,
                   "rss_current_peak_kb": None, "vmhwm_kb": None,
                   "sampled_from": None, "sampled_to": None, "intervals": [],
                   "boundary_lag_s": None,
                   "probe_failures": self.unknown.get(label)}
        if self.unknown.get(label):
            return unknown
        bs = self._boundary(label, "start")
        be = self._boundary(label, "end")
        if bs is None or be is None:
            unknown["reason"] = ("missing %s boundary tick observation" %
                                 ("start" if bs is None else "end"))
            return unknown
        tb, te = bs["t"], be["t"]
        dt_total = te - tb
        if dt_total <= 0:
            unknown["reason"] = "degenerate observed aperture (dt %.6f s)" % dt_total
            return unknown
        intervals = [r for r in all_s
                     if r.get("boundary") is None and r.get("cores") is not None
                     and r["t"] > tb and r["t"] <= te]
        rss = [r["vmrss_kb"] for r in all_s if r["t"] >= tb and r["t"] <= te]
        hwm = max(r["vmhwm_kb"] for r in all_s if r["t"] >= tb and r["t"] <= te)
        base = {
            "unknown": False,
            "reason": None,
            "samples": len(all_s),
            "core_samples": len(intervals),
            "cores_mean": (be["ticks"] - bs["ticks"]) / CLK_TCK / dt_total,
            "cores_peak": max(r["cores"] for r in intervals) if intervals else None,
            "rss_current_mean_kb": int(sum(rss) / len(rss)) if rss else None,
            "rss_current_peak_kb": max(rss) if rss else None,
            "vmhwm_kb": hwm,
            "sampled_from": tb,
            "sampled_to": te,
            "boundary_lag_s": {"start": tb - start, "end": te - end},
            "intervals": [{"t0": r["t"] - r["dt_s"], "dt_s": r["dt_s"],
                           "cores": r["cores"]} for r in intervals],
            "probe_failures": self.unknown.get(label),
        }
        if len(intervals) < min_samples:
            base["unknown"] = True
            base["reason"] = "fewer than %d contained in-window intervals (%d)" % (
                min_samples, len(intervals))
        return base


# --------------------------------------------------------------------------
# single-owner TLS1.3 byte-exact echo backend (separate peer role)
# --------------------------------------------------------------------------

class EchoBackend:
    """TLS1.3 byte-exact echo endpoint, thread-per-connection, admission-capped.

    Test-only knobs (echo_delay_s, swallow_after, corrupt_seq_lt) let the
    selftest inject real byte streams; defaults reproduce the authentic echo."""

    def __init__(self, addr, certfile, keyfile, deadline=30.0,
                 echo_delay_s=0.0, swallow_after=None, corrupt_seq_lt=None,
                 max_workers=1024):
        self.addr = addr
        self.deadline = deadline
        self.echo_delay_s = echo_delay_s
        self.swallow_after = swallow_after
        self.corrupt_seq_lt = corrupt_seq_lt
        self.max_workers = max_workers
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(certfile, keyfile)
        self.ctx = ctx
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(addr)
        self.sock.listen(64)
        self.sock.settimeout(0.25)
        self.bytes_recv = 0
        self.bytes_sent = 0
        self.conns = 0
        self.errors = 0
        self.rejected = 0
        self._lock = threading.Lock()
        self._stop = False
        self._workers = set()
        self.thread = None

    def port(self):
        return self.sock.getsockname()[1]

    def start(self):
        self.thread = threading.Thread(target=self._run, name="seam-backend",
                                       daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def join(self, timeout=None):
        t = self.thread
        if t is not None and t.is_alive():
            t.join(timeout=timeout if timeout is not None else self.deadline + 2.0)
        with self._lock:
            workers = list(self._workers)
        for w in workers:
            w.join(timeout=2.0)
        return not (t and t.is_alive())

    def run_forever(self):
        # standalone backend process: block in the accept/dispatch loop until
        # the supervisor TERMs us or the deadline elapses.
        self._run()

    def _run(self):
        started = _mono()
        while not self._stop and _mono() - started < self.deadline:
            try:
                raw, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                if len(self._workers) >= self.max_workers:
                    self.rejected += 1
                    try:
                        raw.close()
                    except OSError:
                        pass
                    continue
                self.conns += 1
                t = threading.Thread(target=self._serve, args=(raw,),
                                     name="seam-backend-w", daemon=True)
                self._workers.add(t)
            t.start()

    def _serve(self, raw):
        tls = None
        try:
            raw.settimeout(self.deadline)
            tls = self.ctx.wrap_socket(raw, server_side=True)
            while True:
                chunk = tls.recv(1 << 16)
                if not chunk:
                    break
                with self._lock:
                    self.bytes_recv += len(chunk)
                out = self._apply_knobs(chunk)
                if self.echo_delay_s > 0:
                    time.sleep(self.echo_delay_s)
                if out:
                    tls.sendall(out)
                    with self._lock:
                        self.bytes_sent += len(out)
        except (OSError, ssl.SSLError):
            with self._lock:
                self.errors += 1
        finally:
            try:
                if tls is not None:
                    tls.close()
            except OSError:
                pass
            try:
                raw.close()
            except OSError:
                pass
            with self._lock:
                self._workers.discard(threading.current_thread())

    def _apply_knobs(self, chunk):
        if self.swallow_after is None and self.corrupt_seq_lt is None:
            return chunk
        out = bytearray()
        pos = 0
        while pos + FRAME_HDR_LEN <= len(chunk):
            plen, seq = struct.unpack(">IQ", chunk[pos:pos + FRAME_HDR_LEN])
            if plen > FRAME_PAYLOAD:
                break
            end = pos + FRAME_HDR_LEN + plen
            if end > len(chunk):
                break
            frame = chunk[pos:end]
            pos = end
            if self.swallow_after is not None and seq >= self.swallow_after:
                continue
            if self.corrupt_seq_lt is not None and seq < self.corrupt_seq_lt:
                frame = frame[:FRAME_HDR_LEN] + bytes(
                    b ^ 0xFF for b in frame[FRAME_HDR_LEN:])
            out += frame
        return bytes(out)


# --------------------------------------------------------------------------
# client: per-connection state and the single-owner measurement run
# --------------------------------------------------------------------------

class _Frame:
    __slots__ = ("ci", "seq", "phase", "buf", "off", "sent_attempt",
                 "ts_admit", "ts_send")

    def __init__(self, ci, seq, phase):
        self.ci = ci
        self.seq = seq
        self.phase = phase
        self.buf = build_frame(ci, seq)
        self.off = 0
        self.sent_attempt = False
        self.ts_admit = None
        self.ts_send = None


class _Conn:
    __slots__ = ("ci", "tls", "want", "pending", "cur", "asm", "sent_queue",
                 "sent_count", "echoed_count", "sent_ts", "needs_local_recv",
                 "last_progress", "closed", "error", "eof")

    def __init__(self, ci, tls):
        self.ci = ci
        self.tls = tls
        self.want = None        # "r" | "w" : required readiness to resume pending op
        self.pending = None     # "send" | "recv" : the single TLS op slot
        self.cur = None         # _Frame being transmitted (or admitted) or None
        self.asm = FrameAssembler()
        self.sent_queue = collections.deque()   # ordered fully-sent seqs, echo order
        self.sent_count = 0
        self.echoed_count = 0
        self.sent_ts = {}       # seq -> ts_send (post-call), for in-flight frames
        self.needs_local_recv = False
        self.last_progress = None
        self.closed = False
        self.error = None
        self.eof = False


class ClientRun:
    """Open-loop paced generator + echo validator under ONE IO owner."""

    def __init__(self, args):
        self.args = args
        self.target_bps = args.target_mbps * 1_000_000.0 / 8.0
        self.interval = FRAME_PAYLOAD / self.target_bps
        self.planned_warmup = int(self.target_bps * args.warmup // FRAME_PAYLOAD)
        self.planned_measure = int(self.target_bps * args.seconds // FRAME_PAYLOAD)
        self.planned_total = self.planned_warmup + self.planned_measure
        warm_rem = int(self.target_bps * args.warmup) - self.planned_warmup * FRAME_PAYLOAD
        meas_rem = int(self.target_bps * args.seconds) - self.planned_measure * FRAME_PAYLOAD
        self.remainder_bytes = {"warmup": warm_rem, "measure": meas_rem}
        self.conns = []
        self.nconns = args.conns
        self.sel = selectors.DefaultSelector()
        self.next_seq = 0
        self.outstanding = 0
        self.counts = {k: {"warmup": 0, "measure": 0} for k in (
            "admitted", "backpressure", "missed_end", "offered_unsent",
            "sent", "send_failed", "echoed", "unechoed", "conn_errors",
            "protocol", "timeout")}
        self.partial_accepted_frame = {"warmup": 0, "measure": 0}
        self.partial_accepted_payload = {"warmup": 0, "measure": 0}
        self.hists = {name: Histogram() for name in
                      ("sched_to_echo", "actual_send_to_echo", "send_lag")}
        self.timing = {k: 0 for k in (
            "in_window_sent_frames", "in_window_sent_payload_bytes",
            "in_window_echoed_frames", "in_window_echoed_payload_bytes",
            "drain_sent_frames", "drain_sent_payload_bytes",
            "drain_echoed_frames", "drain_echoed_payload_bytes")}
        self.failures = {}
        self.origin = None
        self.warmup_end = None
        self.window_end = None
        self.drain_end = None
        self.drain_started = False
        self._warmup_boundary = False
        self.terminated = False
        self.done = False
        self._last_sample = 0.0
        labels = [("client", os.getpid())]
        if args.backend_pid:
            labels.append(("backend", args.backend_pid))
        if args.proxy_pid:
            labels.append(("proxy", args.proxy_pid))
        self.sampler = ProcSampler(labels)

    def _phase_of_seq(self, k):
        return "warmup" if k < self.planned_warmup else "measure"

    def _now_phase(self, now):
        if self.origin is None or now < self.warmup_end:
            return "warmup"
        return "measure"

    def _due(self, seq):
        # warmup schedule anchored at origin; measurement schedule anchored at
        # warmup_end so the first measurement slot is never before it.
        if seq < self.planned_warmup:
            return self.origin + seq * self.interval
        return self.warmup_end + (seq - self.planned_warmup) * self.interval

    # --- setup (one absolute setup IO deadline, shared by every subop) ---

    def setup(self):
        setup_end = _mono() + SETUP_DEADLINE
        opened = []
        try:
            for ci in range(self.args.conns):
                left = setup_end - _mono()
                if left <= 0:
                    raise RuntimeError("setup deadline exceeded before dial")
                if self.args.mode == "via-proxy":
                    raw = connect_tunnel(self.args.target_addr, self.args.peer_host,
                                         self.args.peer_port, setup_end)
                else:
                    raw = socket.create_connection(self.args.target_addr,
                                                   timeout=max(left, 1e-3))
                opened.append(raw)
                left = setup_end - _mono()
                if left <= 0:
                    raise RuntimeError("setup deadline exceeded before handshake")
                tls = self.args.ctx.wrap_socket(
                    raw, server_hostname=self.args.peer_host,
                    do_handshake_on_connect=False)
                opened.append(tls)
                tls.settimeout(max(left, 1e-3))
                tls.do_handshake()
                if _mono() > setup_end:
                    raise RuntimeError("setup deadline exceeded after handshake")
                version = tls.version()
                if not (version or "").startswith("TLSv1.3"):
                    raise RuntimeError("endpoint negotiated %r, not TLSv1.3" % version)
                tls.setblocking(False)
                conn = _Conn(ci, tls)
                self.conns.append(conn)
                # idle interest: READ only (waiting for echoes); no WRITE spin
                self.sel.register(tls, selectors.EVENT_READ, conn)
        except Exception:
            for s in opened:
                try:
                    s.close()
                except OSError:
                    pass
            for conn in self.conns:
                try:
                    conn.tls.close()
                except OSError:
                    pass
            raise
        self.origin = _mono()
        self.warmup_end = self.origin + self.args.warmup
        self.window_end = self.origin + self.args.warmup + self.args.seconds
        self.drain_end = self.window_end + DRAIN_DEADLINE
        for conn in self.conns:
            conn.last_progress = _mono()

    # --- admission / schedule ---

    def _admit_due(self, now):
        while self.next_seq < self.planned_total:
            seq = self.next_seq
            phase = self._phase_of_seq(seq)
            due = self._due(seq)
            if now < due:
                break
            if now >= self.window_end:
                # C1: no admission after window end; remaining planned slots
                # missed, attributed to their own phase.
                for s in range(self.next_seq, self.planned_total):
                    self.counts["missed_end"][self._phase_of_seq(s)] += 1
                self.next_seq = self.planned_total
                break
            target = self.conns[seq % len(self.conns)]
            if target.closed or target.cur is not None:
                # transmit path busy or conn gone: explicit unsent, no replay
                self.counts["backpressure"][phase] += 1
                self.next_seq += 1
                continue
            if self.outstanding >= OUTSTANDING_FRAMES_CAP:
                self.counts["backpressure"][phase] += 1
                self.next_seq += 1
                continue
            self._admit(target, seq, phase, now)
            self.next_seq += 1

    def _admit(self, conn, seq, phase, now):
        f = _Frame(conn.ci, seq, phase)
        f.ts_admit = now
        conn.cur = f
        self.outstanding += 1
        self.counts["admitted"][phase] += 1
        if conn.pending is None:
            # only claim the IO slot when free; an interrupted op is never
            # overwritten by admission.
            conn.pending = "send"
            conn.want = "w"
        elif conn.pending == "recv" and conn.want == "r":
            # the interrupted recv is quiesced (it needs network data, nothing
            # local buffered): the admitted frame may take the slot to transmit.
            conn.pending = "send"
            conn.want = "w"
        # else: interrupted recv needing WRITE (or an in-flight send) keeps the
        # slot until that exact operation is resumed and completes.

    # --- readiness / interest (single-owner, per-state) ---

    def _ready_for(self, conn, mask):
        if conn.pending == "send":
            if conn.want == "r":
                return bool(mask & selectors.EVENT_READ)
            return bool(mask & selectors.EVENT_WRITE)
        if conn.pending == "recv":
            if conn.want == "w":
                return bool(mask & selectors.EVENT_WRITE)
            return bool(mask & selectors.EVENT_READ)
        # idle: only a READ event may begin echo receive
        return bool(mask & selectors.EVENT_READ)

    def _interest(self, conn):
        if conn.pending == "send":
            return selectors.EVENT_READ if conn.want == "r" else selectors.EVENT_WRITE
        if conn.pending == "recv":
            return selectors.EVENT_WRITE if conn.want == "w" else selectors.EVENT_READ
        return selectors.EVENT_READ   # idle never registers WRITE

    def _sync_interest(self):
        for conn in self.conns:
            if conn.closed:
                continue
            try:
                self.sel.modify(conn.tls, self._interest(conn), conn)
            except (KeyError, ValueError, OSError):
                pass

    # --- per-event IO dispatch ---

    def _try_send(self, conn, now):
        f = conn.cur
        if f is None:
            conn.pending = None
            conn.want = None
            return
        if now >= self.window_end and not f.sent_attempt:
            # new-write dispatch boundary: never-attempted frames are not
            # transmitted after the window (no catch-up). Classification as
            # untouched offered-unsent, not as an interrupted write.
            self.counts["offered_unsent"][f.phase] += 1
            self.outstanding = max(0, self.outstanding - 1)
            conn.cur = None
            conn.pending = None
            conn.want = None
            return
        f.sent_attempt = True
        try:
            n = conn.tls.send(f.buf[f.off:])
        except ssl.SSLWantReadError:
            conn.want = "r"
            conn.pending = "send"
            return
        except ssl.SSLWantWriteError:
            conn.want = "w"
            conn.pending = "send"
            return
        except (ssl.SSLError, OSError) as exc:
            self._conn_fail(conn, "operational-error", "send failed: %s" % exc, now)
            return
        post = _mono()          # completion observation: AFTER successful send
        if n <= 0:
            return
        conn.last_progress = post
        f.off += n
        if f.off >= len(f.buf):
            f.ts_send = post
            conn.sent_count += 1
            self.counts["sent"][f.phase] += 1
            conn.sent_ts[f.seq] = post
            conn.sent_queue.append(f.seq)
            if f.phase == "measure":
                if post < self.window_end:
                    self.timing["in_window_sent_frames"] += 1
                    self.timing["in_window_sent_payload_bytes"] += FRAME_PAYLOAD
                else:
                    self.timing["drain_sent_frames"] += 1
                    self.timing["drain_sent_payload_bytes"] += FRAME_PAYLOAD
                due = self._due(f.seq)
                if post < self.window_end:
                    self.hists["send_lag"].add((post - due) * 1e6)
            conn.cur = None
            conn.pending = None
            conn.want = None
            return
        conn.want = "w"
        conn.pending = "send"

    def _try_recv(self, conn, now):
        visited = 0
        while visited < RECV_VISIT:
            try:
                chunk = conn.tls.recv(1 << 16)
            except ssl.SSLWantReadError:
                conn.want = "r"
                conn.pending = "recv"
                conn.needs_local_recv = False
                if conn.cur is not None:
                    # read side quiesced (needs network data) with a frame
                    # admitted: hand the slot to the send.
                    conn.pending = "send"
                    conn.want = "w"
                return
            except ssl.SSLWantWriteError:
                conn.want = "w"
                conn.pending = "recv"
                conn.needs_local_recv = False
                return
            except (ssl.SSLError, OSError) as exc:
                self._conn_fail(conn, "operational-error", "recv failed: %s" % exc, now)
                return
            post = _mono()      # completion observation: AFTER successful recv
            conn.last_progress = post
            if not chunk:
                conn.eof = True
                conn.pending = None
                conn.want = None
                if conn.sent_ts:
                    self._terminalize(conn, post)
                return
            visited += 1
            try:
                frames = conn.asm.feed(chunk)
            except ValueError as exc:
                self.failures["protocol"] = True
                self.counts["protocol"][self._now_phase(post)] += 1
                conn.pending = None
                return
            # multiple frames from one chunk share this post-recv completion
            for _plen, seq, payload in frames:
                self._handle_echo(conn, seq, payload, post)
        if visited >= RECV_VISIT:
            # C2: buffered plaintext may remain with no fresh kernel event
            conn.needs_local_recv = True

    def _handle_echo(self, conn, seq, payload, now):
        queue = conn.sent_queue
        if not queue:
            # premature echo: seq was never fully sent
            self.failures["protocol"] = True
            self.counts["protocol"][self._now_phase(now)] += 1
            return
        front = queue[0]
        phase = self._phase_of_seq(seq)
        if seq != front:
            # a prior echo is missing, or a duplicate/out-of-order echoed frame
            self.failures["missing-bytes"] = True
            self.failures["protocol"] = True
            self.counts["protocol"][phase] += 1
            return
        if payload != frame_payload(conn.ci, seq):
            self.failures["corruption"] = True
            self.counts["protocol"][phase] += 1
            return
        queue.popleft()
        conn.echoed_count += 1
        self.outstanding = max(0, self.outstanding - 1)
        self.counts["echoed"][phase] += 1
        ts_send = conn.sent_ts.pop(seq, None)
        in_window = now < self.window_end
        if phase == "measure":
            if in_window:
                self.timing["in_window_echoed_frames"] += 1
                self.timing["in_window_echoed_payload_bytes"] += FRAME_PAYLOAD
                due = self._due(seq)
                self.hists["sched_to_echo"].add((now - due) * 1e6)
                if ts_send is not None:
                    self.hists["actual_send_to_echo"].add((now - ts_send) * 1e6)
            else:
                self.timing["drain_echoed_frames"] += 1
                self.timing["drain_echoed_payload_bytes"] += FRAME_PAYLOAD

    def _conn_fail(self, conn, reason, detail, now):
        if conn.closed:
            return
        conn.closed = True
        conn.error = detail
        self.counts["conn_errors"][self._now_phase(now)] += 1
        self._terminalize(conn, now)
        self.failures.setdefault(reason, True)

    def _terminalize(self, conn, now):
        """Orderly termination of a conn's outstanding work with observed bytes:
        never-completed partial frame -- including an attempted TLS write with
        zero accepted bytes -- -> operational-invalid (send_failed, 0 accepted
        bytes), untouched frame -> offered-unsent, incomplete asm tail and
        sent-but-unechoed frames -> missing-bytes, per-seq phase charging,
        outstanding released exactly once."""
        f = conn.cur
        if f is not None:
            if f.off > 0 or f.sent_attempt:
                # partial or attempted-but-unfinished transmission: real
                # missing work even when zero application bytes were accepted
                self.partial_accepted_frame[f.phase] += f.off
                self.partial_accepted_payload[f.phase] += max(0, f.off - FRAME_HDR_LEN)
                self.outstanding = max(0, self.outstanding - 1)
                self.counts["send_failed"][f.phase] += 1
                self.failures["operational-error"] = True
            else:
                self.counts["offered_unsent"][f.phase] += 1
                self.outstanding = max(0, self.outstanding - 1)
            conn.cur = None
            conn.pending = None
            conn.want = None
        if conn.asm.incomplete():
            self.failures["missing-bytes"] = True
            phase = self._now_phase(now)
            self.counts["protocol"][phase] += 1
        leftover = len(conn.sent_ts)
        if leftover:
            for seq in tuple(conn.sent_ts):
                self.counts["unechoed"][self._phase_of_seq(seq)] += 1
            self.outstanding = max(0, self.outstanding - leftover)
            self.failures.setdefault("missing-bytes", True)
        conn.sent_ts.clear()
        conn.sent_queue.clear()
        try:
            conn.tls.close()
        except OSError:
            pass
        try:
            self.sel.unregister(conn.tls)
        except (KeyError, ValueError):
            pass

    # --- window-end / drain (C1) ---

    def _handle_window_end(self, now):
        if self.drain_started:
            return
        self.drain_started = True
        self.sampler.sample(boundary="end")   # measurement-window end tick observation
        for conn in self.conns:
            if conn.closed:
                continue
            f = conn.cur
            if f is not None:
                if f.off > 0 or f.sent_attempt:
                    pass  # in-progress pre-cutoff write may finish under drain (C1)
                else:
                    self.counts["offered_unsent"][f.phase] += 1
                    self.outstanding = max(0, self.outstanding - 1)
                    conn.cur = None
                    if conn.pending == "send" and conn.want == "w":
                        # the discarded never-attempted frame held the send
                        # slot: free it to the drain echo receive.
                        conn.pending = "recv"
                        conn.want = "r"
                    # else: an interrupted operation still occupies the slot;
                    # discarding the frame touches only the frame, never the
                    # interrupted receive or its required direction.
            if conn.pending is None and conn.cur is None:
                # no operation occupies the slot: start the drain echo receive
                conn.pending = "recv"
                conn.want = "r"

    # --- stall / timeout ---

    def _check_stalls(self, now):
        if now >= self.window_end:
            return
        for conn in self.conns:
            if conn.closed or (conn.cur is None and not conn.sent_ts
                               and not conn.needs_local_recv):
                continue
            if conn.last_progress is not None and now - conn.last_progress > STALL_LIMIT:
                self.counts["timeout"][self._now_phase(now)] += 1
                self.failures.setdefault("timeout", True)
                self._conn_fail(conn, "timeout", "no progress for %.1fs" % STALL_LIMIT, now)

    # --- main owner loop ---

    def run(self):
        while not self.done:
            now = _mono()
            # C2: fair bounded local recv continuation without a kernel event
            for conn in list(self.conns):
                if conn.needs_local_recv and not conn.closed:
                    conn.needs_local_recv = False
                    self._try_recv(conn, now)
            now = _mono()
            self._admit_due(now)
            if self.warmup_end is not None and now >= self.warmup_end \
                    and not self._warmup_boundary:
                self.sampler.sample(boundary="start")  # measurement-window start tick observation
                self._warmup_boundary = True
            if now >= self.window_end:
                self._handle_window_end(now)
            self._check_stalls(now)
            if now >= self.window_end and self._clean_early():
                self.terminated = True
                self.done = True
                break
            if now >= self.drain_end:
                self.terminated = True
                self.done = True
                break
            if not any(not c.closed for c in self.conns):
                self.terminated = True
                self.done = True
                break
            self._sync_interest()
            next_wake = self._next_wake(now)
            timeout = min(max(next_wake - now, 0.0), 0.05)
            try:
                events = self.sel.select(timeout=timeout)
            except OSError:
                events = []
            if events:
                self._service_events(events)
            now = _mono()
            if now - self._last_sample >= SAMPLE_PERIOD:
                self.sampler.sample()
                self._last_sample = now
            if self._last_sample == 0.0:
                self._last_sample = now
        self._finalize()

    def _service_events(self, events):
        for key, mask in events:
            conn = key.data
            if conn.closed:
                continue
            conow = _mono()
            if not self._ready_for(conn, mask):
                continue   # wrong-direction-only readiness: never dispatch
            if conn.pending == "send":
                self._try_send(conn, conow)
            else:
                self._try_recv(conn, conow)

    def _next_wake(self, now):
        if self.next_seq < self.planned_total:
            return self._due(self.next_seq)
        return min(self.drain_end, now + 0.05)

    def _clean_early(self):
        if self.outstanding != 0:
            return False
        return all(c.cur is None and not c.needs_local_recv and not c.asm.incomplete()
                   for c in self.conns)

    def _apply_cpu_verdict(self):
        """Unknown CPU evidence on a required subject invalidates the run."""
        if self.sampler.window_summary("client", self.warmup_end, self.window_end)["unknown"]:
            self.failures["unknown-cpu"] = True
        if self.args.mode in ("via-proxy", "direct-proxy"):
            if not self.args.proxy_pid:
                self.failures["unknown-cpu"] = True
            elif self.sampler.window_summary("proxy", self.warmup_end,
                                             self.window_end)["unknown"]:
                self.failures["unknown-cpu"] = True

    def _finalize(self):
        try:
            self.sampler.sample()
        except Exception:
            pass
        if not self.terminated:
            return
        for conn in list(self.conns):
            if (not conn.closed) or conn.sent_ts:
                self._terminalize(conn, _mono())
        self._apply_cpu_verdict()

    # --- report ---

    def report(self):
        for p in ("warmup", "measure"):
            planned = self.planned_warmup if p == "warmup" else self.planned_measure
            split = self.counts["admitted"][p] + self.counts["backpressure"][p] \
                + self.counts["missed_end"][p]
            if split != planned:
                self.failures["accounting"] = True
            if self.counts["admitted"][p] != (
                    self.counts["sent"][p] + self.counts["send_failed"][p]
                    + self.counts["offered_unsent"][p]):
                self.failures["accounting"] = True
            if self.counts["sent"][p] != (
                    self.counts["echoed"][p] + self.counts["unechoed"][p]):
                self.failures["accounting"] = True
        clean_counts = all(self.counts[k]["measure"] == 0 for k in
                           ("backpressure", "missed_end", "offered_unsent",
                            "send_failed", "unechoed", "timeout", "conn_errors",
                            "protocol"))
        fulfilled = clean_counts and not self.failures
        window_dt = (self.window_end - self.warmup_end
                     if self.window_end and self.warmup_end else 0.0)
        report = {
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "kind": self.args.kind,
            "mode": self.args.mode,
            "verdict": "invalid" if self.failures else "valid",
            "valid": not bool(self.failures),
            "workload_fulfilled": fulfilled,
            "reasons": sorted(str(k) for k in self.failures),
            "identity": _identity_block(),
            "params": {
                "conns": self.args.conns,
                "frame_payload": FRAME_PAYLOAD,
                "frame_header": FRAME_HDR_LEN,
                "target_mbps": self.args.target_mbps,
                "target_bytes_per_s": self.target_bps,
                "warmup_s": self.args.warmup,
                "measure_s": self.args.seconds,
                "interval_s": self.interval,
                "planned_warmup_frames": self.planned_warmup,
                "planned_measure_frames": self.planned_measure,
                "measure_remainder_bytes": self.remainder_bytes["measure"],
                "outstanding_cap_frames": OUTSTANDING_FRAMES_CAP,
                "outstanding_cap_bytes": OUTSTANDING_BYTES_CAP,
                "setup_deadline_s": SETUP_DEADLINE,
                "drain_deadline_s": DRAIN_DEADLINE,
            },
            "phases": {
                p: {
                    "planned_frames": self.planned_warmup if p == "warmup"
                                      else self.planned_measure,
                    "planned_payload_bytes": (self.planned_warmup if p == "warmup"
                                              else self.planned_measure) * FRAME_PAYLOAD
                                             + self.remainder_bytes[p],
                    "admitted": self.counts["admitted"][p],
                    "backpressure_unsent": self.counts["backpressure"][p],
                    "missed_at_end": self.counts["missed_end"][p],
                    "offered_unsent": self.counts["offered_unsent"][p],
                    "sent": self.counts["sent"][p],
                    "send_failed": self.counts["send_failed"][p],
                    "echoed": self.counts["echoed"][p],
                    "unechoed": self.counts["unechoed"][p],
                    "conn_errors": self.counts["conn_errors"][p],
                    "protocol": self.counts["protocol"][p],
                    "timeout": self.counts["timeout"][p],
                    "accepted_frame_bytes": self.counts["sent"][p] * FRAME_SIZE
                                            + self.partial_accepted_frame[p],
                    "accepted_payload_bytes": self.counts["sent"][p] * FRAME_PAYLOAD
                                              + self.partial_accepted_payload[p],
                    "partial_accepted_frame_bytes": self.partial_accepted_frame[p],
                    "partial_accepted_payload_bytes": self.partial_accepted_payload[p],
                    "echoed_frame_bytes": self.counts["echoed"][p] * FRAME_SIZE,
                    "echoed_payload_bytes": self.counts["echoed"][p] * FRAME_PAYLOAD,
                }
                for p in ("warmup", "measure")
            },
            "interval_vs_cohort": {
                "measurement_window_s": window_dt,
                "achieved_client_payload_mbps": (
                    (self.timing["in_window_sent_payload_bytes"] / window_dt)
                    * 8.0 / 1_000_000.0 if window_dt > 0 else None),
                "in_window_sent_frames": self.timing["in_window_sent_frames"],
                "in_window_sent_payload_bytes": self.timing["in_window_sent_payload_bytes"],
                "in_window_echoed_frames": self.timing["in_window_echoed_frames"],
                "in_window_echoed_payload_bytes": self.timing["in_window_echoed_payload_bytes"],
                "drain_sent_frames": self.timing["drain_sent_frames"],
                "drain_sent_payload_bytes": self.timing["drain_sent_payload_bytes"],
                "drain_echoed_frames": self.timing["drain_echoed_frames"],
                "drain_echoed_payload_bytes": self.timing["drain_echoed_payload_bytes"],
            },
            "latency": self._latency_report(),
            "sampling": {label: self.sampler.window_summary(
                             label, self.warmup_end, self.window_end)
                         for label, _pid in self.sampler.labels},
            "window": {
                "origin_monotonic": self.origin,
                "warmup_end": self.warmup_end,
                "window_end": self.window_end,
                "drain_end": self.drain_end,
            },
            "measurement_notes": (
                "latency histograms contain only measurement-cohort echoes that "
                "completed in-window; completion timestamps are captured after "
                "the successful send/recv return; frames returned in one recv "
                "chunk share that single post-recv completion time; sampling "
                "aggregates are bounded by the observed measurement aperture "
                "(explicit start/end boundary tick observations, observed "
                "timestamps and boundary lag disclosed; not exact scheduled-"
                "window isolation), VmHWM is the process lifetime high-water "
                "mark; no invented latency threshold is applied."),
        }
        return report

    def _latency_report(self):
        out = {}
        for name, h in self.hists.items():
            out[name] = {
                "count": h.count,
                "p50_us": h.quantile(0.50) if h.count else None,
                "p95_us": h.quantile(0.95) if h.count else None,
                "p99_us": h.quantile(0.99) if h.count else None,
                "max_us": h.exact_max_us,
                "overflow_count": h.overflow,
                "bin_us": h.bin_us,
            }
        return out


# --------------------------------------------------------------------------
# selftest (clean + corruption + swallow + histogram + owner-boundary checks)
# --------------------------------------------------------------------------

def _gen_ca_and_cert(tmpdir):
    ca_key = os.path.join(tmpdir, "ca.key")
    ca_pem = os.path.join(tmpdir, "ca.pem")
    key = os.path.join(tmpdir, "server.key")
    csr = os.path.join(tmpdir, "server.csr")
    pem = os.path.join(tmpdir, "server.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", ca_key, "-out", ca_pem, "-days", "2", "-nodes",
                    "-subj", "/CN=bench-ca"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-keyout", key,
                    "-out", csr, "-days", "2", "-nodes", "-subj", "/CN=example.com"],
                   check=True, capture_output=True)
    with open(os.path.join(tmpdir, "ext.cnf"), "w") as fh:
        fh.write("subjectAltName=DNS:example.com\n")
    subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_pem,
                    "-CAkey", ca_key, "-CAcreateserial", "-out", pem, "-days", "1",
                    "-extfile", os.path.join(tmpdir, "ext.cnf")],
                   check=True, capture_output=True)
    return pem, key, ca_pem


def _make_client_args(backend_port, backend_pid, temp=None, warmup=0.0,
                      seconds=0.5, target_mbps=40.0, conns=2, proxy_pid=None,
                      mode="proxyless"):
    return argparse.Namespace(
        mode=mode, target_addr=("127.0.0.1", backend_port),
        peer_host="example.com", peer_port=backend_port, cafile=temp, ctx=None,
        tunnel=None, conns=conns, target_mbps=target_mbps, warmup=warmup,
        seconds=seconds, kind="smoke", backend_pid=backend_pid,
        proxy_pid=proxy_pid, json_out=None,
        proxy_host="127.0.0.1", proxy_port=8080,
        backend_addr="127.0.0.1", backend_port=backend_port)


def _run_proxyless(tmpdir, seconds, target_mbps, conns, warmup=0.0, **backend_kw):
    pem, key, ca_pem = _gen_ca_and_cert(tmpdir)
    backend = EchoBackend(("127.0.0.1", 0), pem, key, deadline=30.0, **backend_kw)
    backend.start()
    time.sleep(0.2)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=ca_pem)
    args = _make_client_args(backend.port(), os.getpid(), temp=ca_pem,
                             warmup=warmup, seconds=seconds,
                             target_mbps=target_mbps, conns=conns)
    args.ctx = ctx
    run = ClientRun(args)
    run.setup()
    run.run()
    rep = run.report()
    backend.stop()
    backend.join(timeout=5.0)
    return rep


class _StubTls:
    """Deterministic non-blocking TLS stub: returns scripted results per call."""

    def __init__(self, send_results=("want-relay",), recv_results=()):
        self.send_results = list(send_results)
        self.recv_results = list(recv_results)
        self.send_calls = 0
        self.recv_calls = 0

    def send(self, data):
        self.send_calls += 1
        step = self.send_results[min(self.send_calls - 1,
                                     len(self.send_results) - 1)]
        if step == "want-read":
            raise ssl.SSLWantReadError(2, "want read")
        if step == "want-write":
            raise ssl.SSLWantWriteError(3, "want write")
        if step == "err":
            raise OSError("injected send failure")
        return step

    def recv(self, n):
        self.recv_calls += 1
        step = self.recv_results[min(self.recv_calls - 1,
                                     len(self.recv_results) - 1)]
        if step == "want-read":
            raise ssl.SSLWantReadError(2, "want read")
        if step == "want-write":
            raise ssl.SSLWantWriteError(3, "want write")
        if step == "eof":
            return b""
        if step == "err":
            raise OSError("injected recv failure")
        return step

    def close(self):
        pass

    def version(self):
        return "TLSv1.3"


class _DelayTls:
    """Real-behaviour TLS stub that sleeps before returning, to prove that
    completion timestamps are captured after the I/O return."""

    def __init__(self, send_n=FRAME_SIZE, first_recv=b"", delay=0.04):
        self.send_n = send_n
        self.first_recv = first_recv
        self.delay = delay
        self.send_calls = 0
        self.recv_calls = 0

    def send(self, data):
        self.send_calls += 1
        time.sleep(self.delay)
        return min(self.send_n, len(data))

    def recv(self, n):
        self.recv_calls += 1
        time.sleep(self.delay)
        if self.recv_calls == 1:
            return self.first_recv
        return b""

    def close(self):
        pass

    def version(self):
        return "TLSv1.3"


def _mk_run():
    a = argparse.Namespace(mode="proxyless", target_addr=("127.0.0.1", 1),
        peer_host="example.com", peer_port=1, cafile=None, ctx=None,
        conns=1, target_mbps=40.0, warmup=0.5, seconds=1.0, kind="smoke",
        backend_pid=None, proxy_pid=None, json_out=None,
        backend_addr="127.0.0.1", backend_port=1,
        proxy_host="127.0.0.1", proxy_port=8080)
    r = ClientRun(a)
    # real monotonic base so subsequent _mono() calls (cutoff checks, post-IO
    # stamps, pre/post assertions) stay coherent with self.window_end.
    base = _mono()
    r.origin = base
    r.warmup_end = base + 1000.0
    r.window_end = r.warmup_end + 1.0
    r.drain_end = r.window_end + DRAIN_DEADLINE
    conn = _Conn(0, _StubTls())
    r.conns = [conn]
    return r, conn


def run_selftest(tmpdir):
    if not os.path.isdir(tmpdir):
        os.makedirs(tmpdir, exist_ok=True)
    checks = []

    def check(name, cond, detail=""):
        checks.append((name, bool(cond), detail))

    # 1) clean proxyless byte-exact run: valid, fulfilled, conserved
    try:
        rep = _run_proxyless(tmpdir, seconds=0.5, target_mbps=40.0, conns=2)
    except Exception as exc:  # noqa: BLE001
        check("run-clean", False, "%r" % exc)
        rep = None
    if rep is not None:
        m = rep["phases"]["measure"]
        check("valid", rep["valid"], "reasons=%r" % rep["reasons"])
        check("fulfilled", rep["workload_fulfilled"])
        check("conservation-planned",
              m["admitted"] + m["backpressure_unsent"] + m["missed_at_end"]
              == m["planned_frames"],
              "admitted=%d bp=%d missed=%d planned=%d" % (
                  m["admitted"], m["backpressure_unsent"], m["missed_at_end"],
                  m["planned_frames"]))
        check("admitted-conserved",
              m["admitted"] == m["sent"] + m["send_failed"] + m["offered_unsent"],
              "admitted=%d sent=%d failed=%d unsent=%d" % (
                  m["admitted"], m["sent"], m["send_failed"], m["offered_unsent"]))
        check("echo-conserved", m["sent"] == m["echoed"] + m["unechoed"],
              "sent=%d echoed=%d unechoed=%d" % (m["sent"], m["echoed"], m["unechoed"]))
        check("admitted-echoed", m["admitted"] > 0 and
              m["admitted"] == m["echoed"],
              "admitted=%d echoed=%d" % (m["admitted"], m["echoed"]))
        check("tls13-latency", rep["latency"]["sched_to_echo"]["count"] > 0)
        ivc = rep["interval_vs_cohort"]
        check("in-window-echoed",
              ivc["in_window_echoed_frames"] + ivc["drain_echoed_frames"]
              == m["echoed"] and
              ivc["in_window_echoed_frames"] ==
              rep["latency"]["sched_to_echo"]["count"] and
              ivc["in_window_sent_frames"] == m["sent"],
              "inwin=%d drain=%d echoed=%d hist=%d sent=%d" % (
                  ivc["in_window_echoed_frames"], ivc["drain_echoed_frames"],
                  m["echoed"], rep["latency"]["sched_to_echo"]["count"],
                  m["sent"]))
        check("identity-tool-sha",
              bool(rep["identity"]["tool_sha256"]) and
              len(rep["identity"]["tool_sha256"]) == 64,
              "tool_sha256=%r" % rep["identity"]["tool_sha256"])

    # 2) corruption injection -> invalid corruption
    try:
        rep = _run_proxyless(tmpdir, seconds=0.4, target_mbps=40.0, conns=2,
                             corrupt_seq_lt=1)
        check("corruption-invalid", (not rep["valid"]) and
              any("corruption" in r for r in rep["reasons"]),
              "reasons=%r" % rep["reasons"])
    except Exception as exc:  # noqa: BLE001
        check("corruption-invalid", False, "%r" % exc)

    # 3) swallow after seq -> invalid missing-bytes
    try:
        rep = _run_proxyless(tmpdir, seconds=0.4, target_mbps=40.0, conns=2,
                             swallow_after=8)
        check("swallow-invalid", (not rep["valid"]) and
              any("missing-bytes" in r for r in rep["reasons"]),
              "reasons=%r" % rep["reasons"])
    except Exception as exc:  # noqa: BLE001
        check("swallow-invalid", False, "%r" % exc)

    # 4) histogram overflow truthfulness (C6)
    h = Histogram()
    h.add(LIN_MAX_US - 1)
    h.add(LIN_MAX_US + 50)
    check("hist-max", h.exact_max_us == LIN_MAX_US + 50,
          "max=%r" % h.exact_max_us)
    check("hist-overflow-count", h.overflow == 1, "overflow=%d" % h.overflow)
    q99 = h.quantile(0.99)
    check("hist-q99-overflow-bound", q99 is not None and q99["overflow"],
          "q99=%r" % q99)

    # --- B1: readiness matrix + per-state interest (pure decision checks) ---
    r0, c0 = _mk_run()
    cases = [
        ("send", "w", selectors.EVENT_WRITE, True, "send wants write, write event"),
        ("send", "w", selectors.EVENT_READ, False, "send wants write, read-only event"),
        ("send", "r", selectors.EVENT_READ, True, "send wants read, read event"),
        ("send", "r", selectors.EVENT_WRITE, False, "send wants read, write-only event"),
        ("recv", "r", selectors.EVENT_READ, True, "recv wants read, read event"),
        ("recv", "r", selectors.EVENT_WRITE, False, "recv wants read, write-only event"),
        ("recv", "w", selectors.EVENT_WRITE, True, "recv wants write, write event"),
        ("recv", "w", selectors.EVENT_READ, False, "recv wants write, read-only event"),
        (None, "r", selectors.EVENT_READ, True, "idle, read event"),
        (None, "w", selectors.EVENT_WRITE, False, "idle must not dispatch on write"),
    ]
    for i, (pending, want, mask, exp, label) in enumerate(cases):
        r0.conns[0].pending = pending
        r0.conns[0].want = want
        check("b1-ready-%02d" % i,
              r0._ready_for(r0.conns[0], mask) is exp, label)
    for i, (pending, want, exp_int) in enumerate([
            ("send", "w", selectors.EVENT_WRITE),
            ("send", "r", selectors.EVENT_READ),
            ("recv", "r", selectors.EVENT_READ),
            ("recv", "w", selectors.EVENT_WRITE),
            (None, None, selectors.EVENT_READ)]):
        r0.conns[0].pending = pending
        r0.conns[0].want = want
        check("b1-interest-%02d" % i, r0._interest(r0.conns[0]) == exp_int,
              "pending=%r want=%r -> %d (want %d)" % (
                  pending, want, r0._interest(r0.conns[0]), exp_int))

    # --- B1: admission must never overwrite an interrupted recv ---
    r1, c1 = _mk_run()
    c1.pending = "recv"
    c1.want = "w"
    r1._admit(c1, 0, "measure", r1.origin)
    check("b1-admit-keeps-pending-recv",
          c1.pending == "recv" and c1.want == "w" and c1.cur is not None,
          "pending=%r want=%r cur=%r" % (c1.pending, c1.want, c1.cur))
    c1.pending = None
    c1.want = None
    r1._admit(c1, 1, "measure", r1.origin)
    check("b1-admit-claims-idle-slot",
          c1.pending == "send" and c1.want == "w",
          "pending=%r want=%r" % (c1.pending, c1.want))

    # --- B2: dispatch-cutoff never starts post-window work; interrupted keeps ---
    r2, c2 = _mk_run()
    f = _Frame(0, 0, "measure")
    f.ts_admit = r2.origin
    f.off = 0
    f.sent_attempt = False
    c2.cur = f
    c2.pending = "send"
    c2.want = "w"
    r2._try_send(c2, r2.window_end + 0.1)
    check("b2-no-new-write-past-window",
          c2.cur is None and c2.pending is None and
          r2.counts["offered_unsent"]["measure"] == 1 and
          c2.tls.send_calls == 0,
          "cur=%r pending=%r unsent=%d send_calls=%d" % (
              c2.cur, c2.pending, r2.counts["offered_unsent"]["measure"],
              c2.tls.send_calls))
    f2 = _Frame(0, 1, "measure")
    f2.sent_attempt = True
    f2.off = 0
    c2.cur = f2
    c2.pending = "send"
    c2.want = "w"
    c2.tls.send_results = ["want-read"]
    r2._try_send(c2, r2.window_end + 0.1)
    check("b2-interrupted-write-continues-drain",
          c2.cur is f2 and c2.pending == "send" and c2.want == "r" and
          c2.tls.send_calls == 1 and
          r2.counts["offered_unsent"]["measure"] == 1,
          "cur=%r pending=%r want=%r calls=%d unsent=%d" % (
              c2.cur, c2.pending, c2.want, c2.tls.send_calls,
              r2.counts["offered_unsent"]["measure"]))

    # --- B2: window-end classification uses attempt flag, not off==0 ---
    r3, c3 = _mk_run()
    fa = _Frame(0, 0, "measure")
    fa.sent_attempt = True
    fa.off = 0
    c3.cur = fa
    c3.pending = "send"
    c3.want = "w"
    r3._handle_window_end(r3.window_end)
    check("b2-window-end-keeps-attempted",
          c3.cur is fa and c3.pending == "send",
          "cur=%r pending=%r" % (c3.cur, c3.pending))
    rb, cb = _mk_run()
    fb = _Frame(0, 0, "measure")
    fb.sent_attempt = False
    cb.cur = fb
    cb.pending = "send"
    cb.want = "w"
    rb._handle_window_end(rb.window_end)
    check("b2-window-end-unsent-never-attempted",
          cb.cur is None and
          rb.counts["offered_unsent"]["measure"] == 1,
          "cur=%r unsent=%d" % (cb.cur, rb.counts["offered_unsent"]["measure"]))

    # --- B3: echo eligibility by ordered sent population ---
    r4, c4 = _mk_run()
    c4.sent_queue.append(8)
    c4.sent_ts[8] = r4.origin + 0.1
    r4._handle_echo(c4, 8, frame_payload(0, 8), r4.origin + 0.2)
    check("b3-skipped-slot-valid-echo",
          not r4.failures and c4.echoed_count == 1,
          "failures=%r echoed=%d" % (r4.failures, c4.echoed_count))
    r5, c5 = _mk_run()
    c5.sent_queue.append(8)
    c5.sent_ts[8] = r5.origin + 0.1
    r5._handle_echo(c5, 16, frame_payload(0, 16), r5.origin + 0.2)
    check("b3-out-of-order-echo-invalid",
          r5.failures.get("missing-bytes") and r5.failures.get("protocol"),
          "failures=%r" % r5.failures)
    r6, c6 = _mk_run()
    r6._handle_echo(c6, 0, frame_payload(0, 0), r6.origin + 0.2)
    check("b3-premature-echo-invalid",
          r6.failures.get("protocol") and c6.echoed_count == 0,
          "failures=%r echoed=%d" % (r6.failures, c6.echoed_count))

    # --- B3: partial send at terminal is operational-invalid ---
    r7, c7 = _mk_run()
    fp = _Frame(0, 0, "measure")
    fp.sent_attempt = True
    fp.off = 100
    c7.cur = fp
    c7.pending = "send"
    r7._terminalize(c7, r7.window_end + 0.1)
    check("b3-partial-at-terminal-invalid",
          r7.failures.get("operational-error") and
          r7.counts["send_failed"]["measure"] == 1,
          "failures=%r send_failed=%d" % (r7.failures,
                                          r7.counts["send_failed"]["measure"]))

    # --- B4: ts_send captured AFTER the successful send return ---
    r8, _ = _mk_run()
    dt8 = _DelayTls(send_n=FRAME_SIZE, delay=0.04)
    c8 = _Conn(0, dt8)
    r8.conns = [c8]
    f8 = _Frame(0, 0, "measure")
    c8.cur = f8
    c8.pending = "send"
    c8.want = "w"
    pre = _mono()
    r8._try_send(c8, pre)
    post_obs = c8.sent_ts.get(0)
    check("b4-send-ts-after-return",
          c8.cur is None and post_obs is not None and
          (post_obs - pre) >= 0.03,
          "post-prev=%r" % (post_obs - pre if post_obs is not None else None))

    # --- B4: recv completion time after the recv return ---
    r9, _ = _mk_run()
    chunk9 = build_frame(0, 0)
    dt9 = _DelayTls(first_recv=chunk9, delay=0.04)
    c9 = _Conn(0, dt9)
    r9.conns = [c9]
    c9.sent_queue.append(0)
    c9.sent_ts[0] = r9.origin + 0.01
    pre9 = _mono()
    r9._try_recv(c9, pre9)
    check("b4-recv-completion-after-return",
          c9.echoed_count == 1 and c9.last_progress is not None and
          (c9.last_progress - pre9) >= 0.03,
          "echoed=%d last_progress-post-minus-pre=%r" % (
              c9.echoed_count,
              c9.last_progress - pre9 if c9.last_progress is not None else None))

    # --- B5: schedule anchors measurement at warmup_end; hist is measure-only ---
    r10a, _ = _mk_run()
    check("b5-measure-anchor",
          abs(r10a._due(r10a.planned_warmup) - r10a.warmup_end) < 1e-6,
          "due=%r warmup_end=%r" % (
              r10a._due(r10a.planned_warmup), r10a.warmup_end))
    check("b5-warmup-anchor",
          abs(r10a._due(0) - r10a.origin) < 1e-6,
          "due=%r origin=%r" % (r10a._due(0), r10a.origin))
    try:
        rep10 = _run_proxyless(tmpdir, seconds=0.5, target_mbps=40.0, conns=2,
                               warmup=0.5)
        m10 = rep10["phases"]["measure"]
        w10 = rep10["phases"]["warmup"]
        ivc10 = rep10["interval_vs_cohort"]
        check("b5-warmup-not-in-hist",
              rep10["latency"]["sched_to_echo"]["count"] ==
              ivc10["in_window_echoed_frames"] and
              ivc10["in_window_echoed_frames"] + ivc10["drain_echoed_frames"]
              == m10["echoed"] and
              ivc10["in_window_sent_frames"] == m10["sent"],
              "hist=%d inwin=%d drain=%d echoed=%d sent=%d" % (
                  rep10["latency"]["sched_to_echo"]["count"],
                  ivc10["in_window_echoed_frames"],
                  ivc10["drain_echoed_frames"], m10["echoed"], m10["sent"]))
        check("b5-warmup-windowed",
              w10["echoed"] > 0 and
              rep10["latency"]["sched_to_echo"]["count"] <= m10["echoed"],
              "warmup_echoed=%d hist=%d" % (
                  w10["echoed"], rep10["latency"]["sched_to_echo"]["count"]))
    except Exception as exc:  # noqa: BLE001
        check("b5-warmup-not-in-hist", False, "%r" % exc)
        check("b5-warmup-windowed", False, "%r" % exc)

    # --- B6: CPU sampling Unknown never becomes clean ---
    s = ProcSampler([("missing", 2 ** 31 - 1)])
    s.sample()
    s.sample()
    w = s.window_summary("missing", 0.0, 1e18)
    check("b6-missing-pid-unknown", w["unknown"], "summary=%r" % w)
    r11, _ = _mk_run()
    r11.args.mode = "via-proxy"
    r11.args.proxy_pid = 0
    r11.sampler.unknown["client"] = "injected"
    r11._apply_cpu_verdict()
    check("b6-via-proxy-no-pid-invalid",
          r11.failures.get("unknown-cpu") is True,
          "failures=%r" % r11.failures)

    # --- B7: absolute setup deadline is not renewed ---
    import socket as _socket
    pa, pb = _socket.socketpair()
    try:
        start7 = _mono()
        res = read_http_head(pa, _mono() + 0.05)
        elapsed7 = _mono() - start7
        check("b7-absolute-deadline-not-renewed",
              res is None and elapsed7 < 1.0,
              "res=%r elapsed=%.3f" % (res, elapsed7))
    finally:
        pa.close()
        pb.close()

    # --- B8: shell supervision init-before-traps; stop waits + classifies ---
    shell8 = r'''
set -eu
ALU=0; SRV=0; DNSPID=0; CLEANED=0
O8=/tmp/seam_shell8.out
: > "$O8"
stop() { pid="$1"; strict="$2"
    [ "${pid:-0}" -gt 0 ] 2>/dev/null || return 0
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null; w=$?
        if [ "$strict" -eq 1 ]; then echo "early:$w" >> "$O8"; return 1; fi
        echo "already:$w" >> "$O8"; return 0
    fi
    kill -TERM "$pid" 2>/dev/null || true
    waited=0; killed=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge 20 ]; then kill -9 "$pid" 2>/dev/null || true; killed=1; fi
        if [ "$waited" -ge 30 ]; then echo "leak" >> "$O8"; return 1; fi
        sleep 0.05; waited=$((waited+1))
    done
    wait "$pid" 2>/dev/null; w=$?
    case "$w" in
        0|143) echo "term:$w" >> "$O8"; return 0 ;;
        *) echo "abn:$w" >> "$O8"; [ "$strict" -eq 1 ] && return 1 || return 0 ;;
    esac
}
cleanup() { [ "$CLEANED" -eq 1 ] && return 0; CLEANED=1; stop "$DNSPID" 0 || true; stop "$SRV" 0 || true; stop "$ALU" 0 || true; }
trap 'cleanup; exit 130' INT TERM
trap 'rc=$?; cleanup; exit $rc' EXIT
sleep 30 &
ALU=$!
rc=0
stop "$ALU" 1 >> "$O8" 2>&1 || rc=$?
[ "$rc" -eq 0 ]
'''
    proc8 = subprocess.run(["/bin/sh", "-c", shell8], capture_output=True,
                           text=True, timeout=20)
    out8 = ""
    try:
        with open("/tmp/seam_shell8.out") as fh:
            out8 = fh.read()
    except OSError:
        pass
    check("b8-shell-init-stop-waits-classifies",
          proc8.returncode == 0 and "term:" in out8 and
          "abn:" not in out8 and "leak" not in out8,
          "rc=%d out=%r err=%r" % (proc8.returncode, out8, proc8.stderr))

    # --- F1 (alumina-45g9): cutoff preserves interrupted recv direction and
    # the single IO slot. A recv/WANT_WRITE at cutoff must keep want=w; a
    # READ-only event must not dispatch; WRITE must resume the exact receive;
    # discarding a never-attempted frame behind a recv/WANT_WRITE must not
    # erase the receive state. Actual _handle_window_end/_service_events. ---
    fk = collections.namedtuple("Fk", ["data"])
    rfa, cfa = _mk_run()          # F1-A: WRITE-only resumes the exact receive
    cfa.pending = "recv"
    cfa.want = "w"
    cfa.sent_queue.append(7)
    cfa.sent_ts[7] = rfa.origin + 0.1
    cfa.tls.recv_results = ["want-read"]
    rfa._handle_window_end(rfa.window_end)
    check("f1-cutoff-keeps-recv/want-w",
          cfa.pending == "recv" and cfa.want == "w" and rfa.drain_started,
          "pending=%r want=%r drain=%r" % (cfa.pending, cfa.want, rfa.drain_started))
    rfa._service_events([(fk(cfa), selectors.EVENT_WRITE)])
    check("f1-write-resumes-exact-recv",
          cfa.tls.recv_calls == 1 and cfa.pending == "recv" and cfa.want == "r",
          "recv_calls=%d pending=%r want=%r" % (cfa.tls.recv_calls, cfa.pending, cfa.want))
    rfb, cfb = _mk_run()          # F1-B: READ-only must never dispatch
    cfb.pending = "recv"
    cfb.want = "w"
    cfb.sent_queue.append(8)
    cfb.sent_ts[8] = rfb.origin + 0.1
    cfb.tls.recv_results = ["want-read"]
    rfb._handle_window_end(rfb.window_end)
    rfb._service_events([(fk(cfb), selectors.EVENT_READ)])
    check("f1-read-only-no-dispatch",
          cfb.tls.recv_calls == 0 and cfb.pending == "recv" and cfb.want == "w",
          "recv_calls=%d pending=%r want=%r" % (cfb.tls.recv_calls, cfb.pending, cfb.want))
    rfc, cfc = _mk_run()          # F1-C: discard frame, keep interrupted recv
    cfc.pending = "recv"
    cfc.want = "w"
    rfc._admit(cfc, 0, "measure", rfc.origin)
    check("f1-admit-behind-recv/want-w-keeps-slot",
          cfc.cur is not None and cfc.pending == "recv" and cfc.want == "w",
          "cur=%r pending=%r want=%r" % (cfc.cur, cfc.pending, cfc.want))
    rfc._handle_window_end(rfc.window_end)
    check("f1-discard-frame-keeps-recv-state",
          cfc.cur is None and cfc.pending == "recv" and cfc.want == "w" and
          rfc.counts["offered_unsent"]["measure"] == 1 and rfc.outstanding == 0,
          "cur=%r pending=%r want=%r unsent=%d outstanding=%d" % (
              cfc.cur, cfc.pending, cfc.want,
              rfc.counts["offered_unsent"]["measure"], rfc.outstanding))

    # --- F2 (alumina-45g9): terminalize separates an attempted TLS write
    # with zero accepted bytes (send_failed + operational-error, 0 accepted
    # bytes, accounting conserved) from a never-attempted untouched frame
    # (offered_unsent). ---
    rf2a, cf2a = _mk_run()
    fa2 = _Frame(0, 0, "measure")
    fa2.sent_attempt = True
    fa2.off = 0
    cf2a.cur = fa2
    cf2a.pending = "send"
    rf2a.counts["admitted"]["measure"] = 1
    rf2a.outstanding = 1
    rf2a._terminalize(cf2a, rf2a.window_end + 0.1)
    eq2a = (rf2a.counts["admitted"]["measure"] ==
            rf2a.counts["sent"]["measure"] + rf2a.counts["send_failed"]["measure"] +
            rf2a.counts["offered_unsent"]["measure"])
    check("f2-attempted-zero-terminal-invalid",
          rf2a.counts["send_failed"]["measure"] == 1 and
          rf2a.counts["offered_unsent"]["measure"] == 0 and
          rf2a.partial_accepted_frame["measure"] == 0 and
          rf2a.partial_accepted_payload["measure"] == 0 and
          rf2a.failures.get("operational-error") and
          rf2a.outstanding == 0 and eq2a,
          "failed=%d unsent=%d acc=%d payload=%d outstanding=%d eq=%s" % (
              rf2a.counts["send_failed"]["measure"],
              rf2a.counts["offered_unsent"]["measure"],
              rf2a.partial_accepted_frame["measure"],
              rf2a.partial_accepted_payload["measure"],
              rf2a.outstanding, eq2a))
    rf2b, cf2b = _mk_run()
    fb2 = _Frame(0, 0, "measure")
    fb2.sent_attempt = False
    fb2.off = 0
    cf2b.cur = fb2
    cf2b.pending = "send"
    rf2b.counts["admitted"]["measure"] = 1
    rf2b.outstanding = 1
    rf2b._terminalize(cf2b, rf2b.window_end + 0.1)
    check("f2-never-attempted-terminal-unsent",
          rf2b.counts["offered_unsent"]["measure"] == 1 and
          rf2b.counts["send_failed"]["measure"] == 0 and
          rf2b.outstanding == 0 and
          not rf2b.failures.get("operational-error"),
          "unsent=%d failed=%d outstanding=%d op_err=%r" % (
              rf2b.counts["offered_unsent"]["measure"],
              rf2b.counts["send_failed"]["measure"],
              rf2b.outstanding, rf2b.failures.get("operational-error")))
    rf2c, cf2c = _mk_run()        # actual _try_send WANT path, then drain death
    fc2 = _Frame(0, 0, "measure")
    cf2c.cur = fc2
    cf2c.pending = "send"
    cf2c.want = "w"
    cf2c.tls.send_results = ["want-read"]
    rf2c.counts["admitted"]["measure"] = 1
    rf2c.outstanding = 1
    rf2c._try_send(cf2c, rf2c.warmup_end)           # attempt raises WANT pre-window
    rf2c._terminalize(cf2c, rf2c.window_end + 0.1)  # drain ends, no completion
    check("f2-trysend-want-then-terminal",
          cf2c.tls.send_calls == 1 and fc2.off == 0 and fc2.sent_attempt and
          rf2c.counts["send_failed"]["measure"] == 1 and
          rf2c.partial_accepted_payload["measure"] == 0 and
          rf2c.outstanding == 0 and rf2c.failures.get("operational-error"),
          "calls=%d off=%d attempt=%r failed=%d acc=%d outstanding=%d op_err=%r" % (
              cf2c.tls.send_calls, fc2.off, fc2.sent_attempt,
              rf2c.counts["send_failed"]["measure"],
              rf2c.partial_accepted_payload["measure"],
              rf2c.outstanding, rf2c.failures.get("operational-error")))

    # --- F3 (alumina-45g9): observed-aperture CPU selection with explicit
    # start/end boundary baselines, observed timestamps, disclosed boundary
    # lag and typed Unknown; warmup/drain deltas never counted, the terminal
    # observed end delta always included. ---
    def _f3rec(t, ticks, boundary=None, cores=None, dt_s=None, rss=128, hwm=512):
        rec = {"t": t, "ticks": ticks, "vmrss_kb": rss, "vmhwm_kb": hwm,
               "dt_s": dt_s, "cores": cores}
        if boundary is not None:
            rec["boundary"] = boundary
        return rec
    sf3 = ProcSampler([("subject", 1)])
    tb3, te3 = 5.010, 65.020
    sf3.samples["subject"] = [
        _f3rec(4.900, 1_000_000, cores=99.0, dt_s=0.5),
        _f3rec(tb3, 1_010_000, boundary="start", cores=909.0, dt_s=0.110),
        _f3rec(5.500, 1_010_000, cores=0.0, dt_s=0.490),
        _f3rec(5.800, 1_010_000, cores=0.0, dt_s=0.300),
        _f3rec(64.900, 1_059_000, cores=50.0, dt_s=0.300),
        _f3rec(te3, 1_060_000, boundary="end"),
        _f3rec(66.000, 1_500_000, cores=200.0, dt_s=0.980),
    ]
    w3 = sf3.window_summary("subject", 5.0, 65.0)
    exp3 = (1_060_000 - 1_010_000) / CLK_TCK / (te3 - tb3)
    lag3 = w3.get("boundary_lag_s")
    lag_ok = (isinstance(lag3, dict) and lag3.get("start") is not None and
              lag3.get("end") is not None and
              abs(lag3["start"] - 0.010) < 1e-9 and
              abs(lag3["end"] - 0.020) < 1e-9)
    check("f3-mean-observed-aperture",
          not w3.get("unknown") and w3.get("sampled_from") == tb3 and
          w3.get("sampled_to") == te3 and lag_ok and
          w3.get("cores_mean") is not None and
          abs(w3["cores_mean"] - exp3) < 1e-9,
          "unknown=%r from=%r to=%r lag=%r mean=%r exp=%r" % (
              w3.get("unknown"), w3.get("sampled_from"), w3.get("sampled_to"),
              w3.get("boundary_lag_s"), w3.get("cores_mean"), exp3))
    check("f3-peak-excludes-warmup-drain",
          w3.get("cores_peak") == 50.0,
          "peak=%r" % w3.get("cores_peak"))
    check("f3-end-delta-included",
          w3.get("cores_mean") is not None and
          abs(w3["cores_mean"] * (te3 - tb3) -
              (1_060_000 - 1_010_000) / CLK_TCK) < 1e-9,
          "mean=%r" % w3.get("cores_mean"))
    sf3z = ProcSampler([("subject", 1)])
    sf3z.samples["subject"] = [_f3rec(tb3, 10, boundary="start"),
                               _f3rec(te3, 90, boundary="end")]
    w3z = sf3z.window_summary("subject", 5.0, 65.0)
    check("f3-zero-intervals-unknown",
          w3z["unknown"] and "fewer than" in (w3z["reason"] or ""),
          "unknown=%r reason=%r" % (w3z["unknown"], w3z["reason"]))
    sf3o = ProcSampler([("subject", 1)])
    sf3o.samples["subject"] = [_f3rec(tb3, 10, boundary="start"),
                               _f3rec(30.0, 40, cores=1.0, dt_s=1.0),
                               _f3rec(te3, 90, boundary="end")]
    w3o = sf3o.window_summary("subject", 5.0, 65.0)
    check("f3-one-interval-unknown",
          w3o["unknown"] and "fewer than" in (w3o["reason"] or ""),
          "unknown=%r reason=%r" % (w3o["unknown"], w3o["reason"]))
    sf3m = ProcSampler([("subject", 1)])
    sf3m.samples["subject"] = [_f3rec(tb3, 10, boundary="start")]
    w3m = sf3m.window_summary("subject", 5.0, 65.0)
    check("f3-missing-boundary-unknown",
          w3m["unknown"] and "boundary" in (w3m["reason"] or ""),
          "unknown=%r reason=%r" % (w3m["unknown"], w3m["reason"]))
    sf3p = ProcSampler([("subject", 1)])
    sf3p.unknown["subject"] = "injected probe failure"
    sf3p.samples["subject"] = [_f3rec(tb3, 10, boundary="start"),
                               _f3rec(10.0, 20, cores=1.0, dt_s=1.0),
                               _f3rec(11.0, 30, cores=1.0, dt_s=1.0),
                               _f3rec(te3, 90, boundary="end")]
    w3p = sf3p.window_summary("subject", 5.0, 65.0)
    check("f3-failed-probe-unknown",
          w3p["unknown"], "unknown=%r reason=%r" % (w3p["unknown"], w3p["reason"]))

    # --- direct-proxy (qryg.9 native runner): opaque-proxy route sampling. The
    # route carries direct TLS to the proxy (no CONNECT handshake) yet the proxy
    # remains a required CPU subject, reported under a neutral label distinct
    # from via-proxy and proxyless. ---
    r12, _c12 = _mk_run()
    r12.args.mode = "direct-proxy"
    r12.args.proxy_pid = 0
    r12.sampler.unknown["client"] = "injected"
    r12._apply_cpu_verdict()
    check("direct-proxy-no-pid-invalid",
          r12.failures.get("unknown-cpu") is True,
          "failures=%r" % r12.failures)
    check("direct-proxy-target-is-proxy",
          route_target_addr("direct-proxy", "127.0.0.1", 8080, "8.8.8.8", 443)
          == ("127.0.0.1", 8080) and
          route_target_addr("via-proxy", "127.0.0.1", 8080, "8.8.8.8", 443)
          == ("127.0.0.1", 8080) and
          route_target_addr("proxyless", "127.0.0.1", 8080, "8.8.8.8", 443)
          == ("8.8.8.8", 443),
          "route target must track the client mode")
    r13, _c13 = _mk_run()
    r13.args.mode = "direct-proxy"
    r13.args.proxy_pid = 4242
    sf3b = ProcSampler([("proxy", 4242), ("client", os.getpid())])
    sf3b.samples["proxy"] = [
        _f3rec(4.0, 1_000_000),
        _f3rec(5.0, 1_010_000, boundary="start", cores=5.0, dt_s=0.2),
        _f3rec(30.0, 1_090_000, cores=5.0, dt_s=0.2),
        _f3rec(60.0, 1_150_000, cores=5.0, dt_s=0.2),
        _f3rec(65.0, 1_200_000, boundary="end"),
    ]
    sf3b.samples["client"] = list(sf3b.samples["proxy"])
    r13.sampler = sf3b
    r13.sampler.unknown = {}
    r13._apply_cpu_verdict()
    check("direct-proxy-cpu-required-known",
          r13.failures.get("unknown-cpu") is None,
          "failures=%r" % r13.failures)
    w13 = sf3b.window_summary("proxy", 5.0, 65.0)
    check("direct-proxy-proxy-sampled",
          not w13.get("unknown") and w13.get("cores_mean") is not None,
          "summary=%r" % w13)

    # --- F4 (alumina-45g9): strict supervision fails the session on a forced
    # SIGKILL for every required child label. Exercises the ACTUAL stop()
    # body extracted from scripts/seam_echo.sh, not a copy. ---
    seamsh = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seam_echo.sh")
    with open(seamsh, "rb") as fh:
        f4_lines = fh.read().splitlines()
    f4_start = next(i for i, l in enumerate(f4_lines) if l.startswith(b"stop() {"))
    f4_end = next(i for i in range(f4_start + 1, len(f4_lines))
                  if f4_lines[i].strip() == b"}")
    f4_stop = b"\n".join(f4_lines[f4_start:f4_end + 1]).decode()
    f4_probe = (
        "set -eu\n"
        "OUT=/tmp/f4.$$\n"
        ": > \"$OUT\"\n"
        + f4_stop +
        "\n"
        "caseA() { pid=\"$1\"; set +e; stop \"$pid\" backend 1 >> \"$OUT\" 2>&1; "
        "echo \"rcA=$?\" >> \"$OUT\"; set -e; }\n"
        "caseB() { pid=\"$1\"; set +e; stop \"$pid\" backend 1 >> \"$OUT\" 2>&1; "
        "echo \"rcB=$?\" >> \"$OUT\"; set -e; }\n"
        "caseC() { pid=\"$1\"; set +e; stop \"$pid\" backend 1 >> \"$OUT\" 2>&1; "
        "echo \"rcC=$?\" >> \"$OUT\"; set -e; }\n"
        "# A: TERM-ignoring backend child -> strict forced kill must fail\n"
        "sh -c 'trap \"\" TERM; sleep 30' &\n"
        "a=$!\nsleep 0.2\n"
        "caseA \"$a\"\n"
        "# B: expected TERM -> strict reap ok\n"
        "sleep 30 &\n"
        "caseB \"$!\"\n"
        "# C: already-dead abnormal -> strict reap fails\n"
        "sh -c 'exit 2' &\n"
        "c=$!\nwait \"$c\" || true\n"
        "caseC \"$c\"\n"
        "cat \"$OUT\"\n")
    f4_res = subprocess.run(["/bin/sh", "-c", f4_probe], capture_output=True,
                            text=True, timeout=40)
    def _f4rc(tag, out):
        for ln in out.splitlines():
            if ln.startswith(tag):
                return ln.split("=", 1)[1]
        return None
    f4_out = f4_res.stdout
    check("f4-forced-kill-strict-fails",
          f4_res.returncode == 0 and _f4rc("rcA=", f4_out) == "1" and
          "forced SIGKILL" in f4_out,
          "probe_rc=%r rcA=%r out=%r" % (
              f4_res.returncode, _f4rc("rcA=", f4_out), f4_out))
    check("f4-expected-term-strict-ok",
          _f4rc("rcB=", f4_out) == "0", "out=%r" % f4_out)
    check("f4-already-dead-strict-fails",
          _f4rc("rcC=", f4_out) == "1", "out=%r" % f4_out)

    # --- B9: identity receipt block carries tool hash + controls ---
    blk9 = _identity_block()
    check("b9-identity-tool-sha",
          bool(blk9.get("tool_sha256")) and len(blk9["tool_sha256"]) == 64,
          "tool_sha256=%r" % blk9.get("tool_sha256"))
    saved = {}
    for k, v in (("BENCH_SOURCE_HEAD", "deadbeef"), ("BENCH_IMAGE_ID", "img1"),
                 ("BENCH_RUST_TARGET", "aarch64-unknown-linux-musl"),
                 ("BENCH_BINARY_SHA256", "b1"), ("BENCH_CONFIG_SHA", "c1")):
        saved[k] = os.environ.get(k)
        os.environ[k] = v
    try:
        blk9b = _identity_block()
        check("b9-identity-controls",
              blk9b["source_head"] == "deadbeef" and
              blk9b["image_id"] == "img1" and
              blk9b["rust_target"] == "aarch64-unknown-linux-musl" and
              blk9b["retained_binary_sha256"] == "b1" and
              blk9b["config_sha256"] == "c1",
              "source_head=%r image_id=%r rust=%r bin=%r cfg=%r" % (
                  blk9b["source_head"], blk9b["image_id"],
                  blk9b["rust_target"], blk9b["retained_binary_sha256"],
                  blk9b["config_sha256"]))
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    ok = all(c[1] for c in checks)
    for name, passed, detail in checks:
        print("  %s %s %s" % ("PASS" if passed else "FAIL", name, detail),
              flush=True)
    return 0 if ok else 1


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _nonfinite(v):
    try:
        f = float(v)
        return not (f == f and f < float("inf"))
    except (TypeError, ValueError):
        return True


def route_target_addr(mode, proxy_host, proxy_port, backend_addr, backend_port):
    if mode == "proxyless":
        return (backend_addr, backend_port)
    return (proxy_host, proxy_port)


def _build_client_ctx(cafile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=cafile)
    return ctx


def main(argv):
    ap = argparse.ArgumentParser(prog=TOOL_NAME, description=__doc__)
    ap.add_argument("--role", required=True,
                    choices=["backend", "client", "dns-responder", "selftest"])
    ap.add_argument("--mode", choices=["proxyless", "via-proxy", "direct-proxy"],
                    default="proxyless")
    ap.add_argument("--backend-addr", default="127.0.0.1")
    ap.add_argument("--backend-port", type=int, default=443)
    ap.add_argument("--proxy-host", default="127.0.0.1")
    ap.add_argument("--proxy-port", type=int, default=8080)
    ap.add_argument("--peer-host", default="example.com")
    ap.add_argument("--peer-port", type=int, default=443)
    ap.add_argument("--cafile")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--dns-bind", default="127.0.0.1:53")
    ap.add_argument("--dns-answer", action="append", default=[])
    ap.add_argument("--conns", type=int, default=DEFAULT_CONNS)
    ap.add_argument("--target-mbps", type=float, default=DEFAULT_TARGET_MBPS)
    ap.add_argument("--seconds", type=float, default=DEFAULT_SECONDS)
    ap.add_argument("--warmup", type=float, default=DEFAULT_WARMUP)
    ap.add_argument("--kind", choices=["smoke", "timed"], default="timed")
    ap.add_argument("--backend-pid", type=int, default=0)
    ap.add_argument("--proxy-pid", type=int, default=0)
    ap.add_argument("--json-out")
    ap.add_argument("--echo-delay-s", type=float, default=0.0)
    ap.add_argument("--swallow-after", type=int, default=None)
    ap.add_argument("--corrupt-seq-lt", type=int, default=None)
    ap.add_argument("--selftest-tmp", default=None)
    args = ap.parse_args(argv)

    if args.kind == "smoke":
        args.seconds, args.warmup = 2.0, 0.0

    if args.conns < 1 or args.conns > 64:
        print("seam-err: conns must be in [1,64]", file=sys.stderr)
        return 3
    if args.target_mbps <= 0 or args.target_mbps > 2000 or _nonfinite(args.target_mbps):
        print("seam-err: target-mbps out of range", file=sys.stderr)
        return 3
    if args.seconds <= 0 or args.seconds > 600 or _nonfinite(args.seconds):
        print("seam-err: seconds out of range", file=sys.stderr)
        return 3
    if args.warmup < 0 or args.warmup > 120 or _nonfinite(args.warmup):
        print("seam-err: warmup out of range", file=sys.stderr)
        return 3

    if args.role == "selftest":
        return run_selftest(args.selftest_tmp or "/tmp")

    if args.role == "dns-responder":
        host, _, port = args.dns_bind.partition(":")
        answers = {}
        for ans in args.dns_answer:
            name, _, ip = ans.partition(":")
            answers[name.encode()] = socket.inet_aton(ip)
        DnsResponder((host, int(port)), answers).run()
        return 0

    if args.role == "backend":
        if not (args.cert and args.key):
            print("seam-err: backend requires --cert and --key", file=sys.stderr)
            return 3
        backend = EchoBackend(
            (args.backend_addr, args.backend_port), args.cert, args.key,
            deadline=args.warmup + args.seconds + 20.0,
            echo_delay_s=args.echo_delay_s,
            swallow_after=args.swallow_after,
            corrupt_seq_lt=args.corrupt_seq_lt)
        backend.run_forever()
        print("BACKEND-STOP: recv=%d sent=%d conns=%d errors=%d" % (
            backend.bytes_recv, backend.bytes_sent, backend.conns, backend.errors),
            file=sys.stderr, flush=True)
        return 0

    if args.role == "client":
        if args.mode != "proxyless" and not args.proxy_pid:
            print("seam-err: %s measurement requires --proxy-pid "
                  "(CPU evidence for the proxy subject)" % args.mode,
                  file=sys.stderr)
            return 3
        args.target_addr = route_target_addr(
            args.mode, args.proxy_host, args.proxy_port,
            args.backend_addr, args.backend_port)
        try:
            args.ctx = _build_client_ctx(args.cafile)
        except Exception as exc:
            print("seam-err: cafile invalid: %s" % exc, file=sys.stderr)
            return 3
        run = ClientRun(args)
        try:
            run.setup()
        except Exception as exc:
            print("seam-err: setup failed: %s" % exc, file=sys.stderr)
            return 3
        try:
            run.run()
        except Exception as exc:
            print("seam-err: owner loop failed: %s" % exc, file=sys.stderr)
            return 3
        rep = run.report()
        out = json.dumps(rep, indent=2, sort_keys=True)
        if args.json_out:
            try:
                with open(args.json_out, "w") as fh:
                    fh.write(out + "\n")
            except OSError as exc:
                print("seam-err: cannot write report: %s" % exc, file=sys.stderr)
                return 1
            print("REPORT: %s" % args.json_out, flush=True)
        else:
            print(out, flush=True)
        print("SEAM-VERDICT: valid=%s fulfilled=%s reasons=%r exit=%d" % (
            rep["valid"], rep["workload_fulfilled"], rep["reasons"],
            0 if rep["valid"] else 3), flush=True)
        return 0 if rep["valid"] else 3

    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
