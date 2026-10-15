#!/bin/sh
# seam_echo.sh -- run the minimal single-owner stdlib SSLSocket measurement
# seam against the retained native binaries (AS-IS first) or proxyless, inside
# the pinned harness container, foreground, supervised, disposable.
#
# Usage: seam_echo.sh <proxyless|as-is|to-be> <smoke|timed>
# Fixed workload contract (alumina-gjq4): 8 conns, 4096 B frame + 12 B header
# counted separately, open-loop 100 decimal Mbps client payload, 5 s warmup /
# 60 s measure (smoke overrides to 2 s / 0 s), setup/drain 5 s each. No extra
# client args are forwarded (A2).
#
# Topology mirrors scripts/e2e_relay.sh and the reviewed bench supervisor:
# native Linux via rootful podman flock-vm-root, --network none, loopback
# global-unicast alias, DNS-over-TCP responder, binary dropped to uid 65534 via
# setpriv:
#     example.com -> 8.8.8.8   TLS1.3 byte-exact framed echo backend
#                              (seam_echo.py --role backend), genuine CA-signed
#                              cert with SAN example.com validated by the client.
#
#   proxyless: client -> backend directly (no proxy in the path).
#   as-is:     client -> CONNECT via the retained AS-IS alumina binary
#              (sha256 170fae6c..., reused AS-IS, never rebuilt) -> backend.
#   to-be:     client -> CONNECT via the retained TO-BE candidate binary
#              (sha256 8a9f1f5b..., reused, never rebuilt) -> backend; the
#              same config/topology/order as as-is, AS-IS listed first.
#
# Session exit 0 -> client valid + all children reaped cleanly
#              3 -> measurement invalid (honest, reported in JSON)
#              1 -> harness/supervision/protocol failure
set -eu

ROOT="$(pwd)"
MODE="${1:?usage: seam_echo.sh <proxyless|as-is|to-be> <smoke|timed>}"
KIND="${2:?usage: seam_echo.sh <proxyless|as-is|to-be> <smoke|timed>}"
shift 2
if [ "$#" -gt 0 ]; then
    echo "SEAM-BLOCKED: additional args unsupported (fixed workload contract)" >&2
    exit 2
fi
case "$KIND" in smoke|timed) ;; *) echo "SEAM-BLOCKED: kind must be smoke or timed" >&2; exit 2 ;; esac

CONN="${PODMAN_ROOT_CONNECTION:-flock-vm-root}"
E2E_IMAGE="${E2E_IMAGE:-localhost/alumina-e2e:e2e-20261011}"
E2E_IMAGE_ID="9191d288353391e4751525e83196e8127884d73daa395ced6fafc4a96d71564f"
BASE_ID="ad70ceb90f563e9fe2ef7064b92dc1347aeaeb71e5369ba8b242498ba030a6f8"
# Retained native binaries (never rebuilt): AS-IS first, TO-BE later.
ASIS_REL="alumina-vdpi.2/baseline/alumina-musl"
ASIS_SHA="170fae6c1dbfce1907bb2b2ec02599808c4d9404b243ccd24b8834490d3ab72f"
TOBE_REL="alumina-vdpi/tobe/baseline/alumina-musl"
TOBE_SHA="8a9f1f5b288abc1ec649e9a98302caa8e088d1f5e55c432950a59167d869dec8"
# One case both rejects unknown modes and maps every legal mode to its retained
# candidate (empty for proxyless). AS-IS is listed before TO-BE.
case "$MODE" in
    as-is)     CANDIDATE_REL="$ASIS_REL"; CANDIDATE_SHA="$ASIS_SHA" ;;
    to-be)     CANDIDATE_REL="$TOBE_REL"; CANDIDATE_SHA="$TOBE_SHA" ;;
    proxyless) CANDIDATE_REL=""; CANDIDATE_SHA="" ;;
    *) echo "SEAM-BLOCKED: mode must be proxyless, as-is or to-be" >&2; exit 2 ;;
esac
OUTDIR="$ROOT/.ooda/benchmarks"
TS="$(date +%Y%m%dT%H%M%SZ)"
STAMP="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)-seam-$MODE-$KIND-$TS"

command -v podman >/dev/null 2>&1 || { echo "SEAM-BLOCKED: podman required" >&2; exit 1; }
podman --connection "$CONN" info >/dev/null 2>&1 || {
    echo "SEAM-BLOCKED: rootful podman connection $CONN unreachable" >&2; exit 1; }
id=$(podman --connection "$CONN" image inspect "$E2E_IMAGE" --format '{{.Id}}' 2>/dev/null || echo "?")
[ "$id" = "$E2E_IMAGE_ID" ] || {
    echo "SEAM-BLOCKED: harness tag '$E2E_IMAGE' resolves to '$id', not $E2E_IMAGE_ID" >&2
    exit 1
}
parent=$(podman --connection "$CONN" image inspect "$E2E_IMAGE_ID" --format '{{.Parent}}' 2>/dev/null || echo "?")
[ "$parent" = "$BASE_ID" ] || {
    echo "SEAM-BLOCKED: harness image parent mismatch (got $parent, want $BASE_ID)" >&2
    exit 1
}
echo "SEAM-HARNESS-IMAGE: $E2E_IMAGE (id $E2E_IMAGE_ID, conn $CONN, mode $MODE, kind $KIND)"

BENCH_SOURCE_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
BENCH_DIRTY_COUNT="$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
BENCH_RUST_TARGET="aarch64-unknown-linux-musl"
BENCH_BINARY_SHA256=""
ASIS_REL_SAFE="$ASIS_REL"

if [ -n "$CANDIDATE_REL" ]; then
    [ -f "$ROOT/.ooda/$CANDIDATE_REL" ] || {
        echo "SEAM-BLOCKED: retained $MODE binary missing (.ooda/$CANDIDATE_REL)" >&2; exit 1; }
    computed=$(shasum -a 256 "$ROOT/.ooda/$CANDIDATE_REL" | awk '{print $1}')
    [ "$computed" = "$CANDIDATE_SHA" ] || {
        echo "SEAM-BLOCKED: retained $MODE binary identity mismatch (got $computed)" >&2
        exit 1
    }
    BENCH_BINARY_SHA256="$CANDIDATE_SHA"
    echo "SEAM-BINARY-IDENTITY: .ooda/$CANDIDATE_REL sha256=$CANDIDATE_SHA (retained $MODE, reused)"
fi

[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"

if [ "$KIND" = "smoke" ]; then
    SECONDS=2
    WARMUP=0
else
    SECONDS=60
    WARMUP=5
fi

stage=$(cat <<'SNIP'
set -eu
mkdir -p /work /out
printf '%s\n' \
    'allowlist = ["example.com:443"]' \
    'listen = "127.0.0.1:8080"' \
    'startup_unresolved_allowance = 0' \
    '[any_illegal]' \
    'scope = "connection"' \
    '[actions]' \
    'kind = ["flare_only"]' \
    'scope = ["connection"]' > /work/config.toml
printf '%s\n' 'nameserver 127.0.0.1' > /work/resolv.conf
# genuine CA + endpoint cert: client validates chain and SAN=example.com
openssl req -x509 -newkey rsa:2048 -keyout /work/ca.key -out /work/ca.pem \
    -days 2 -nodes -subj "/CN=bench-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -keyout /work/server.key -out /work/server.csr \
    -days 2 -nodes -subj "/CN=example.com" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:example.com' > /work/ext.cnf
openssl x509 -req -in /work/server.csr -CA /work/ca.pem -CAkey /work/ca.key \
    -CAcreateserial -out /work/server.pem -days 1 -extfile /work/ext.cnf >/dev/null 2>&1
chown -R 65534:65534 /work
SNIP
)

run=$(cat <<'SNIP'
set -eu
cd /work
ip addr add 8.8.8.8/32 dev lo

# Acquisition slots are initialized before any trap is installed so a failure
# at any point still reaps every owned child (B8). One idempotent supervision
# owner handles both the normal teardown (strict) and the trap path (lenient).
ALU=0
SRV=0
DNSPID=0
CLEANED=0
stop() {
    pid="$1"
    label="$2"
    strict="$3"
    [ "${pid:-0}" -gt 0 ] 2>/dev/null || return 0
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null; w=$?
        if [ "$strict" -eq 1 ]; then
            echo "  SEAM-REAP-FAIL: $label pid $pid exited before reap (status $w) -- unexpected death" >&2
            return 1
        fi
        echo "  SEAM-CLEANUP: $label pid $pid already exited (status $w)" >&2
        return 0
    fi
    kill -TERM "$pid" 2>/dev/null || true
    waited=0
    killed=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge 30 ]; then
            kill -9 "$pid" 2>/dev/null || true
            killed=1
        fi
        if [ "$waited" -ge 50 ]; then
            echo "  SEAM-REAP-FAIL: $label pid $pid leaked after TERM+SIGKILL grace" >&2
            return 1
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
    wait "$pid" 2>/dev/null; w=$?
    if [ "$killed" -eq 1 ]; then
        echo "  SEAM-REAP: $label pid $pid forced SIGKILL after TERM grace (status $w)" >&2
        if [ "$strict" -eq 1 ]; then
            # a required child that needed SIGKILL is not a clean supervised
            # exit; the session is harness-failed for every label, not just the
            # measured subject.
            echo "  SEAM-REAP-FAIL: $label did not exit on TERM" >&2
            return 1
        fi
        return 0
    fi
    if [ "$w" -eq 0 ] || [ "$w" -eq 143 ]; then
        echo "  SEAM-REAP: $label pid $pid via TERM (status $w)" >&2
        return 0
    fi
    echo "  SEAM-REAP-FAIL: $label pid $pid abnormal TERM status $w" >&2
    if [ "$strict" -eq 1 ]; then
        return 1
    fi
    return 0
}
cleanup() {
    [ "$CLEANED" -eq 1 ] && return 0
    CLEANED=1
    stop "$ALU" alumina 0 || true
    stop "$SRV" backend 0 || true
    stop "$DNSPID" dns 0 || true
    return 0
}
trap 'cleanup; exit 130' INT TERM
trap 'rc=$?; cleanup; exit $rc' EXIT

# DNS-over-TCP responder mapping example.com -> 8.8.8.8 (used by as-is proxy)
python3 /app/scripts/seam_echo.py --role dns-responder \
    --dns-bind 127.0.0.1:53 --dns-answer example.com:8.8.8.8 2>/tmp/dns.log &
DNSPID=$!
sleep 0.3

# TLS1.3 byte-exact framed echo backend (genuine CA-signed cert)
python3 /app/scripts/seam_echo.py --role backend \
    --backend-addr 8.8.8.8 --backend-port 443 \
    --cert /work/server.pem --key /work/server.key >/tmp/backend.log 2>&1 &
SRV=$!

python3 - "$SRV" <<'PYEOF'
import socket, sys, time
pid = int(sys.argv[1])
deadline = time.time() + 10
while time.time() < deadline:
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 443)); s.close()
        print("SEAM-BACKEND-READY", flush=True); sys.exit(0)
    except OSError:
        time.sleep(0.2)
sys.exit("backend not listening in time")
PYEOF

ALU=0
ALUARGS=""
if [ -n "$CANDIDATE_REL" ]; then
    install -m 0755 "/ooda/$CANDIDATE_REL" /work/alumina
    setpriv --reuid 65534 --regid 65534 --clear-groups \
        /bin/sh -c "cd /work && exec /work/alumina" >/tmp/alumina.log 2>&1 &
    ALU=$!
    ALUARGS="--proxy-pid $ALU"
    python3 - <<'PYEOF'
import socket, time, sys
deadline = time.time() + 60
while time.time() < deadline:
    try:
        s = socket.create_connection(("127.0.0.1", 8080), timeout=1.0)
        s.close()
        print("SEAM-PROXY-READY", flush=True); sys.exit(0)
    except OSError:
        time.sleep(0.5)
sys.exit("proxy listener never became reachable")
PYEOF
fi

if [ -n "$CANDIDATE_REL" ]; then
    CLIENT_MODE="via-proxy"
else
    CLIENT_MODE="proxyless"
fi
REPORT="/out/$STAMP.json"
driver_rc=0
# B9: attach effective fixed-config and immutable-image identity to the run for
# the reporter; the executed-copy hash is computed in-process by the client.
export BENCH_CONFIG_SHA="$(sha256sum /work/config.toml 2>/dev/null | awk '{print $1}' || true)"
export BENCH_IMAGE_ID="${BENCH_IMAGE_ID:-$E2E_IMAGE_ID}"
python3 /app/scripts/seam_echo.py --role client --mode "$CLIENT_MODE" \
    --backend-addr 8.8.8.8 --backend-port 443 \
    --proxy-host 127.0.0.1 --proxy-port 8080 \
    --peer-host example.com --peer-port 443 \
    --cafile /work/ca.pem \
    --conns 8 --target-mbps 100 \
    --seconds "$SECONDS" --warmup "$WARMUP" \
    --backend-pid "$SRV" $ALUARGS \
    --json-out "$REPORT" --kind "$KIND" 2>/tmp/client.log || driver_rc=$?
sed 's/^/  client> /' /tmp/client.log 2>/dev/null || true

rc2=0
# These are terminated-by-us (success); unexpected early death is a failure.
stop "$SRV" "backend" 1 || rc2=$?
stop "$DNSPID" "dns" 1 || rc2=$?
if [ "$ALU" -gt 0 ]; then
    stop "$ALU" "alumina" 1 || rc2=$?
fi
# Disarm traps only after a successful reap; on failure the armed EXIT trap
# re-runs the idempotent lenient cleanup before exit.
if [ "$rc2" -ne 0 ]; then
    echo "SEAM-FAIL: reap_rc=$rc2" >&2
    exit 1
fi
trap - INT TERM EXIT
CLEANED=1

echo "--- backend stderr ---"
sed 's/^/  backend> /' /tmp/backend.log 2>/dev/null || true
if [ "$ALU" -gt 0 ]; then
    echo "--- alumina stderr ---"
    sed 's/^/  alumina> /' /tmp/alumina.log 2>/dev/null || true
fi

# Session statuses: 0 valid + clean reap; 3 honest invalid; 1 harness failure.
if [ "$rc2" -ne 0 ]; then
    echo "SEAM-FAIL: reap_rc=$rc2" >&2
    exit 1
fi
if [ "$driver_rc" -eq 3 ]; then
    echo "SEAM-INVALID: measurement invalid (see report $REPORT); child reaps clean" >&2
    exit 3
fi
if [ "$driver_rc" -ne 0 ]; then
    echo "SEAM-FAIL: driver_rc=$driver_rc" >&2
    exit 1
fi
echo "SEAM-OK: $MODE/$KIND report=$REPORT (supervised, clean)"
exit 0
SNIP
)

# Host-owned container identity + cancellation cleanup (B8): a named container
# lets an INT/TERM on the host force removal immediately instead of waiting on
# podman --timeout. Idempotent; --rm remains as the clean-exit path.
CN="seam-${MODE}-$$"
HOST_CLEANED=0
host_cleanup() {
    [ "$HOST_CLEANED" -eq 1 ] && return 0
    HOST_CLEANED=1
    podman --connection "$CONN" rm -f "$CN" >/dev/null 2>&1 || true
    return 0
}
trap 'host_cleanup; exit 130' INT TERM
trap 'rc=$?; host_cleanup; exit $rc' EXIT

rcc=0
podman --connection "$CONN" run --rm --name "$CN" --pull=never --timeout 300 \
    -v "$ROOT:/app:ro,Z" \
    -v "$ROOT/.ooda:/ooda:ro,Z" \
    -v "$OUTDIR:/out:Z" \
    --network none \
    --security-opt no-new-privileges \
    --cap-add NET_ADMIN \
    --user 0:0 \
    -e MODE="$MODE" \
    -e KIND="$KIND" \
    -e SECONDS="$SECONDS" \
    -e WARMUP="$WARMUP" \
    -e STAMP="$STAMP" \
    -e BENCH_SOURCE_HEAD="$BENCH_SOURCE_HEAD" \
    -e BENCH_DIRTY_COUNT="$BENCH_DIRTY_COUNT" \
    -e BENCH_RUST_TARGET="$BENCH_RUST_TARGET" \
    -e BENCH_BINARY_SHA256="$BENCH_BINARY_SHA256" \
    -e BENCH_IMAGE_ID="$E2E_IMAGE_ID" \
    -e CANDIDATE_REL="$CANDIDATE_REL" \
    "$E2E_IMAGE_ID" sh -c "$stage
$run" || rcc=$?

if [ "$rcc" -ne 0 ]; then
    if [ "$rcc" -eq 130 ]; then
        echo "SEAM-HOST-CANCELLED: interrupted; container $CN cleaned up" >&2
    else
        echo "SEAM-HOST-FAIL: exit $rcc" >&2
    fi
    host_cleanup
    exit "$rcc"
fi
host_cleanup
exit 0
