#!/bin/sh
# qryg/harness_native.sh -- runs INSIDE the pinned seam harness container as
# the qryg.9 native-competitor extension of the reviewed seam measurement.
# Owns ONLY the fixture children (dns / tls backend) exactly as the accepted
# seam run body does (scripts/seam_echo.sh stop/cleanup owner, B8); the
# candidate process is a separate container and its reap is
# container-runtime-owned by the host supervisor, never this script.
#
# Lifecycle driven by handshake files under the shared /w scratch (a 777
# directory mounted from the host into BOTH containers, plus /out for the
# seam report):
#   $STAMP.netns-ready              -> written here once netns+backend up
#   $STAMP.candidate.pid            -> written by the candidate's entry script
#   $STAMP.client-done              -> client rc handed to the supervisor
#   $STAMP.supervisor-candidate-done-> supervisor confirms candidate reaped
#
# Runtimes, workload and all numeric bounds are the accepted seam contract
# (alumina-gjq4): 8 conns / 4096 B frame + 12 B header / 100 decimal Mbps /
# setup+drain 5 s caps. The two attach waits default to the seam-inherited
# 60 s proxy-ready magnitude; podman --timeout 300 is the stock safety cap.
set -eu

cd /work
ip addr add 8.8.8.8/32 dev lo

# Acquisition slots initialized before any trap is installed so a failure at
# any point still reaps every owned child (B8, byte-identical to seam_echo.sh).
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

# DNS-over-TCP responder mapping example.com -> 8.8.8.8 (seam_echo.sh:201-225)
python3 /app/scripts/seam_echo.py --role dns-responder \
    --dns-bind 127.0.0.1:53 --dns-answer example.com:8.8.8.8 2>/tmp/dns.log &
DNSPID=$!
sleep 0.3

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

printf '%s\n' "$STAMP" > "/w/$STAMP.netns-ready"

CAND_PID=""
w=0
while [ ! -r "/w/$STAMP.candidate.pid" ] && [ "$w" -lt "${QRYG_ATTACH_WAIT_S:-60}" ]; do
    sleep 0.5
    w=$((w + 1))
done
CAND_PID="$(cat "/w/$STAMP.candidate.pid" 2>/dev/null || true)"
if [ -z "$CAND_PID" ]; then
    echo "QR-HARNESS-FAIL: candidate pid never appeared (attach wait ${QRYG_ATTACH_WAIT_S:-60}s)" >&2
    exit 1
fi

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

REPORT="/out/$STAMP.json"
driver_rc=0
export BENCH_CONFIG_SHA="$(sha256sum /work/config.toml 2>/dev/null | awk '{print $1}' || true)"
python3 /app/scripts/seam_echo.py --role client --mode "$CLIENT_MODE" \
    --backend-addr 8.8.8.8 --backend-port 443 \
    --proxy-host 127.0.0.1 --proxy-port 8080 \
    --peer-host example.com --peer-port 443 \
    --cafile /work/ca.pem \
    --conns 8 --target-mbps 100 \
    --seconds "$SECONDS" --warmup "$WARMUP" \
    --backend-pid "$SRV" --proxy-pid "$CAND_PID" \
    --json-out "$REPORT" --kind "$KIND" 2>/tmp/client.log || driver_rc=$?
sed 's/^/  client> /' /tmp/client.log 2>/dev/null || true

rc2=0
stop "$SRV" "backend" 1 || rc2=$?
stop "$DNSPID" "dns" 1 || rc2=$?
# Keep traps armed on reap failure so the idempotent lenient cleanup re-runs
# on exit and retries the owned reap; disarm only after a clean reap (F2,
# matching the inherited seam_echo.sh owner: exit keeps the EXIT trap armed).
if [ "$rc2" -ne 0 ]; then
    echo "QR-HARNESS-FAIL: reap_rc=$rc2" >&2
else
    trap - INT TERM EXIT
    CLEANED=1
fi

printf '%s\n' "$driver_rc" > "/w/$STAMP.client-done"
if [ "$rc2" -ne 0 ]; then
    : > "/w/$STAMP.harness-reapfail"
fi

w=0
while [ ! -r "/w/$STAMP.supervisor-candidate-done" ] && [ "$w" -lt "${QRYG_DONE_WAIT_S:-60}" ]; do
    sleep 0.5
    w=$((w + 1))
done
if [ ! -r "/w/$STAMP.supervisor-candidate-done" ]; then
    echo "QR-HARNESS-FAIL: supervisor-candidate-done never appeared" >&2
    exit 1
fi

if [ "$rc2" -ne 0 ]; then
    exit 1
fi
exit 0
