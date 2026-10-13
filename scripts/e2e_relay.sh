#!/bin/sh
# E2E CONNECT/SNI opaque-relay gate against the ACTUAL production binary.
# Native Linux only: rootful podman (flock-vm-root) on a harness image derived
# from the pinned rust base, no-new-privileges, --network none (fully isolated:
# the driver, DNS responder and all upstreams live on loopback aliases inside
# the container network namespace; nothing can reach an external host). The
# binary is dropped to uid 65534 with empty caps exactly as boot-fixtures does.
#
# The driver is run in the foreground and every fixture process/thread is
# waited on with a deadline and reaped; RBI children are killed on exit and the
# podman command owns the whole lifecycle (outer command stays foreground, no
# leaked background servers).
#
# The harness image immutable ID (recorded by the verify.sh e2e receipt) is
# re-verified against its mutable tag and its expected parent (the pinned base
# sha) on the rootful connection; the gate fails closed if the image or its
# parent identity is missing, or if the tag no longer resolves to the recorded
# immutable ID, so the exact-base provenance of every executed run is receipted
# and the executed image is the recorded immutable ID.
set -eu

ROOT="$(pwd)"
# Harness image: derived ONCE from the pinned rust base + openssl/python3/
# setpriv/ip (provisioned offline; never pulled at run time). The parent must
# be the pinned base sha, checked below as an identity gate.
BASE="docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a"
BASE_ID="ad70ceb90f563e9fe2ef7064b92dc1347aeaeb71e5369ba8b242498ba030a6f8"
E2E_IMAGE="${E2E_IMAGE:-localhost/alumina-e2e:e2e-20261011}"
CONN="${PODMAN_ROOT_CONNECTION:-flock-vm-root}"

# R1: the executed artifact PROFILE must be the same observed native triple the
# build used. verify.sh exports E2E_TARGET (observed from the build owner); a
# standalone invocation observes it from the pinned build image and fails
# closed if no triple can be observed. --target-dir never selects the triple;
# the triple is carried here into the consumer path.
# N1: observe the build-owner native profile with the PRODUCER's own exit
# checked before any parsing. stdout/stderr are captured together so a failing
# producer (even one that wrote a plausible host line) is never masked by a
# later filter's exit 0, and the reason is not swallowed by 2>/dev/null.
# Parsing (`sed 's/^host: //p'`) runs only on the captured buffer of an exit-0
# producer. The inner `sh -c 'rustc -vV'` (no sed pipe) lets podman propagate
# the container's rustc exit directly.
observe_build_target() {
    _probe_out="$("$@" 2>&1)" || _probe_rc=$?
    if [ "${_probe_rc:-0}" -ne 0 ]; then
        printf 'E2E-RELAY-BLOCKED: build target probe failed before parse (exit %s):\n%s\n' \
            "$_probe_rc" "$_probe_out" >&2
        exit 1
    fi
    printf '%s\n' "$_probe_out"
}

if [ -z "${E2E_TARGET:-}" ]; then
    _probe_buf=$(observe_build_target \
        podman --connection "$CONN" run --rm --pull=never \
        docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a \
        sh -c 'rustc -vV') || exit 1
    # parse only from the successfully captured buffer (producer exit already 0)
    E2E_TARGET=$(printf '%s\n' "$_probe_buf" | sed -n 's/^host: //p')
fi
case "$E2E_TARGET" in
    "" | *[!A-Za-z0-9._-]*)
        echo "E2E-RELAY-BLOCKED: E2E_TARGET not set and not observable from build owner ('${E2E_TARGET}')" >&2
        exit 1
        ;;
esac
export E2E_TARGET
BIN="target/${E2E_TARGET}/release/alumina"
BINPATH="/app/${BIN}"

# B1 false-clean guard: E2E_EARLY_ONLY is a diagnostic-only subset (a single
# case) and MUST NOT reach the publication gate. The gate is a full-coverage
# hard-zero proof; a subset run must either be rejected here or emit a
# distinct non-certifying result. We reject non-empty values outright so no
# single-case run can ever be reported as the full CONNECT/SNI gate green.
if [ -n "${E2E_EARLY_ONLY:-}" ]; then
    echo "E2E-RELAY-BLOCKED: E2E_EARLY_ONLY subset selection is diagnostic-only and cannot certify the publication gate" >&2
    exit 2
fi

command -v podman >/dev/null 2>&1 || {
    echo "E2E-RELAY-BLOCKED: podman required on the host" >&2
    exit 1
}
podman --connection "$CONN" info >/dev/null 2>&1 || {
    echo "E2E-RELAY-BLOCKED: rootful podman connection $CONN unreachable" >&2
    exit 1
}
# Harness image: run the exact immutable ID the e2e receipt recorded when
# verify.sh exported E2E_IMAGE_ID (resolved on the recorded rootful connection,
# E2E_ROOT_CONN). On THIS consumer connection the mutable tag must still resolve
# to that same immutable ID, then the container runs the ID itself -- a retag
# between receipt and run can never swap the executed image. Parent (pinned
# base) provenance is preserved for both paths. Standalone (no E2E_IMAGE_ID)
# keeps the previous tag-based selection.
HARNESS_IMAGE="${E2E_IMAGE:-localhost/alumina-e2e:e2e-20261011}"
if [ -n "${E2E_IMAGE_ID:-}" ]; then
    tag_id=$(podman --connection "$CONN" image inspect "$HARNESS_IMAGE" --format '{{.Id}}' 2>/dev/null || echo "?")
    [ "$tag_id" = "$E2E_IMAGE_ID" ] || {
        echo "E2E-RELAY-BLOCKED: harness tag '$HARNESS_IMAGE' on $CONN resolves to '$tag_id', not the receipt's immutable $E2E_IMAGE_ID; refusing a retagged image" >&2
        exit 1
    }
    HARNESS_IMAGE="$E2E_IMAGE_ID"
else
    podman --connection "$CONN" image exists "$HARNESS_IMAGE" || {
        echo "E2E-RELAY-BLOCKED: harness image $HARNESS_IMAGE absent on $CONN (provision from pinned base first)" >&2
        exit 1
    }
fi
parent=$(podman --connection "$CONN" image inspect "$HARNESS_IMAGE" --format '{{.Parent}}' 2>/dev/null || echo "?")
[ "$parent" = "$BASE_ID" ] || {
    echo "E2E-RELAY-BLOCKED: harness image parent mismatch (got $parent, want $BASE_ID); base provenance not tied to pinned $BASE" >&2
    exit 1
}
echo "E2E-RELAY-HARNESS-IMAGE: executed image $HARNESS_IMAGE (tag ${E2E_IMAGE:-localhost/alumina-e2e:e2e-20261011}, conn $CONN)"
[ -x "$ROOT/$BIN" ] || {
    echo "E2E-RELAY-BLOCKED: production static binary missing ($BIN); run 'verify.sh e2e relay' which rebuilds it first" >&2
    exit 1
}

stage_snippet=$(cat <<'SNIP'
set -eu
mkdir -p /work
printf '%s\n' \
    'allowlist = ["example.com", "echo.example.org", "down.example.org", "neg.example.org"]' \
    'listen = "127.0.0.1:8080"' \
    'startup_unresolved_allowance = 0' > /work/config.toml
printf '%s\n' 'nameserver 127.0.0.1' > /work/resolv.conf
chown -R 65534:65534 /work
SNIP
)

run=$(cat <<'SNIP'
set -eu
cd /work
# R2: authoritative readelf static gate on the EXACT binary that will be
# executed (this harness image carries GNU readelf; verified before wiring).
# Probe exits are checked separately - never a masked pipeline. This replaces
# the removed custom ELF parser with the existing binutils seam.
static_gate() {
    bin="$1"
    [ -x "$bin" ] || {
        echo "E2E-STATIC-ELF FAIL: release binary missing: $bin" >&2
        exit 1
    }
    dyn_rc=0
    dyn_out=$(readelf -d "$bin" 2>&1) || dyn_rc=$?
    [ "$dyn_rc" -eq 0 ] || {
        echo "E2E-STATIC-ELF FAIL: readelf -d exit $dyn_rc (probe failure is not PASS)" >&2
        exit 1
    }
    # POSIX parameter expansion (no case/grep): NEEDED -> not static
    if [ "${dyn_out#*NEEDED*}" != "$dyn_out" ]; then
        echo "E2E-STATIC-ELF FAIL: dynamic NEEDED entries present" >&2
        exit 1
    fi
    interp_rc=0
    interp_out=$(readelf -l "$bin" 2>&1) || interp_rc=$?
    [ "$interp_rc" -eq 0 ] || {
        echo "E2E-STATIC-ELF FAIL: readelf -l exit $interp_rc (probe failure is not PASS)" >&2
        exit 1
    }
    # PT_INTERP present -> dynamically linked via interpreter
    if [ "${interp_out#*INTERP*}" != "$interp_out" ]; then
        echo "E2E-STATIC-ELF FAIL: PT_INTERP present" >&2
        exit 1
    fi
    echo "E2E-STATIC-ELF: PASS readelf static gate on $bin"
}
static_gate "/app/target/${E2E_TARGET}/release/alumina"

# The crate's martian/SSRF eligibility guard rejects loopback/private/bogons
# as CONNECT relay targets, so upstreams live on global-unicast IPv4 bound to
# lo inside the --network none namespace: 8.8.8.8 (TLS -rev), 8.8.4.4 (raw
# echo), 208.67.222.222 (nothing listening -> refused -> 502), and
# 208.67.222.220 (counting-only listener proving rejected hellos forwarded
# zero bytes). All local; no external host is reachable from this namespace.
ip addr add 8.8.8.8/32 dev lo
ip addr add 8.8.4.4/32 dev lo
ip addr add 208.67.222.222/32 dev lo
ip addr add 208.67.222.220/32 dev lo

# self-signed cert identifying the allowlisted CONNECT hostname
openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem \
    -days 2 -nodes -subj "/CN=example.com" >/dev/null 2>&1

# upstream TLS1.3 reverse-echo server (authentic app bytes returned reversed)
openssl s_server -accept 8.8.8.8:443 -cert /tmp/cert.pem -key /tmp/key.pem \
    -tls1_3 -rev -quiet >/tmp/server.log 2>&1 &
SRV=$!

# launch the ACTUAL production binary, dropped to uid 65534 with empty caps
# under no-new-privileges (the container runs with that flag)
setpriv --reuid 65534 --regid 65534 --clear-groups /bin/sh -c \
    "cd /work && exec /app/target/${E2E_TARGET}/release/alumina" >/tmp/alumina.log 2>&1 &
ALU=$!

# Interrupt/failure cleanup: any INT/TERM/EXIT after children start must stop
# them (the gate is foreground; an interrupted run must not leak children).
cleanup_children() {
    kill -TERM "$ALU" "$SRV" 2>/dev/null || true
    sleep 0.1
    kill -KILL "$ALU" "$SRV" 2>/dev/null || true
    return 0
}
trap 'cleanup_children; exit 130' INT TERM

# Foreground supervisor: run the driver, then reap BOTH children. The binary
# and s_server are process-lifetime fixtures whose only shutdown is our
# signal, so termination-by-us is SUCCESS; a process that is already dead
# before we reap, or still alive after the TERM+KILL bounded grace, is the
# leak/unexpected-death that must fail the gate.
driver_rc=0
python3 /app/scripts/e2e_relay.py || driver_rc=$?

reap() {
    pid="$1"
    label="$2"
    [ "$pid" -le 0 ] && return 0
    # already dead before our TERM: unexpected fixture death (the driver never
    # kills ALU/SRV), so its wait status is recorded and the gate fails.
    if ! kill -0 "$pid" 2>/dev/null; then
        if wait "$pid" 2>/dev/null; then ws=0; else ws=$?; fi
        echo "  E2E-REAP: $label pid $pid already exited before reap (status $ws) -- unexpected death" >&2
        return 1
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
            echo "  E2E-REAP-FAIL: $label pid $pid still alive after TERM+SIGKILL grace; leaked" >&2
            return 1
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
    # reap the exit so no zombie escapes the namespace (record TRUE status;
    # a signal-terminated child gives a non-zero wait status, not a success)
    if wait "$pid" 2>/dev/null; then ws=0; else ws=$?; fi
    if [ "$killed" -eq 1 ]; then
        echo "E2E-REAP: $label pid $pid via SIGKILL after ${waited}x0.1s (status $ws)"
    else
        echo "E2E-REAP: $label pid $pid via SIGTERM after ${waited}x0.1s (status $ws)"
    fi
    return 0
}

rc2=0
reap "$ALU" "alumina" || rc2=$?
reap "$SRV" "s_server" || rc2=$?
trap - INT TERM

echo "--- alumina stdout/stderr ---"
sed 's/^/  alumina> /' /tmp/alumina.log || true
echo "--- upstream s_server log ---"
sed 's/^/  srv> /' /tmp/server.log || true

# Driver rc is the verdict; a failed reap is also a harness failure.
if [ "$driver_rc" -ne 0 ] || [ "$rc2" -ne 0 ]; then
    echo "E2E-RELAY-FAIL: driver_rc=$driver_rc reap_rc=$rc2" >&2
    exit 1
fi
exit 0
SNIP
)

rcc=0
podman --connection "$CONN" run --rm --pull=never \
    -v "$ROOT:/app:ro,Z" \
    --network none \
    --security-opt no-new-privileges \
    --cap-add NET_ADMIN \
    --user 0:0 \
    -e E2E_TARGET="${E2E_TARGET}" \
    -e E2E_DNS_TS="${E2E_DNS_TS:-}" \
    "$HARNESS_IMAGE" sh -c "$stage_snippet
$run" || rcc=$?

if [ "$rcc" -eq 0 ]; then
    echo "E2E-RELAY-OK: isolated real-IO CONNECT/SNI opaque-relay gate green against target/${E2E_TARGET}/release/alumina"
else
    echo "E2E-RELAY-FAIL: exit $rcc" >&2
    exit 1
fi
