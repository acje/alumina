#!/bin/sh
# Native foreground SIGTERM shutdown gate against the ACTUAL production binary.
# Native Linux only: rootful podman (flock-vm-root) on the harness image derived
# from the pinned rust base (python3/setpriv/ip), no-new-privileges,
# --network none (fully isolated: driver, DNS responder and all upstreams live
# on loopback aliases inside the container network namespace). The binary is
# dropped to uid 65534 with empty caps exactly as e2e_relay does.
#
# Every case binary is spawned and reaped FOREGROUND by the python driver with a
# bounded deadline; the podman command owns the whole lifecycle (outer command
# stays foreground, no leaked background servers). The driver is the sole child
# of this script.
set -eu

ROOT="$(pwd)"
BASE="docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a"
BASE_ID="ad70ceb90f563e9fe2ef7064b92dc1347aeaeb71e5369ba8b242498ba030a6f8"
E2E_IMAGE="${E2E_IMAGE:-localhost/alumina-e2e:e2e-20261011}"
CONN="${PODMAN_ROOT_CONNECTION:-flock-vm-root}"

if [ -z "${E2E_TARGET:-}" ]; then
    _probe_buf=$(podman --connection "$CONN" run --rm --pull=never \
        docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a \
        sh -c 'rustc -vV' 2>&1) || _probe_rc=$?
    if [ "${_probe_rc:-0}" -ne 0 ]; then
        echo "E2E-SHUTDOWN-BLOCKED: build target probe failed (exit ${_probe_rc:-0})" >&2
        exit 1
    fi
    E2E_TARGET=$(printf '%s\n' "$_probe_buf" | sed -n 's/^host: //p')
fi
case "$E2E_TARGET" in
    "" | *[!A-Za-z0-9._-]*)
        echo "E2E-SHUTDOWN-BLOCKED: E2E_TARGET not set and not observable from build owner" >&2
        exit 1
        ;;
esac
export E2E_TARGET
BIN="target/${E2E_TARGET}/release/alumina"

command -v podman >/dev/null 2>&1 || {
    echo "E2E-SHUTDOWN-BLOCKED: podman required on the host" >&2
    exit 1
}
podman --connection "$CONN" info >/dev/null 2>&1 || {
    echo "E2E-SHUTDOWN-BLOCKED: rootful podman connection $CONN unreachable" >&2
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
        echo "E2E-SHUTDOWN-BLOCKED: harness tag '$HARNESS_IMAGE' on $CONN resolves to '$tag_id', not the receipt's immutable $E2E_IMAGE_ID; refusing a retagged image" >&2
        exit 1
    }
    HARNESS_IMAGE="$E2E_IMAGE_ID"
else
    podman --connection "$CONN" image exists "$HARNESS_IMAGE" || {
        echo "E2E-SHUTDOWN-BLOCKED: harness image $HARNESS_IMAGE absent on $CONN (provision from pinned base first)" >&2
        exit 1
    }
fi
parent=$(podman --connection "$CONN" image inspect "$HARNESS_IMAGE" --format '{{.Parent}}' 2>/dev/null || echo "?")
[ "$parent" = "$BASE_ID" ] || {
    echo "E2E-SHUTDOWN-BLOCKED: harness image parent mismatch (got $parent, want $BASE_ID)" >&2
    exit 1
}
echo "E2E-SHUTDOWN-HARNESS-IMAGE: executed image $HARNESS_IMAGE (tag ${E2E_IMAGE:-localhost/alumina-e2e:e2e-20261011}, conn $CONN)"
[ -x "$ROOT/$BIN" ] || {
    echo "E2E-SHUTDOWN-BLOCKED: production static binary missing ($BIN); run 'verify.sh e2e shutdown' which rebuilds it first" >&2
    exit 1
}

stage_snippet=$(cat <<'SNIP'
set -eu
mkdir -p /work
printf '%s\n' \
    'allowlist = ["drain.example.org", "force.example.org"]' \
    'listen = "127.0.0.1:8080"' \
    'startup_unresolved_allowance = 0' > /work/config.toml
printf '%s\n' 'nameserver 127.0.0.1' > /work/resolv.conf
chown -R 65534:65534 /work
SNIP
)

run=$(cat <<'SNIP'
set -eu
bin="/app/target/${E2E_TARGET}/release/alumina"
[ -x "$bin" ] || {
    echo "E2E-SHUTDOWN-STATIC-ELF FAIL: release binary missing: $bin" >&2
    exit 1
}
dyn_rc=0
dyn_out=$(readelf -d "$bin" 2>&1) || dyn_rc=$?
[ "$dyn_rc" -eq 0 ] || {
    echo "E2E-SHUTDOWN-STATIC-ELF FAIL: readelf -d exit $dyn_rc (probe failure is not PASS)" >&2
    exit 1
}
if [ "${dyn_out#*NEEDED*}" != "$dyn_out" ]; then
    echo "E2E-SHUTDOWN-STATIC-ELF FAIL: dynamic NEEDED entries present" >&2
    exit 1
fi
interp_rc=0
interp_out=$(readelf -l "$bin" 2>&1) || interp_rc=$?
[ "$interp_rc" -eq 0 ] || {
    echo "E2E-SHUTDOWN-STATIC-ELF FAIL: readelf -l exit $interp_rc (probe failure is not PASS)" >&2
    exit 1
}
if [ "${interp_out#*INTERP*}" != "$interp_out" ]; then
    echo "E2E-SHUTDOWN-STATIC-ELF FAIL: PT_INTERP present" >&2
    exit 1
fi
echo "E2E-SHUTDOWN-STATIC-ELF: PASS static gate on $bin"

# upstreams on global-unicast IPv4 bound to lo inside --network none
ip addr add 8.8.8.8/32 dev lo
ip addr add 208.67.222.220/32 dev lo

python3 /app/scripts/e2e_shutdown.py
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
    -e SHUTDOWN_PRESWITCH_BYTES="${SHUTDOWN_PRESWITCH_BYTES:-600}" \
    ${CASE_FILTER:+-e CASE_FILTER="${CASE_FILTER}"} \
    "$HARNESS_IMAGE" sh -c "$stage_snippet
$run" || rcc=$?

if [ "$rcc" -eq 0 ]; then
    if [ -n "${CASE_FILTER:-}" ]; then
        echo "E2E-SHUTDOWN-OK-SCOPED: native SIGTERM shutdown gate green for CASE_FILTER=${CASE_FILTER} against target/${E2E_TARGET}/release/alumina (scoped selection, not full-suite green)"
    else
        echo "E2E-SHUTDOWN-OK: native SIGTERM shutdown gate green against target/${E2E_TARGET}/release/alumina"
    fi
else
    echo "E2E-SHUTDOWN-FAIL: exit $rcc" >&2
    exit 1
fi
