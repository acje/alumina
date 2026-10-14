#!/bin/sh
# qryg_runner.sh -- host-side foreground supervisor for the qryg.9 native
# competitor runner (HAProxy 3.2.25 / Envoy 1.39.4 direct binaries) under the
# accepted single-owner seam measurement, joined into the seam harness
# container's shared network + PID namespaces (alumina-p0on amendment,
# alumina-rbuj oracle).
#
# Usage: qryg_runner.sh <haproxy|envoy> <smoke|timed>
#
# One foreground invocation owns two containers; every subprocess is awaited
# before this script returns (no detached/unawaited service):
#   harness   -- pinned seam harness image (id 9191d288..) : --network none,
#               lo alias 8.8.8.8/32, DNS responder, TLS backend, then the seam
#               client with the candidate in-namespace PID as --proxy-pid; its
#               fixture children (dns/backend) are reaped by itself.
#   candidate -- pinned official image joining --network container:<harness>
#               and --pid container:<harness>; direct binary (HAProxy -db,
#               no -W, nbthread 1; Envoy -c CONNECT-terminate --concurrency 1
#               as uid 65534). A mounted entry script writes the in-namespace
#               PID then execs the proxy. Reap is container-runtime-owned:
#               podman stop/wait/rm classify TERM 143 / clean 0 acceptable,
#               forced kill 137 invalid, early death invalid.
#
# Route labels are policy-honest, never equivalence: HAProxy is direct TLS to
# the proxy (no CONNECT) => seam --mode direct-proxy; Envoy CONNECT-terminates
# => seam --mode via-proxy. The seam report keeps mode = the actual client
# route; candidate identity + native config hash + thread count live in the
# companion <stamp>.native.json emitted beside the seam report.
#
# Exit: 0 valid run + clean reap; 3 measurement invalid (honest, reported);
#      1 supervisor/harness/candidate failure or identity mismatch; 2 usage.
# Bounds: no invented numeric ceilings -- accepted setup/drain/window caps
#      from the seam workload (alumina-gjq4) plus stock supervisor safety only
#      (podman --timeout 300 per container, seam-inherited 60 s attach waits).
# Identity pins (aztk/raa7): harness 9191d288.. parent ad70cebf..;
#      HAProxy d483b789../3947a542..; Envoy a084f595../ce82b213...
set -eu

ROOT="$(pwd)"
CAND="${1:?usage: qryg_runner.sh <haproxy|envoy> <smoke|timed>}"
KIND="${2:?usage: qryg_runner.sh <haproxy|envoy> <smoke|timed>}"
shift 2 || true
if [ "$#" -gt 0 ]; then
    echo "QR-BLOCKED: additional args unsupported" >&2
    exit 2
fi
case "$KIND" in smoke|timed) ;; *) echo "QR-BLOCKED: kind must be smoke or timed" >&2; exit 2 ;; esac
case "$CAND" in haproxy|envoy) ;; *) echo "QR-BLOCKED: candidate must be haproxy or envoy" >&2; exit 2 ;; esac

CONN="${QRYG_CONN:-flock-vm-root}"
OUTDIR="${QRYG_OUTDIR:-$ROOT/.ooda/benchmarks/qryg-native}"

E2E_IMAGE_ID="9191d288353391e4751525e83196e8127884d73daa395ced6fafc4a96d71564f"
E2E_BASE_ID="ad70ceb90f563e9fe2ef7064b92dc1347aeaeb71e5369ba8b242498ba030a6f8"
HAPROXY_IMG_ID="d483b7896ae82de219b492b77ba57c5c5e6306562f74e063c25c6de37e15339b"
HAPROXY_MANIFEST="3947a5423cb51b6cc2e165ec0c3b8575e622c46bf39a247d065eff15ab8fa9da"
ENVOY_IMG_ID="a084f595b889eb2e7c9af1abcc7565a9520fd45b63a7653f5181a55dd2cc9735"
ENVOY_MANIFEST="ce82b213b2c9190aa9fa2fc76678743a690681cbd668de32dd749e3e4da52862"

case "$CAND" in
    haproxy)
        CAND_IMG_ID="$HAPROXY_IMG_ID"
        CAND_MANIFEST="$HAPROXY_MANIFEST"
        CAND_CFG="haproxy.cfg"
        CAND_ENTRY="entry_haproxy.sh"
        CLIENT_MODE="direct-proxy"
        CAND_USER_FLAGS=""
        ;;
    envoy)
        CAND_IMG_ID="$ENVOY_IMG_ID"
        CAND_MANIFEST="$ENVOY_MANIFEST"
        CAND_CFG="envoy_connect.yaml"
        CAND_ENTRY="entry_envoy.sh"
        CLIENT_MODE="via-proxy"
        CAND_USER_FLAGS="--user 65534:65534"
        ;;
esac

TS="$(date +%Y%m%dT%H%M%SZ)"
STAMP="qryg-$CAND-$KIND-$TS-$$"
WORKDIR="$OUTDIR/$STAMP.work"
H_CN="qryg-h-$CAND-$$"
C_CN="qryg-c-$CAND-$$"

HOST_CLEANED=0
C_ACQ=0
H_ACQ=0

# Single cleanup owner for every exit path (success, failure, cancellation).
# The candidate container is removed first: it joins the harness netns/PIDns,
# so tearing it down before the harness is required by topology (rbuj).
# Every acquired local podman run job is awaited once; C_JOB/H_JOB are cleared
# on reap so they are never waited twice. Removal/reap failures are retained:
# HOST_CLEANED stays 0 and a non-zero rc is returned rather than a claim of
# completed cleanup (F1).
host_cleanup() {
    [ "$HOST_CLEANED" -eq 1 ] && return 0
    hcr=0
    if [ "$C_ACQ" -eq 1 ]; then
        podman --connection "$CONN" rm -f "$C_CN" >/dev/null 2>&1 || hcr=1
        if [ "$C_JOB" -gt 0 ] 2>/dev/null; then
            wait "$C_JOB" 2>/dev/null || true
            C_JOB=0
        fi
    fi
    if [ "$H_ACQ" -eq 1 ]; then
        podman --connection "$CONN" rm -f "$H_CN" >/dev/null 2>&1 || hcr=1
        if [ "$H_JOB" -gt 0 ] 2>/dev/null; then
            wait "$H_JOB" 2>/dev/null || true
            H_JOB=0
        fi
    fi
    if [ "$hcr" -eq 0 ]; then
        HOST_CLEANED=1
        return 0
    fi
    echo "QR-CLEANUP-FAIL: owned removal incomplete (rc=$hcr)" >&2
    return "$hcr"
}
trap 'host_cleanup || :; exit 130' INT TERM
trap 'rc=$?; host_cleanup || :; exit $rc' EXIT

fail() {
    echo "QR-FAIL: $*" >&2
    exit 1
}

# --- pre-flight: podman, pinned identities, configs -------------------------
command -v podman >/dev/null 2>&1 || fail "podman required"
podman --connection "$CONN" info >/dev/null 2>&1 || fail "podman connection $CONN unreachable"
h_id=$(podman --connection "$CONN" image inspect "$E2E_IMAGE_ID" --format '{{.Id}}' 2>/dev/null || echo "?")
[ "$h_id" = "$E2E_IMAGE_ID" ] || fail "harness tag/id mismatch (got $h_id, want $E2E_IMAGE_ID)"
h_parent=$(podman --connection "$CONN" image inspect "$E2E_IMAGE_ID" --format '{{.Parent}}' 2>/dev/null || echo "?")
[ "$h_parent" = "$E2E_BASE_ID" ] || fail "harness image parent mismatch (got $h_parent, want $E2E_BASE_ID)"
c_id=$(podman --connection "$CONN" image inspect "$CAND_IMG_ID" --format '{{.Id}}' 2>/dev/null || echo "?")
[ "$c_id" = "$CAND_IMG_ID" ] || fail "candidate image id mismatch (got $c_id, want $CAND_IMG_ID)"
if podman --connection "$CONN" image inspect "$CAND_IMG_ID" --format '{{index .RepoDigests 0}}' 2>/dev/null \
    | grep -q "@sha256:$CAND_MANIFEST"; then
    :
else
    fail "candidate RepoDigest does not pin manifest sha256:$CAND_MANIFEST"
fi
[ -f "$ROOT/scripts/qryg/$CAND_CFG" ] || fail "native config missing: scripts/qryg/$CAND_CFG"
[ -f "$ROOT/scripts/qryg/$CAND_ENTRY" ] || fail "entry wrapper missing: scripts/qryg/$CAND_ENTRY"
[ -f "$ROOT/scripts/qryg/harness_native.sh" ] || fail "harness_native.sh missing"

mkdir -p "$OUTDIR" "$WORKDIR"
chmod 777 "$WORKDIR"

BENCH_SOURCE_HEAD="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
BENCH_DIRTY_COUNT="$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
NATIVE_CFG_SHA="$(shasum -a 256 "$ROOT/scripts/qryg/$CAND_CFG" 2>/dev/null | awk '{print $1}')"
if [ -z "$NATIVE_CFG_SHA" ]; then
    NATIVE_CFG_SHA="$(sha256sum "$ROOT/scripts/qryg/$CAND_CFG" 2>/dev/null | awk '{print $1}' || true)"
fi

if [ "$KIND" = "smoke" ]; then
    SECONDS=2
    WARMUP=0
else
    SECONDS=60
    WARMUP=5
fi

# stage: byte-identical to scripts/seam_echo.sh (certs, resolv, config.toml)
stage=$(cat <<'SNIP'
set -eu
mkdir -p /work /out
printf '%s\n' \
    'allowlist = ["example.com"]' \
    'listen = "127.0.0.1:8080"' \
    'startup_unresolved_allowance = 0' \
    '[any_illegal]' \
    'scope = "connection"' \
    '[actions]' \
    'kind = ["flare_only"]' \
    'scope = ["connection"]' > /work/config.toml
printf '%s\n' 'nameserver 127.0.0.1' > /work/resolv.conf
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

echo "QR-HARNESS-IMAGE: $E2E_IMAGE_ID conn $CONN cand $CAND kind $KIND"
echo "QR-STAMP: $STAMP"

H_JOB=0
C_JOB=0
CAND_PID=""
PROXY_PID_IN_NS=""

# --- start harness (backgrounded inside this foreground supervisor; awaited) --
podman --connection "$CONN" run --name "$H_CN" --rm --pull=never \
    --timeout 300 \
    -v "$ROOT:/app:ro,Z" \
    -v "$ROOT/.ooda:/ooda:ro,Z" \
    -v "$OUTDIR:/out:Z" \
    -v "$WORKDIR:/w:Z" \
    --network none \
    --security-opt no-new-privileges \
    --cap-add NET_ADMIN \
    --user 0:0 \
    -e STAMP="$STAMP" \
    -e CLIENT_MODE="$CLIENT_MODE" \
    -e SECONDS="$SECONDS" \
    -e WARMUP="$WARMUP" \
    -e KIND="$KIND" \
    -e BENCH_SOURCE_HEAD="$BENCH_SOURCE_HEAD" \
    -e BENCH_DIRTY_COUNT="$BENCH_DIRTY_COUNT" \
    -e BENCH_RUST_TARGET="" \
    -e BENCH_BINARY_SHA256="" \
    -e BENCH_IMAGE_ID="$E2E_IMAGE_ID" \
    "$E2E_IMAGE_ID" sh -c "$stage
sh /app/scripts/qryg/harness_native.sh" >"$WORKDIR/harness.log" 2>&1 &
H_JOB=$!
H_ACQ=1

i=0
while [ ! -f "$WORKDIR/$STAMP.netns-ready" ]; do
    if ! kill -0 "$H_JOB" 2>/dev/null; then
        sleep 0.5
        fail "harness exited ($(cat "$WORKDIR/harness.log" 2>/dev/null | tail -3 | tr '\n' ' ')) before netns-ready"
    fi
    i=$((i + 1))
    if [ "$i" -ge 600 ]; then
        fail "netns-ready wait exceeded stock podman --timeout (300s)"
    fi
    sleep 0.5
done

# --- start candidate (backgrounded; teardown is container-runtime-owned) -----
podman --connection "$CONN" run --name "$C_CN" --pull=never --timeout 300 \
    --network "container:$H_CN" --pid "container:$H_CN" \
    --security-opt no-new-privileges $CAND_USER_FLAGS \
    --entrypoint "/cfg/$CAND_ENTRY" \
    -v "$ROOT/scripts/qryg:/cfg:ro,Z" \
    -v "$WORKDIR:/w:Z" \
    -e STAMP="$STAMP" \
    "$CAND_IMG_ID" >"$WORKDIR/candidate.log" 2>&1 &
C_JOB=$!
C_ACQ=1

i=0
while [ ! -f "$WORKDIR/$STAMP.client-done" ]; do
    if ! kill -0 "$H_JOB" 2>/dev/null; then
        sleep 0.5
        fail "harness exited before client-done (see $WORKDIR/harness.log)"
    fi
    if ! kill -0 "$C_JOB" 2>/dev/null; then
        sleep 0.5
        fail "candidate run job exited before client-done (see $WORKDIR/candidate.log)"
    fi
    i=$((i + 1))
    if [ "$i" -ge 600 ]; then
        fail "client-done wait exceeded stock podman --timeout (300s)"
    fi
    sleep 0.5
done
driver_rc="$(cat "$WORKDIR/$STAMP.client-done" 2>/dev/null || echo 1)"
PROXY_PID_IN_NS="$(cat "$WORKDIR/$STAMP.candidate.pid" 2>/dev/null || echo 0)"
echo "QR-CLIENT-DONE: driver_rc=$driver_rc proxy_pid_in_ns=$PROXY_PID_IN_NS"

# --- teardown: candidate first, harness stays up until candidate reaped -----
# Thread probe is tri-state: only a positive count is reported as a number.
# Producer failure or a zero/missing count is explicit Unknown with a reason,
# never a factual 0 (F3; gjq4 reporter requires disclosure or clear Unknown).
THREADS=""
THREADS_REASON=""
if [ -n "$PROXY_PID_IN_NS" ] && [ "$PROXY_PID_IN_NS" -gt 0 ] 2>/dev/null; then
    probe_rc=0
    probe_out="$(podman --connection "$CONN" exec "$H_CN" sh -c \
        'd=/proc/'"$PROXY_PID_IN_NS"'; [ -d "$d/task" ] || exit 9; ls "$d/task" 2>/dev/null | wc -l' 2>/dev/null)" || probe_rc=$?
    if [ "$probe_rc" -ne 0 ]; then
        THREADS_REASON="thread probe producer failed (probe_rc=$probe_rc)"
    else
        case "$probe_out" in
            ''|*[!0-9]*)
                THREADS_REASON="thread probe non-numeric ('$probe_out')"
                ;;
            *)
                if [ "$probe_out" -lt 1 ]; then
                    THREADS_REASON="thread probe counted 0 (task dir missing or proxy pid gone)"
                else
                    THREADS="$probe_out"
                fi
                ;;
        esac
    fi
else
    THREADS_REASON="proxy pid not established (proxy_pid_in_namespace=$PROXY_PID_IN_NS)"
fi
CM_KIND=""
cand_state="$(podman --connection "$CONN" inspect "$C_CN" --format '{{.State.Status}}' 2>/dev/null || echo 'gone')"
podman --connection "$CONN" stop "$C_CN" >/dev/null 2>&1 || true
cand_rc="$(podman --connection "$CONN" wait "$C_CN" 2>/dev/null || echo 1)"
case "$cand_rc" in
    ''|*[!0-9]*) cand_rc="1" ;;
esac
if [ "$cand_state" != "running" ]; then
    CM_KIND="early-death"
elif [ "$cand_rc" -eq 137 ]; then
    CM_KIND="forced-kill-137"
elif [ "$cand_rc" -eq 0 ] || [ "$cand_rc" -eq 143 ]; then
    CM_KIND="ok"
else
    CM_KIND="unexpected-rc"
fi
echo "QR-CANDIDATE: state_before_stop=$cand_state wait_rc=$cand_rc classify=$CM_KIND threads=${THREADS:-Unknown}${THREADS_REASON:+ ($THREADS_REASON)}"

printf '%s\n' "$CM_KIND" > "$WORKDIR/$STAMP.supervisor-candidate-done"

rc_h=0
if [ "$H_JOB" -gt 0 ] 2>/dev/null; then
    wait "$H_JOB" || rc_h=$?
    H_JOB=0
fi
echo "QR-HARNESS: job_rc=$rc_h"
host_cleanup && CLEAN_RC=0 || CLEAN_RC=$?
echo "QR-CLEANUP: owned containers cleanup rc=$CLEAN_RC"

SEAM_REPORT="$OUTDIR/$STAMP.json"
VERDICT=0
case "$CM_KIND" in
    ok) ;;
    *) VERDICT=1 ;;
esac
if [ -f "$WORKDIR/$STAMP.harness-reapfail" ]; then
    echo "QR-FAIL: harness reported reap failure" >&2
    VERDICT=1
fi
# A reported measurement (valid 0 or honest-invalid 3) requires an actual seam
# report; an absent report means pre-report setup/harness failure, never an
# invalid verdict that claims a report (F4).
if { [ "$driver_rc" -eq 0 ] || [ "$driver_rc" -eq 3 ]; } && [ ! -f "$SEAM_REPORT" ]; then
    echo "QR-FAIL: seam delivered rc=$driver_rc but no report at $SEAM_REPORT (pre-report harness/setup failure)" >&2
    VERDICT=1
elif [ "$driver_rc" -eq 0 ]; then
    :
elif [ "$driver_rc" -eq 3 ]; then
    [ "$VERDICT" -eq 0 ] && VERDICT=3
else
    echo "QR-FAIL: unexpected seam rc=$driver_rc" >&2
    VERDICT=1
fi
[ "$rc_h" -eq 0 ] || VERDICT=1
if [ "$CLEAN_RC" -ne 0 ]; then
    echo "QR-FAIL: owned container cleanup incomplete (rc=$CLEAN_RC)" >&2
    VERDICT=1
fi

{
    printf '{\n'
    printf '  "tool": "qryg_runner",\n'
    printf '  "candidate": "%s",\n' "$CAND"
    printf '  "kind": "%s",\n' "$KIND"
    printf '  "stamp": "%s",\n' "$STAMP"
    printf '  "client_mode": "%s",\n' "$CLIENT_MODE"
    printf '  "harness_image_id": "%s",\n' "$E2E_IMAGE_ID"
    printf '  "candidate_image_id": "%s",\n' "$CAND_IMG_ID"
    printf '  "candidate_manifest_digest": "sha256:%s",\n' "$CAND_MANIFEST"
    printf '  "native_config": "%s",\n' "$CAND_CFG"
    printf '  "native_config_sha256": "%s",\n' "${NATIVE_CFG_SHA:-}"
    printf '  "proxy_pid_in_namespace": %s,\n' "$PROXY_PID_IN_NS"
    printf '  "candidate_threads": %s,\n' "${THREADS:-null}"
    printf '  "candidate_threads_reason": "%s",\n' "$THREADS_REASON"
    printf '  "candidate_was_running_at_stop": %s,\n' "$([ "$cand_state" = "running" ] && echo true || echo false)"
    printf '  "candidate_wait_rc": %s,\n' "$cand_rc"
    printf '  "candidate_classification": "%s",\n' "$CM_KIND"
    printf '  "driver_rc": %s,\n' "$driver_rc"
    printf '  "harness_job_rc": %s,\n' "$rc_h"
    printf '  "session_exit": %s,\n' "$VERDICT"
    printf '  "seam_report": "%s"\n' "$SEAM_REPORT"
    printf '}\n'
} > "$OUTDIR/$STAMP.native.json"
echo "QR-NATIVE-META: $OUTDIR/$STAMP.native.json"

if [ "$VERDICT" -eq 3 ]; then
    echo "QR-INVALID: measurement invalid (see seam report); candidate/harness clean" >&2
elif [ "$VERDICT" -eq 1 ]; then
    echo "QR-FAIL: session failed (classify=$CM_KIND driver_rc=$driver_rc harness_rc=$rc_h)" >&2
fi
echo "QR-OK: $CAND/$KIND session_exit=$VERDICT stamp=$STAMP"
exit "$VERDICT"
