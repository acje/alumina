#!/bin/sh
# qryg_runner_selftest.sh -- targeted harmless-stub tests for the qryg.9
# native runner (scripts/qryg_runner.sh + configs/entry/harness under
# scripts/qryg/). No candidate binary is executed, no real container is
# started, no VM is touched: a fake podman in a sandbox PATH answers
# info/inspect and simulates the two container jobs' shared-scratch
# handshake, while the ACTUAL runner drives the whole flow (selector,
# identity pre-flight, net+PID join flags, PID plumbing, teardown
# classification). Pattern follows the accepted qryg.6 T1 harmless-stub
# selector probe.
#
# Exit 0 = all targeted checks pass (qryg.9 verify.mid hard 0).
# 1 = any check fails; prints PASS/FAIL lines and a summary.
set -eu

ROOT="$(pwd)"
SBX="$ROOT/.ooda/tmp/alumina-qryg.9-selftest-$$"
rm -rf "$SBX"; mkdir -p "$SBX/bin" "$SBX/out"
export SBX
PASS=0; FAIL=0; TOTAL=0
finish() { rc="$?"; if [ "${QRYSELFTEST_KEEP:-0}" = "1" ]; then
    echo "KEPT sandbox: $SBX"; else rm -rf "$SBX"; fi
    trap - INT TERM EXIT; exit "$rc"; }
trap 'finish' INT TERM EXIT
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "PASS $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "FAIL $1"; }
chk() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$3' want '$2')"; fi; }

# --- fake podman (harmless stub; PATH-scoped, never the real binary) --------
cat > "$SBX/bin/podman" <<'STUB'
#!/bin/sh
[ "${1:-}" = "--connection" ] && shift 2
cmd="${1:-}"; shift || true
n="$(cat "$SBX/seq" 2>/dev/null || echo 0)"; n=$((n+1)); echo "$n" > "$SBX/seq"
printf '%s\t%s' "$n" "$cmd" >> "$SBX/podman.log"
for a in "$@"; do printf '\t%s' "$a" >> "$SBX/podman.log"; done
printf '\n' >> "$SBX/podman.log"
work=""; stamp=""; name=""
i=0
while [ "$i" -lt "$#" ]; do
    eval "arg=\${$((i+1))}"
    case "$arg" in
        -v) i=$((i+1)); eval "v=\${$((i+1))}"
            case "$v" in *:/w:Z) work="${v%:/w:Z}" ;; esac ;;
        --name) i=$((i+1)); eval "name=\${$((i+1))}" ;;
        -e) i=$((i+1)); eval "e=\${$((i+1))}"
            case "$e" in STAMP=*) stamp="${e#STAMP=}" ;; esac ;;
    esac
    i=$((i+1))
done
case "$cmd" in
    info) exit 0 ;;
    image)
        [ "${1:-}" = "inspect" ] || exit 0
        shift
        id="$1"; shift 2
        fmt="$1"
        case "$fmt" in
            *Parent*) echo "$HARNESS_PARENT" ;;
            *RepoDigests*) echo "$REPODIGEST" ;;
            *) if [ "${FAKE_MISMATCH:-0}" = "1" ]; then echo "bogus-id"; else echo "$id"; fi ;;
        esac
        exit 0 ;;
    run)
        case "$name" in
            qryg-h-*)
                sleep 0.1
                : > "$work/$stamp.netns-ready"
                # released by candidate.pid (normal) or by a host_cleanup rm
                # marker (F1 cancellation/early-failure path)
                a=0; while [ ! -r "$work/$stamp.candidate.pid" ] && [ ! -e "$SBX/rm.$name" ] && [ "$a" -lt 200 ]; do sleep 0.05; a=$((a+1)); done
                if [ "${FAKE_H_EARLY:-0}" = "1" ]; then exit 1; fi
                printf '%s\n' "${FAKE_CLIENT_RC:-0}" > "$work/$stamp.client-done"
                if [ "${FAKE_NO_REPORT:-0}" != "1" ]; then
                    mkdir -p "$QRYG_OUTDIR"
                    printf '{"valid":true}\n' > "$QRYG_OUTDIR/$stamp.json"
                fi
                b=0; while [ ! -r "$work/$stamp.supervisor-candidate-done" ] && [ ! -e "$SBX/rm.$name" ] && [ "$b" -lt 200 ]; do sleep 0.05; b=$((b+1)); done
                exit 0 ;;
            qryg-c-*)
                printf '%s\n' "${FAKE_CAND_PID:-4242}" > "$work/$stamp.candidate.pid"
                if [ "${FAKE_CAND_EARLY:-0}" = "1" ]; then exit 1; fi
                c=0; while [ ! -r "$SBX/stop.$name" ] && [ ! -e "$SBX/rm.$name" ] && [ "$c" -lt 400 ]; do sleep 0.05; c=$((c+1)); done
                exit 0 ;;
        esac
        exit 0 ;;
    stop) : > "$SBX/stop.$1"; exit 0 ;;
    wait) echo "$FAKE_WAIT_RC"; exit 0 ;;
    inspect) echo "${FAKE_CAND_STATE:-running}"; exit 0 ;;
    exec)
        if [ "${FAKE_EXEC_RC:-0}" = "0" ]; then echo "${FAKE_THREADS:-4}"; fi
        exit "${FAKE_EXEC_RC:-0}" ;;
    rm) : > "$SBX/rm.$2"; exit "${FAKE_RM_RC:-0}" ;;
    *) exit 0 ;;
esac
exit 0
STUB
chmod +x "$SBX/bin/podman"

export HARNESS_PARENT="ad70ceb90f563e9fe2ef7064b92dc1347aeaeb71e5369ba8b242498ba030a6f8"
export REPODIGEST_HAPROXY="docker.io/library/haproxy@sha256:3947a5423cb51b6cc2e165ec0c3b8575e622c46bf39a247d065eff15ab8fa9da"
export REPODIGEST_ENVOY="docker.io/envoyproxy/envoy@sha256:ce82b213b2c9190aa9fa2fc76678743a690681cbd668de32dd749e3e4da52862"

invoke_runner() { # cand kind  -- actual runner under fake podman, PATH-scoped
    ( export PATH="$SBX/bin:$PATH"
      export QRYG_OUTDIR="$SBX/out"
      export FAKE_CLIENT_RC="${FAKE_CLIENT_RC:-0}"
      export FAKE_CAND_PID="${FAKE_CAND_PID:-4242}"
      export FAKE_WAIT_RC="${FAKE_WAIT_RC:-143}"
      export FAKE_CAND_STATE="${FAKE_CAND_STATE:-running}"
      export FAKE_THREADS="${FAKE_THREADS:-4}"
      export FAKE_MISMATCH="${FAKE_MISMATCH:-0}"
      export FAKE_EXEC_RC="${FAKE_EXEC_RC:-0}"
      export FAKE_NO_REPORT="${FAKE_NO_REPORT:-0}"
      export FAKE_RM_RC="${FAKE_RM_RC:-0}"
      export FAKE_H_EARLY="${FAKE_H_EARLY:-0}"
      export FAKE_CAND_EARLY="${FAKE_CAND_EARLY:-0}"
      if [ "$1" = "envoy" ]; then export REPODIGEST="$REPODIGEST_ENVOY"; else export REPODIGEST="$REPODIGEST_HAPROXY"; fi
      cd "$ROOT" && sh scripts/qryg_runner.sh "$1" "$2" )
}

jval() { sed -n "s/.*\"$1\": *\"\{0,1\}\([^,}\"]*\)\"\{0,1\}\(,\{0,1\}\).*/\1/p" "$2" 2>/dev/null | head -1; }
chk_ge() { if [ "$2" -ge "$3" ] 2>/dev/null; then ok "$1"; else bad "$1 (got '$2' want >=$3)"; fi; }
TAB=$(printf '\t')
companion() { ls -t "$SBX/out"/*.native.json 2>/dev/null | head -1; }

# ===========================================================================
# A. config + entry + client-wiring source checks (targeted, no execution)
# ===========================================================================
hap_cfg="$ROOT/scripts/qryg/haproxy.cfg"
envio_cfg="$ROOT/scripts/qryg/envoy_connect.yaml"
chk cfg-haproxy-nbthread1 \
    "$(sed -n 's/.*nbthread \([0-9]*\).*/\1/p' "$hap_cfg" | head -1)" "1"
chk cfg-haproxy-sni-allowlist \
    "$(grep -c 'req.ssl_sni example.com' "$hap_cfg" | tr -d ' ')" "1"
chk cfg-haproxy-inspect-gate \
    "$(grep -c 'req.ssl_hello_type 1' "$hap_cfg" | tr -d ' ')" "1"
chk cfg-haproxy-fixed-backend \
    "$(grep -c 'server example 8.8.8.8:443' "$hap_cfg" | tr -d ' ')" "1"
chk cfg-envoy-connect-matcher \
    "$(grep -c 'connect_matcher' "$envio_cfg" | tr -d ' ')" "1"
chk cfg-envoy-connt-upgrade \
    "$(grep -c "upgrade_type: CONNECT" "$envio_cfg" | tr -d ' ')" "1"
chk cfg-envoy-timeout0 \
    "$(grep -c 'timeout: 0s' "$envio_cfg" | tr -d ' ')" "1"
chk cfg-envoy-fixed-backend \
    "$(grep -c 'address: 8.8.8.8' "$envio_cfg" | tr -d ' ')" "1"
chk cfg-envoy-rawtcp-notls \
    "$(grep -c 'transport_socket' "$envio_cfg" | tr -d ' ')" "0"
chk entry-haproxy-db-nofw \
    "$(grep -c 'exec /usr/local/sbin/haproxy -db -f /cfg/haproxy.cfg' "$ROOT/scripts/qryg/entry_haproxy.sh" | tr -d ' ')" "1"
chk entry-envoy-conc1 \
    "$(grep -c 'exec /usr/local/bin/envoy -c /cfg/envoy_connect.yaml --concurrency 1' "$ROOT/scripts/qryg/entry_envoy.sh" | tr -d ' ')" "1"
chk entry-pid-write \
    "$(grep -c 'echo "\$\$" > "/w/${STAMP}.candidate.pid"' "$ROOT/scripts/qryg/entry_haproxy.sh" | tr -d ' ')" "1"
chk wiring-client-mode \
    "$(grep -c -- '--mode "$CLIENT_MODE"' "$ROOT/scripts/qryg/harness_native.sh" | tr -d ' ')" "1"
chk wiring-proxy-pid \
    "$(grep -c -- '--proxy-pid "$CAND_PID"' "$ROOT/scripts/qryg/harness_native.sh" | tr -d ' ')" "1"
chk wiring-backend-pid \
    "$(grep -c -- '--backend-pid "$SRV"' "$ROOT/scripts/qryg/harness_native.sh" | tr -d ' ')" "1"
chk wiring-unchanged-owner \
    "$(grep -c -- 'stop "$SRV" "backend" 1' "$ROOT/scripts/qryg/harness_native.sh" | tr -d ' ')" "1"

# ===========================================================================
# B. selector (negative) + identity pre-flight (positive-block)
# ===========================================================================
set +e
"$ROOT/scripts/qryg_runner.sh" bogus smoke >/dev/null 2>&1
rc_bad=$?
"$ROOT/scripts/qryg_runner.sh" haproxy bogus >/dev/null 2>&1
rc_badkind=$?
set -e
chk selector-unknown-candidate "$rc_bad" "2"
chk selector-unknown-kind "$rc_badkind" "2"

: > "$SBX/podman.log"
export FAKE_MISMATCH=1
set +e
invoke_runner haproxy smoke >/dev/null 2>&1
rc_mm=$?
set -e
chk identity-mismatch-blocked "$rc_mm" "1"

# ===========================================================================
# C. clean haproxy smoke (direct-proxy route): selector/PID/reap positive
# ===========================================================================
: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_MISMATCH=0 FAKE_CLIENT_RC=0 FAKE_CAND_PID=4242 FAKE_WAIT_RC=143 FAKE_CAND_STATE=running FAKE_THREADS=5
set +e
invoke_runner haproxy smoke >/dev/null 2>"$SBX/h.err"
rc_haproxy=$?
set -e
chk runner-haproxy-clean "$rc_haproxy" "0"
chk haproxy-companion-mode "$(jval client_mode "$(companion)")" "direct-proxy"
chk haproxy-companion-pid "$(jval proxy_pid_in_namespace "$(companion)")" "4242"
chk haproxy-companion-classify "$(jval candidate_classification "$(companion)")" "ok"
chk haproxy-companion-threads "$(jval candidate_threads "$(companion)")" "5"
chk haproxy-pid-join \
    "$(grep -c -- "--pid${TAB}container:qryg-h-haproxy-" "$SBX/podman.log" | tr -d ' ')" "1"
chk haproxy-net-join \
    "$(grep -c -- "--network${TAB}container:qryg-h-haproxy-" "$SBX/podman.log" | tr -d ' ')" "1"
chk_ge haproxy-image-id \
    "$(grep -c 'd483b7896ae82de219b492b77ba57c5c5e6306562f74e063c25c6de37e15339b' "$SBX/podman.log" | tr -d ' ')" "1"
chk haproxy-entry \
    "$(grep -c -- "--entrypoint${TAB}/cfg/entry_haproxy.sh" "$SBX/podman.log" | tr -d ' ')" "1"
chk haproxy-mode-env \
    "$(grep -c -- "-e${TAB}CLIENT_MODE=direct-proxy" "$SBX/podman.log" | tr -d ' ')" "1"
chk haproxy-stop-before-wait \
    "$(awk '$2=="stop"{s=NR} $2=="wait"{if(!w)w=NR} END{print(s>0 && w>s)?"1":"0"}' "$SBX/podman.log")" "1"

# ===========================================================================
# D. clean envoy timed (via-proxy route; concurrency/user plumbing)
# ===========================================================================
: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
set +e
invoke_runner envoy timed >/dev/null 2>"$SBX/e.err"
rc_envoy=$?
set -e
chk runner-envoy-clean "$rc_envoy" "0"
chk envoy-companion-mode "$(jval client_mode "$(companion)")" "via-proxy"
chk envoy-companion-classify "$(jval candidate_classification "$(companion)")" "ok"
chk_ge envoy-image-id \
    "$(grep -c 'a084f595b889eb2e7c9af1abcc7565a9520fd45b63a7653f5181a55dd2cc9735' "$SBX/podman.log" | tr -d ' ')" "1"
chk envoy-entry \
    "$(grep -c -- "--entrypoint${TAB}/cfg/entry_envoy.sh" "$SBX/podman.log" | tr -d ' ')" "1"
chk envoy-user-drop \
    "$(grep -c -- "--user${TAB}65534:65534" "$SBX/podman.log" | tr -d ' ')" "1"
chk envoy-mode-env \
    "$(grep -c -- "-e${TAB}CLIENT_MODE=via-proxy" "$SBX/podman.log" | tr -d ' ')" "1"
chk envoy-no-haproxy-image \
    "$(grep -c 'd483b7896ae82de219b492b77ba57c5c5e6306562f74e063c25c6de37e15339b' "$SBX/podman.log" | tr -d ' ')" "0"

# ===========================================================================
# E. teardown classification negatives: forced kill 137 / early death
# ===========================================================================
: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_MISMATCH=0 FAKE_CLIENT_RC=0 FAKE_CAND_PID=4242 FAKE_WAIT_RC=137 FAKE_CAND_STATE=running
set +e
invoke_runner haproxy smoke >/dev/null 2>&1
rc_kill=$?
set -e
chk reap-forced-kill-invalid "$rc_kill" "1"
chk reap-forced-kill-class "$(jval candidate_classification "$(companion)")" "forced-kill-137"

: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_WAIT_RC=99 FAKE_CAND_STATE=exited FAKE_CLIENT_RC=0
set +e
invoke_runner haproxy smoke >/dev/null 2>&1
rc_early=$?
set -e
chk reap-early-death-invalid "$rc_early" "1"
chk reap-early-death-class "$(jval candidate_classification "$(companion)")" "early-death"

# ===========================================================================
# F. honest measurement invalid (seam exit 3) propagates as session exit 3
# ===========================================================================
: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_WAIT_RC=143 FAKE_CAND_STATE=running FAKE_CLIENT_RC=3
set +e
invoke_runner haproxy smoke >/dev/null 2>&1
rc_inv=$?
set -e
chk runner-honest-invalid-exit3 "$rc_inv" "3"
chk runner-honest-invalid-driver3 "$(jval driver_rc "$(companion)")" "3"

# ===========================================================================
# G. F3 thread-probe tri-state: failed/zero/missing evidence is Unknown, never 0
# ===========================================================================
: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_MISMATCH=0 FAKE_CLIENT_RC=0 FAKE_CAND_PID=4242 FAKE_WAIT_RC=143 FAKE_CAND_STATE=running FAKE_THREADS=0 FAKE_EXEC_RC=0
set +e
invoke_runner haproxy smoke >/dev/null 2>&1
rc_t0=$?
set -e
chk thread-zero-session-valid "$rc_t0" "0"
chk thread-zero-is-unknown "$(jval candidate_threads "$(companion)")" "null"
chk thread-zero-reason "$(jval candidate_threads_reason "$(companion)")" "thread probe counted 0 (task dir missing or proxy pid gone)"

: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_THREADS=7 FAKE_EXEC_RC=0
set +e
invoke_runner haproxy smoke >/dev/null 2>&1
set -e
chk thread-positive-count "$(jval candidate_threads "$(companion)")" "7"
chk thread-positive-no-reason "$(jval candidate_threads_reason "$(companion)")" ""

: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_THREADS=4 FAKE_EXEC_RC=9
set +e
invoke_runner haproxy smoke >/dev/null 2>&1
set -e
chk thread-producer-fail-unknown "$(jval candidate_threads "$(companion)")" "null"
chk thread-producer-fail-reason "$(jval candidate_threads_reason "$(companion)")" "thread probe producer failed (probe_rc=9)"

# ===========================================================================
# H. F4 absent seam report is harness failure (1), never reported-invalid (3)
# ===========================================================================
: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_EXEC_RC=0 FAKE_CLIENT_RC=3 FAKE_NO_REPORT=1
prev_comp="$(companion)"
set +e
invoke_runner haproxy smoke >/dev/null 2>"$SBX/h.err"
rc_nr3=$?
set -e
now_comp="$(companion)"
chk missing-report-fresh-companion "$([ "$prev_comp" != "$now_comp" ] && echo fresh || echo stale)" "fresh"
chk missing-report-invalid-is-harness "$rc_nr3" "1"
chk missing-report-session-1 "$(jval session_exit "$now_comp")" "1"
chk missing-report-explicit-fail "$(grep -c 'no report at' "$SBX/h.err" | tr -d ' ')" "1"

: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_CLIENT_RC=0
set +e
invoke_runner haproxy smoke >/dev/null 2>&1
rc_nr0=$?
set -e
chk missing-report-valid-entry-not-claim "$rc_nr0" "1"

# ===========================================================================
# I. F1 owned-lifecycle: TERM after acquisition, premature death, rm failure
# ===========================================================================
# I-a: SIGTERM once both run jobs are acquired -> cleanup candidate-first, 130
: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_CLIENT_RC=0 FAKE_CAND_PID=4242 FAKE_WAIT_RC=143 FAKE_CAND_STATE=running FAKE_THREADS=4
( export PATH="$SBX/bin:$PATH" QRYG_OUTDIR="$SBX/out" REPODIGEST="$REPODIGEST_HAPROXY"
  export FAKE_MISMATCH=0 FAKE_CLIENT_RC=0 FAKE_CAND_PID=4242 FAKE_WAIT_RC=143 FAKE_CAND_STATE=running FAKE_THREADS=4
  export FAKE_EXEC_RC=0 FAKE_NO_REPORT=0 FAKE_RM_RC=0 FAKE_H_EARLY=0 FAKE_CAND_EARLY=0
  cd "$ROOT" && exec sh scripts/qryg_runner.sh haproxy smoke ) >/dev/null 2>$SBX/t.err &
runpid=$!
ready=0; a=0
while [ "$a" -lt 400 ]; do
    runs=$(awk -F'\t' '$2=="run"{n++} END{print n+0}' "$SBX/podman.log")
    if [ "$runs" -ge 2 ] && [ -n "$(find "$SBX/out" -name '*.candidate.pid' -newer "$SBX/podman.log" 2>/dev/null | head -1)" ]; then
        ready=1; break
    fi
    if ! kill -0 "$runpid" 2>/dev/null; then break; fi
    sleep 0.05; a=$((a+1))
done
chk term-both-jobs-started "$ready" "1"
set +e
kill -TERM "$runpid"
wait "$runpid"; rc_term=$?
set -e
chk term-exit-130 "$rc_term" "130"
chk term-rm-both "$(awk -F'\t' '$2=="rm"{n++} END{print n+0}' "$SBX/podman.log")" "2"
chk term-candidate-first "$(awk -F'\t' '$2=="rm"{print substr($4,1,9); exit}' "$SBX/podman.log")" "qryg-c-ha"

# I-b: candidate premature death before client-done -> session 1 + cleanup both
: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_MISMATCH=0 FAKE_CLIENT_RC=0 FAKE_CAND_PID=4242 FAKE_WAIT_RC=143 FAKE_CAND_STATE=running FAKE_THREADS=4 FAKE_CAND_EARLY=1 FAKE_H_EARLY=0 FAKE_RM_RC=0
set +e
invoke_runner haproxy smoke >/dev/null 2>&1
rc_ce=$?
set -e
chk cand-early-invalid "$rc_ce" "1"
chk cand-early-cleanup-both "$(awk -F'\t' '$2=="rm"{n++} END{print n+0}' "$SBX/podman.log")" "2"

# I-c: harness premature death before client-done -> session 1 + cleanup both
: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_CAND_EARLY=0 FAKE_H_EARLY=1
set +e
invoke_runner haproxy smoke >/dev/null 2>&1
rc_he=$?
set -e
chk h-early-invalid "$rc_he" "1"
chk h-early-cleanup-both "$(awk -F'\t' '$2=="rm"{n++} END{print n+0}' "$SBX/podman.log")" "2"

# I-d: removal/reap failure (disconnected runtime) retained, not claimed clean
: > "$SBX/podman.log"; printf '0\n' > "$SBX/seq"
export FAKE_CAND_EARLY=0 FAKE_H_EARLY=0 FAKE_RM_RC=1
prev_comp="$(companion)"
set +e
invoke_runner haproxy smoke >/dev/null 2>"$SBX/e.err"
rc_rf=$?
set -e
now_comp="$(companion)"
chk rm-fail-fresh-companion "$([ "$prev_comp" != "$now_comp" ] && echo fresh || echo stale)" "fresh"
chk rm-fail-supervisor-1 "$rc_rf" "1"
chk rm-fail-session-exit "$(jval session_exit "$now_comp")" "1"
chk_ge rm-fail-retain-line \
    "$(grep -c 'QR-CLEANUP-FAIL' "$SBX/e.err" | tr -d ' ')" "1"

# ===========================================================================
# J. F2 fixture reap ownership: ACTUAL harness_native.sh body under stubbed
# fixture python3/ip. The body is copied byte-exact with only the five scratch
# path tokens redirected to the sandbox (/work,/w/ cannot be provisioned on
# the host); the structural abstract-delta check below proves the copy differs
# only there, so the real trap/stop/cleanup/disarm control flow runs unchanged.
# ===========================================================================
mkdir -p "$SBX/hbin"
cat > "$SBX/hbin/ip" <<'IP'
#!/bin/sh
exit 0
IP
cat > "$SBX/hbin/sha256sum" <<'SHA'
#!/bin/sh
printf '%064x  %s\n' 0 "${1:-}"
SHA
cat > "$SBX/hbin/python3" <<'PY'
#!/bin/sh
if [ "${1:-}" = "-" ]; then exit 0; fi
role=""; jout=""; want_role=0; want_jout=0
for a in "$@"; do
    case "$a" in
        --role) want_role=1 ;;
        --role=*) role="${a#--role=}" ;;
        --json-out) want_jout=1 ;;
        --json-out=*) jout="${a#--json-out=}" ;;
        *)
            if [ "$want_role" = "1" ]; then role="$a"; want_role=0; fi
            if [ "$want_jout" = "1" ]; then jout="$a"; want_jout=0; fi ;;
    esac
done
case "$role" in
    dns-responder) sleep 1000 ;;
    backend)
        if [ "${FAKE_LEAK_BACKEND:-0}" = "1" ]; then
            trap '' TERM
            while :; do sleep 0.1; done
        else
            sleep 1000
        fi ;;
    client)
        if [ -n "$jout" ]; then printf '{"valid":true}\n' > "$jout"; fi
        exit "${FAKE_CLIENT_RC:-0}" ;;
    *) exit 0 ;;
esac
PY
chmod +x "$SBX/hbin/ip" "$SBX/hbin/sha256sum" "$SBX/hbin/python3"

harness_body_run() {
    name="$1"; leak="$2"; want_rc="$3"; want_reapfail="$4"
    HB="$SBX/hbody-$name"
    mkdir -p "$HB/work" "$HB/out" "$HB/app" "$HB/tmp" "$HB/bin"
    sed -e "s#/w/#@QRYW@/#g" \
        -e "s#/work#@QRYW@#g" \
        -e "s#/out/#@QRYO@/#g" \
        -e "s#/app/#@QRYA@/#g" \
        -e "s#/tmp/#@QRYT@/#g" \
        "$ROOT/scripts/qryg/harness_native.sh" \
        | sed -e "s#@QRYW@#$HB/work#g" \
              -e "s#@QRYO@#$HB/out#g" \
              -e "s#@QRYA@#$HB/app#g" \
              -e "s#@QRYT@#$HB/tmp#g" > "$HB/harness.sh"
    # structural proof the copy differs from the actual body ONLY by the five
    # scratch path tokens: abstracting the sandbox paths back out of the copy
    # must reproduce the original with the tokens abstracted.
    expected_abs=$(sed -e "s#/w/#@W@/#g" -e "s#/work#@W@#g" \
        -e "s#/out/#@O@/#g" -e "s#/app/#@A@/#g" -e "s#/tmp/#@T@/#g" \
        "$ROOT/scripts/qryg/harness_native.sh")
    actual_abs=$(sed -e "s#$HB/work#@W@#g" -e "s#$HB/out#@O@#g" \
        -e "s#$HB/app#@A@#g" -e "s#$HB/tmp#@T@#g" "$HB/harness.sh")
    chk "hbody-$name-only-scratch-delta" \
        "$([ "$expected_abs" = "$actual_abs" ] && echo identical || echo differs)" "identical"
    [ "$(echo "$expected_abs" | grep -c '@W@' | tr -d ' ')" -gt 0 ] && ok "hbody-$name-paths-rewritten" || bad "hbody-$name-paths-rewritten"
    STAMP="hbody-$name"
    export STAMP CLIENT_MODE=direct-proxy SECONDS=2 WARMUP=0 KIND=smoke
    export FAKE_LEAK_BACKEND="$leak" FAKE_CLIENT_RC=0
    ( a=0
      while [ ! -r "$HB/work/$STAMP.netns-ready" ] && [ "$a" -lt 200 ]; do sleep 0.05; a=$((a+1)); done
      printf '%s\n' 4242 > "$HB/work/$STAMP.candidate.pid" ) &
    wp=$!
    ( b=0
      while [ ! -r "$HB/work/$STAMP.client-done" ] && [ "$b" -lt 400 ]; do sleep 0.05; b=$((b+1)); done
      : > "$HB/work/$STAMP.supervisor-candidate-done" ) &
    sp=$!
    set +e
    ( cd "$HB/work" && PATH="$HB/bin:$SBX/hbin:$PATH" sh "$HB/harness.sh" ) >"$HB/harness.out" 2>&1
    rc=$?
    set -e
    wait "$wp" 2>/dev/null || true
    wait "$sp" 2>/dev/null || true
    chk "hbody-$name-exit" "$rc" "$want_rc"
    chk "hbody-$name-reapfail" \
        "$([ -f "$HB/work/$STAMP.harness-reapfail" ] && echo 1 || echo 0)" "$want_reapfail"
    chk "hbody-$name-client-done" \
        "$(cat "$HB/work/$STAMP.client-done" 2>/dev/null || echo none)" "0"
    if [ "$want_reapfail" = "1" ]; then
        # F2 observable: the bare EXIT trap re-ran lenient cleanup on exit, so
        # the already-reaped backend gets a SEAM-CLEANUP line. Pre-fix the trap
        # was disarmed and no such retry line appeared.
        chk "hbody-$name-armed-retry" \
            "$(grep -c 'SEAM-CLEANUP: backend' "$HB/harness.out" | tr -d ' ')" "1"
    else
        chk "hbody-$name-no-retry-seen" \
            "$(grep -c 'SEAM-CLEANUP:' "$HB/harness.out" | tr -d ' ')" "0"
    fi
}

harness_body_run reap-ok 0 0 0
harness_body_run reap-fail 1 1 1

echo "---"
echo "QRYSELFTEST: total=$TOTAL pass=$PASS fail=$FAIL"
if [ "$FAIL" -eq 0 ]; then
    exit 0
fi
exit 1
