#!/bin/sh
set -eu

TIER="${1:-}"
SCOPE="${2:-}"

usage() {
    echo "usage: verify.sh {mid|boundary|fixtures} {foundations|boot|phase1} | verify.sh docs" >&2
    exit 2
}

[ -n "$TIER" ] || usage
[ -n "$SCOPE" ] || [ "$TIER" = "docs" ] || usage

TOOLCHAIN="1.99.0"

INTENDED="Cargo.toml Cargo.lock rust-toolchain.toml deny.toml scripts/verify.sh scripts/cargo_config_probe.py scripts/fixture_metadata_probe.py README.md src/lib.rs src/main.rs src/alloc.rs src/fault.rs src/fuzz.rs src/config.rs src/resolver.rs src/preflight.rs src/inventory.rs src/boot.rs tests/foundations.rs tests/boot.rs"

# docslink gate roots: the exact nonempty argv docslink_check consumes. Shared
# with the identity snapshot so the boundary content identity covers precisely
# the bytes docslink_check reads (drift-proof by construction).
DOCSLINK_ROOTS="docs/alumina-proxy.md docs/architecture.md docs/build-plan.md docs/traceability.md docs/verification.md docs/qa-package/README.md README.md"

# B1: every relevant before/after identity input consumed by the boundary run:
# source/config/lock/toolchain/deny plus the docs and .gitignore that
# docslink_check and the working-tree view consume. Changing build outputs (the
# compiled artifact) are intentionally excluded from this stability set and are
# recorded separately at executed output. README.md is already covered by
# INTENDED; the remaining DOCSLINK_ROOTS are added here so a gate-root edit
# cannot silently drop an identity input.
GATE_ROOT_EXTRAS=""
for root in $DOCSLINK_ROOTS; do
    case " $INTENDED " in
        *" $root "*) ;;
        *) GATE_ROOT_EXTRAS="$GATE_ROOT_EXTRAS $root" ;;
    esac
done
IDENTITY_FILES="$INTENDED .gitignore$GATE_ROOT_EXTRAS scripts/docs_check/check.mjs scripts/docs_check/package.json scripts/docs_check/package-lock.json scripts/docs_check/test.mjs"

# Snapshot locations live under target/ (gitignored) so they never alter the
# working-tree scope recorded in the status snapshot.
IDENTITY_BEFORE="target/identity-before"
IDENTITY_AFTER="target/identity-after"

static_gate() {
    binfile="$1"
    [ -x "$binfile" ] || {
        echo "static-ELF FAIL: release binary missing: $binfile" >&2
        exit 1
    }
    dyn_rc=0
    dyn_out=$(readelf -d "$binfile" 2>&1) || dyn_rc=$?
    [ "$dyn_rc" -eq 0 ] || {
        echo "static-ELF FAIL: readelf -d exit $dyn_rc (probe failure is not PASS)" >&2
        exit 1
    }
    case "$dyn_out" in
        *NEEDED*)
            echo "static-ELF FAIL: dynamic NEEDED entries present" >&2
            exit 1
            ;;
    esac
    interp_rc=0
    interp_out=$(readelf -l "$binfile" 2>&1) || interp_rc=$?
    [ "$interp_rc" -eq 0 ] || {
        echo "static-ELF FAIL: readelf -l exit $interp_rc (probe failure is not PASS)" >&2
        exit 1
    }
    case "$interp_out" in
        *INTERP*)
            echo "static-ELF FAIL: PT_INTERP present" >&2
            exit 1
            ;;
    esac
    echo "STATIC-ELF-CHECKS-OK"
}

whitespace_gate() {
    command -v git >/dev/null 2>&1 || {
        echo "WHITESPACE-GATE-BLOCKED: git required and absent (no host proof receipt consumed)" >&2
        exit 1
    }
    # native git must see the actual mounted repository metadata, not a copy
    [ -f .git/HEAD ] || {
        echo "WHITESPACE-GATE-BLOCKED: .git/HEAD not visible (actual checkout required)" >&2
        exit 1
    }
    rc=0
    head=$(git rev-parse --verify HEAD 2>&1) || rc=$?
    [ "$rc" -eq 0 ] || {
        echo "WHITESPACE-GATE-BLOCKED: git rev-parse exit $rc (repository unreadable)" >&2
        exit 1
    }
    git diff --check || {
        echo "whitespace FAIL: tracked diff contains whitespace errors" >&2
        exit 1
    }
    for f in $INTENDED; do
        [ -f "$f" ] || {
            echo "whitespace FAIL: intended file missing: $f" >&2
            exit 1
        }
        rc=0
        out=$(git diff --no-index --check /dev/null "$f" 2>&1) || rc=$?
        case "$rc" in
            0 | 1) ;;
            *)
                echo "whitespace FAIL: $f (git exit $rc)" >&2
                exit 1
                ;;
        esac
        case "$out" in
            *[![:space:]]*)
                echo "whitespace FAIL: $f" >&2
                exit 1
                ;;
        esac
    done
    echo "WHITESPACE-GATE-OK (native git, HEAD=$head)"
}

# Reverse-dependent closure derivation: single-crate repo, cargo metadata
# names every package that links `alumina`; the closure is `alumina` itself.
closure_metadata() {
    cargo metadata --format-version 1 --locked >/dev/null
    echo "CLOSURE-OK (single-crate closure = alumina)"
}

mid_foundations() {
    [ "$(uname -s)" = "Linux" ] || {
        echo "F0 static-Linux proof requires Linux execution" >&2
        exit 1
    }
    closure_metadata
    echo "PRODUCTION-RELEASE-BUILD (no alloc-witness):"
    cargo +${TOOLCHAIN} build --locked --release
    static_gate "target/release/alumina"
    # NOTE: the release binary is NOT executed here. The binary boots only
    # under the privilege profile staged by `verify.sh fixtures boot`; running
    # it as this environment's root fires the root-UID rejection (78), so a
    # direct exec here would be a negative fixture, not a foundation gate.
    echo "WITNESS-TESTS (--features alloc-witness):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --features alloc-witness --test foundations
    echo "WITNESS-OFF-TESTS (F2/F4 subset):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --test foundations
    echo "FMT:"
    cargo +${TOOLCHAIN} fmt --check
    echo "CLIPPY (production, no alloc-witness):"
    cargo +${TOOLCHAIN} aclippy -p alumina --locked --all-targets -- -D warnings
    echo "CLIPPY (test-harness with alloc-witness):"
    cargo +${TOOLCHAIN} aclippy -p alumina --locked --all-targets --features alloc-witness -- -D warnings
    whitespace_gate
    echo "FOUNDATIONS-MID-OK"
}

mid_boot() {
    [ "$(uname -s)" = "Linux" ] || {
        echo "boot mid requires Linux execution" >&2
        exit 1
    }
    closure_metadata
    echo "PRODUCTION-RELEASE-BUILD (boot binary):"
    cargo +${TOOLCHAIN} build --locked --release
    static_gate "target/release/alumina"
    echo "BOOT-TESTS (strict parser + validated types + storage inventory):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --test boot
    echo "BOOT-TESTS-WITNESS (alloc retention bound):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --features alloc-witness --test boot
    echo "FOUNDATIONS-REGRESSION:"
    cargo +${TOOLCHAIN} atest -p alumina --locked --test foundations
    echo "FMT:"
    cargo +${TOOLCHAIN} fmt --check
    echo "CLIPPY:"
    cargo +${TOOLCHAIN} aclippy -p alumina --locked --all-targets -- -D warnings
    whitespace_gate
    echo "BOOT-MID-OK"
}

# Boundary-only union of the `mid foundations` and `mid boot` command sets
# (same input union), executed once each so the boundary never runs the
# highest-value native common commands twice (release build, static gate,
# foundations+boot tests with and without alloc-witness, fmt, clippy both
# variants, whitespace gate). The standalone `mid foundations` / `mid boot`
# selectors are unchanged and remain dispatchable on their own.
#
# Ordering: the clippy pair keeps the exact adjacency proven green by the
# standalone foundation selector (alloc-witness clippy immediately after
# production clippy, with the alloc-witness lib last built by the witness
# tests). The boot tests are intentionally deferred until AFTER the clippy
# block (diverging from `mid boot`, which runs them before clippy) so the
# alloc-witness boot tests never precede the alloc-witness clippy phase. That
# deliberate reorder avoids an aw-clippy-after-aw-boot-test adjacency in one
# cargo invocation, which can otherwise trip a clippy-per-target fingerprint
# E0463 (can't find crate for `alumina`) on the alloc-witness-only mio_matrix
# test over the shared persistent target dir.
mid_union() {
    [ "$(uname -s)" = "Linux" ] || {
        echo "mid union requires Linux execution" >&2
        exit 1
    }
    closure_metadata
    echo "PRODUCTION-RELEASE-BUILD (boundary union, no alloc-witness):"
    cargo +${TOOLCHAIN} build --locked --release
    static_gate "target/release/alumina"
    echo "WITNESS-TESTS (--features alloc-witness):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --features alloc-witness --test foundations
    echo "WITNESS-OFF-TESTS (F2/F4 subset):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --test foundations
    echo "FMT:"
    cargo +${TOOLCHAIN} fmt --check
    echo "CLIPPY (production, no alloc-witness):"
    cargo +${TOOLCHAIN} aclippy -p alumina --locked --all-targets -- -D warnings
    echo "CLIPPY (test-harness with alloc-witness):"
    cargo +${TOOLCHAIN} aclippy -p alumina --locked --all-targets --features alloc-witness -- -D warnings
    echo "BOOT-TESTS (strict parser + validated types + storage inventory):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --test boot
    echo "BOOT-TESTS-WITNESS (alloc retention bound):"
    cargo +${TOOLCHAIN} atest -p alumina --locked --features alloc-witness --test boot
    whitespace_gate
    echo "UNION-MID-OK"
}

# Linux kernel privilege fixtures. The proof-only `fixture-facts` feature build
# is executed (a clearly-separate variant artifact under target/fixture-facts;
# the production target/release artifact is left untouched, with before/after
# digest equality enforced) so the fixture binary prints its own kernel facts
# to stderr at actual entry. Each fixture runs that variant from the ro-mounted
# actual checkout (never a copy) from cwd=/work holding the fixed documented
# config/resolver inputs, under a different kernel-grounded process-attribute
# profile. Fixture stdout and stderr are captured as separate streams: a
# negative fixture requires EMPTY stdout and byte-exact stderr (exact facts line
# plus exact diagnostic); the positive fixture requires the exact banner line on
# stdout (legitimate inventory retained) and byte-exact stderr facts; each
# asserts the integer exit (0 / EX_CONFIG 78). A metadata probe rejects a setid
# mode, proves security.capability absence + variant digest match on the
# executed variant via the xattr filesystem API, with probe errors kept
# distinct from verified absence.
# Quick reference:
#   PODMAN_CONNECTION       rootless builder (default flock-vm)
#   PODMAN_ROOT_CONNECTION  rootful builder for --cap-add probes (default
#                           flock-vm-root)
boot_fixtures() {
    command -v podman >/dev/null 2>&1 || {
        echo "BOOT-FIXTURES-BLOCKED: podman required on the host" >&2
        exit 1
    }
    CONN="${PODMAN_CONNECTION:-flock-vm}"
    ROOTCONN="${PODMAN_ROOT_CONNECTION:-flock-vm-root}"
    ROOT="$(pwd)"
    podman --connection "$CONN" info >/dev/null 2>&1 || {
        echo "BOOT-FIXTURES-BLOCKED: cannot reach podman connection $CONN" >&2
        exit 1
    }
    IMAGE="docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a"
    # Fail closed: a missing image or rootful connection is a BLOCKER, never a
    # silent SKIP->0. The capability-set axes below are kernel fixtures that
    # require the actual container privileges.
    podman --connection "$CONN" image exists "$IMAGE" || {
        echo "BOOT-FIXTURES-BLOCKED: builder image absent on $CONN; pull required" >&2
        exit 1
    }
    podman --connection "$ROOTCONN" info >/dev/null 2>&1 || {
        echo "BOOT-FIXTURES-BLOCKED: cannot reach rootful connection $ROOTCONN" >&2
        exit 1
    }
    podman --connection "$ROOTCONN" image exists "$IMAGE" || {
        echo "BOOT-FIXTURES-BLOCKED: builder image absent on $ROOTCONN; pull required" >&2
        exit 1
    }
    BIN="target/release/alumina"
    [ -x "$ROOT/$BIN" ] || {
        echo "BOOT-FIXTURES-BLOCKED: static binary missing ($BIN); run 'verify.sh mid boot' first" >&2
        exit 1
    }
    release_sha_before=$(sha256_digest file "$ROOT/$BIN") || exit 1
    echo "BUILD fixture-facts variant (proof-only feature; separate target dir; production artifact untouched):"
    linux_dispatch 'cargo +1.99.0 build --release --locked --features fixture-facts --target-dir target/fixture-facts'
    VARBIN="$ROOT/target/fixture-facts/release/alumina"
    [ -x "$VARBIN" ] || {
        echo "BOOT-FIXTURES-BLOCKED: fixture-facts variant binary missing after build" >&2
        exit 1
    }
    variant_sha=$(sha256_digest file "$VARBIN") || exit 1
    release_sha_after=$(sha256_digest file "$ROOT/$BIN") || exit 1
    # In-run fresh-variant marker: record the exact variant this run built next
    # to the artifact so docs/qa-package/validate.sh can prove the exercised binary
    # has current-run provenance (never a stale by-existing pass). Written every
    # run, unconditionally, after the rebuild.
    printf '%s\n' "$variant_sha" > "$ROOT/target/fixture-facts/release/variant.sha256"
    echo "  fresh-variant marker (in-run build): $ROOT/target/fixture-facts/release/variant.sha256 = $variant_sha"
    echo "  fixture-facts variant sha256 $variant_sha"
    # Production before/after equality is an explicit gate, never a printed
    # observation: the proof-only variant build must not touch the production
    # artifact (unr B4).
    if [ "$release_sha_before" = "$release_sha_after" ]; then
        echo "  production release sha256 $release_sha_after (before build $release_sha_before; unchanged)"
    else
        echo "BOOT-FIXTURES FAIL: production artifact digest changed across variant build ($release_sha_before -> $release_sha_after)" >&2
        exit 1
    fi

    # write the fixed documented inputs into a disposable container /work dir
    # (cwd-relative contract: main.rs reads config.toml + resolv.conf from the
    # working directory), then drop privileges inside that dir.
    stage() {
        printf '%s\n' \
            'set -eu' \
            'mkdir -p /work' \
            "printf '%s\\n' 'allowlist = [\"example.com\"]' 'listen = \"0.0.0.0:8080\"' 'startup_unresolved_allowance = 0' > /work/config.toml" \
            "printf '%s\\n' 'nameserver 127.0.0.1' > /work/resolv.conf" \
            'chown -R 65534:65534 /work' \
            'apk add --no-cache util-linux >/dev/null 2>&1 || true'
        true
    }

    outf=$(mktemp) || exit 1
    errf=$(mktemp) || exit 1
    trap 'rm -f "$outf" "$errf"' EXIT

    run_fixture() {
        label="$1"
        expected="$2"
        conn="$3"
        shift 3
        run_cmd="$1"
        shift
        FIXTURE_LABEL="$label"
        > "$outf"
        > "$errf"
        set +e
        podman --connection "$conn" run --rm -v "$ROOT:/app:ro,Z" "$@" "$IMAGE" sh -c "$(stage) && $run_cmd" >"$outf" 2>"$errf"
        rc=$?
        set -e
        FIXTURE_OUTF="$outf"
        FIXTURE_ERRF="$errf"
        echo "FIXTURE $label: exit=$rc"
        sed 's/^/  out>/' "$outf"
        sed 's/^/  err>/' "$errf"
        case "$rc" in
            "$expected") ;;
            *) echo "FIXTURE $label FAIL: expected exit $expected, got $rc" >&2; exit 1 ;;
        esac
    }

    # Stream-discipline predicates (unr B3): stdout and stderr are retained as
    # raw files (never command substitution, which strips trailing newline
    # bytes). Negative stdout must be an EMPTY file - any captured byte, even
    # newline-only, fails. Exact-line checks use grep -Fx whole-line match on
    # the retained stdout; byte-exact stderr is a cmp against an explicitly
    # newline-terminated expected file, so an extra or missing trailing newline
    # fails.
    fixture_require_stdout_empty() {
        if [ -s "$FIXTURE_OUTF" ]; then
            echo "FIXTURE $FIXTURE_LABEL FAIL: expected empty stdout, got:" >&2
            sed 's/^/  /' "$FIXTURE_OUTF" >&2
            exit 1
        fi
    }

    fixture_require_stdout_exact() {
        line="$1"
        grep -Fx -- "$line" "$FIXTURE_OUTF" >/dev/null || {
            echo "FIXTURE $FIXTURE_LABEL FAIL: stdout lacks exact line: $line" >&2
            exit 1
        }
    }

    fixture_require_stderr_exact() {
        expected="$1"
        expectf=$(mktemp) || exit 1
        printf '%s\n' "$expected" > "$expectf"
        cmp -s "$FIXTURE_ERRF" "$expectf" || {
            echo "FIXTURE $FIXTURE_LABEL FAIL: stderr not byte-exact." >&2
            echo "  expected:" >&2
            sed 's/^/    /' "$expectf" >&2
            echo "  got:" >&2
            sed 's/^/    /' "$FIXTURE_ERRF" >&2
            rm -f "$expectf"
            exit 1
        }
        rm -f "$expectf"
    }

    # Fixed-string stdout probes against the captured fixture stdout. The
    # script runs under `set -eu`, and `$?` is only reliably observed through
    # an if/else guard (a bare `grep; rc=$?` is killed by set -e the instant
    # grep is nonzero -- no-match for not_contains is the REQUIRED outcome, so
    # it must never die silently). Probe error stays distinct from absence:
    # contains passes only on a match and diagnoses a probe error;
    # not_contains passes only on the documented no-match exit (1), and a
    # probe error (2) is a FAIL -- absence is never inferred from an
    # unreadable or failed probe stream.
    fixture_require_stdout_contains() {
        fragment="$1"
        if grep -Fq -- "$fragment" "$FIXTURE_OUTF"; then
            rc=0
        else
            rc=$?
        fi
        if [ "$rc" -eq 0 ]; then
            return 0
        fi
        if [ "$rc" -eq 2 ]; then
            echo "FIXTURE $FIXTURE_LABEL ERROR: stdout probe failed (exit 2); required fragment unverifiable: $fragment" >&2
        else
            echo "FIXTURE $FIXTURE_LABEL FAIL: stdout lacks fixed-string fragment: $fragment" >&2
        fi
        exit 1
    }

    fixture_require_stdout_not_contains() {
        fragment="$1"
        if grep -Fq -- "$fragment" "$FIXTURE_OUTF"; then
            rc=0
        else
            rc=$?
        fi
        case "$rc" in
            1)
                return 0
                ;;
            0)
                echo "FIXTURE $FIXTURE_LABEL FAIL: stdout must not contain fixed-string fragment: $fragment" >&2
                exit 1
                ;;
            *)
                echo "FIXTURE $FIXTURE_LABEL ERROR: stdout probe failed (exit $rc); absence not established: $fragment" >&2
                exit 1
                ;;
        esac
    }

    # 1) POSITIVE: NoNewPrivs=1, process dropped to uid 65534 with empty cap
    #    sets. The fixture-facts variant runs the CURRENT serving startup under
    #    the approved privilege profile. The resolver points at loopback where
    #    nothing listens (deterministic connection-refused; no environment
    #    network dependency), so the 90 s window cannot short-close on an early
    #    serve decision. A supervisor then signals the mid-window process with
    #    a real SIGTERM and bounded-waits for its exit: the startup window
    #    settles the typed terminated outcome (startup_final status="terminated",
    #    no listener bound), a clean shutdown drain emits shutdown_final
    #    status="drained", and the child exits 0 -- never the obsolete
    #    non-serving scaffold banner, never a hung serve (a child still alive
    #    after signal + 10 s fails the fixture; a supervised-child deadline is
    #    a FAIL, never a pass). The binary's own entry facts (all four sets
    #    empty, NNP set) must remain the exact stderr.
    pos_script=$(cat <<'POSPOS'
cd /work
/app/target/fixture-facts/release/alumina &
pid=$!
sleep 3
kill -TERM "$pid" 2>/dev/null || true
i=0
while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 10 ]; do i=$((i+1)); sleep 1; done
if kill -0 "$pid" 2>/dev/null; then
    echo "FIXTURE-POSITIVE-FAIL: supervised serving child alive after SIGTERM + 10s"
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    exit 2
fi
if wait "$pid"; then rc=0; else rc=$?; fi
printf "FIXTURE-POSITIVE-SUPERVISED: reaped child rc=%s\n" "$rc"
exit "$rc"
POSPOS
)
    run_fixture "positive" 0 "$CONN" \
        "setpriv --reuid 65534 --regid 65534 --clear-groups /bin/sh -c '$pos_script'" \
        --security-opt no-new-privileges --user 0:0
    # The typed records prove the actual startup-serving/typed-terminal path:
    # the window ended on the terminated decision and the drain was clean. The
    # obsolete non-serving scaffold banner is barred: its presence would be the
    # false-clean this migration removes.
    fixture_require_stdout_contains "level=info kind=startup_final"
    fixture_require_stdout_contains 'status="terminated"'
    fixture_require_stdout_contains "level=info kind=shutdown_final"
    fixture_require_stdout_contains 'status="drained"'
    fixture_require_stdout_contains "FIXTURE-POSITIVE-SUPERVISED: reaped child rc=0"
    fixture_require_stdout_not_contains "PHASE1-BOOT-OK"
    fixture_require_stderr_exact "kernel-facts: ruid=65534 euid=65534 suid=65534 fsuid=65534 cap_eff=0 cap_prm=0 cap_amb=0 no_new_privs=1"

    # 2) ROOT: euid 0 -> EX_CONFIG 78 (root-UID diagnostic); all four UID axes
    #    reported zero at entry. Negative fixtures must have EMPTY stdout and
    #    byte-exact stderr: exactly the facts line then the diagnostic.
    run_fixture "root-rejected" 78 "$CONN" \
        "cd /work && /app/target/fixture-facts/release/alumina" \
        --security-opt no-new-privileges --user 0:0
    fixture_require_stdout_empty
    fixture_require_stderr_exact "$(printf '%s\n' \
        "kernel-facts: ruid=0 euid=0 suid=0 fsuid=0 cap_eff=800405fb cap_prm=800405fb cap_amb=0 no_new_privs=1" \
        "alumina: prerequisite failure: process has a root UID (real/effective/saved/filesystem)")"

    # 3) NNP-MISSING: no no_new_privs flag -> EX_CONFIG 78 (missing-flag
    #    diagnostic); caps empty, uid dropped.
    run_fixture "no-new-privs-missing" 78 "$CONN" \
        "setpriv --reuid 65534 --regid 65534 --clear-groups /bin/sh -c 'cd /work && /app/target/fixture-facts/release/alumina'" \
        --user 0:0
    fixture_require_stdout_empty
    fixture_require_stderr_exact "$(printf '%s\n' \
        "kernel-facts: ruid=65534 euid=65534 suid=65534 fsuid=65534 cap_eff=0 cap_prm=0 cap_amb=0 no_new_privs=0" \
        "alumina: prerequisite failure: no_new_privs not set")"

    # 4) CAPS-EFFECTIVE: rootful container grants cap_net_admin into the
    #    bounding set; setpriv raises it into inheritable+ambient so the
    #    dropped uid 65534 process execs with CapEff/CapPrm/CapAmb non-empty.
    #    Preflight checks effective first -> EX_CONFIG 78 with the
    #    non-empty-effective-capability-set diagnostic. The binary's own entry
    #    facts observe all three capability sets non-empty (0x1000 each),
    #    asserting effective-first refusal rather than per-axis isolation.
    run_fixture "caps-effective" 78 "$ROOTCONN" \
        "setpriv --reuid 65534 --regid 65534 --clear-groups --inh-caps=+net_admin --ambient-caps=+net_admin /bin/sh -c 'cd /work && /app/target/fixture-facts/release/alumina'" \
        --security-opt no-new-privileges --cap-add NET_ADMIN --user 0:0
    fixture_require_stdout_empty
    fixture_require_stderr_exact "$(printf '%s\n' \
        "kernel-facts: ruid=65534 euid=65534 suid=65534 fsuid=65534 cap_eff=1000 cap_prm=1000 cap_amb=1000 no_new_privs=1" \
        "alumina: prerequisite failure: non-empty effective capability set")"

    # 5) PERMITTED-ONLY APPLICABILITY (corrects the earlier KEEP_CAPS/capsh
    #    VM rationale per authoritative evidence alumina-5zn + orientation
    #    alumina-mlb): for a non-root exec of an ordinary non-setid executable
    #    WITHOUT file capabilities, the kernel execve rule gives
    #    P'(permitted) = P'(effective) = P(ambient) (capabilities(7);
    #    commoncap.c v6.6). A non-root exec clears pre-existing
    #    permitted/effective, so CapEff=0 with CapPrm non-zero is NOT reachable
    #    at this binary entry; with empty ambient all sets are empty, with
    #    non-empty ambient all three are non-empty together (fixture 4
    #    observes exactly this). Ambient-only is likewise unreachable because
    #    ambient always feeds both permitted and effective (no independent
    #    isolation axis exists for this executable). SECBIT_KEEP_CAPS is
    #    cleared on execve and is not a permitted-retention mechanism. The
    #    kernel nonempty-permitted and nonempty-ambient refusal policy is
    #    UNCHANGED; each synthetic axis is asserted independently below by the
    #    unchanged decision-table unit test.
    echo "FIXTURE permitted-only: APPLICABILITY (alumina-5zn) - ordinary non-setid no-file-cap exec gives P'=E'=ambient; isolated CapEff=0/CapPrm!=0 not reachable; ambient-only not reachable"
    echo "FIXTURE permitted-only: kernel nonempty-permitted and nonempty-ambient refusal policy UNCHANGED; decision-table unit test preflight_rejects_each_unmet_prerequisite_independently asserts each axis"

    # 6) METADATA: authoritative Linux xattr proof on the executed variant
    #    (same inode the fixtures ran) that security.capability is absent -
    #    via the xattr filesystem API, never getcap-output-absence - plus file
    #    mode and artifact sha256. The probe also rejects a setid mode (the
    #    ordinary-nonsetid applicability is void for a setid executable) and a
    #    digest differing from the identified variant sha. Probe errors
    #    (stat/listxattr/getxattr failure, non-regular file) are BLOCKERS,
    #    never verified absence.
    echo "METADATA (setid-reject + security.capability absence + mode + variant sha256 match on executed variant):"
    metar=0
    metaout=$(podman --connection "$CONN" run --rm -v "$ROOT:/app:ro,Z" --user 0:0 "$IMAGE" \
        sh -c 'apk add --no-cache python3 >/dev/null 2>&1 || true
python3 /app/scripts/fixture_metadata_probe.py /app/target/fixture-facts/release/alumina "$1"' -- "$variant_sha" 2>&1) || metar=$?
    printf '%s\n' "$metaout" | sed 's/^/  /'
    [ "$metar" -eq 0 ] || {
        echo "BOOT-FIXTURES FAIL: metadata probe exit $metar (probe error / setid / digest mismatch is not verified absence)" >&2
        exit 1
    }
    printf '%s\n' "$metaout" | grep -qF "security.capability=absent" || {
        echo "BOOT-FIXTURES FAIL: executed variant carries security.capability (or record missing)" >&2
        exit 1
    }
    echo "METADATA-OK: executed variant ordinary non-setid, security.capability absent, sha256 matches $variant_sha"

    echo "BOOT-FIXTURES-RAN (separate-stream capture; negative stdout empty + stderr byte-exact facts+diagnostic; positive supervised typed-terminated startup record (startup_final status=terminated + shutdown_final status=drained, reaped exit 0) with retained stdout; integer exit 0/78; all cap sets observed non-empty in caps-effective; permitted-only applicability disposition; production digest unchanged; setid-reject + security.capability absence + variant sha256 match proven)"
}

# One effective Node environment preflight: refuse ANY set NODE_OPTIONS/NODE_PATH
# -- non-empty or empty alike -- before ANY Node invocation (the docs adapter and
# the boundary identity version probe), because a set option is an explicit
# execution-affecting override even when empty. An unset variable is the only
# accepted state.
node_env_preflight() {
    if [ -n "${NODE_OPTIONS+x}" ]; then
        echo "NODE-REFUSED: NODE_OPTIONS is set (${NODE_OPTIONS}); execution-affecting Node options not covered by default-condition intake" >&2
        exit 1
    fi
    if [ -n "${NODE_PATH+x}" ]; then
        echo "NODE-REFUSED: NODE_PATH is set (${NODE_PATH}); execution-affecting module resolution not covered by default-condition intake" >&2
        exit 1
    fi
}

docslink_check() {
    # Offline AST + authoritative slugger adapter (scripts/docs_check/check.mjs):
    # fixed argv, literal fragment lookup, distinct operational failure. Document
    # bytes are filesystem data passed to node; they never reach a shell here.
    command -v node >/dev/null 2>&1 || {
        echo "DOCSLINK-BLOCKED: node required for offline AST docs check (absent)" >&2
        exit 1
    }
    [ -f scripts/docs_check/check.mjs ] || {
        echo "DOCSLINK-BLOCKED: scripts/docs_check/check.mjs missing (no docs check)" >&2
        exit 1
    }
    node_env_preflight
    drc=0
    node scripts/docs_check/check.mjs $DOCSLINK_ROOTS || drc=$?
    case "$drc" in
        0) ;;
        1)
            echo "DOCSLINK-CHECK-FAIL (missing file or literal fragment mismatch)" >&2
            exit 1
            ;;
        2)
            echo "DOCSLINK-CHECK-OP-FAIL (operational or unsupported construct)" >&2
            exit 2
            ;;
        *)
            echo "DOCSLINK-CHECK-FAIL (adapter exit $drc)" >&2
            exit 1
            ;;
    esac
    echo "DOCSLINK-CHECK-OK"
}

# One authoritative SHA256 operation for every identity input. Selection:
# sha256sum preferred, else shasum -a 256 (a SHA256 field must carry real
# SHA256, never shasum's default SHA1). The producer exit and a non-empty
# digest are both checked inside this function; callers see only the bare hex
# digest or a non-zero status, so a missing or failed hasher can never become
# an empty string carried by a masking pipeline. mode=file hashes the path in
# $2; mode=stdin hashes stdin. The selected hasher name is exposed in
# IDENTITY_HASHER for the env record.
sha256_digest() {
    mode="$1"
    path="${2:-}"
    IDENTITY_HASHER=""
    r=0
    out=""
    if command -v sha256sum >/dev/null 2>&1; then
        IDENTITY_HASHER="sha256sum"
        if [ "$mode" = "file" ]; then out=$(sha256sum "$path" 2>&1) || r=$?
        else out=$(sha256sum 2>&1) || r=$?; fi
    elif command -v shasum >/dev/null 2>&1; then
        IDENTITY_HASHER="shasum"
        if [ "$mode" = "file" ]; then out=$(shasum -a 256 "$path" 2>&1) || r=$?
        else out=$(shasum -a 256 2>&1) || r=$?; fi
    else
        echo "SOURCE-IDENTITY FAIL: neither sha256sum nor shasum present (identity impossible, not PASS)" >&2
        return 1
    fi
    [ "$r" -eq 0 ] || {
        echo "SOURCE-IDENTITY FAIL: hash producer exit $r for ${path:-stdin} (read failure, not PASS)" >&2
        printf '%s\n' "$out" >&2
        return 1
    }
    digest=$(printf '%s\n' "$out" | cut -d' ' -f1)
    [ -n "$digest" ] || {
        echo "SOURCE-IDENTITY FAIL: empty digest for ${path:-stdin} (not PASS)" >&2
        return 1
    }
    printf '%s\n' "$digest"
}

# The executed artifact is a mandatory postbuild identity input: its absence is
# a fail-closed condition (never a silently dropped identity field).
artifact_identity() {
    bin="$1"
    [ -f "$bin" ] || {
        echo "ARTIFACT-IDENTITY FAIL: executed artifact missing: $bin (identity impossible, not PASS)" >&2
        return 1
    }
    ah=$(sha256_digest file "$bin") || return 1
    echo "  executed artifact sha256 $ah  $bin"
}

# Authoritative filesystem observation for the config-candidate inventory
# (qkl option B): one standard-library stat boundary decides whether a
# candidate is present/absent, with EACCES/traversal, dangling-symlink and
# non-regular outcomes kept distinct from verified absence. Python3 is the
# permitted operational interpreter (host stdlib, no deps); its absence
# fails closed, exactly like the other boundary prerequisites.
config_observe() {
    path="$1"
    command -v python3 >/dev/null 2>&1 || {
        echo "SOURCE-IDENTITY FAIL: python3 required for cargo-config observation, not found" >&2
        exit 1
    }
    status=$(python3 scripts/cargo_config_probe.py "$path" 2>&1) || {
        echo "SOURCE-IDENTITY FAIL: cargo-config observation failed for: $path ($status)" >&2
        exit 1
    }
    printf '%s\n' "$status"
}

identity_snapshot() {
    dir="$1"
    rc=0
    head=$(git rev-parse --verify HEAD 2>&1) || rc=$?
    [ "$rc" -eq 0 ] || {
        echo "SOURCE-IDENTITY FAIL: git rev-parse HEAD exit $rc (head unreadable, not PASS)" >&2
        exit 1
    }
    mkdir -p "$dir"
    printf '%s\n' "$head" >"$dir/head"
    git status --porcelain >"$dir/status" 2>&1 || {
        echo "SOURCE-IDENTITY FAIL: git status exit $? (dirty scope unreadable, not PASS)" >&2
        exit 1
    }
    # Record which hasher sha256_digest selects. This is a tool-existence probe
    # for the env record only; hashing itself stays exclusively in sha256_digest
    # (a command-substitution cannot propagate the global back to a caller).
    IDENTITY_HASHER=""
    if command -v sha256sum >/dev/null 2>&1; then IDENTITY_HASHER="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then IDENTITY_HASHER="shasum"; fi
    : >"$dir/inputs.sha256"
    for f in $IDENTITY_FILES; do
        [ -f "$f" ] || {
            echo "SOURCE-IDENTITY FAIL: identity input missing: $f" >&2
            exit 1
        }
        h=$(sha256_digest file "$f") || {
            echo "SOURCE-IDENTITY FAIL: hash $f" >&2
            exit 1
        }
        printf '%s  %s\n' "$h" "$f" >>"$dir/inputs.sha256"
    done
    # Effective Cargo config inventory (finite ancestor closure, qkl seam A):
    # Cargo's hierarchical search consults the cwd ancestry -- EVERY parent up
    # to the filesystem root -- plus the selected Cargo home
    # ${CARGO_HOME:-$HOME/.cargo}. Both spellings are inventoried at every stop
    # (config, config.toml); where both exist at one path Cargo prefers the
    # extensionless `config` spelling (Cargo Book, hierarchical structure). We
    # record candidates only: no TOML precedence/merge interpreter, no claim
    # either spelling is necessarily consumed. Path/name plus a SHA256 digest
    # or a verified-absence marker; any unreadable or non-regular candidate
    # fails closed. Replaces the prior four hardcoded fields with one
    # traversal, so a candidate above the checkout now changes this record.
    config_home="${CARGO_HOME:-$HOME/.cargo}"
    alihash=$(printf '%s\n' '[alias]' 'atest = ["test", "--quiet", "--no-fail-fast"]' 'aclippy = ["clippy", "--quiet", "--message-format=short"]' | sha256_digest stdin) || exit 1
    {
        printf 'toolchain=%s\n' "$TOOLCHAIN"
        printf 'hasher=%s\n' "${IDENTITY_HASHER:-<none>}"
        printf 'cargo_home=%s\n' "${CARGO_HOME:-<unset>}"
        printf 'cargo_target_dir=%s\n' "${CARGO_TARGET_DIR:-<unset>}"
        printf 'rustflags=%s\n' "${RUSTFLAGS:-<unset>}"
        printf 'rustc=%s\n' "${RUSTC:-<unset>}"
        printf 'rustc_wrapper=%s\n' "${RUSTC_WRAPPER:-<unset>}"
        printf 'rustc_workspace_wrapper=%s\n' "${RUSTC_WORKSPACE_WRAPPER:-<unset>}"
        printf 'cargo_incremental=%s\n' "${CARGO_INCREMENTAL:-<unset>}"
        printf 'cargo_term_progress_when=%s\n' "${CARGO_TERM_PROGRESS_WHEN:-<unset>}"
        printf 'podman_connection=%s\n' "${PODMAN_CONNECTION:-flock-vm}"
        printf 'podman_root_connection=%s\n' "${PODMAN_ROOT_CONNECTION:-flock-vm-root}"
        printf 'cargo_home_effective=%s\n' "$config_home"
        node_env_preflight
        command -v node >/dev/null 2>&1 || {
            echo "SOURCE-IDENTITY FAIL: node path producer failed (node absent; identity impossible, not PASS)" >&2
            exit 1
        }
        nodepath=$(command -v node 2>&1)
        nv=$(node --version 2>&1) || {
            echo "SOURCE-IDENTITY FAIL: node --version exit $? (version unobservable, not PASS)" >&2
            exit 1
        }
        [ -n "$nv" ] || {
            echo "SOURCE-IDENTITY FAIL: node --version empty output (version unobservable, not PASS)" >&2
            exit 1
        }
        nvh=$(printf '%s\n' "$nv" | sha256_digest stdin) || exit 1
        printf 'node_executable=%s\n' "$nodepath"
        printf 'node_version=%s\n' "$nv"
        printf 'node_version_sha256=%s\n' "$nvh"
        if [ -z "${NODE_OPTIONS+x}" ]; then printf 'node_options=<unset>\n'
        elif [ -n "$NODE_OPTIONS" ]; then printf 'node_options=%s\n' "$NODE_OPTIONS"
        else printf 'node_options=<empty>\n'; fi
        if [ -z "${NODE_PATH+x}" ]; then printf 'node_path=<unset>\n'
        elif [ -n "$NODE_PATH" ]; then printf 'node_path=%s\n' "$NODE_PATH"
        else printf 'node_path=<empty>\n'; fi
        if [ -z "${NODE_ENV+x}" ]; then printf 'node_env=<unset>\n'
        elif [ -n "$NODE_ENV" ]; then printf 'node_env=%s\n' "$NODE_ENV"
        else printf 'node_env=<empty>\n'; fi
        printf 'installed_closure_vs_lock=package-lock.json identity-covered; node_modules installed closure reconciled at commander intake (1gx.15 default-condition 67-file ledger)\n'
        printf 'cargo_config_namespace=host: cwd ancestry through filesystem root plus selected Cargo home\n'
        d="$(pwd)"
        while :; do
            for n in config config.toml; do
                if [ "$d" = "/" ]; then p="/.cargo/$n"; else p="$d/.cargo/$n"; fi
                st=$(config_observe "$p")
                case "$st" in
                    absent) printf 'cargo_config absent    %s\n' "$p" ;;
                    present)
                        h=$(sha256_digest file "$p") || { echo "SOURCE-IDENTITY FAIL: unreadable cargo config candidate: $p" >&2; exit 1; }
                        printf 'cargo_config present   %s  %s\n' "$h" "$p"
                        ;;
                    denied|dangling|nonregular|error)
                        echo "SOURCE-IDENTITY FAIL: cargo config candidate not observable ($st): $p" >&2
                        exit 1
                        ;;
                    *)
                        echo "SOURCE-IDENTITY FAIL: cargo config observation unknown status '$st' for: $p" >&2
                        exit 1
                        ;;
                esac
            done
            [ "$d" = "/" ] && break
            d="${d%/*}"
            [ -n "$d" ] || d="/"
        done
        for n in config config.toml; do
            p="$config_home/$n"
            st=$(config_observe "$p")
            case "$st" in
                absent) printf 'cargo_config selected absent    %s\n' "$p" ;;
                present)
                    h=$(sha256_digest file "$p") || { echo "SOURCE-IDENTITY FAIL: unreadable selected cargo config: $p" >&2; exit 1; }
                    printf 'cargo_config selected present   %s  %s\n' "$h" "$p"
                    ;;
                denied|dangling|nonregular|error)
                    echo "SOURCE-IDENTITY FAIL: selected cargo config not observable ($st): $p" >&2
                    exit 1
                    ;;
                *)
                    echo "SOURCE-IDENTITY FAIL: cargo config observation unknown status '$st' for: $p" >&2
                    exit 1
                    ;;
            esac
        done
        printf 'container_cargo_config_namespace=/app/.cargo mirrors repo cwd (inventoried above); fixed fresh /cargo-home provisioned alias block\n'
        printf 'container_alias_block_sha256=%s\n' "$alihash"
    } >"$dir/env"
    echo "SOURCE-IDENTITY: snapshot $dir (HEAD=$head, inputs $(wc -l <"$dir/inputs.sha256"))"
}

identity_compare() {
    before="$1"
    after="$2"
    ok=1
    cmp -s "$before/head" "$after/head" || { echo "SOURCE-IDENTITY-CHANGED FAIL: HEAD differs before/after" >&2; ok=0; }
    cmp -s "$before/status" "$after/status" || { echo "SOURCE-IDENTITY-CHANGED FAIL: working-tree status differs before/after" >&2; ok=0; }
    cmp -s "$before/inputs.sha256" "$after/inputs.sha256" || { echo "SOURCE-IDENTITY-CHANGED FAIL: input hashes differ before/after" >&2; ok=0; }
    cmp -s "$before/env" "$after/env" || { echo "SOURCE-IDENTITY-CHANGED FAIL: build env differs before/after" >&2; ok=0; }
    [ "$ok" -eq 1 ] || {
        echo "SOURCE-IDENTITY-CHANGED FAIL: boundary inputs not stable; refusing completion markers" >&2
        exit 1
    }
    echo "SOURCE-IDENTITY-STABLE-OK (HEAD, status, inputs and env identical before/after)"
}

audit_deny_owner() {
    have=1
    command -v cargo-audit >/dev/null 2>&1 || have=0
    command -v cargo-deny >/dev/null 2>&1 || have=0
    if [ "$have" -eq 1 ]; then
        echo "AUDIT-DENY (hard gate, boundary host):"
        ar=0
        cargo +${TOOLCHAIN} audit || ar=$?
        [ "$ar" -eq 0 ] || { echo "AUDIT-DENY FAIL: cargo audit exit $ar" >&2; exit 1; }
        dr=0
        cargo +${TOOLCHAIN} deny check || dr=$?
        [ "$dr" -eq 0 ] || { echo "AUDIT-DENY FAIL: cargo deny exit $dr" >&2; exit 1; }
        echo "AUDIT-DENY-OK (audit exit $ar; deny exit $dr)"
    else
        echo "AUDIT-DENY-BLOCKED: cargo audit or cargo deny absent on this boundary host; applicable phase1 audit/deny cannot complete" >&2
        exit 1
    fi
}

# Host -> existing Linux dispatch: boundary children that must run on Linux are
# executed inside the already-provisioned flock-vm container (same exact image
# and CARGO_HOME alias environment as the accepted btk/c7o runs), never by
# calling Linux-only functions directly on a Darwin host.
linux_dispatch() {
    inner="$1"
    command -v podman >/dev/null 2>&1 || {
        echo "LINUX-DISPATCH-BLOCKED: podman required on the host" >&2
        exit 1
    }
    podman --connection flock-vm info >/dev/null 2>&1 || {
        echo "LINUX-DISPATCH-BLOCKED: flock-vm connection unreachable (probe, not PASS)" >&2
        exit 1
    }
    ROOT="$(pwd)"
    IMAGE="docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a"
    prov='mkdir -p /cargo-home
printf "%s\n" "[alias]" "atest = [\"test\", \"--quiet\", \"--no-fail-fast\"]" "aclippy = [\"clippy\", \"--quiet\", \"--message-format=short\"]" > /cargo-home/config.toml
rustup component add clippy rustfmt >/dev/null 2>&1 || true
command -v git >/dev/null 2>&1 || apk add --no-cache git >/dev/null 2>&1 || true
'
    drc=0
    podman --connection flock-vm run --rm --pull=never \
        -v "$ROOT:/app:Z" \
        -e CARGO_HOME=/cargo-home \
        -e CARGO_INCREMENTAL=0 \
        -e CARGO_TERM_PROGRESS_WHEN=never \
        -w /app \
        "$IMAGE" sh -c "$prov$inner" || drc=$?
    [ "$drc" -eq 0 ] || {
        echo "LINUX-MID FAIL: '$inner' exit $drc" >&2
        exit 1
    }
}

boundary_phase1() {
    echo "phase1 boundary (owner seam H1): host sole coordinator; Linux MID via existing flock-vm dispatch"
    identity_snapshot "$IDENTITY_BEFORE"
    linux_dispatch 'sh scripts/verify.sh mid union'
    boot_fixtures
    docslink_check
    git diff --check
    echo "GIT-DIFF-CHECK-OK"
    audit_deny_owner
    identity_snapshot "$IDENTITY_AFTER"
    identity_compare "$IDENTITY_BEFORE" "$IDENTITY_AFTER"
    artifact_identity target/release/alumina || exit 1
    echo "F3 mio operation matrix: IMPLEMENTED (tests/mio_matrix.rs: 8 tests incl. linux_epoll_operation_matrix with poll/register/reregister/deregister + alloc-witness controls; recorded native release evidence docs/verification.md#native-proofs-scoped-exact-input, z9m0/po3c); current-serving completeness witness still OPEN (cnrd T3) - not 'unbuilt matrix', not 'complete'"
    echo "NotImplemented: DNS wire parser fuzz (Slice 2)"
    echo "NotImplemented: CONNECT/ClientHello parser fuzz (Slices 3-4)"
    echo "NotImplemented: log-record encoding fuzz (Slice 6)"
    echo "NotImplemented: deployment confinement + E2E release gates (Slice 7)"
    echo "RELEASE-NOT-READY: later-slice and release gates remain NotImplemented, not green"
    echo "BOUNDARY-OWNER-COORD-OK: all applicable phase1 children coordinated and exited 0 on this host"
    echo "FINAL-PHASE1-COMPLETION: BLOCKED — pending fixture/doc/Rust repairs and review approval before any phase1 done-claim (no E2E equivalence claimed)"
}

# Real-IO CONNECT/SNI opaque-relay and native SIGTERM shutdown gates against the
# ACTUAL production binary rebuilt from the exact current source (never a stale
# artifact): native Linux release build (or container dispatch on a non-Linux
# host), then the gate's harness script runs it in a fully network-isolated
# container. The source/binary identity receipt is mandatory so the executed
# artifact is tied to the reviewed candidate, and every e2e case must exit hard
# zero.
#
# e2e_build_receipt is the single shared build/receipt owner for BOTH gates. It
# rebuilds the exact candidate ONCE per invocation, checks producer exits and
# source/artifact correspondence through execution (never a masked pipeline,
# never a framework), and prints the identity line; each standalone selector
# (e2e/relay, e2e/shutdown) stays independently dispatchable and runs only its
# own harness after the shared receipt.
# Exact-candidate input digest record (pre/post-build and after the executed
# harness): HEAD + dirty diff + untracked harness py/sh + gate script. The diff
# producer exit is checked SEPARATELY (never a masked pipeline); the untracked
# harness scripts are hashed explicitly (git diff excludes them). Requires $TGT.
e2e_receipt_fields() {
    _gate="$1"
    _harness_py="$2"
    _harness_sh="$3"
    rcd=0
    git diff HEAD >"$TGT/$_gate-diff.$$" 2>&1 || rcd=$?
    [ "$rcd" -eq 0 ] || {
        echo "E2E-$_gate-BLOCKED: git diff HEAD exit $rcd (unreadable diff, not a receipt)" >&2
        exit 1
    }
    rgh=0
    head=$(git rev-parse --verify HEAD 2>&1) || rgh=$?
    [ "$rgh" -eq 0 ] && [ -n "$head" ] || {
        echo "E2E-$_gate-BLOCKED: git rev-parse --verify HEAD exit $rgh (unreadable HEAD, not a receipt)" >&2
        exit 1
    }
    diffhash=$(sha256_digest file "$TGT/$_gate-diff.$$") || exit 1
    harness1=$(sha256_digest file "$_harness_py") || exit 1
    harness2=$(sha256_digest file "$_harness_sh") || exit 1
    shellhash=$(sha256_digest file "scripts/verify.sh") || exit 1
    printf '%s %s %s %s %s\n' "$head" "$diffhash" "$harness1" "$harness2" "$shellhash"
}

# B3 through-execution correspondence: after the harness has consumed the
# binary from the live read-only checkout mount, re-derive the exact same input
# digest record plus the binary digest and refuse certification if either
# changed. Endpoint-stability assurance is scoped to the serial, actual-checkout
# owner: a durable source or artifact change observed before the post-execution
# re-hash is attributed to this invocation and refuses certification; this does
# not claim to detect a transient replacement that is restored before the final
# hash. The verdict therefore remains tied to the stable candidate this run
# actually executed.
e2e_verify_stable() {
    _gate="$1"
    _harness_py="$2"
    _harness_sh="$3"
    prev_inputs=$(cat "$TGT/.e2e-$_gate-inputs" 2>/dev/null) || {
        echo "E2E-$_gate-BLOCKED: e2e receipt inputs file missing ($TGT/.e2e-$_gate-inputs); certification impossible" >&2
        exit 1
    }
    prev_bin=$(cat "$TGT/.e2e-$_gate-binhash" 2>/dev/null) || {
        echo "E2E-$_gate-BLOCKED: e2e receipt binhash file missing ($TGT/.e2e-$_gate-binhash); certification impossible" >&2
        exit 1
    }
    now_inputs=$(e2e_receipt_fields "$_gate" "$_harness_py" "$_harness_sh") || exit 1
    now_bin=$(sha256_digest file "$ROOT/$BIN") || exit 1
    if [ "$now_inputs" != "$prev_inputs" ]; then
        echo "E2E-$_gate-BLOCKED: source inputs changed across harness execution (receipt no longer corresponds); refusing certification" >&2
        echo "  before=$prev_inputs" >&2
        echo "  now   =$now_inputs" >&2
        exit 1
    fi
    if [ "$now_bin" != "$prev_bin" ]; then
        echo "E2E-$_gate-BLOCKED: executed binary changed across harness execution ($prev_bin -> $now_bin); refusing certification" >&2
        exit 1
    fi
    echo "E2E-$_gate-CORRESPONDENCE-OK: inputs+binary unchanged across harness execution"
}

e2e_build_receipt() {
    _gate="$1"
    _harness_py="$2"
    _harness_sh="$3"
    ROOT="$(pwd)"
    # B3: observation and build must share one actual connection. linux_dispatch
    # (the sole sanctioned build dispatch) hardcodes flock-vm with the pinned
    # builder image; a PODMAN_CONNECTION override would make the probe observe a
    # different owner than the build runs, so any value other than flock-vm is
    # rejected BEFORE any probe/build effect.
    case "${PODMAN_CONNECTION:-flock-vm}" in
        flock-vm) ;;
        *)
            echo "E2E-$_gate-BLOCKED: unsupported PODMAN_CONNECTION override '${PODMAN_CONNECTION}' (build dispatch hardcodes flock-vm; probe would observe a different owner); unset it or use flock-vm" >&2
            exit 1
            ;;
    esac
    if [ "$(uname -s)" = "Linux" ]; then
        _builder="native-host"
    else
        _builder="flock-vm"
    fi
    # R1: the artifact PROFILE is explicitly observed from the build owner (the
    # native host triple under which the release build actually runs), not
    # guessed from --target-dir. The identical triple is carried into the cargo
    # build AND into the artifact consumer path, so the executed binary is the
    # one Cargo just produced - a stale default-path artifact can never be
    # consumed. On the non-Linux dispatch route the triple is observed inside
    # the same rust image that performs the build.
    # N1: observe the build-owner native profile with the PRODUCER's own exit
    # checked before any parsing. stdout/stderr are captured together so a
    # failing producer (even one that wrote a plausible host line) is never
    # masked by a later filter's exit 0, and the reason is not swallowed by
    # 2>/dev/null. Parsing (`sed 's/^host: //p'`) runs only on the captured
    # buffer of an exit-0 producer.
    observe_build_target() {
        _probe_out="$("$@" 2>&1)" || _probe_rc=$?
        if [ "${_probe_rc:-0}" -ne 0 ]; then
            printf 'E2E-%s-BLOCKED: build target probe failed before parse (exit %s):\n%s\n' \
                "$_gate" "$_probe_rc" "$_probe_out" >&2
            exit 1
        fi
        printf '%s\n' "$_probe_out"
    }
    if [ "$(uname -s)" = "Linux" ]; then
        _probe_buf=$(observe_build_target rustc +${TOOLCHAIN} -vV) || exit 1
    else
        _probe_buf=$(observe_build_target \
            podman --connection "${PODMAN_CONNECTION:-flock-vm}" run --rm --pull=never \
            docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a \
            sh -c 'rustc -vV') || exit 1
    fi
    # parse only from the successfully captured buffer (producer exit already 0)
    E2E_TARGET=$(printf '%s\n' "$_probe_buf" | sed -n 's/^host: //p')
    case "$E2E_TARGET" in
        "" | *$'\n'* | *" "*)
            echo "E2E-$_gate-BLOCKED: could not observe native build target profile ('${E2E_TARGET}')" >&2
            exit 1
            ;;
    esac
    export E2E_TARGET
    TGT="$ROOT/target"
    BIN="target/${E2E_TARGET}/release/alumina"
    closure_metadata
    # Pre-build source-input stability record (exact-candidate inputs hashed by
    # the shared owner; explicitly includes the untracked harness scripts).
    mkdir -p "$TGT"
    before=$(e2e_receipt_fields "$_gate" "$_harness_py" "$_harness_sh") || exit 1
    if [ "$(uname -s)" = "Linux" ]; then
        echo "PRODUCTION-RELEASE-BUILD (native Linux, exact current source, target=${E2E_TARGET}):"
        cargo +${TOOLCHAIN} build --locked --release --target "$E2E_TARGET" --target-dir "$TGT"
    else
        echo "PRODUCTION-RELEASE-BUILD (native Linux via container dispatch; host $(uname -s), target=${E2E_TARGET}):"
        linux_dispatch "cargo +1.99.0 build --locked --release --target ${E2E_TARGET} --target-dir /app/target"
    fi
    after=$(e2e_receipt_fields "$_gate" "$_harness_py" "$_harness_sh") || exit 1
    # Pre/post build source-input stability: the candidate inputs (HEAD +
    # dirty diff + untracked harness + gate script) must be unchanged across
    # the build, or a mid-build source change would detach the receipt from the
    # executed binary.
    if [ "$before" != "$after" ]; then
        echo "E2E-$_gate-BLOCKED: source inputs changed during the build (receipt would not correspond)" >&2
        echo "  before=$before" >&2
        echo "  after =$after" >&2
        exit 1
    fi
    [ -x "$ROOT/$BIN" ] || {
        echo "E2E-$_gate-BLOCKED: production static binary missing after rebuild ($BIN for target $E2E_TARGET)" >&2
        exit 1
    }
    echo "e2e/$_gate identity (executed binary tied to exact candidate):"
    head=$(git rev-parse --verify HEAD 2>&1) || {
        echo "E2E-$_gate-BLOCKED: git rev-parse HEAD failed" >&2
        exit 1
    }
    binhash=$(sha256_digest file "$ROOT/$BIN") || exit 1
    # B3/R1: resolve the ACTUAL harness-image tag + immutable ID from the
    # rootful connection the harness consumers open (e2e_relay.sh/e2e_shutdown.sh
    # use ${PODMAN_ROOT_CONNECTION:-flock-vm-root}). An unresolvable ID is a
    # blocker. The immutable ID is EXPORTED to the consumers, which must
    # re-check that the tag still resolves to this ID on their connection and
    # then run the ID itself (R1: the receipt's image is the image executed).
    E2E_IMAGE="${E2E_IMAGE:-localhost/alumina-e2e:e2e-20261011}"
    E2E_ROOT_CONN="${PODMAN_ROOT_CONNECTION:-flock-vm-root}"
    harness_id=$(podman --connection "$E2E_ROOT_CONN" image inspect --format '{{.Id}}' "$E2E_IMAGE" 2>/dev/null) \
        || harness_id=""
    if [ -z "$harness_id" ]; then
        echo "E2E-$_gate-BLOCKED: harness image '$E2E_IMAGE' id unresolvable on ${E2E_ROOT_CONN}: ${E2E_ROOT_CONN}" >&2
        exit 1
    fi
    export E2E_IMAGE E2E_IMAGE_ID="$harness_id" E2E_ROOT_CONN
    # Durable through-execution receipt (consumed by e2e_verify_stable after
    # the harness runs): exact-candidate inputs + executed binary digest.
    printf '%s\n' "$after" >"$TGT/.e2e-$_gate-inputs"
    printf '%s\n' "$binhash" >"$TGT/.e2e-$_gate-binhash"
    printf '  HEAD=%s target=%s dirty-diff-sha256=%s harness-py-sha256=%s harness-sh-sha256=%s binary-sha256=%s\n' \
        "$head" "$E2E_TARGET" "$(printf '%s' "$after" | cut -d' ' -f2)" \
        "$(printf '%s' "$after" | cut -d' ' -f3)" "$(printf '%s' "$after" | cut -d' ' -f4)" "$binhash"
    printf '  builder=%s builder-image=%s harness-image=%s harness-image-id=%s harness-conn=%s\n' \
        "$_builder" "docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a" \
        "$E2E_IMAGE" "$harness_id" "$E2E_ROOT_CONN"
}

e2e_relay() {
    e2e_build_receipt relay scripts/e2e_relay.py scripts/e2e_relay.sh
    sh scripts/e2e_relay.sh
    e2e_verify_stable relay scripts/e2e_relay.py scripts/e2e_relay.sh
}

# Native SIGTERM shutdown gate against the ACTUAL production binary, rebuilt
# from the exact current source behind the same identity receipt as the relay
# gate via the shared e2e_build_receipt owner (source/binary correspondence is
# mandatory so the executed artifact is tied to the reviewed candidate). The
# gate drives real SIGTERM into the served binary: idle wake, no-self-exit,
# pre-serving observation, early drain, deadline-forced closure (repeat-signal
# no-extension), stalled stdout and silent DNS cooperation. Every case child is
# supervised foreground.
e2e_shutdown() {
    e2e_build_receipt shutdown scripts/e2e_shutdown.py scripts/e2e_shutdown.sh
    sh scripts/e2e_shutdown.sh
    e2e_verify_stable shutdown scripts/e2e_shutdown.py scripts/e2e_shutdown.sh
}

case "$TIER/$SCOPE" in
    mid/foundations) mid_foundations ;;
    mid/boot) mid_boot ;;
    mid/union) mid_union ;;
    fixtures/boot) boot_fixtures ;;
    boundary/phase1) boundary_phase1 ;;
    e2e/relay) e2e_relay ;;
    e2e/shutdown) e2e_shutdown ;;
    docs/*) docslink_check ;;
    *) usage ;;
esac
