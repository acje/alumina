#!/bin/sh
# qa-package/validate.sh — local static native QA package identity + smoke.
# Records source/artifact identity and runs the repo-native local candidate
# gate (Linux MID, fixtures boot positives + negatives, audit/deny, docs).
# Hard-0 policy: mandatory prerequisites fail-BEFORE-EFFECT — a prerequisite
# absence (source identity, sha256 hasher, `file` availability for the
# static-ELF probe) is an ERROR that aborts the run before any gate effect,
# never a silent skip and never a pass-by-existing. The static-ELF CONTENT
# probe itself necessarily runs after boundary phase1 builds and executes the
# exercised fixture-facts artifact in this run; what must hold before any
# effect is that the probe TOOL is available. The exercised artifact probed
# here is the fixture-facts variant the wrapper's own fixtures gate builds and
# executes from exact source in this very run (B3: one consistent build ->
# identity/static/hash -> smoke path; no stale path can pass by existing), and
# its freshness is proven against the in-run build marker that fixtures gate
# writes. The docs control runs once, inside boundary phase1 (the same
# docslink_check the `docs` selector runs). No remote target is ever contacted;
# only foreground --rm runners are used.
set -u
set -o pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT" || { echo "QA-PACKAGE-ERROR: cannot cd to repo root" >&2; exit 1; }

fail=0
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "QA-PACKAGE-VALIDATE start: $now host=$(uname -s)/$(uname -m) toolchain=1.99.0"

# Mandatory prerequisites fail BEFORE any gate effect: each absence aborts the
# run immediately (exit 1), so the heavy native boundary gate below is never
# entered with a known-broken identity base.
prereq_fail() {
    echo "$1" >&2
    echo "QA-PACKAGE-PREREQ-FAIL: mandatory prerequisite failed before any gate effect" >&2
    exit 1
}

# Mandatory prerequisite 1: a sha256 hasher (sha256sum preferred, else shasum).
HASHER=
if command -v sha256sum >/dev/null 2>&1; then
    HASHER=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    HASHER="shasum -a 256"
else
    prereq_fail "no sha256 hasher (sha256sum or shasum); artifact hash impossible"
fi

# Mandatory prerequisite 2: git for exact-input source identity.
command -v git >/dev/null 2>&1 || prereq_fail "git absent; exact-input source identity impossible"
git rev-parse --verify -q HEAD >/dev/null 2>&1 || prereq_fail "source HEAD not resolvable; exact-input identity impossible"
HEAD_ID=$(git rev-parse --verify HEAD 2>/dev/null) || prereq_fail "git rev-parse producer failed"
echo "source HEAD: $HEAD_ID"
# Working-tree status-list identity (list of changed paths), explicitly
# NOT a content identity; the artifact digest below carries the content
# identity of the actual tested bytes.
git status --porcelain >/dev/null 2>&1 || prereq_fail "git status unreadable; working-tree identity impossible"
PORCELAIN=$(git status --porcelain 2>/dev/null | $HASHER 2>/dev/null | cut -d' ' -f1) || prereq_fail "working-tree status-list hash producer failed"
[ -n "$PORCELAIN" ] || prereq_fail "working-tree status-list hash empty"
echo "source working-tree status-list identity (NOT content identity): $PORCELAIN"

# Mandatory prerequisite 3: the `file` probe for the mandatory static-ELF
# content check of the exercised artifact. Availability must hold BEFORE any
# gate effect (no post-build surprise when the probe tool is found missing);
# the rendered `file` verdict still runs only after boundary phase1 produces
# the artifact.
command -v file >/dev/null 2>&1 || prereq_fail "'file' absent; mandatory static-ELF probe impossible"

# Fresh-variant proof: the exercised fixture-facts artifact must match the
# variant boot_fixtures built IN THIS RUN. boot_fixtures (inside boundary
# phase1) rebuilds the variant unconditionally and records its in-run sha in
# the marker file next to the binary; absence, emptiness or mismatch means the
# probed artifact has no provable in-run provenance and must not pass (stale
# path must never pass by existing). This is a fingerprint/integrity check in
# the QA wrapper, directly positive/negative fault-tested.
assert_fresh_variant() {
    want_sha="$1"
    marker="$2"
    [ -r "$marker" ] || {
        echo "QA-PACKAGE-ERROR: fresh-variant marker absent ($marker); artifact freshness unprovable" >&2
        return 1
    }
    built_sha=$(cat "$marker" 2>/dev/null) || {
        echo "QA-PACKAGE-ERROR: fresh-variant marker unreadable ($marker)" >&2
        return 1
    }
    [ -n "$built_sha" ] || {
        echo "QA-PACKAGE-ERROR: fresh-variant marker empty ($marker)" >&2
        return 1
    }
    [ "$built_sha" = "$want_sha" ] || {
        echo "QA-PACKAGE-ERROR: exercised artifact sha256 $want_sha does not match this run's built fixture-facts variant $built_sha" >&2
        return 1
    }
    if [ "$boundary_ok" -eq 1 ]; then
        echo "exercised fixture-facts variant freshness: built in this run (sha256 $built_sha)"
    else
        echo "exercised fixture-facts variant integrity: sha256 $built_sha matches variant marker (boundary phase1 failed; digest equality is integrity-only, not this-run attribution)"
    fi
}

# The exercised artifact is the fixture-facts variant that the fixtures gate
# (run below, inside boundary phase1) builds from exact source and executes
# under the approved privilege profile in this same run, with variant sha and
# metadata (non-setid, security.capability absence, production-digest
# unchanged) proven by that gate's METADATA-OK predicate.
BIN=target/fixture-facts/release/alumina

boundary_ok=0
if sh scripts/verify.sh boundary phase1; then
    boundary_ok=1
else
    echo "QA-PACKAGE-FAIL: boundary phase1 gate failed" >&2
    fail=1
fi

if [ -n "$HASHER" ] && [ -x "$ROOT/$BIN" ]; then
    # Mandatory static-ELF content probe (only a static Linux ELF is an
    # acceptable packaged artifact). Probe-TOOL availability is already a hard
    # preflight (prereq 3, before any gate effect); this renders the verdict on
    # the artifact the fixtures gate just built in this run. The file(1) probe
    # runs once with its producer status checked separately: a probe failure is
    # an OPERATIONAL error, a missing "statically linked" is a CONTENT failure.
    fileout=
    if fileout=$(file "$ROOT/$BIN" 2>&1); then
        printf '%s\n' "$fileout"
        printf '%s\n' "$fileout" | grep -q "statically linked" || {
            echo "QA-PACKAGE-FAIL: exercised artifact content probe does not report a statically linked ELF: $BIN" >&2
            fail=1
        }
    else
        echo "QA-PACKAGE-ERROR: file(1) probe failed for $BIN (operational error, not a content verdict)" >&2
        fail=1
    fi
    # Mandatory artifact content digest; a hasher failure is an ERROR, not a
    # masked echo success.
    ARTIFACT_SHA=
    ARTIFACT_SHA=$($HASHER "$ROOT/$BIN" 2>/dev/null | cut -d' ' -f1) || {
        echo "QA-PACKAGE-ERROR: artifact hasher failed for $BIN" >&2
        fail=1
    }
    if [ -n "$ARTIFACT_SHA" ]; then
        if [ "$boundary_ok" -eq 1 ]; then
            echo "exercised artifact (fixture-facts variant, this run): $BIN"
        else
            echo "exercised artifact (fixture-facts variant; boundary phase1 failed -- unchanged artifact, integrity-only, not this-run attribution): $BIN"
        fi
        echo "exercised artifact sha256: $ARTIFACT_SHA"
        if ! assert_fresh_variant "$ARTIFACT_SHA" "$ROOT/target/fixture-facts/release/variant.sha256"; then
            fail=1
        fi
    else
        echo "QA-PACKAGE-ERROR: artifact digest empty for $BIN" >&2
        fail=1
    fi
elif [ -n "$HASHER" ]; then
    echo "QA-PACKAGE-FAIL: exercised artifact missing after boundary phase1 ($BIN); fixture gate did not produce it" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "QA-PACKAGE-VALIDATE-OK"
else
    echo "QA-PACKAGE-VALIDATE-FAIL" >&2
    exit 1
fi
