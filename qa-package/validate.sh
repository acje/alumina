#!/bin/sh
# qa-package/validate.sh — local static native QA package identity + smoke.
# Records source/artifact identity and runs the repo-native local candidate
# gate (Linux MID, fixtures boot positives + negatives, audit/deny, docs).
# Hard-0 policy: mandatory prerequisites (source identity, sha256 hasher,
# static-ELF probe) and every producer exit fail CLOSED; an unresolved
# identity is an ERROR, never a PASS and never a silent skip. The exercised
# artifact probed here is the fixture-facts variant the wrapper's own fixtures
# gate builds and executes from exact source in this very run (B3: one
# consistent build -> identity/static/hash -> smoke path; no stale path can
# pass by existing). No remote target is ever contacted; only foreground
# --rm runners are used.
set -u
set -o pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT" || { echo "QA-PACKAGE-ERROR: cannot cd to repo root" >&2; exit 1; }

fail=0
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "QA-PACKAGE-VALIDATE start: $now host=$(uname -s)/$(uname -m) toolchain=1.99.0"

# Mandatory prerequisite 1: a sha256 hasher (sha256sum preferred, else shasum).
HASHER=
if command -v sha256sum >/dev/null 2>&1; then
    HASHER=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    HASHER="shasum -a 256"
else
    echo "QA-PACKAGE-ERROR: no sha256 hasher (sha256sum or shasum); artifact hash impossible" >&2
    fail=1
fi

# Mandatory prerequisite 2: git for exact-input source identity.
if ! command -v git >/dev/null 2>&1; then
    echo "QA-PACKAGE-ERROR: git absent; exact-input source identity impossible" >&2
    fail=1
else
    HEAD_ID=
    if ! git rev-parse --verify -q HEAD >/dev/null 2>&1; then
        echo "QA-PACKAGE-ERROR: source HEAD not resolvable; exact-input identity impossible" >&2
        fail=1
    else
        HEAD_ID=$(git rev-parse --verify HEAD 2>/dev/null) || { echo "QA-PACKAGE-ERROR: git rev-parse producer failed" >&2; fail=1; }
        if [ -n "$HEAD_ID" ]; then echo "source HEAD: $HEAD_ID"; fi
    fi
    # Working-tree status-list identity (list of changed paths), explicitly
    # NOT a content identity; the artifact digest below carries the content
    # identity of the actual tested bytes.
    PORCELAIN=
    if ! git status --porcelain >/dev/null 2>&1; then
        echo "QA-PACKAGE-ERROR: git status unreadable; working-tree identity impossible" >&2
        fail=1
    else
        PORCELAIN=$(git status --porcelain 2>/dev/null | $HASHER 2>/dev/null | cut -d' ' -f1) || {
            echo "QA-PACKAGE-ERROR: working-tree status-list hash producer failed" >&2
            fail=1
        }
        if [ -z "$PORCELAIN" ]; then
            echo "QA-PACKAGE-ERROR: working-tree status-list hash empty" >&2
            fail=1
        else
            echo "source working-tree status-list identity (NOT content identity): $PORCELAIN"
        fi
    fi
fi

# The exercised artifact is the fixture-facts variant that the fixtures gate
# (run below, inside boundary phase1) builds from exact source and executes
# under the approved privilege profile in this same run, with variant sha and
# metadata (non-setid, security.capability absence, production-digest
# unchanged) proven by that gate's METADATA-OK predicate.
BIN=target/fixture-facts/release/alumina

sh scripts/verify.sh boundary phase1 || {
    echo "QA-PACKAGE-FAIL: boundary phase1 gate failed" >&2
    fail=1
}

if [ -n "$HASHER" ] && [ -x "$ROOT/$BIN" ]; then
    # Mandatory static-ELF probe (only a static Linux ELF is an acceptable
    # packaged artifact); a missing probe tool is an ERROR, never a skip.
    if command -v file >/dev/null 2>&1; then
        file "$ROOT/$BIN"
        file "$ROOT/$BIN" | grep -q "statically linked" || {
            echo "QA-PACKAGE-FAIL: exercised artifact is not a statically linked ELF: $BIN" >&2
            fail=1
        }
    else
        echo "QA-PACKAGE-ERROR: 'file' absent; mandatory static-ELF probe impossible" >&2
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
        echo "exercised artifact (fixture-facts variant, this run): $BIN"
        echo "exercised artifact sha256: $ARTIFACT_SHA"
    else
        echo "QA-PACKAGE-ERROR: artifact digest empty for $BIN" >&2
        fail=1
    fi
elif [ -n "$HASHER" ]; then
    echo "QA-PACKAGE-FAIL: exercised artifact missing after boundary phase1 ($BIN); fixture gate did not produce it" >&2
    fail=1
fi

sh scripts/verify.sh docs || {
    echo "QA-PACKAGE-FAIL: docs gate failed" >&2
    fail=1
}

if [ "$fail" -eq 0 ]; then
    echo "QA-PACKAGE-VALIDATE-OK"
else
    echo "QA-PACKAGE-VALIDATE-FAIL" >&2
    exit 1
fi
