# Alumina — local static native QA package (testQA candidate)

This is the **local, isolated** static native QA package for the `alumina`
resolver at checkpoint `579b9ce`. It bundles run/validation instructions, a
non-secret example configuration, and an artifact/source identity record. It
makes **no external deployment** and contains **no secrets**.

The repository as a whole is a **scoped testQA-ready candidate**, not a
production-qualified or externally-deployed system — see the four-claim ledger
in [../README.md](../README.md) and the measured harness evaluation in
[../docs/harness-evaluation.md](../docs/harness-evaluation.md).

## Package contents

| File | Purpose |
|---|---|
| `config.example.toml` | Example runtime configuration (fixed documented inputs, no secrets) |
| `resolv.example.conf` | Example resolver input (deterministic local loopback; never leaves the host) |
| `validate.sh` | Identity capture + local isolated smoke (positive/negative) + docs + deny/audit; hard-0 gate |

## Artifact / source identity

The repository builds **three distinct intended native Linux variants**; each
has its own build command, its own exact scope, and its own digest. They are
**not** interchangeable and no artificial identity is applied across them.

| Variant | Path on disk | Build | Tested/scope |
|---|---|---|---|
| **Exercised smoke artifact (fixture-facts)** | `target/fixture-facts/release/alumina` | built by the `fixtures boot` gate (inside `qa-package/validate.sh` → `scripts/verify.sh boundary phase1`) from exact source **in the same run** | static ELF (verified by `validate.sh`), then **executed** under the approved privilege profile (uid 65534, no_new_privs) as the supervised typed-terminated positive + the exit-78 negatives; variant sha + non-setid + `security.capability` absence + production-digest unchanged are proven by the gate's `METADATA-OK` predicate in-run |
| **Production release (MID)** | `target/release/alumina` | `scripts/verify.sh mid boot` (Linux `linux_dispatch`, exact source) | built + `STATIC-ELF-CHECKS` + whitespace + witness gates (`FOUNDATIONS-MID-OK` / `BOOT-MID-OK`); **not executed** by this package wrapper |
| **Production release (e2e musl target)** | `target/aarch64-unknown-linux-musl/release/alumina` | `scripts/verify.sh e2e relay` / `e2e shutdown` builds | native relay/shutdown **receipts reused** from bead `alumina-ucxi` at the exact `579b9ce` candidate; **not rebuilt or exercised** by this package wrapper — reused only in that exact identified scope |

`qa-package/validate.sh` records per-run: source `HEAD`, the working-tree
**status-list** identity (list of changed paths — explicitly *not* a content
identity), and the sha256 + static-ELF type of the exercised fixture-facts
artifact it just built and ran.

## The authoritative smoke: the existing native fixture runner

The packaged binary is a **Linux aarch64 static ELF**: it cannot execute on
the Darwin host directly and must run inside an aarch64 Linux environment.
There is **no separate smoke command in this package**. The **sole
authoritative local smoke** is the repository's existing bounded native
fixture runner — the exact, guard-bitten entry point — which `validate.sh`
delegates to (via `scripts/verify.sh boundary phase1`):

```sh
sh scripts/verify.sh fixtures boot
```

That runner builds the fixture-facts variant from exact source, executes it
under the approved privilege profile (dropped to uid 65534, `no_new_privs`,
empty caps) with the fixture's own staged fixed inputs in a disposable
container, bounds the child with a real SIGTERM + 10 s deadline (a surviving
child fails the fixture), and asserts the typed records with guard-bitten
predicates (plant/fail/revert/clean proven). The only authorized execution
route for the binary is the pinned builder image over the existing `flock-vm`
connection — foreground `--rm` only, **no cloud start, no VM/TCP-remote target
rotation, no daemon**.

## Example inputs are illustrative — never executed by any gate

`config.example.toml` and `resolv.example.conf` document a fixed, non-secret
configuration shape. They are **illustrative only and executed by nothing in
this package**: the fixture runner stages its own fixed inputs, and
`validate.sh` never reads the example files. Specifying them as runnable
inputs, or relabelling the fixture gate's passed inputs as the examples, would
be a false claim. The resolver example is loopback-only (deterministic local
refusal), so nothing in this package ever dials an external host.

## Documented binary outcomes (grounded in the fixture gate)

These are verified facts about the binary from the fixture gate on the
fixture-facts variant — they are not a separate run:

- **Supervised typed-terminated:** stdout records `level=info kind=startup_final
  ... status="terminated"` then `level=info kind=shutdown_final ...
  status="drained"`, the supervisory receipt `FIXTURE-POSITIVE-SUPERVISED:
  reaped child rc=0`, and the child reaped at exit 0.
- **Privilege negatives:** root uid, missing `no_new_privs`, or raised caps →
  **exit 78** with a diagnostic naming the failing prerequisite; negative
  fixtures keep empty stdout and byte-exact stderr.
- **Unresolved-allowlist bound:** with `startup_unresolved_allowance = 0` and
  no resolvable name in the startup window, the binary exits **EX_TEMPFAIL
  (75)** — a bounded intentional failure, never a hang and never a false
  clean.

## Validating the package

```sh
sh qa-package/validate.sh
```

The validator is repo-native, uses no remote target, and only foreground
`--rm` runners:

1. Mandatory prerequisites fail **closed**: source identity (`git rev-parse`),
   a sha256 hasher (`sha256sum`/`shasum`), and the static-ELF probe (`file`)
   are each required; any absence is an explicit `QA-PACKAGE-ERROR`, never a
   silent skip.
2. Runs the phase-1 boundary gate (`sh scripts/verify.sh boundary phase1`):
   Linux MID (`mid foundations` + `mid boot`), the supervised typed-terminated
   `fixtures boot` positive plus the exit-78 negatives/security failures, and
   `cargo audit` + `cargo deny check`.
3. Probes the **exercised fixture-facts artifact that gate just built**: static
   ELF type + sha256, from exact source in the same run — no stale path can
   pass by existing.
4. Runs the docs gate (`sh scripts/verify.sh docs`).
5. Emits `QA-PACKAGE-VALIDATE-OK` and exits 0 **only** when identity is
   resolved and every sub-gate is hard-0; any failure or unresolved identity
   prints `QA-PACKAGE-VALIDATE-FAIL` and a non-zero exit.

## Known-open items (not claims of completion)

- F3 current-serving completeness witness is still open (the mio operation
  matrix itself is implemented — `tests/mio_matrix.rs`; see build-plan §0).
- F4 parser-fuzzing campaigns are not shipped.
- Deployment confinement, external validation, and production qualification
  are out of scope for this package (four-claim ledger).
- `RELEASE-NOT-READY` remains the honest diagnostic for the boundary; this
  package never converts it to a release clean.
