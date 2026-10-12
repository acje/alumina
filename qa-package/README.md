# Alumina — local static native QA package (testQA candidate)

This is the **local, isolated** static native QA package for the `alumina`
resolver at committed HEAD `8934adb`. Native e2e receipts are **reused** at the
exact `579b9ce` candidate (no Rust source changed between the commits; the
exercised fixture-facts variant is built from the exact current source in-run
by `validate.sh`). It bundles run/validation instructions, a non-secret example
configuration, and an artifact/source identity record. It makes **no external
deployment** and contains **no secrets**.

The repository is a **scoped testQA-ready candidate**, not a
production-qualified or externally-deployed system (four-claim ledger in
[../README.md](../README.md); measured harness fitness in
[../docs/harness-evaluation.md](../docs/harness-evaluation.md)).

## Package contents

| File | Purpose |
|---|---|
| `config.example.toml` | Example runtime configuration (fixed documented inputs, no secrets) |
| `resolv.example.conf` | Example resolver input (deterministic local loopback; never leaves the host) |
| `validate.sh` | Identity capture + local isolated smoke (positive/negative) + docs + deny/audit; hard-0 gate |

## Artifact / source identity

Three **distinct intended native Linux variants**; each has its own build
command, scope and digest — not interchangeable, no artificial shared identity:

| Variant | Path | Built/tested |
|---|---|---|
| Exercised smoke artifact (fixture-facts) | `target/fixture-facts/release/alumina` | built by the `fixtures boot` gate from exact source in-run; static-ELF + executed under privilege profile (typed-terminated positive + exit-78 negatives); sha + non-setid + `security.capability` absence proven in-run (`METADATA-OK`) |
| Production release (MID) | `target/release/alumina` | built by `mid boot`; static-ELF + whitespace + witness gates; **not executed** by this wrapper |
| Production release (e2e musl) | `target/aarch64-unknown-linux-musl/release/alumina` | native relay/shutdown **receipts reused** from bead `alumina-ucxi` at exact `579b9ce`; not rebuilt/exercised by this wrapper |

`validate.sh` records per-run: source `HEAD`, working-tree status-list identity
(changed-path list, not content), and sha256 + static-ELF of the exercised
fixture-facts artifact it just built and ran.

## The authoritative smoke: the existing native fixture runner

The packaged binary is a **Linux aarch64 static ELF** — it cannot run on the
Darwin host; there is **no separate smoke command**. The sole authoritative
local smoke is the repository's native fixture runner (`validate.sh` delegates
via `scripts/verify.sh boundary phase1`):

```sh
sh scripts/verify.sh fixtures boot
```

That runner is a **host Podman coordinator (Darwin allowed by source)**: it
builds the fixture-facts variant from exact source, executes it under the
approved privilege profile (uid 65534, `no_new_privs`, empty caps) with staged
fixed inputs in a disposable container, bounds the child with real SIGTERM +
10 s deadline, and asserts the typed records with guard-bitten predicates
(plant/fail/revert/clean proven). **Standalone prerequisites:** the production
release binary `target/release/alumina` must already be built (`sh
scripts/verify.sh mid boot` first), and the existing rootless `flock-vm` **and**
rootful `flock-vm-root` connections with the pinned builder image present on
both are required — `verify.sh` checks them and fails closed otherwise. The
only authorized execution route is the pinned builder image over the
`flock-vm`/`flock-vm-root` connections — foreground `--rm` only, **no cloud
start, no VM/TCP-remote target rotation, no daemon**. The wrapper
`validate.sh` invokes `boundary phase1` (which dispatches mid foundations+boot,
then fixtures), then probes the fixture-facts static/hash and re-invokes docs.
Its convenience is **build ordering only** — it never provisions VMs,
connections, or images (existing infrastructure remains prerequisite), and it
**never invokes the E2E selectors** (`e2e relay`/`e2e shutdown` are separate
host selectors, not part of this smoke wrapper).

## Example inputs are illustrative — never executed by any gate

`config.example.toml` and `resolv.example.conf` document a fixed, non-secret
configuration shape; they are **illustrative only and executed by nothing**.
The fixture runner stages its own fixed inputs; `validate.sh` never reads the
examples. Specifying them as runnable inputs, or relabelling the fixture gate's
inputs as the examples, would be a false claim. The resolver example is
loopback-only, so nothing in this package ever dials an external host.

## Documented binary outcomes (grounded in the fixture gate)

- **Supervised typed-terminated:** `startup_final status="terminated"` →
  `shutdown_final status="drained"`, receipt `FIXTURE-POSITIVE-SUPERVISED:
  reaped child rc=0`, child reaped at exit 0.
- **Privilege negatives:** root uid / missing `no_new_privs` / raised caps →
  exit 78 with a naming diagnostic; empty stdout, byte-exact stderr.
- **Unresolved-allowlist bound:** `startup_unresolved_allowance = 0` + no
  resolvable name → EX_TEMPFAIL 75 — bounded intentional failure, never a hang
  or false clean.

## Validating the package

```sh
sh qa-package/validate.sh
```

1. Mandatory prerequisites fail **closed** (`git rev-parse`, sha256 hasher,
   `file` static-ELF probe): any absence is `QA-PACKAGE-ERROR`, never a silent
   skip.
2. Runs `scripts/verify.sh boundary phase1`: Linux MID, supervised
   `fixtures boot` positive + exit-78 negatives, `cargo audit` + `cargo deny
   check`.
3. Probes the exercised fixture-facts artifact the gate just built: static ELF
   + sha256 from exact source in the same run.
4. Runs the docs gate (`sh scripts/verify.sh docs`).
5. Emits `QA-PACKAGE-VALIDATE-OK`, exit 0, only when identity resolved and
   every sub-gate hard-0; else `QA-PACKAGE-VALIDATE-FAIL` + non-zero.

## Known-open items (not claims of completion)

- F3 current-serving completeness witness open (matrix implemented —
  `tests/mio_matrix.rs`; build-plan §0).
- F4 parser-fuzzing campaigns not shipped.
- Deployment confinement, external validation, production qualification out of
  scope (four-claim ledger); `RELEASE-NOT-READY` stays the honest boundary
  diagnostic — never converted to a release clean.
