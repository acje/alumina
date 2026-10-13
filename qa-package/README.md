# Alumina — local static native QA package (testQA candidate)

This is the **local, isolated** static native QA package for the `alumina`
resolver at the current candidate: HEAD `bbda19f` with the approved
serde-removal manifest/lock diff and the native verification consolidation
diff applied (canonical `alumina.md` byte-unchanged). The exercised
fixture-facts variant is built from the exact current source in-run by
`validate.sh`. It bundles run/validation instructions, a non-secret example
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
| Production release (e2e musl) | `target/aarch64-unknown-linux-musl/release/alumina` | native relay/shutdown gates green directly at the current candidate (`sh scripts/verify.sh e2e relay`: 11/11; `e2e shutdown`: 10/10; harness image `localhost/alumina-e2e:e2e-20261011`, immutable ID `9191d288…`); **not executed by this wrapper** |

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
release binary `target/release/alumina` must already be built — on Linux `sh
scripts/verify.sh mid boot`; on macOS run `sh scripts/verify.sh boundary
phase1` (the `mid` selectors fail closed off-Linux) — and the existing
rootless `flock-vm` **and** rootful `flock-vm-root` connections with the
pinned builder image present on both are required — `verify.sh` checks them
and fails closed otherwise. The
only authorized execution route is the pinned builder image over the
`flock-vm`/`flock-vm-root` connections — foreground `--rm` only, **no cloud
start, no VM/TCP-remote target rotation, no daemon**. The wrapper
`validate.sh` invokes `boundary phase1` (which dispatches the mid union once,
then fixtures), then probes the fixture-facts static/hash/freshness. The docs
control runs once inside `boundary phase1` (the same `docslink_check` the
`docs` selector runs); the wrapper does not re-invoke it.
Its convenience is **build ordering only** — it never provisions VMs,
connections, or images (existing infrastructure remains prerequisite), and it
**never invokes the E2E selectors** (`e2e relay`/`e2e shutdown` are separate
host selectors, not part of this smoke wrapper).

## Selector host context (sole owner)

Source-derived prerequisite context for every `scripts/verify.sh` selector
(durable authoritative source table in bd `alumina-1d5x`). Tool/connection/
image availability is **not asserted here** (not re-tested; no runnable-now
claim), and this repo never provisions VMs, connections or images.

- `mid foundations` / `mid boot` — **Linux-only**; fail closed on any
  non-Linux host. On macOS they run through `boundary phase1` (Linux dispatch
  via the rootless `flock-vm` connection, `--pull=never`, pinned builder
  image; requires `podman`, a reachable `flock-vm` and the pinned image
  present).
- `fixtures boot` — **host Podman coordinator (Darwin allowed by source)**;
  requires existing rootless `flock-vm` and rootful `flock-vm-root`
  connections with the pinned builder image present on both (`--pull=never`),
  prebuilt `target/release/alumina` (requires it, does not build it), and a
  SHA256 tool.
- `e2e relay` / `e2e shutdown` — **directly host-runnable (Linux or
  Darwin)**; each rebuilds the exact-source production target in-run (no
  prebuilt artifact needed) and runs **host Cargo metadata** plus git/SHA
  identity receipts. Build route depends on host: on Linux the native build
  uses host `rustc +1.99.0`; on Darwin the target probe and rebuild run
  `podman --connection flock-vm run --rm --pull=never
  <pinned rust image>` — **only `flock-vm` is accepted; any
  `PODMAN_CONNECTION` override is rejected by `e2e_build_receipt` before any
  probe/build effect** (the leftover-rootless-builder alternative is not a
  supported route) — then `linux_dispatch` hardcodes `flock-vm` +
  `--pull=never`. Gate execution then needs the **rootful** connection
  (`${PODMAN_ROOT_CONNECTION:-flock-vm-root}`) and `E2E_IMAGE` default
  `localhost/alumina-e2e:e2e-20261011`: the immutable harness image ID is
  resolved on that rootful connection, recorded in the receipt, and the
  consumers re-verify the tag resolves to it and run the ID itself.
- `boundary phase1` — **host coordinator**: dispatches the Linux MID union once
  (foundations + boot command sets), then fixtures, docs, git diff,
  audit/deny, identity. Host
  tools required and fail closed when absent: `podman` + reachable `flock-vm`;
  Node with **`NODE_OPTIONS`/`NODE_PATH` unset** and
  `scripts/docs_check/check.mjs`; `git`; `sha256sum` (or `shasum`);
  `python3` (config-candidate observation); `cargo-audit` + `cargo-deny`.
  **Never invokes the e2e selectors**; exit-zero coordination is not release
  qualification.
- `docs` (`verify.sh docs`) — offline four-doc link gate: requires Node with
  **`NODE_OPTIONS`/`NODE_PATH` unset** and `scripts/docs_check/check.mjs`
  present; runs no network.

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

1. Mandatory prerequisites fail **before any gate effect** (`git rev-parse`,
   sha256 hasher, `file`): any absence is `QA-PACKAGE-PREREQ-FAIL` and aborts
   the run before the heavy native gate, never a silent skip and never a
   pass-by-existing.
2. Runs `scripts/verify.sh boundary phase1`: the Linux MID union once, then
   supervised `fixtures boot` positive + exit-78 negatives, the docs link gate
   once (`docslink_check`), `cargo audit` + `cargo deny check`.
3. Probes the exercised fixture-facts artifact the gate just built: static ELF
   + sha256 + freshness proven against the in-run variant marker the fixture
   gate wrote.
4. Emits `QA-PACKAGE-VALIDATE-OK`, exit 0, only when identity resolved, the
   fresh-variant proof holds and every sub-gate hard-0; else
   `QA-PACKAGE-VALIDATE-FAIL` + non-zero.

## Known-open items (not claims of completion)

- F3 current-serving completeness witness open (matrix implemented —
  `tests/mio_matrix.rs`; build-plan §0).
- F4 parser-fuzzing campaigns not shipped.
- Deployment confinement, external validation, production qualification out of
  scope (four-claim ledger); `RELEASE-NOT-READY` stays the honest boundary
  diagnostic — never converted to a release clean.
