# Alumina — single-binary HTTPS CONNECT egress proxy

Statically-linked, single-binary HTTPS CONNECT egress proxy for constrained
servers (golden-path fixed profile). **Sole governing specification:**
[`alumina.md`](alumina.md) (repository root) — no other document changes
canonical requirements; its bytes are fixed (sha256
`322b68eeb112f95960a67843ebafcd65b92da90ca0024f3422fdb95a5395b836`).

## State (four-claim ledger)

At HEAD `8934adb` the repository is:

1. **Implemented and correctness-tested** — boot (strict config/resolver,
   privilege preflight, startup-DNS window), the wired single-owner serving
   runtime (`main` → `Runtime::serve`), CONNECT/ClientHello relay, SIGTERM
   shutdown, post-boot DNS refresh driver.
2. **A scoped local testQA candidate** — reproducible static binary, example
   config, identity record ([qa-package/README.md](qa-package/README.md));
   **no external deployment**.
3. **Not deployed/validated** — no nonprod/prod target is authorized or
   identified (`alumina.md` §8; build-plan §7).
4. **Not production-qualified** — open gates: F3 current-serving completeness
   witness, F4 parser-fuzzing campaigns, deployment confinement / initial
   deployment, performance (build-plan §2/§7; traceability §5). The
   qualification stays BLOCKED until those pass; **no runtime completion claim
   is made**.

## Documents (ownership)

| Document | Role |
|---|---|
| [`alumina.md`](alumina.md) | **Canonical spec** — sole governing requirements |
| [docs/architecture.md](docs/architecture.md) | Conceptual design + as-built single-owner mapping (decisions D1–D7) |
| [docs/build-plan.md](docs/build-plan.md) | Qualification owner — gates F0–F4, seven slices, current status |
| [docs/traceability.md](docs/traceability.md) | Requirement → design → proof matrix + unresolved-evidence ledger |
| [alumina-refinement.md](alumina-refinement.md) | Material normative candidates for user review only |
| [docs/harness-evaluation.md](docs/harness-evaluation.md) | Measured harness fitness (dated, scoped) |
| [qa-package/README.md](qa-package/README.md) | Local testQA run/validation instructions |

## As-built single-owner model

`main` is the one boot owner: preallocate retained serving workspaces →
startup DNS window (`ServeStorage::run_startup`) → on a Serve decision attach
the startup listener and enter `Runtime::serve`. One `mio` poll observes DNS
freshness and traffic readiness together; the cooperative turn starts due DNS
exchanges itself (`src/runtime.rs`). Serving state (parser/inspector/gate/
cursors per slot, event buffer) is preallocated before the DNS window; the two
512 KiB per-tunnel buffers are reused across CONNECT parse / ClientHello
inspection / relay. See [architecture §1](docs/architecture.md#1-governing-invariants-invariant-led-design).

The **provisional protocol-parser layer** (`dns`, `connect`, `client_hello`,
`startup_dns`) is correct-by-construction, fixed-storage input to later
slices — **not** qualified serving code.

## Runtime surface and fixed inputs

- Reads `./config.toml` (≤ 4096 B, all keys mandatory, no defaults) and
  `./resolv.conf` (first nameserver, numeric unicast, port 53). No CLI args,
  no env policy overrides; one listening socket; **SIGTERM is the only handled
  lifecycle signal** (SIGPIPE is ignored; catchable admin signals cannot
  reload config — `alumina.md:149`).
- Privilege preflight (non-root, empty caps, `no_new_privs`); unmet
  prerequisites → EX_CONFIG 78; unresolved beyond allowance → EX_TEMPFAIL 75.

## Toolchain

Rust `1.99.0` (edition 2024); static target `aarch64-unknown-linux-musl`;
pinned builder image `docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a`;
`panic = "abort"`.

## Verification

Host-run selectors and gates (all `sh scripts/verify.sh …` selectors and host
Cargo commands):

```
cargo +1.99.0 atest -p alumina --locked
cargo +1.99.0 atest -p alumina --locked --features alloc-witness
cargo +1.99.0 fmt --check
cargo +1.99.0 aclippy -p alumina --locked --all-targets -- -D warnings
sh scripts/verify.sh docs                       # native 4-doc offline link gate
sh scripts/verify.sh fixtures boot              # host Podman coordinator; Darwin allowed
sh scripts/verify.sh e2e relay                  # host-runnable; auto-dispatches Linux build on Darwin
sh scripts/verify.sh e2e shutdown               # host-runnable via rootful harness
sh scripts/verify.sh boundary phase1            # host coordinator: mid+fixtures+docs+audit/deny+identity; never E2E
```

Source-derived per-selector command context (durable authoritative table, bd
`alumina-1d5x`). Rows describe what each selector requires per `scripts/`
source — availability of the local connections/images/tools is **not asserted
here** (not re-tested; no runnable-now claim), and nothing in this repo
provisions them:

| Selector | Host context |
|---|---|
| `mid foundations` / `mid boot` | **Linux-only** direct selectors; no host auto-dispatch, no intrinsic Podman requirement; refuse non-Linux (fail closed). Native Cargo 1.99.0, static readelf, git. Produces `target/release/alumina` (not executed by MID). |
| `fixtures boot` | **Host Podman coordinator; Darwin allowed by source.** Requires existing rootless `flock-vm` **and** rootful `flock-vm-root` connections, pinned rust image present on both, **prebuilt `target/release/alumina`**, SHA256 tool. Builds/executes the separate fixture-facts variant; production digest unchanged. |
| `e2e relay` / `e2e shutdown` | **Directly host-runnable.** Linux builds natively; on Darwin the selector probes the container target, `linux_dispatch` rebuilds the exact-source production target, then the rootful Podman harness runs the gate. Existing rootful connection + `E2E_IMAGE` default `localhost/alumina-e2e:e2e-20261011`; host Cargo metadata still runs. |
| `boundary phase1` | **Host coordinator.** Dispatches mid foundations+boot, then fixtures, docs, git diff, audit/deny, identity. Needs existing Podman connections/images, host Cargo/audit/deny, Node, Git/SHA/Python. **Never invokes `e2e relay`/`e2e shutdown`**; exit-zero coordination is not release qualification. |

On a non-Linux host, direct `mid` selectors refuse — run those slices through
`boundary phase1`, the only route that dispatches them. `fixtures boot` and
the `e2e` selectors are directly host-runnable and do not need boundary. The
wrapper `qa-package/validate.sh` invokes `boundary phase1`, then probes the
fixture-facts static/hash and re-invokes docs — it **never executes E2E and
never provisions VMs, connections, or images** (build ordering only; existing
infrastructure remains prerequisite).

`atest`/`aclippy` are the fleet Cargo aliases (host config; each Linux MID
dispatch writes the same aliases into its throwaway container config — the repo
does not duplicate them). Eight-doc offline link check (all retained Markdown
including this file and the register): `node scripts/docs_check/check.mjs
README.md alumina.md alumina-refinement.md docs/architecture.md
docs/build-plan.md docs/traceability.md docs/harness-evaluation.md
qa-package/README.md`.

Native Linux proofs are **scoped to exact candidates, never blanket**:
`mid foundations`/`mid boot`, `fixtures boot`, `e2e relay`, `e2e shutdown`,
and the alloc-witness matrix are recorded against `1538a1b`/`579b9ce`/HEAD
with exact-input identity receipts (bd evidence beads; reused locally in the
QA package). The startup-DNS transport is independently **reviewed and
approved** (bd `alumina-c14m`, round 2) and wired into `main`; its
**serving qualification** (F1 serving-phase alloc witness, F2 gate-transition
campaigns, F4 fuzz, BOUNDARY) remains open.

## Repository layout

`src/main.rs` boot owner → `src/runtime.rs` shared-readiness serving loop;
`src/{serve,boot,config,resolver,preflight,inventory}.rs` boot path;
`src/{dns,connect,client_hello,startup_dns,cache,schedule,worker,gate,serving,eligibility,log}.rs`
serving/parser core; `src/{alloc,fault,fuzz}.rs` F1/F2/F4 scaffolds;
`scripts/` verification owners; `tests/` integration corpus.

## Known limitations / not implemented (honest)

- Deployment confinement, initial deployment, remaining native E2E profiles,
  fuzz campaign receipts, platform/confinement/performance qualification —
  **open** (build-plan §7; traceability §5).
- The serving loop is wired and native relay/shutdown paths are proven for the
  exact candidates above; the F3 current-serving completeness witness and full
  BOUNDARY remain open.
- `getrandom` dependency intake complete, `cargo deny`/`cargo audit` clean; no
  product-wide zero-alloc claim is made.
