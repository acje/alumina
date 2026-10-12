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
4. **Not production-qualified** — open gates: F3 serving completeness witness,
   F4 fuzz campaigns, deployment confinement/initial deployment, performance
   (build-plan §2/§7; traceability §5). Qualification stays BLOCKED until those
   pass; **no runtime completion claim is made**.

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

## As-built model

`main` is the single boot owner, `Runtime` the single serving owner (one `mio`
poll); ownership, transitions, buffer reuse and the provisional parser layer
are in [architecture §1/§2](docs/architecture.md#1-governing-invariants-invariant-led-design)
and build-plan §0.

## Runtime surface and fixed inputs

- `./config.toml` (≤ 4096 B, mandatory keys, no defaults) and `./resolv.conf`
  (first nameserver, numeric unicast, port 53); no CLI args, no env overrides;
  one listening socket; **SIGTERM the only handled lifecycle signal**
  (`alumina.md:149`).
- Privilege preflight (non-root, empty caps, `no_new_privs`): unmet → EX_CONFIG
  78; unresolved beyond allowance → EX_TEMPFAIL 75.

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

Selector host context / prerequisites (incl. `mid` Linux-only fail-closed and
`fixtures`/`e2e` host-runnable details): sole owner is
[qa-package/README.md](qa-package/README.md); durable source table in bd
`alumina-1d5x`.

`atest`/`aclippy` are the fleet Cargo aliases (host config; each Linux MID
dispatch writes the same aliases into its throwaway container config — the repo
does not duplicate them). Nine-doc offline link check (all retained Markdown
including this file, the register and AGENTS.md): `node
scripts/docs_check/check.mjs README.md AGENTS.md alumina.md
alumina-refinement.md docs/architecture.md docs/build-plan.md
docs/traceability.md docs/harness-evaluation.md qa-package/README.md`.

### Native proofs (scoped, exact-input)

Native proofs are **scoped to exact candidates, never blanket**: `mid
foundations`/`mid boot`, `fixtures boot`, `e2e relay`, `e2e shutdown`, and the
alloc-witness matrix are recorded against `1538a1b`/`579b9ce`/HEAD with
exact-input identity receipts (bd beads). The F3 mio operation matrix is
**implemented** (`tests/mio_matrix.rs`, 8 tests incl.
`linux_epoll_operation_matrix`, native evidence bd `z9m0`/`po3c`); its
current-serving completeness witness remains open (bd `cnrd` T3). The
startup-DNS transport is independently **reviewed and approved** (bd
`alumina-c14m`, round 2) and wired into `main`; its **serving qualification**
(F1 serving witness, F2 campaigns, F4 fuzz, BOUNDARY) remains open.

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
- F3 serving completeness witness and full BOUNDARY remain open; exact
  candidates above are proven for relay/shutdown, never a blanket claim.
- `getrandom` intake complete; `cargo deny`/`cargo audit` clean; no
  product-wide zero-alloc claim is made.
