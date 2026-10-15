# Verification — instructions and command set

Verification here is **scoped and exact-input**: proofs are recorded for
specific candidates, never blanket, and a completed check at one candidate is
not reused for another unless the inputs are identical. Repository status and
known limitations are the README; qualification gates stay open and are owned
by [docs/build-plan.md](build-plan.md) (status owner
[docs/qa-package/README.md](qa-package/README.md)). This file is the
verification **instruction / command-set** authority (relocated from the README
"Verification" section).

## Command set

Host-run selectors and gates (all `sh scripts/verify.sh …` selectors and host
Cargo commands):

```
cargo +1.99.0 atest -p alumina --locked
cargo +1.99.0 atest -p alumina --locked --features alloc-witness
cargo +1.99.0 fmt --check
cargo +1.99.0 aclippy -p alumina --locked --all-targets -- -D warnings
sh scripts/verify.sh docs                       # native offline docs link gate
sh scripts/verify.sh fixtures boot              # host Podman coordinator; Darwin allowed
sh scripts/verify.sh e2e relay                  # host-runnable; auto-dispatches Linux build on Darwin
sh scripts/verify.sh e2e shutdown               # host-runnable via rootful harness
sh scripts/verify.sh boundary phase1            # host coordinator: mid+fixtures+docs+audit/deny+identity; never E2E
```

`atest`/`aclippy` are the fleet Cargo aliases (host config; each Linux MID
dispatch writes the same aliases into its throwaway container config — the repo
does not duplicate them).

### Full affected-corpus offline check

`verify.sh docs` runs the offline link gate on the **7-root canonical set**
(`DOCSLINK_ROOTS` in `scripts/verify.sh`): `README.md`, `docs/alumina-proxy.md`,
`docs/architecture.md`, `docs/build-plan.md`, `docs/traceability.md`,
`docs/verification.md`, `docs/qa-package/README.md`. The full retained Markdown
corpus — all **14** docs, including `docs/repository-layout-review.md` and
`docs/tripwire-architecture-review.md` — is checked with the explicit nonempty
argv command:

```
node scripts/docs_check/check.mjs README.md AGENTS.md alumina-refinement.md docs/alumina-proxy.md docs/architecture.md docs/build-plan.md docs/traceability.md docs/harness-evaluation.md docs/repository-layout-review.md docs/tripwire-architecture-review.md docs/benchmarks/100mbps-comparison.md docs/benchmarks/feature-match-matrix.md docs/verification.md docs/qa-package/README.md
```

Selector host context / prerequisites (incl. `mid` Linux-only fail-closed and
`fixtures`/`e2e` host-runnable details, `boundary phase1` never executing E2E):
sole owner is [docs/qa-package/README.md](qa-package/README.md).

## Offline docs link checker

`scripts/docs_check/check.mjs` is a zero-network offline AST link checker. It
parses Markdown, builds heading slugs with `github-slugger`, and verifies
every **local** link target exists and its literal fragment matches a generated
slug (`DOCSLINK-MISSING` / `DOCSLINK-MISSING-FRAGMENT`); operational or
unsupported constructs fail `DOCSLINK-OP-FAIL` and are never read as clean.
Limitations (documented, retained as approved — not removed, node deps stay):

- External `http:`/`https:`/`mailto:` links are **out of scope**, not failed.
- Long-form `rustdoc`/`cargo doctests` are **not** part of this gate.
- A zero-argument invocation is an **operational false-clean** — never a pass.
- Fragment verification is AST-literal: a fragment must match the slugger
  output exactly (local paths, GitHub slug rules).

The checker's own behavioral controls run via `node scripts/docs_check/test.mjs`.

## Native proofs (scoped, exact-input)

Native proofs are scoped to exact candidates, never blanket (`mid
foundations`/`mid boot`, `fixtures boot`, `e2e relay`, `e2e shutdown`, and the
alloc-witness matrix are recorded against exact-input identity receipts in bd
beads). `boundary phase1` never executes E2E; exit-zero coordination is not
release qualification. Where a prerequisite is absent or a gate is not
runnable-now, the classification stays an honest `BLOCKED` diagnostic — never
converted to a clean or claimed result.
