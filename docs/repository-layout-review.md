# Alumina — Repository Layout Review (advisory)

**Status:** advisory document. No restructuring is implemented or authorized by
this review. Assessed at repository `acje/alumina-proxy`, branch `main`, HEAD
`59ad25508e0a1ed468423b2fa10b1d10a2809763`. Canonical spec
`docs/alumina-proxy.md` (sha256 `322b68ee…5b836`) — **historical pre-rp2e spec
digest at assessment**; the current post-rp2e canonical spec sha256 is
`b5b1c9f…137d` (full `b5b1c9fae649feff81ad9910ca7af999987c7036ee447d91c1f10c3db700137d`).
The canonical spec itself is unchanged by this review.

**Recommendation in one line:** adopt **Layout A** — extract the two largest
inline `cfg(test)` tails (`src/serving.rs`, `src/runtime.rs`) into sibling
`tests.rs` child modules — as the only navigation improvement with bounded,
reversible, no-public-API cost; treat **Layout B** (an additional production
child for the startup window) as conditional on measured benefit after A; reject
mandatory `controlplane/`/`dataplane`/`monitoring`/`runner/` directory
boundaries.

## 1. Scope, status and method

- **In scope:** read-only code/test architecture assessment plus in-checkout
  `.DS_Store` Finder-metadata cleanup. No source, runtime, dependency, spec, or
  README edits. The three original untracked benchmark drafts
  (`scripts/bench_frame_echo.{py,sh}` and `scripts/bench_frame_echo.py.new`)
  and the canonical spec are preserved byte-for-byte.
- **Method:** measured counts from the observe pass; module-ownership and seam
  reading from the orientation pass; constraint check against the canonical
  spec and `docs/architecture.md`. `architecture.md` is a **design statement**,
  not runtime proof; its `Status` line pins the older HEAD `8934adb` — treat it
  as design context, never as current-runtime evidence.
- **Sources:** the mission's three evidence artefacts are the basis for §2–§8:
  observe (counts and citations), oracle summary (spec constraints), and
  orientation (ranked layouts). Coverage and qualification limits are stated in
  [§10](#10-basis-and-coverage-limitations).

## 2. Current measured tree

Counts are the observe pass's brace-tracked heuristic census (see
[§10](#10-basis-and-coverage-limitations)):

| Area | Files | Lines |
|---|---|---|
| `src/` total | 23 | 23,369 (12,003 production + 11,366 inline `cfg(test)` = 48.6%) |
| `tests/` external | 6 | 2,005 |
| `scripts/` (non-`node_modules`) | — | 14,692 (incl. `verify.sh` 1,141 and 3 protected bench drafts) |
| `docs/` Markdown | 12 | 2,315 (canonical spec `alumina-proxy.md` 236) |

Largest source files by total lines, with production/test split:

| File | Total | Production | Inline tests | Notes |
|---|---|---|---|---|
| `src/serving.rs` | 6,218 | 2,538 | 3,675 | tail `mod tests` at 2563..EOF; inline helpers at 37, 418 |
| `src/startup_dns.rs` | 3,024 | 1,772 | 1,250 | tail `mod tests` at 1775 |
| `src/runtime.rs` | 2,072 | 374 | 1,697 | tail at 376..EOF (82% test) |
| `src/log.rs` | 1,594 | 1,060 | 533 | 1 pub item in 1,594 lines |
| `src/dns.rs` | 1,576 | 1,003 | 572 | |
| `src/worker.rs` | 1,400 | 655 | 744 | |

The production/test columns are **approximate classifications**, not
guaranteed-additive splits: the heuristic may exclude `cfg(...)` attribute and
boundary lines, so per-file production + test need not equal the total (e.g.
serving 2,538 + 3,675 = 6,213 vs 6,218; runtime 374 + 1,697 = 2,071 vs 2,072).

External `tests/`: `boot.rs` 695, `mio_matrix.rs` 483, `foundations.rs` 324,
`eligibility.rs` 322, `stdout_stall.rs` 102, `main_thread_stack.rs` 79.

## 3. What the hotspots actually are

The apparent large-file growth is mostly **test mass living beside its
implementation**, not production complexity:

- `src/serving.rs` is a deliberate **deep module**: 11 public items but
  the whole decision machine (refusal, read/write/connect stage enums, gate,
  slot workspaces, startup tallies) is private. Byte ownership, gate opening,
  budget accounting and release-once are kept together — a cohesion witness, not
  an oversight.
- `src/runtime.rs` is genuinely **small production code** (374 lines): a
  shared-readiness coordinator that joins DNS freshness, traffic readiness and
  the signal pipe into one poll, plus a consuming `attach` that enforces the
  one-time transfer into the attached serving owner (serving without a listener
  is unrepresentable). Startup order itself is composed in `main.rs`, not
  encoded by `attach`. Its 1,697-line test tail dominates the file, not its
  body.
- `src/startup_dns.rs` is a bounded startup DNS-over-TCP transport with its own
  window-ledger bookkeeping; its production body is 1,772 lines.
- `tests/` (2,005 lines) is smaller than the inline `cfg(test)` mass (11,366
  lines). A layout review that only looks at `tests/` under-reads test
  ownership.

No numeric line cap is proposed: file length alone is not a seam.

## 4. Named responsibilities, interfaces and private-invariant owners

Single binary, one worker thread, no async runtime. `main.rs` composes one
intended startup order (composition evidence, not a type guarantee):

`main.rs` (boot owner) → `boot.rs` (preflight + config + resolver +
`TrafficStorage::allocate` + ledger) → `ServeStorage::boot` → 
`Preallocated::preallocate` → `prepare_stdout_log_sink` → `run_startup` (startup
DNS window; `&mut self`, type unchanged) → `attach(listener)` **consumes**
`Preallocated` → `Runtime::serve`.

| Module | Responsibility | Interface / invariant owner |
|---|---|---|
| `main.rs` | process composition; single boot owner | no CLI; wires the chain |
| `boot.rs` | local-input validation only; never DNS/serving | owns preflight/config/resolver/inventory allocation |
| `serve.rs` | `ServeStorage` private owner (config/cache/schedules/DNS/worker/clock/logs); aligned decision view; readiness settlement; `ServingMode`/`StartupDecision` set once | startup-readiness rule; degraded set never reopened |
| `runtime.rs` | shared-readiness coordinator; one poll; bounded cooperative DNS turns | `Preallocated` consumed by `attach`; compile_fail E0599 doctest |
| `serving.rs` | actual serving event loop: mio sockets, CONNECT parse, refusal bodies, dial, ClientHello, relay, release-once | private decision enums; gate/open transitions; slot workspaces |
| `worker.rs` | worker-policy core: cache CONNECT decisions, phases, deadlines, typed slot/tunnel indexes | clean decision leaf; no serving/serve/startup_dns/log imports |
| `log.rs` | boot-owned bounded allocation-free logging; nonblocking drain | 1 pub item; queue fixed 256×8 KiB |
| `config`/`resolver`/`preflight`/`inventory` | strict parse, resolver read, Linux privilege preflight, storage ledger | shared bottom of the dependency graph |

Fixed-buffer and ownership invariants (canonical spec, unchanged):

- Fixed buffers are single-sourced: `HOLD_CAP = DOWN_CAP =
  crate::inventory::BUFFER_BYTES`, and the log queue asserts
  `QUEUE_SLOTS * SLOT_BYTES == LOG_QUEUE_BYTES`.
- 128 MiB = tunnel traffic storage only (canonical `:183`); boot-time storage
  preallocated (`:143`).
- **Zero-allocation invariant** (canonical `:206`): serving/refresh paths,
  including dependencies, do not allocate/deallocate heap storage.
- **Ownership invariant** (canonical `:211`): each connection's mutable state
  belongs to exactly one worker.
- **Runtime surface** (canonical `:235`): exactly one listening socket, no other
  inbound interface; SIGTERM-only lifecycle. Log is in-band best-effort
  (canonical `:194`), not an independent service.

Public/private seam: `lib.rs` declares all modules `pub`, but real API control
is item-level and dominated by `pub(crate)`/private — `log.rs` has exactly one
pub item. **Consequence:** any internal restructure needs no real public API;
`pub(crate)`/private is the sanctioned seam, and a `tests.rs` split must not
widen private→pub just to test.

Dependency seams and one correction:

- `serving.rs` is the integration hub (11 production `use crate::` edges);
  `worker.rs` is a clean decision leaf; `boot.rs` is a leaf.
- **Correction to the oracle summary:** a production **source/type dependency
  cycle exists between `log` and `startup_dns`** — `log.rs` imports
  `startup_dns::NameOutcome` while `startup_dns` uses `log::LogStoreError` and
  log APIs. This is an import/types cycle, not cyclic *mutable ownership*; do
  not introduce a neutral vocabulary module purely to cure import aesthetics.
- Startup order is **composed in `main.rs`**, not type-enforced: `run_startup`
  borrows the same `Preallocated` (`&mut self`) and `Runtime::new` attaches
  without any startup DNS. What the types do enforce is the consuming transfer:
  `attach(self, listener)` consumes the pre-attach type, serving on the
  pre-attach owner is excluded (compile_fail doctest), and a second attach is
  impossible. Any layout must keep that one way into an attached serving owner
  and keep `main.rs`' wiring of the startup window.

## 5. Test ownership (advisory policy)

Actual helper duplication observed: `TempDir` implementation in
`src/boot.rs` and `tests/boot.rs`; config/ephemeral-port helpers in
`src/serving.rs` and `src/runtime.rs`. No global fixture framework follows
automatically. Reuse only helpers with an identical fixture/lifetime contract,
in test-only scope; leave owner-specific private seeding local.

Proposed ownership map:

- **Child unit/private tests** own state transitions, cursors, partial writes,
  gate/refusal/EOF and release.
- **`runtime` child** owns composition, fairness, the one-wait evidence
  (DNS + traffic + signal) — keep the hot owner-turn fixture here.
- **`serve` child** owns aligned storage, cache-clock view, readiness/listener
  outcomes; **`startup_dns` child** owns transport and window bookkeeping;
  **worker/cache/parser/gate/log** children own their mechanisms.
- **External `tests/`** own public contract, OS/dependency evidence and
  true-process cases. `tests/boot.rs` is not a duplicate of private boot
  composition tests at `src/boot.rs` — the name overlap is not dedup evidence.

## 6. Ranked layout options

### 6.1 Layout A — recommended: test-tail extraction (navigation-only)

Rust child-module lookup permits `foo.rs` + `foo/tests.rs` with no `mod.rs`
rename. A `cfg(test)` child module reads parent private items via `super::*`
without widening visibility:

```
src/serving.rs        existing production module + cfg(test) seams, gated in owner
src/serving/tests.rs  existing serving private-mechanism tests (same serving::tests)
src/runtime.rs        existing production coordinator + cfg(test) gates
src/runtime/tests.rs  existing owner-composition tests
src/<other>.rs        unchanged initially; same child pattern only as justified
tests/ ... scripts/ ...  existing public-contract / native / runner surfaces retained
```

- ~5.35k raw test-tail lines relocate in the first serving+runtime pair;
  production lines unchanged; module paths (`alumina::X`) unchanged.
- Added logic: only module declarations, no adapters. Earlier `cfg(test)`
  fields, impls and cross-module seams stay gated in their owner — do not
  blindly move all inline helpers into the sibling test module.
- **Reversible per module**; no behavioural delta, no test-count change, no
  feature/doctest identity change when executed under a later contract.

### 6.2 Layout B — conditional: A plus a startup production child

```
src/serving.rs          sole Serving type: poll/dispatch, slots, tunnel lifecycle
src/serving/startup.rs  impl Serving: run_startup_window + StartupTallies
src/serving/tests.rs    serving private-mechanism tests incl. startup coupling
src/runtime.rs + src/runtime/tests.rs   unchanged from A
```

Move the **whole** startup method (≈194 raw lines at `serving.rs:894-1087`)
plus its small tallies type; not per-step wrappers. The child can access
private parent fields; the associated method keeps existing `pub(crate)`
visibility so `Runtime` can still call it. No fields widen.

Cost/benefit: one more source hop during lifecycle reasoning; benefit is a
smaller tunnel-reading surface. **Choose B only if A's navigation benefit is
measured and B still reads well end-to-end** (e.g. the startup-SIGTERM
settlement trace). B must not create a DNS-owned wait, drop the settlement
recheck, or turn startup into an independent runner — those are rejection
conditions.

### 6.3 Rejected candidates and reasons

| Candidate | Rejected because |
|---|---|
| Mandatory `controlplane/`, `dataplane/`, `monitoring/`, `runner/` directories | Rejected as poor **maintainability advice**, not a spec violation: a rigid four-directory hierarchy organizes across the single shared scheduler without hiding information (shallow organization for this owner). If those labels were realized as independent workers/services/interfaces or allocating paths they would violate canonical `:206`/`:211`/`:235` and `architecture.md` §9 — directory names alone do not. Keep them as **responsibility labels**: controlplane = cache/schedule/DNS/authz policy; dataplane = Serving sockets/parsers/gate/relay + worker; monitoring = bounded LogStore (in-band); boot = main composition + boot/config/resolver/preflight/inventory. |
| Split setup and relay into independent components | The same two buffers, gate, budget and visit accounting surround both; splitting breaks the serving cohesion witness. |
| Move all private tests to external `tests/` | Existing tests inspect private buffers/state; external tests cannot reach `super::*` without public widening. |
| Break out buffer/accounting wrapper abstractions | Over-abstraction; shared visit accounting surrounds routing; a wrapper adds indirection without hiding complexity. |

## 7. Conditional migration (authorization required — not part of this review)

1. Snapshot source identity and a qualified test inventory including
   `cfg(...)`/feature gating, doctests and `harness = false` targets; record
   existing doc source-path links.
2. Relocate **one test tail per reversible structural increment**, serving then
   runtime (order is not a contract). Preserve test-module identity, `cfg`,
   helpers, constructors and test count.
3. Only if B is selected: move the complete startup implementation + tallies in
   a **separate** structural increment.
4. Update affected doc source-path links; replace fragile `:line` pointers with
   stable symbol/section references where practicable. The canonical spec
   `docs/alumina-proxy.md` never changes.
5. Execution belongs to a later contract using the repo-native gates
   (`docs/verification.md`); structural moves still need feature-sensitive
   unit/doctest identity preservation, the alloc witness and native applicable
   proofs on the actual candidate. macOS results cannot be inferred as
   native-Linux success.

## 8. Evaluation against sourced principles (Ousterhout — primary evidence actually read)

Primary sources **actually read** by the observe pass (not training recall):

1. Stanford CS book page — [A Philosophy of Software Design](https://web.stanford.edu/~ouster/cgi-bin/book.php)
   (and `aposd.php`): confirms author (John Ousterhout), title *A Philosophy of
   Software Design*, 2nd ed. July 2021, and the 2nd-edition changes (new
   "Decide What Matters" chapter; reworked "General-Purpose Modules are Deeper";
   explicit comparisons with Martin's *Clean Code* on method length and
   comments).
2. The author's discussion README —
   [aposd-vs-clean-code](https://github.com/johnousterhout/aposd-vs-clean-code/raw/main/README.md) —
   read-visible portion, verbatim extracts recorded in the observe evidence:

   - Complexity: *"the fundamental goal of software design is to make it easy
     to understand and modify the system … complexity [is] things that make it
     hard to understand and modify"*, driven by the information a developer
     must hold in their head and how accessible/obvious it is.
   - Deep vs shallow: *"The best methods … provide a lot of functionality but
     have a very simple interface"* (deep); smaller decomposition that does not
     reduce what the programmer must know is *"shallow"*.
   - Entanglement: if understanding one method requires reading another, that
     is *"a red flag"*; tightly related code should be brought together.
   - Over-decomposition: *Clean Code* gives *"strong, concrete, quantitative
     advice about when to chop things up, with virtually no guidance for how to
     tell you've gone too far"*; *"complexity is in the eye of the reader"*.

**Applied reading:**

- Information burden justifies separating test mass from production bodies
  (Layout A): navigation now exposes the small production coordinator and the
  deep serving module without paging through 3.6k-line test tails. This is a
  real but shallow benefit — a navigation aid, not new encapsulation.
- Depth argues *against* chopping `serving.rs` production by file length or
  extracting buffer/accounting wrappers — its byte/gate/release transitions are
  the entangled code that should stay together.
- Entanglement warns *for* Layout B's whole-method move if attempted, and
  against per-step wrappers in a split.
- No numeric function/file limit is proposed (over-decomposition warning).

**Explicit house-style tension (flagged, not resolved):** Ousterhout argues
comments are required for abstraction and favors explanatory comments; the
fleet house style bans plain Rust comments and restricts doc comments to actual
contracts. This review does **not** mandate comments or waive doctrine; durable
rationale belongs in documents/beads, not prose attached to code.

## 9. Recommendation

1. **Now:** keep the current layout; treat §6 role labels as a responsibility
   map, not directory mandates. (This review changes no code.)
2. **Next authorized contract:** implement **Layout A** first (serving then
   runtime test-tail extraction), measure navigation benefit on a real
   maintainer task; choose **B** only if it still reads well.
3. **Never as mandatory organization:** a prescribed four-directory role
   hierarchy, setup/relay split, private-test externalization or buffer wrapper
   extraction unless a future contract demonstrates a concrete maintainability
   gain. Directory moves that keep one owner/poll/API are not canonical
   violations; they are judged purely on maintainability.

## 10. Basis and coverage limitations

- **Counts are heuristic and non-additive at row level.** The line census is
  the observe pass's brace-tracked `cfg(test)` awk measurement (spot-checked on
  `config.rs` and `inventory.rs`), not a fresh re-census by this review; bucket
  columns may exclude `cfg(...)` attribute/boundary lines and need not sum to
  raw file totals (see the serving/runtime rows in §2); a qualifying inventory
  before execution belongs to the migration contract.
- **Book-text gap (honest).** The full APOSD 2nd-edition chapter text was **not
  read**: the official extract PDF is image-only (no text layer; OCR
  unavailable in the environment). Chapter names come from the Stanford book
  page only; the quotes in §8 come from the read-visible portion of the
  aposd-vs-clean-code README, not from the untruncated book. No claim extends
  beyond those two actually-read primary sources.
- **Not verified here:** cargo build/test/native-Linux gates were not run (this
  is advice + metadata cleanup, per mission bounds); `serving.rs` production
  internals were read to line 2550 in the orientation pass, but no exhaustive
  seam map of the remaining production body exists; actual GitHub web state
  beyond git refs (`ls-remote`/fetch) was not queried.
