# Alumina — harness fitness evaluation (measured, 2026-10-12)

Normal-document evaluation of the repository-native harness against the
`alumina` serving/fixture surface, **measured at the exact candidate
`579b9ce`** on 2026-10-12 and **maintained (kept) at HEAD `8934adb` for
reference**. Receipts are historical and scoped to that exact measured input —
unchanged Rust alone does not establish full input equivalence against later
commits (harness/scripts changed), so rows below remain scoped and this is
never a fresh-run or qualification upgrade. Coverage claims are scoped to what
a gate actually exercised at an exact candidate; **no universal timing or
coverage is inferred**. See the four-claim ledger in `README.md` and the local
QA package.

## Conditions of every measurement

- Host macOS darwin/arm64; podman 6.1.3; `flock-vm`/`flock-vm-root` over
  ssh at `127.0.0.1:65343`. Linux target aarch64; pinned builder
  `docker.io/library/rust@sha256:484dce…779a`; toolchain 1.99.0.
- **Cache state:** warm persistent target dir + warm host tools/advisory DB;
  **container side disposable and cold per run** (fresh `--rm` container,
  empty `/cargo-home`, re-fetched crates.io). "Warm target, fresh container
  registry" is the accurate description.
- Concurrency **serial**; date 2026-10-12; measured input = exact candidate
  source `579b9ce` plus the harness/docs/package file deltas at that revision
  — historical, maintained at HEAD for reference only (not full-input
  equivalent to HEAD).

## Measured timings by tier

| Tier / gate | Scope exercised | Measured wall (serial; warm target/host caches, fresh registry) |
|---|---|---|
| INNER `atest -p alumina --locked` | unit corpus 263 + boot 32 + eligibility 5 + foundations 6 + stdout_stall 1 + main_thread_stack + doctests | unit phase 12.55 s (cargo-reported); full invocation within 120 s, exit 0 |
| INNER `atest … --features alloc-witness` | alloc-witness matrix: 3 cross-platform tests host; Linux epoll matrix 8/8 native (ucxi: HOST-ALLOC=3 / NATIVE=8, exact candidate, reused) | 43.8 s host, exit 0; plain run executes 0 matrix tests (feature-gated off) |
| INNER `fmt --check` / `aclippy -D warnings` | formatting; clippy | 0.5 s / 0.7 s, exit 0 |
| MID `verify.sh mid foundations` + `mid boot` | static ELF + whitespace + witness tests | 5.4 s combined (fresh registry; release hit target cache), exit 0 |
| MID `verify.sh fixtures boot` | supervised typed-terminated positive + exit-78 negatives + kernel facts + xattr absence | 14.4 s first / 13.3 s four-step, exit 0 |
| MID `verify.sh docs` | native 4-doc offline link gate (`check.mjs`) | exit 0 (`DOCSLINK-CHECK-OK`) |
| MID/BOUNDARY `deny check` + `audit` | advisories/bans/licenses + 28 locked deps | 6.3 s / 4.3 s, exit 0 (warm advisory DB) |
| BOUNDARY `e2e relay` + `e2e shutdown` | DNS-over-TCP responder, raw-echo/TLS/counting fixtures, byte-exact + effect + distinct-timeout; SIGTERM grace + drain | **reused** from ucxi exact-`579b9ce` receipts — not re-run; timing in those receipts |

## Coverage by dimension

| Dimension | Where exercised | Status / gap |
|---|---|---|
| Canonical protocol | `e2e relay` (ucxi reuse) + DNS wire unit corpus | CONNECT/SNI positive + plaintext-close covered; HRR/fatal-alert + F2 gate-transition campaigns unfilled |
| DNS | wire parse units; startup TIDs; refresh due-initiation/retry/backoff (ucxi reuse) | F4 DNS-wire fuzz campaign not shipped (scaffold only) |
| Gates | all rows exit-0 with identity receipts | full BOUNDARY BLOCKED; `RELEASE-NOT-READY` never converted to clean |
| Deadlines | startup window + bounded child wait + SIGTERM grace | covered; no inferred universal deadline |
| Resources | alloc-witness foundations/boot/startup-DNS; 8 MiB main-thread stack; 128 MiB store + workspaces | serving/refresh completeness witness open (F3) |
| Error/Unknown separation | typed error split; e2e distinct timeouts; fixture negatives vs positive; probe error ≠ no-match | covered |
| Confinement | `fixtures boot` privilege profile + xattr absence probe | covered locally; deployment confinement separate/open |
| Script fidelity | repo-native drivers only | covered; no rewritten scripts |

## Fault / false-clean analysis (guard-bite, 2026-10-12)

- **Four-step re-proof against the ACTUAL enforcement surfaced a real bug:**
  the first helper captured `$?` with a bare `grep …; rc=$?`, which `set -e`
  killed on the first nonzero grep — for `not_contains`, nonzero (no-match) is
  the REQUIRED outcome, so the negative probe died without a marker. Fixed with
  an if/else guard that preserves rc under `set -e`; then baseline `fixtures
  boot` exit 0 → plant (receipt `reaped child rc=99`, never emitted) exit 1
  `FIXTURE positive FAIL` → revert → clean exit 0.
- **Probe-error vs no-match distinct:** `fixture_require_stdout_contains`
  passes only on match (0), treats probe error (2) as `ERROR … unverifiable`,
  missing fragment as `FAIL`; `not_contains` requires the no-match exit (1);
  absence never inferred from a failed probe stream.
- **Supervisor receipt is an asserted predicate** (`FIXTURE-POSITIVE-
  SUPERVISED: reaped child rc=0`); a malformed/truncated receipt now fails the
  gate (planted-red above).
- **DNS false-clean eliminated:** fixture `resolv.conf` uses loopback
  (deterministic refusal), replacing the unreachable external resolver that
  silently pushed the 90 s window to failure.
- **Quoting defect fixed by evidence:** only double-quoted formats inside the
  outer `sh -c '…'`, else a single quote truncates the payload and drops
  `exit "$rc"` (silent false-green).
- Fuzz/limits reproducibility: no campaign receipts yet — no fuzz-based
  reproducibility claim is made.

## Prioritized improvements (maintainability → correctness → response → energy → features)

1. **F3 current-serving completeness witness** (correctness): matrix is built;
   complete the current-serving/SIGTERM op-set witness, close `cnrd` T3.
2. **F4 DNS-wire/log-record fuzz campaign + receipts** (correctness/fuzz).
3. **Open protocol vectors** (correctness): HRR/fatal-alert handling and the
   F2 gate-transition campaigns — biggest honest serving coverage gap.
4. **Cold- vs fresh- baseline** (honest speed data): record both once.
5. **Low value, deferred:** trimming the ~14 s `fixtures boot` wall is not worth
   a refactor until a measured need appears.

## Honest limits of this evaluation

- BOUNDARY e2e timings and native alloc-witness/matrix numbers are **reused**
  from ucxi receipts for the exact same candidate; not re-run here.
- Timings are single-host, serial, warm-target/fresh-container, dated
  2026-10-12 — a point measurement, not an aggregate benchmark.
- Coverage rows are gate-scoped at an exact candidate identity; nothing here
  claims production qualification or external validation (four-claim ledger).
