# Alumina — harness fitness evaluation (measured, 2026-10-12)

Normal-document evaluation of the repository-native harness against the
`alumina` serving/fixture surface at checkpoint `579b9ce`, with measured
timings and explicit conditions. Scope discipline: coverage claims below are
scoped to what a given gate actually exercised at an exact candidate; **no
universal timing or coverage is inferred** from these measurements. See the
four-claim ledger in `README.md` and the local QA package
(`qa-package/README.md`) for what is and is not claimed.

## Conditions of every measurement

- Host: macOS darwin/arm64 (Apple Silicon), podman 6.1.3 (libpod).
  Container connections: `flock-vm` (non-root), `flock-vm-root` (root) at
  `ssh://core@127.0.0.1:65343` / `ssh://root@127.0.0.1:65343`.
- Linux target: aarch64, pinned builder image
  `docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a`,
  pinned toolchain 1.99.0.
- Cache state (honest split): the **target dir** is a persistent host mount
  (`-v "$PWD:/app"`) with warm compiled artifacts, and host-side tools
  (rust toolchain, `cargo-audit` advisory DB) are warm. The **container side
  is disposable and cold per run**: every `linux_dispatch` / fixtures run
  starts a fresh `--rm` container with an empty `CARGO_HOME=/cargo-home`, so
  the crates.io index and crate downloads are re-fetched each run (the runs'
  own logs show "Updating crates.io index / Downloading crates"). "Warm
  target, fresh container registry" is therefore the accurate cache
  description; no figure below claims a warm in-container registry.
- Concurrency: **serial** — one cargo/verify invocation at a time (parallel
  cargo on one target dir contends on the build lock and is not a valid
  timing picture).
- Date: 2026-10-12 (single host session; see `qa-package/validate.sh` for the
  per-run identity record).
- Candidate: source `HEAD 579b9ce13154e4ed431769835cb51ac4ff32c9a8` with only
  harness/docs/package files differing from the clean tree (no Rust source
  changed). Three distinct intended native Linux variants (scopes in
  `qa-package/README.md`): exercised smoke artifact
  `target/fixture-facts/release/alumina` sha
  `787364fe…d565` (this wrapper builds + executes it); MID production release
  `target/release/alumina` sha `e18eb535…469b` (built + static-checked);
  e2e musl release `target/aarch64-unknown-linux-musl/release/alumina` sha
  `7b769b9a…e224` (executed under ucxi receipts, reused in exact scope).

## Measured timings by tier

| Tier / gate | Scope exercised | Measured wall (serial; warm target + host caches, fresh container registry) |
|---|---|---|
| INNER `cargo +1.99.0 atest -p alumina --locked` | unit corpus 263 + `tests/boot.rs` 32 + `tests/eligibility.rs` 5 + `tests/foundations.rs` 6 + `tests/stdout_stall.rs` 1 + `main_thread_stack` + doctests | unit phase 12.55 s (cargo-reported); full invocation incl. build completed within a 120 s observation window (exact wall not separately captured), exit 0 |
| INNER `cargo +1.99.0 atest -p alumina --locked --features alloc-witness` | alloc-witness variant: `tests/mio_matrix.rs` module-gated on `feature=alloc-witness` (`:1`); three tests are cross-platform (`boot_allocations_are_attributed_and_excluded` `:42`, `events_drop_negative_control_catches_heap_free` `:76`, `kernel_fd_close_is_not_heap_dealloc` `:89`) and the Linux epoll operation matrix is `#[cfg(target_os = "linux")]` (`:104-106`, epoll unavailable on Darwin) | 43.8 s host, exit 0 — host executes **3** cross-platform matrix tests; native Linux executes **8/8** (ucxi receipts record HOST-ALLOC=3 / NATIVE=8, exact candidate, reused not re-run). The plain (no-feature) run executes **0** matrix tests — the module is feature-gated off, not a feature-run result |
| INNER `cargo +1.99.0 fmt --check` / `aclippy -p alumina --locked --all-targets -- -D warnings` | formatting; clippy with `-D warnings` | 0.5 s / 0.7 s, exit 0 |
| MID Linux `verify.sh mid foundations` + `mid boot` (via `linux_dispatch`) | static ELF + whitespace + witness tests, FOUNDATIONS-MID-OK / BOOT-MID-OK | 5.4 s combined wall (includes fresh-container index/crate downloads on the local VM; release build hit target cache — "Finished … 0.17 s"), exit 0 |
| MID/harness `verify.sh fixtures boot` (supervised typed-terminated positive + exit-78 negatives) | startup-serving / typed-terminated + cleanup + privileges + stderr byte-exact kernel-facts + `security.capability` absence | 14.4 s (first clean) / 13.8–13.3 s (four-step runs), exit 0 |
| MID docs `verify.sh docs` | offline AST/literal docs-link check (`scripts/docs_check/check.mjs`) over `alumina.md` + docs set | exit 0 (`DOCSLINK-CHECK-OK`) |
| MID/BOUNDARY host `cargo +1.99.0 deny check` + `cargo +1.99.0 audit` | advisories/bans/licenses/sources + 28 locked deps | deny 6.3 s / audit 4.3 s, exit 0 (warm advisory DB) |
| BOUNDARY e2e `e2e relay` + `e2e shutdown` (native Linux container drives) | DNS-over-TCP responder, raw-echo/TLS/counting upstream fixtures, byte-exact + upstream-effect + distinct-timeout; SIGTERM grace + drain | **reused** from bead `alumina-ucxi` exact-source `579b9ce` receipts — not re-run this session per contract; timing in those receipts, not re-measured here |

## Coverage by dimension

| Dimension | Where exercised (exact gates above) | Status / gap |
|---|---|---|
| Canonical protocol | Real TCP/TLS clients + raw-echo/counting upstream fixtures in `e2e relay` (reused ucxi receipts); DNS wire categories in unit corpus | CONNECT/SNI positive + plaintext-close covered; **open, not covered:** HRR handling, fatal-alert handling, and the deterministic gate-transition campaigns (canonical §6; build-plan 50–52, 141–142) remain unfilled |
| DNS | Wire parse categories (unit corpus); startup DNS TIDs; refresh driver due-initiation/retry/backoff **reused** from ucxi native receipts at the same candidate — not re-exercised by this package wrapper | **F4 DNS-wire fuzz campaign not shipped** (`src/fuzz.rs` scaffold only — no campaign receipts) |
| Gates (INNER/MID/BOUNDARY) | All rows above exit-0 with identity receipts | MID + fixtures + docs + deny/audit native hard-0 this session; full BOUNDARY remains BLOCKED and `RELEASE-NOT-READY` (diagnostic stays open, never converted to release clean) |
| Deadlines | Startup window + supervised bounded child wait (10 s) + SIGTERM grace `e2e shutdown` drain; startup unresolved → EX_TEMPFAIL 75 | Covered; no inferred universal deadline |
| Resources | `alloc-witness` zero-heap on foundations/boot/startup-DNS; 8 MiB main-thread accept/reset stack run; 128 MiB traffic store + serving workspaces | Partially covered; **product-wide alloc claim and serving/refresh completeness witness remain open** (build-plan §0 / F3 current-serving) |
| Error / Unknown separation | Typed error split (Unknown/error distinct); e2e distinct-timeout assertions; fixture negatives exit-78 distinct from positive; fixture probe **error distinct from no-match** (see below) | Covered; error-is-not-negative discipline retained |
| Confinement | `fixtures boot` privilege profile (uid 65534, no_new_privs, empty caps via setpriv), `security.capability` absence via `fixture_metadata_probe.py` | Covered locally; deployment/production confinement is a separate (open) gate |
| Script fidelity | Repo-native drivers only (`scripts/e2e_relay.py`, `check.mjs`, `fixture_metadata_probe.py`, `cargo_config_probe.py`); exact-source probes | Covered; no rewritten/forged scripts |

## Fault / false-clean analysis

- **Guard-bite re-run against the ACTUAL changed enforcement (four-step,
  raw exits, 2026-10-12).** Re-proving surfaced a real bug: the first helper
  incarnation captured `$?` with a bare `grep …; rc=$?`, which the script's
  `set -eu` silently kills on the first nonzero grep — and for
  `not_contains`, nonzero (no-match) is the REQUIRED outcome, so the negative
  probe died without a marker instead of asserting absence. Fixed with an
  if/else guard that preserves rc under `set -e`. Then, on the corrected
  enforcement:
  1. clean baseline `fixtures boot` — exit **0** (`BOOT-FIXTURES-RAN`);
  2. plant: asserted supervisor-receipt fragment changed to
     `…reaped child rc=99` (never emitted) — exit **1**,
     `FIXTURE positive FAIL: stdout lacks fixed-string fragment:
     FIXTURE-POSITIVE-SUPERVISED: reaped child rc=99`;
  3. revert;
  4. clean `fixtures boot` — exit **0**.
  Raw logs: `.ooda/tmp_fs1.log` (baseline), `.ooda/tmp_fs2.log` (plant),
  `.ooda/tmp_fs4.log` (clean).
- **Probe-error vs no-match (B1 surface now distinct).**
  `fixture_require_stdout_contains` passes only on a match (0), treats a probe
  error (2) as `ERROR … unverifiable`, and a missing fragment as `FAIL`.
  `fixture_require_stdout_not_contains` returns 0 only on the documented
  no-match exit (1); a match (0) is `FAIL` and a probe error (≥2) is
  `ERROR … absence not established`. Absence is never inferred from a failed
  probe stream; the not_contains path is exercised green by the real fixture
  (the obsolete banner is absent), and the contains path is exercised by both
  green (fragments present) and the planted red above.
- **Supervisor receipt is now an asserted predicate.** The positive now
  requires the exact fixed-string
  `FIXTURE-POSITIVE-SUPERVISED: reaped child rc=0` on stdout (in addition to
  the typed `startup_final status="terminated"` / `shutdown_final
  status="drained"` records). The earlier malformed-receipt era (a truncated
  payload that printed a malformed receipt) still reached `BOOT-FIXTURES-RAN`
  because no predicate claimed that line; the planted-red above shows a
  missing/mismatched receipt now fails the gate.
- **DNS false-clean elimination**: the fixture environment sets `resolv.conf`
  to loopback `nameserver 127.0.0.1`, whose connect outcome is deterministic,
  replacing the unreachable external `1.1.1.1` whose refusals silently pushed
  the 90 s window to failure (exit 75 / `startup_final status="failure"`).
- **Quoting defect (found and fixed by evidence)**: the fixture payload uses
  only double-quoted formats inside the outer `sh -c '…'`, because a single
  quote would truncate the payload and drop `exit "$rc"` (silent false-green).
  The corrected payload's receipt is line above.
- Fuzz/limits reproducibility: no campaign receipts exist yet, so **no
  fuzz-based reproducibility claim is made** (F4 scaffold only).

## Prioritized improvements (fleet priorities order: maintainability →
correctness → response → energy → features)

1. **F3 current-serving completeness witness** (correctness): the mio
   operation matrix is implemented (`tests/mio_matrix.rs`); complete the
   current-serving/SIGTERM op-set witness and close cnrd T3. Now that the
   fixtures positive is honest, this is the highest-value correctness close.
2. **F4 DNS-wire/log-record fuzz campaign + receipts** (correctness/fuzz):
   reuse the `src/fuzz.rs` corpus ownership with generated inputs; record
   campaign receipts per run for reproducibility.
3. **Open protocol vectors** (correctness): HRR / fatal-alert handling and the
   deterministic gate-transition campaigns (build-plan 50–52, 141–142) are
   unfilled; they are the harness's biggest honest coverage gap on serving.
4. **Cold- vs fresh- baseline** (honest speed data, iteration-speed rule):
   separate "warm target" from "cold target with warm cached registry" and
   record both once, so future planning does not lean on a single cache
   picture (same host, date recorded).
5. **Low value, deferred**: trimming the ~14 s `fixtures boot` wall time
   (container staging + fresh registry dominates) is not worth a refactor
   until a measured need appears; keep as-is per feature/energy ordering.

## Honest limits of this evaluation

- BOUNDARY e2e relay/shutdown timings and the native alloc-witness/matrix
  numbers are **reused** from ucxi receipts for the exact same candidate; not
  re-run here, so no new host-timing claim is made there.
- Timings are single-host, serial, warm-target/fresh-container-registry, dated
  2026-10-12; they are a point measurement, not an aggregate benchmark.
- Coverage rows are gate-scoped at an exact candidate identity; nothing here
  claims production qualification or external validation (four-claim ledger).
