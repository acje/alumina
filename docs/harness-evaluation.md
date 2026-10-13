# Alumina — harness fitness evaluation (measured, 2026-10-12)

Dated findings for the repository-native harness, measured at exact candidate
`579b9ce` on 2026-10-12 and **kept at HEAD `8934adb` for reference only** —
receipts are scoped to that exact input, not a fresh-run or a qualification
upgrade. Repo status: scoped testQA candidate (docs/qa-package/README.md;
AGENTS.md).

## Conditions (every measurement)

Host macOS darwin/arm64; podman 6.1.3; `flock-vm`/`flock-vm-root` over ssh at
`127.0.0.1:65343`; Linux target aarch64; pinned builder
`docker.io/library/rust@sha256:484dce…779a`; toolchain 1.99.0. Warm persistent
target + warm host tools/advisory DB; container side disposable and cold per
run. Concurrency serial; measured input = exact candidate source `579b9ce`
plus harness/docs/package deltas at that revision.

## Measured timings by tier (findings)

| Tier / gate | Scope exercised | Measured wall (serial; warm target/host caches, fresh registry) |
|---|---|---|
| INNER `atest -p alumina --locked` | unit corpus 263 + boot 32 + eligibility 5 + foundations 6 + stdout_stall 1 + main_thread_stack + doctests | unit phase 12.55 s (cargo-reported); full invocation within 120 s, exit 0 |
| INNER `atest … --features alloc-witness` | alloc-witness matrix: 3 cross-platform tests host; Linux epoll matrix 8/8 native | 43.8 s host, exit 0; plain run executes 0 matrix tests (feature-gated off) |
| INNER `fmt --check` / `aclippy -D warnings` | formatting; clippy | 0.5 s / 0.7 s, exit 0 |
| MID `verify.sh mid foundations` + `mid boot` | static ELF + whitespace + witness tests | 5.4 s combined (fresh registry; release hit target cache), exit 0 |
| MID `verify.sh fixtures boot` | supervised typed-terminated positive + exit-78 negatives + kernel facts + xattr absence | 14.4 s first / 13.3 s four-step, exit 0 |
| MID `verify.sh docs` | offline link gate (`check.mjs`) | exit 0 (`DOCSLINK-CHECK-OK`) |
| MID/BOUNDARY `deny check` + `audit` | advisories/bans/licenses + 28 locked deps | 6.3 s / 4.3 s, exit 0 (warm advisory DB) |
| BOUNDARY `e2e relay` + `e2e shutdown` | byte-exact + effect + distinct-timeout; SIGTERM grace + drain | **reused** from `alumina-ucxi` receipts — not re-run; timing in those receipts |

## Coverage gaps (dated)

- Protocol: CONNECT/SNI positive + plaintext-close covered; HRR/fatal-alert and
  F2 gate-transition campaigns unfilled.
- DNS: wire parse units and startup TIDs covered; F4 DNS-wire fuzz campaign not
  shipped (scaffold only).
- Resources: alloc-witness foundations/boot/startup-DNS covered; serving/refresh
  completeness witness open (F3).
- Confinement: `fixtures boot` privilege profile + xattr absence covered
  locally; deployment confinement separate/open.
- Error/Unknown separation and script fidelity (repo-native drivers only)
  covered.

## Evidence pointers

- Guard-bite four-step and probe-error vs no-match separation: documented in
  `scripts/verify.sh` source + bd fixtures evidence, not restated here.
- Native alloc-witness/matrix and e2e timings: reused from bd `alumina-ucxi`
  receipts at exact `579b9ce`; not re-run here.
- Open gaps and qualification owner: `docs/build-plan.md` §7 / README "Known
  limitations".

## Honest limits

Timings are single-host, serial, warm-target/fresh-container, dated
2026-10-12 — a point measurement, not an aggregate benchmark. Rows are
gate-scoped at the exact candidate and never claim production qualification
(docs/qa-package/README.md).
