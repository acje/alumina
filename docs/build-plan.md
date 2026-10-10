# Alumina — Build Plan (phased vertical slices)

**Status:** planning document. This plan defines *what a future implementation will build and prove, in what order*; it starts **no** implementation. Architecture and ownership: [architecture.md](architecture.md). Complete traceability: [traceability.md](traceability.md). Canonical requirements: `alumina.md` (sole governing specification; no ADRs exist).

Mission scope bounds (verbatim intent): produce planning documents only; do **not** implement, install dependencies, build graphs, commit, push, or sync. This document is the executable-shaped plan that later, separately commissioned build missions will follow.

## 0. Sequencing status — provisional product-first parser layer

This plan's gate-first ordering (§2) remains the owner of **qualification and
release**. A subset of the protocol-serving parser layer was nonetheless
implemented **first**, as provisional product-first increments commissioned
separately from this document (mission `alumina-26l1`, repair directive
`alumina-26l1.1`, repair directive `alumina-26l1.2` for the fixed-storage DNS
parse path, reviewer-approved `alumina-ozm8`). This section records that
re-sequencing so the two cannot be read as the same claim:

- **Implemented (provisional, instrument-free):** DNS response classification
  (`dns.rs`), CONNECT request-head parsing (`connect.rs`), TLS 1.3 ClientHello
  inspection/framing (`client_hello.rs`), and the shared normalized hostname
  type (`config.rs` `FixedHostname`). All use fixed-capacity storage (no
  serving-path allocation), carry focused falsifier/positive tests per
  repaired defect, and pass single-crate INNER gates on the macOS host only
  (`cargo +1.99.0 atest -p alumina --locked`, `fmt --check`, `aclippy -D
  warnings`). The DNS parse path (`dns.rs`) additionally carries
  feature-gated `alloc-witness` zero-heap controls for positive and negative
  background-refresh-phase classification (`cargo atest --features alloc-witness`).
- **"Provisional" is precise:** none has passed the qualification gates this
  plan names. These are correct-by-construction inputs to later slices, **not**
  servable functionality.
- **Deferred (required before any resource-treated serving claim):** F0 Linux
  proof, F1 allocator witnesses on the remaining serving phases (the
  background-refresh-phase DNS parse now carries `alloc-witness` zero-heap
  controls; connect/TLS serving witnesses and a product-wide claim remain
  open), F2 deterministic fault injection of gate transitions, F3 mio operation
  matrix, F4 parser fuzzing, Linux MID/BOUNDARY, E2E deployment/confinement.
  `getrandom` dependency intake is complete (bead `alumina-zjwk`; `build.rs`
  source-reviewed benign; `cargo deny` advisories and `cargo audit` clean), and
  the startup-DNS transport TIDs it blocked now exist as a provisional draft
  (`src/startup_dns.rs`) with focused actual-DNS runtime tests, a counted
  per-exchange network failure separated by type from fatal
  storage/entropy/lifecycle/token-exhaustion errors, uniform schedule backoff
  advancement on every counted failure, and an `alloc-witness`
  allocation-free-including-reconnect witness, verified on the macOS host and
  on native Linux arm64 via the pinned builder image (release +
  `--features alloc-witness`: `tests/mio_matrix.rs` 8/8, startup-DNS unit set
  12/12). A second review round (bead `alumina-4z6b`, NEEDS WORK) was answered
  with the typed split, falsifiers F1/F2, Entropy variant, and lifecycle reset
  fix (evidence bead `alumina-e5ip`); transport review completion is pending.
  The serving integration and full qualification gates remain deferred. No
  product-wide zero-alloc claim is made from the focused parser tests alone.

## 1. Guiding principles

1. **Invariant-led ordering (H1 selected).** Milestones are organized around the invariants in [architecture.md §1](architecture.md#1-governing-invariants-invariant-led-design); resource/feasibility uncertainty is pushed to **early gates**, not allowed to drive requirement ordering.
2. **Every claim is proof-gated.** A design artifact is distinct from an implementation demonstration; never label a proof gap resolved because its intended design is written down (mirrors `alumina.md:230,236`).
3. **Vertical slices.** Each slice delivers a thin working vertical (accept → verify → acceptable evidence) rather than a horizontal layer; slice decomposition follows risk, uncertainty, coupling and independently verifiable increments, each slice remaining a bounded sub-mission. No wall-clock duration is asserted by this planning document: execution budgets are set locally per mission at execution time, not declared as a fleet-wide milestone mandate.
4. **Three-tier verification cadence (fleet canonical).** INNER = changed crate/file only; MID = changed crate + mechanically-derived reverse-dependent closure; BOUNDARY = repository stable candidate once, repo-native owner. Each slice names its tier gate spellings.
5. **No Tokio, no async runtime.** mio + epoll single-worker per `alumina.md:140,147`; apply fleet Rust/Tokio resource contracts (as they apply to a non-Tokio worker) and `rust-dep-intake` for every dependency.

## 2. Early Linux feasibility and dependency-intake gates (before feature slices)

These gates retire the risks that feasibility-led planning would otherwise pull to the front (H2). They run on Linux (spec target); **no Linux behavior is claimed from this macOS host**.

**Gate F0 — Toolchain + build harness pin (Linux).**
- Pin exact Rust toolchain (rust-toolchain.toml) and `mio` version; commit `Cargo.lock`.
- Acceptance: choose and pin **the exact supported static-Linux toolchain** (a release chosen against the minimal-container static-linking requirement) and **prove that selection on Linux**: static binary links, `panic = "abort"`, and that toolchain is the one CI and every verification tier uses. Any `-Z build-std`-style flag is adopted only after that exact pinned toolchain demonstrates the minimal-container link (deferred, not assumed). No toolchain inference from other repositories (this is a planning document; no version is claimed).
  INNER: `cargo +<pin> build --locked`, `cargo +<pin> atest -p <harness-crate> --locked`, `cargo +<pin> fmt --check`, `cargo +<pin> aclippy -p <harness-crate> -- -D warnings`; MID: `cargo +<pin> atest --locked` on the reverse-dependent closure; BOUNDARY: the **complete** repository stable-candidate gate per §5 — supply-chain (deny/audit) and `git diff --check` results come from that single owner run, never a local partial list. The bootstrap binds the exact pins, selectors, features and command spellings for every verification tier — build, test, fmt, clippy, deny/audit, F1/F2 allocator/fault-injection, F4 parser fuzzing, E2E — so no later slice invents new selectors.
- **Dependency intake (F0a):** every new dependency (incl. `mio`, `getrandom`) runs `rust-dep-intake` triage; source review of `build.rs`/proc-macros/build-deps; pin exact versions; `cargo deny` + `cargo audit` green before adoption.

**Gate F1 — Allocator instrumentation + zero-alloc witness harness.**
- A test-only global allocator counts alloc/dealloc per instrumented phase (startup-DNS, serving, background-refresh, logging, shutdown) exactly as `alumina.md:230` requires.
- Acceptance (hard gate): **no heap allocation or deallocation** in the *named* phases once they exist; otherwise the phase's done-claim decays to INNER-red. This instrumentation scaffold is built in Slice 1 and reused by every later slice.
- Reports process and kernel memory separately from the 128 MiB traffic budget.

**Gate F2 — Deterministic fault-injection seam.**
- A **deterministic** I/O harness (scripted outcomes on a wrapper around the socket layer: partial reads/writes, `WouldBlock`, combined readable+writable readiness, readiness-without-data, injected data/EOF/reset at named points, timer expiry at controlled times) — not randomized fuzzing. It pins the dispatcher's gate transitions, satisfying `alumina.md:226-227` determinism requirement.
- Acceptance: the seam can reproduce the q28 gate stress-test schedule (below) under a chosen outcome script; evidence recorded as exact-input (script hash + build + machine).

**Gate F3 — mio operation matrix (T2/G4).** Pin the enumerated `mio` operations used (Poll construction, registration/reregistration/deregistration, Events batch retrieval, error/close paths); source-review the pinned version; allocator-instrument the steady-state loop (rejecting both allocation and deallocation). Result: documented operation matrix + per-op alloc witness, else the slice that needs the unproven op is **blocked** rather than assumed.

**Gate F4 — Parser-fuzzing acceptance (deterministic, separate from F2).** A distinct stage owns a checked-in fuzz corpus, the generated inputs, and the evidence record for every run (deterministic seed + input hashes), covering every parser surface — CONNECT headers, ClientHello/TLS framing, DNS wire parsing, log-record encoding (`alumina.md:225` focused tests + parser fuzzing). Acceptance: corpus and input/evidence ownership recorded; each observed crash/hang/timeout resolved (minimized input hash retained) before the owning slice's done-claim. F4 varies inputs into parsers/bounds without a script; F2 varies *scripted* I/O outcomes into the dispatcher.

Precedence: **F0, F1, F2, F4 land in Slice 1 and the harness bootstrap precedes any feature-slice green claim** — no slice claims green before the instrumentation + fault-injection scaffolds are themselves green on an empty loop. **F3 is required before the first relevant DNS operation**: Slice 2 performs DNS TCP transport, so F3 (mio operation matrix + alloc witness) must complete before Slice 2's DNS operations — not merely before Slices 3+.

## 3. Phase plan (vertical slices)

Each slice: objective → acceptance criteria → verification witnesses → spec mapping (`alumina.md` section citations) → dependency on prior slices. Slice Verify lines name **INNER** and **MID** targeted witnesses (changed-crate tests, instrumented allocator/fault-injection witnesses, parser fuzzing), each green before that slice's MID done-claim. **BOUNDARY** is the single complete repository stable-candidate gate in §5, run once by the repo-native owner on the stable candidate; slices never enumerate a partial BOUNDARY list.

### Slice 1 — Bootstrap, harness, config + startup preflight (invariant foundations)
- **Objective:** crate skeleton with pinned toolchain (F0), allocator instrumentation (F1), fault-injection seam (F2), strict TOML config parse, listener/resolver-config parse, privilege prerequisite check; boot allocation inventory assertions.
- **Acceptance:** 4 KiB doc bound (reject oversized, no truncatin); all keys mandatory, no defaults, no coercion/DISCARD of invalid entries; empty allowlist + missing/incorrect allowance ⇒ EX_CONFIG 78 with the naming diagnostic; root/nonempty-caps/no-`no_new_privs` ⇒ prerequisite failure; boot alloc inventory sums and matches §6 sizes; energy/efficiency: no redundant re-reads, parse in one pass.
- **Verify:** INNER `cargo +pin atest -p <crate> --locked` targeted; MID reverse-dependent closure green; BOUNDARY: complete repository stable-candidate gate per §5 (no partial list asserted at slice level).
- **Spec:** config `alumina.md:54,56,58,60`; bounds `alumina.md:152-185`; prerequisites/boot `alumina.md:150,142-143`; startup order `alumina.md:64`; mapping rows in `traceability.md` §2.
- **Dependency:** none external — this slice *builds* the F0/F1/F2 scaffolds. Per §2 bootstrap precedence, Slice 1 closes its feature done-claim only after those scaffolds are green on an empty loop, and no later slice claims green before them. F0 binds the toolchain/build pins and the exact verification-tier command spellings (§2, §5) at this point.

### Slice 2 — Cache + DNS classification core (ownership/generation foundations)
- **Objective:** wired `resolver`/`dns_parse`/`cache` with one TCP conn + one outstanding query, getrandom TIDs, staging-then-publish cache with generation advance, TTL/fresh/stale/retired deadlines, retirement-before-every-attempt, negative classification (NXDOMAIN name-wide, NODATA per-type, covering SOA rule), provenance + eligibility (`alumina.md:71,73`), exact section-count parsing, bounded CNAME ≤8/loop rejection, DNAME failure.
- **Acceptance:** boundary vectors for every eligibility range (`alumina.md:73`) incl. `64:ff9b::a9fe:a9fe`, `::ffff:10.0.0.1`, `::10.0.0.1`, `2002:a9fe:a9fe::1`, a Teredo-private address — all rejected, neighbors accepted; TTL refresh bounds at 1/29/30/31/299/300/301 s and TTL 0→1 s; NXDOMAIN/NODATA with AA clear and set; obsolete-result isolation across generation advance; retirement admission immediately before/at/after, incl. delayed timer processing.
- **Verify:** INNER targeted unit tests on parse/cache; **Gate F4 parser fuzzing (corpus/inputs/evidence) on the DNS wire parser**; INNER instrumented allocator witness for *background refresh* phase (no allocation or deallocation), green before this slice's MID done-claim; MID reverse-dependent closure green; fault-injection: scripted malformed/mismatched/truncated/oversized responses, timeout, SERVFAIL.
- **Spec:** `alumina.md:68-98`; cache/refresh/backoff `alumina.md:74-82`; reporting `alumina.md:79-81`; verification `alumina.md:225,228-229`.
- **Dependency:** Slice 1 (F0–F2, F4 green) and **Gate F3 (mio op matrix + alloc witness) complete before DNS transport operations**.

### Slice 3 — Tunnel setup: CONNECT + address selection + status codes
- **Objective:** authoritative incremental CONNECT parsing (8 KiB), one-request-per-connection, status-code matrix, per-family attempt counts (no cache addresses retained), ≤4 attempts × 2 s clipped to 10 s setup, IPv4-then-family-alternation rule, fixed selected peer, revalidation before each attempt.
- **Acceptance:** 400/403/502/503/504 semantics per `alumina.md:43`; attempts cycle per `alumina.md:82` family rule; replacement between attempts applies at next attempt; each family stops at current address count; exhaustion → 503; rejected-slot path explicit (bounded handling outside occupied slots, `alumina.md:177,193`; capacity is **128 total incl. ≤32 pending setups**, never 160 slots — preflight).
- **Verify:** INNER setup-state tests; MID reverse-dependent closure green; fault-injection: connect-timeout/success/partial at each deadline boundary (immediate-before/at/after, `alumina.md:189,226`).
- **Spec:** CONNECT `alumina.md:36-43`; attempts `alumina.md:82,170`; capacity `alumina.md:160,177,183,193`; verification `alumina.md:227`.
- **Dependency:** Slices 1–2.

### Slice 4 — ClientHello validation + forwarding gate (security core)
- **Objective:** TLS 1.3-only profile checks (`alumina.md:47-50`), ECH rejection incl. ECH-GREASE, SNI exact-one + normalized-equal to approved hostname, incremental ≤64 KiB incl. framing with separate parse limits, preserve original bytes for forwarding, release at gate open; D3 gate-opening transition on successful-write accounting; Barrier A and Barrier B both enforced; early-activity termination.
- **Acceptance (each is fault-injected, `alumina.md:226`):** data / EOF / reset observed **while gate closed**, after 200, between ClientHello fragments, after validation, during partial upstream writes → terminate setup, metadata-only warn; both barriers; `WouldBlock`, spurious and combined readable/writable readiness; **gate opens before the next upstream read** when successful write accounting crosses H; fast responses first observed after opening are **not** rejected as early activity; coalesced trailing bytes `X` preserved in-order; deadline at/after expiry cannot open the gate even with delayed timers. Interop: real TLS 1.3 endpoints for ordinary handshakes, fragmentation, HelloRetryRequest, fatal alerts.
- **Verify:** INNER parser+gate tests; INNER instrumented allocator witness for *serving* phase (no allocation or deallocation), green before this slice's MID done-claim; MID reverse-dependent closure green; **Gate F4 parser fuzzing on ClientHello/TLS framing**; q28 stress-test schedule reproduced via F2 script hash (including the corrected D4 reading: pre-open upstream reads permitted; only data/EOF/reset terminate).
- **Spec:** ClientHello `alumina.md:45-50`; gate `alumina.md:32,201,226`; byte-conservation `alumina.md:220`; lifecycle `alumina.md:189-190`.
- **Dependency:** Slices 1–3 (F2 seam critical).

### Slice 5 — Relay, closure, lifecycle, shutdown
- **Objective:** relay with backpressure, idle deadline (start at gate open, reset only on successful writes, not reads/readiness), first-EOF drain flow (5 s drain, one direction drains, reverse continues, close at both-EOF or deadline), resource release exactly once; SIGTERM shutdown (stop accepting, 8 s grace, drain, close, **exit without deallocating**; second SIGTERM no extension).
- **Acceptance:** deadline start/end/reset immediately before/at/after incl. delayed handling and overlapping deadlines (`alumina.md:227`); second EOF/SIGTERM without extension; normal drain vs deadline-forced closure with buffered bytes remaining; no double-release.
- **Verify:** INNER relay/lifecycle tests; INNER instrumented allocator witness for shutdown phase, green before this slice's MID done-claim; MID reverse-dependent closure green.
- **Spec:** lifecycle `alumina.md:187-194`; deadlines `alumina.md:181,189-192,221,227`.
- **Dependency:** Slices 3–4.

### Slice 6 — Capacity, logging, resource-profile proof
- **Objective:** capacity behavior (503 never evicts established tunnels; error entry when tunnel-slot/pending-setup/log-queue usage first exceeds 80% and again when it falls below 70%; one warn per rejection), logging queue boundaries (256×8 KiB, whole-record drop + count, no truncation, escaped text, allocation-free format/enqueue, nonblocking sink with partial-write preservation), full cross-phase allocation/deallocation witness.
- **Acceptance:** threshold transitions; worst-case final startup result fits encoded-entry limit incl. framing; stalled sink does not delay tunnel/DNS/deadline progress; allocator witness green for **startup-DNS + serving + background-refresh + logging + shutdown**; process vs kernel memory reported separately (`alumina.md:230`).
- **Verify:** INNER logging/capacity unit tests; INNER cross-phase allocator witnesses (startup-DNS, serving, background-refresh, logging, shutdown), green before this slice's MID done-claim; MID reverse-dependent closure green.
- **Spec:** logging `alumina.md:178-179,193-194,231`; capacity `alumina.md:160,177,193`; resource `alumina.md:152-185,230`.
- **Dependency:** all prior slices.

### Slice 7 — Release gates + deployment readiness
- **Security release gates (blocking, pre-merge):** deployment confinement demonstration (`alumina.md:233`): approved calls succeed through the private endpoint, unapproved CONNECT hosts rejected, direct approved/unapproved address paths denied from the app runtime incl. IPv4/IPv6/alternate ports/UDP/QUIC/private routes/provider paths/alternate proxies, proxy-ignoring clients get no direct egress, workload cannot alter proxy/confinement, unauthorized sources cannot reach the listener, clients retain upstream cert verification, repeat on networking/client-lib/dependency change. Runtime-surface/prerequisite checks (`alumina.md:235`): fail as root / nonempty caps / missing `no_new_privs`; one listening socket; SIGTERM bounded; image contains only specified files.
- **Performance release gates (`alumina.md:236`, conditional):** measure aggregate forwarded payload bytes once; benchmark 1–10 Gbps bursts where CPU/network permit, reporting burst duration, concurrency, payload sizes, CPU, queueing, sustained throughput separately; slow-peer backpressure; DNS + deadline progress under load. The 10 Gbps end requires a deployment whose ceiling permits it; initial Cloud Run Direct VPC target is **≤1 Gbps/instance** (`alumina.md:136`).
- **Initial deployment (`alumina.md:234`):** TCP DNS resolution + end-to-end CONNECT ingress on the selected Cloud Run worker pool; qualify complete direct/CNAME/negative responses for the actual allowlist; measure network startup delay against the fixed 90 s budget; operator-owned CONNECT + authenticated TLS check; compatibility failure ⇒ explicit revision, never automatic fallback.
- **Verify:** INNER release-gate targeted checks for any changed slice crate; MID reverse-dependent closure green; BOUNDARY = repo-native release-checklist owner runs the full stable-candidate gate list on the Linux stable candidate; E2E deployment checks execute and exit 0 (fleet R12).
- **Dependency:** Slice 6 stable candidate.

## 4. Deterministic fault injection — required script boundaries

The F2 harness must be able to script each of the following; each is an acceptance checkpoint named in the matching slice:

1. Gate closed + injected upstream **data / EOF / reset** at: after 200-begin, between ClientHello fragments, after validation, during partial upstream writes (Slice 4).
2. Partial successful writes: H/2 then `WouldBlock`; crossing H with coalesced `X`; gate opens in the same transition (Slice 4).
3. Combined readable+writable readiness with no data (readiness ≠ success), spurious readiness (Slice 4/5).
4. Connect attempts: timeout at exactly 2 s, success at deadline edge, clipped to setup deadline; at-most-4 attempts (Slice 3).
5. Timer expiry immediate-before/at/after for idle, drain, setup, shutdown, DNS exchange; delayed timer delivery; overlapping deadlines (Slices 2/5).
6. Malformed/mismatched/truncated/oversized DNS responses; timeout then service of another due entry; repeated failures across full allowlist; no starvation/duplicate pending work (Slice 2).
7. Log sink stalled mid-partial-write while tunnel/DNS/deadline continue (Slice 6).

## 5. Verification tier policy per slice

- **INNER** — changed crate/module + its direct tests. Never `--workspace`/`--all-features`. Form: `cargo +<pin> build --locked`; `cargo +<pin> atest -p <slice-crate> --locked <targets>`; `cargo +<pin> fmt --check`; `cargo +<pin> aclippy -p <slice-crate> -- -D warnings`; `git diff --check` exit 0 on every increment. Every slice's Verify line names its INNER witness.
- **MID** — changed crate **plus its mechanically-derived reverse-dependent closure** (one-liner per repo AGENTS.md once a Cargo workspace exists); runs once per sub-mission before that sub-mission's done-claim and is named in every slice's Verify line.
- **BOUNDARY** — the **full repository stable-candidate** gate, distinct from the per-slice INNER/MID witnesses, executed once by the repo-native owner (a `scripts/verify.sh` dedicated to the Linux release checklist). Complete — not merely deny/audit/diff: full build + test + fmt + clippy on the stable candidate; `cargo deny`/`cargo audit`; parser-fuzz status (F4) and allocator/fault-injection witnesses for all named phases; `git diff --check`; `git status --short` + `git rev-parse HEAD` scope checks; local doc link/fragment validation; document-only candidate review against all 236 spec lines (this planning cycle). E2E (deployment confinement, initial deployment) run and exit 0 before a release candidate done-claim (fleet R12).
- **Placeholder binding:** the `+<pin>`, `<harness-crate>`, `<slice-crate>` and `<targets>` placeholders above are resolved at the F0 bootstrap (Slice 1, §2) into exact toolchain pins, feature selections and `--locked` command spellings; no later slice invents selectors or features.
- **Allocator/instrumented proofs and fault-injection scripts are exact-input:** record build, workload, concurrency, machine, date, script hash, exclusions in the evidence bead.

## 6. Security and performance release gates — summary

| Gate type | Blocking conditions | Spec citation |
|---|---|---|
| Security: dependency intake | un-pinned or un-reviewed dependency; `mio` op outside the F3 matrix; any build.rs/proc-macro unread | `alumina.md:206,230` |
| Security: forwarding gate | any early-activity path that forwards/logs upstream bytes; readiness mistaken for success | `alumina.md:201,226` |
| Security: runtime surface | any control/health/metrics/reconfig surface; config reload; second SIGTERM extension | `alumina.md:149,192,235` |
| Resource: allocation | any allocation **or deallocation** in a named post-boot phase (startup-DNS, serving, refresh, logging, shutdown) — neither direction may occur | `alumina.md:206,230` |
| Performance | 1–10 Gbps not measured + not reported per `alumina.md:236`; payload counted twice | `alumina.md:236` |
| Deployment | confinement checks not demonstrated; image contents deviate from the fixed set | `alumina.md:233-235` |

## 7. Explicit build non-goals and unresolved risks

- **Non-goals (build effort):** no Tokio/async runtime, no multi-thread data path, no UDP/QUIC/HTTP-2-to-proxy/transparent interception, no DNS-over-TLS/HTTPS, no control/metrics/readiness surface, no automatic fallback or compatibility negotiation (same set as [architecture.md §9](architecture.md#9-explicit-non-goals)).
- **Open risks (explicit, honest):**
  1. mio/transitive-dependency alloc-freedom not yet evidenced (F3 gate).
  2. Generation/window-id non-reuse proof outstanding (width/exhaustion artifact only).
  3. Gate-ordering online proof requires the F2 dispatcher once built; paper model only today.
  4. Stack bound derived, not measured.
  5. All Linux epoll/alloc/confinement/throughput claims unverified on macOS and unverified until Linux gates pass.
  6. Deployment-level obligations (resolver qualification, confinement, image) are external-release work, not internally provable by Alumina.

Each open risk is a future build follow-up; none is started by this planning mission. Bounded follow-up build tasks are recorded in bd, separately labelled, not started (per contract Risk note).
