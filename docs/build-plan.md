# Alumina — Build Plan (phased vertical slices)

**Status:** implementation + qualification owner — *what is built and proved,
in what order*, and the gates that own qualification/release. A large subset is
**implemented and correctness-tested**; the repository is a **scoped testQA-
ready candidate** (scoped status owner AGENTS.md;
[qa-package/README.md](qa-package/README.md)), **not** production-qualified or
externally deployed. Every gate not yet run remains open; this document does
not claim completion. Architecture: [architecture.md](architecture.md).
Traceability: [traceability.md](traceability.md). Canonical requirements:
`docs/alumina-proxy.md` (sole governing specification; no ADRs exist).

## 0. Sequencing status

This plan's gate-first ordering (§2) owns **qualification and release**.
Implemented so far: DNS classification, CONNECT parsing, TLS 1.3 ClientHello
inspection and normalized hostname — **provisional**, correct-by-construction
inputs to later slices, not qualified serving code. The startup-DNS transport
is reviewed and approved (bd `alumina-c14m`) and wired into `main`. Deferred
(required before any serving done-claim): F1 serving-phase witness, F2
fault-injection campaigns, F3 current-serving completeness witness (matrix
implemented, `tests/mio_matrix.rs`; witness open per `cnrd` T3), F4 fuzz
campaign receipts, **full stable-candidate BOUNDARY**, and E2E
deployment/release gates (Slice 7).

Exact-input Linux MID (`mid foundations`/`mid boot`) and `fixtures boot`
already passed **natively at recorded candidates** (`1538a1b`/`579b9ce`/HEAD;
receipts in README "Native proofs", docs/harness-evaluation.md and bd
`alumina-ucxi`) — scoped exact-candidate proofs, not fresh current-input
execution, and they do not cover the open BOUNDARY. No product-wide zero-alloc
claim from focused parser tests alone.

## 1. Guiding principles

1. Invariant-led ordering: milestones organized around architecture invariants;
   resource/feasibility uncertainty pushed to early gates.
2. Every claim is proof-gated: a design artifact ≠ an implementation
   demonstration; never label a proof gap resolved because the design is
   written down.

## 2. Early Linux feasibility and dependency gates

**F0 — Toolchain + build harness pin (Linux).** Pin exact Rust toolchain +
`mio`, commit `Cargo.lock`, prove static link on Linux (`panic = "abort"`),
bind all verification-tier spellings at bootstrap.
**F0a — Dependency intake.** Every dependency runs `rust-dep-intake`; source
review of `build.rs`/proc-macros/build-deps; pin; `cargo deny` + `cargo audit`
green before adoption.
**F1 — Allocator instrumentation.** Test-only global allocator counts
alloc/dealloc per instrumented phase; **hard gate: no heap alloc or dealloc in
the named phases**, else the phase's done-claim decays to INNER-red. Report
process/kernel memory separately from the 128 MiB traffic budget.
**F2 — Deterministic fault-injection seam.** Scripted I/O outcomes (partial
reads/writes, `WouldBlock`, combined readiness, readiness-without-data,
injected data/EOF/reset, controlled timer expiry) — not randomized; pins the
dispatcher's gate transitions (`docs/alumina-proxy.md:226-227`). Evidence exact-input
(script hash + build + machine).
**F3 — mio operation matrix.** Pin enumerated operations (Poll, reg/re-reg/
dereg, Events, error/close); source-review; allocator-instrument the
steady-state loop. Unproven op ⇒ the slice needing it is blocked.
**F4 — Parser fuzzing (deterministic, separate from F2).** Checked-in corpus +
generated inputs + deterministic seed + minimized crash-input hashes covering
CONNECT, ClientHello/TLS, DNS wire, log-record; crashes resolved before the
owning slice's done-claim.

Precedence: F0/F1/F2/F4 land in Slice 1 before any feature-slice green claim;
**F3 completes before Slice 2 DNS transport operations**.

## 3. Phase plan (vertical slices)

Each slice names INNER/MID witnesses; **BOUNDARY** is the single repository
stable-candidate gate (§5), never a partial slice-level list.

**Slice 1 — Bootstrap, harness, config + startup preflight (invariant
foundations).** Skeleton, F0/F1/F2 scaffolds, strict TOML + resolver-config
parse, privilege prerequisite check, boot allocation inventory.
*Verify:* INNER targeted; MID closure; BOUNDARY §5. *Spec:* `:54,56,58,60`,
`:152-185`, `:150,142-143`, `:64`. *Dep:* none external (builds the scaffolds).

**Slice 2 — Cache + DNS classification core.** One TCP conn/one query,
getrandom TIDs, staging-then-publish with generation advance, TTL/fresh/stale/
retired deadlines, retirement-before-every-attempt, negatives, provenance +
eligibility, bounded CNAME. *Verify:* INNER parse/cache; F4 DNS-wire fuzz;
INNER `alloc-witness` on background-refresh; MID; F2 malformed/timeout/SERVFAIL.
*Spec:* `:68-98`, `:74-82`, `:79-81`, `:225,228-229`. *Dep:* Slice 1 + F3.

**Slice 3 — Tunnel setup: CONNECT + address selection + status codes.**
Incremental CONNECT (8 KiB), status-code matrix, per-family attempt counts,
≤4 × 2 s clipped to 10 s, IPv4-then-family alternation, fixed peer, revalidate
per attempt. *Verify:* INNER setup tests; MID; F2 connect timeout/success at
deadline edges. *Spec:* `:36-43`, `:82,170`, `:160,177,183,193`, `:227`.
*Dep:* Slices 1–2.

**Slice 4 — ClientHello validation + forwarding gate (security core).** TLS
1.3-only, ECH rejection incl. GREASE, SNI exact-one normalized-equal, ≤64 KiB
framing, D3 gate-open on write-accounting, both barriers, early-activity
termination. *Acceptance (fault-injected):* data/EOF/reset while closed, after
200, between fragments, during partial writes → terminate, metadata-only warn;
`WouldBlock`/combined readiness not activity; gate opens before next upstream
read at H; coalesced `X` in-order; deadline cannot open the gate; TLS 1.3
interop incl. fragmentation/HRR/fatal alerts. *Verify:* INNER parser+gate;
INNER `alloc-witness` serving phase; MID; F4 ClientHello fuzz; q28 schedule via
F2. *Spec:* `:45-50`, `:32,201,226`, `:220`, `:189-190`. *Dep:* Slices 1–3.

**Slice 5 — Relay, closure, lifecycle, shutdown.** Relay with backpressure;
idle deadline reset only on successful writes; first-EOF drain (5 s, one
direction, reverse continues); release exactly once; SIGTERM (stop accepting, 8
s, drain, exit-without-dealloc, no extension). *Verify:* INNER relay/lifecycle;
INNER `alloc-witness` shutdown; MID; deadline before/at/after + delayed/overlap.
*Spec:* `:187-194`, `:181,189-192,221,227`. *Dep:* Slices 3–4.

**Slice 6 — Capacity, logging, resource-profile proof.** Capacity (503 never
evicts; 80%/70% error thresholds; one warn per rejection); logging queue
(256×8 KiB, drop+count, allocation-free, nonblocking partial-write drain);
full cross-phase allocator witness (startup-DNS + serving + refresh + logging +
shutdown). *Verify:* INNER logging/capacity; INNER cross-phase witnesses before
MID done-claim; MID. *Spec:* `:178-179,193-194,231`, `:160,177,193`,
`:152-185,230`. *Dep:* all prior.

**Slice 7 — Release gates + deployment readiness**
- **Security release gates (blocking):** deployment confinement
  (`docs/alumina-proxy.md:233`): approved calls succeed, unapproved rejected, direct
  paths denied incl. IPv4/IPv6/alternate ports/UDP/QUIC/private/provider/
  alternate proxies, proxy-ignoring clients get no direct egress, workload
  cannot alter controls, unauthorized sources cannot reach the listener,
  clients retain cert verification, repeat on change. Runtime-surface checks
  (`:235`): prereqs fail closed, one listener, SIGTERM bounded, image contents.
- **Performance release gates (`:236`, conditional):** aggregate payload
  measured once; 1–10 Gbps bursts where CPU/network permit; slow-peer
  backpressure; DNS/deadline under load. 10 Gbps needs a fitting ceiling;
  Cloud Run Direct VPC target ≤1 Gbps/instance (`:136`).
- **Initial deployment (`:234`):** TCP DNS + end-to-end CONNECT ingress on the
  worker pool; qualify direct/CNAME/negative responses for the actual
  allowlist; measure startup delay vs 90 s; operator CONNECT + TLS check;
  compatibility failure ⇒ explicit revision.
- *Verify:* INNER release-gate checks; MID closure; BOUNDARY = full stable-
  candidate gate; E2E deployment checks execute and exit 0 (fleet R12).
- *Dep:* Slice 6 stable candidate.

## 4. Deterministic fault injection — required script boundaries

F2 must script each acceptance checkpoint: (1) gate-closed data/EOF/reset at
named points; (2) partial writes H/2 then `WouldBlock`, crossing H with `X`,
gate opens same transition; (3) combined/spurious readiness; (4) connect
attempts: 2 s timeout, deadline-edge success, clipped, ≤4; (5) timer expiry
before/at/after for idle/drain/setup/shutdown/DNS, delayed delivery,
overlapping; (6) malformed/mismatched/truncated/oversized DNS, timeout-serve,
no starvation/duplicate work; (7) log sink stalled mid-write while tunnel/DNS/
deadline continue.

## 5. Verification tier policy per slice

- **INNER** — changed crate/module + direct tests. Never `--workspace`/
  `--all-features`. Form: `cargo +<pin> build --locked`; `cargo +<pin> atest
  -p <slice-crate> --locked <targets>`; `fmt --check`; `aclippy … -D warnings`;
  `git diff --check` exit 0 on every increment.
- **MID** — changed crate **plus its mechanically-derived reverse-dependent
  closure** (single crate, no workspace → the closure is the `alumina` crate
  itself; if a workspace is later introduced, the closure one-liner is pinned
  at the F0 bootstrap). Named in every slice's Verify line.
- **BOUNDARY** — the full repository stable-candidate gate, run once by the
  repo-native owner (`scripts/verify.sh`): full build + test + fmt + clippy,
  deny/audit, F4/allocator/fault-injection witnesses, `git diff --check`,
  `git status --short` + `rev-parse HEAD` scope, local doc link/fragment
  validation, document review against all spec lines. E2E run and exit 0
  before a release done-claim.
- Placeholders (`+<pin>`, `<harness-crate>`, `<slice-crate>`, `<targets>`)
  resolve at the F0 bootstrap into exact spellings; no later slice invents
  selectors. Allocator/fault-injection evidence is exact-input (build,
  workload, concurrency, machine, date, script hash, exclusions).

## 6. Security and performance release gates — summary

| Gate type | Blocking conditions | Spec citation |
|---|---|---|
| Security: dependency intake | un-pinned/un-reviewed dep; mio op outside F3; unread build.rs/proc-macro | `docs/alumina-proxy.md:206,230` |
| Security: forwarding gate | any early-activity path forwarding/logging upstream bytes; readiness mistaken for success | `docs/alumina-proxy.md:201,226` |
| Security: runtime surface | control/health/metrics/reconfig surface; config reload; SIGTERM extension | `docs/alumina-proxy.md:149,192,235` |
| Resource: allocation | any alloc **or dealloc** in a named post-boot phase | `docs/alumina-proxy.md:206,230` |
| Performance | 1–10 Gbps unmeasured/unreported per `:236`; payload double-counted | `docs/alumina-proxy.md:236` |
| Deployment | confinement not demonstrated; image contents deviate from the fixed set | `docs/alumina-proxy.md:233-235` |

## 7. Explicit build non-goals and unresolved risks

- **Non-goals:** no Tokio/async runtime, multi-thread path, UDP/QUIC, HTTP/2
  CONNECT, transparent interception, DNS-over-TLS/HTTPS, control/metrics/
  readiness surface, automatic fallback (same set as architecture §9).
- **Open risks (explicit, honest):**
  1. mio/transitive alloc-freedom not yet evidenced (F3).
  2. Generation/window-id non-reuse proof outstanding (width/exhaustion
     artifact only).
  3. Gate-ordering online proof requires F2 fault-injection campaigns on the
     real dispatcher once run — the serving runtime is wired; the campaigns
     are not (Slice 4).
  4. Stack bound derived, not measured.
  5. Linux epoll/alloc/confinement/throughput claims unverified at runtime
     until the Linux gates pass.
  6. Deployment-level obligations (resolver qualification, confinement, image)
     are external-release work, not internally provable.

Bounded follow-up build tasks are recorded in bd, separately labelled, not
started.
