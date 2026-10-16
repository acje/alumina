# Alumina — Requirement / Resource / Verification Traceability Matrix

**Status:** traceability matrix — the single map from every specification
section, invariant, resource row, and verification requirement to its design
home ([architecture.md](architecture.md)), execution plan
([build-plan.md](build-plan.md)), and proof status. Canonical source:
`docs/alumina-proxy.md` (lines 1–315). The repository is a **scoped testQA-ready
candidate** at HEAD `8934adb` (scoped status owner AGENTS.md): an implemented and
correctness-tested subset carries local runtime evidence, while external
deployment validation and full production qualification remain open.

Status vocabulary: **designed** (named decision D1–Dn / architecture element);
**artifact** (number/identity chosen, not measured); **gate** (future proof
step named in a Slice); **verified-local** (implemented and demonstrated
locally with raw exit-0 evidence on an exact candidate — e.g. `verify.sh mid
foundations`/`mid boot`, `fixtures boot`, `e2e relay`, `e2e shutdown`, deny/
audit, docs — scoped to that exact candidate, never a production or deployment
claim); **external** (deployment/operator obligation); **out-of-scope**
(architecture §9 / build-plan §7).

## 1. Section matrix (all `docs/alumina-proxy.md` sections)

| Spec ref | Section / requirement | Design home | Proof status |
|---|---|---|---|
| L1–7 | Overview: forward proxy, HTTPS-over-TCP, FQDN allowlist, golden-path profile | arch §1/§9 | designed |
| L9–15 | Threat model: VPC compromise; egress restriction; accepted no-upstream-auth limitation | arch §9 | designed |
| L17–21 | Protocol: HTTPS-over-TCP only, fail-closed | arch §4 barriers | designed |
| L23–28 | Flow: CONNECT → authorize → connect → 200 → validate CH → relay → drain | arch §4 | designed |
| L30 | Response-begin vs complete; error policy; only complete 200 permits CH | D1 | designed |
| L32 | Gate opening on successful-write accounting, before next upstream read | D3 | designed → gate (Slice 4) |
| L34 | Incremental parsing, separate limits, absolute deadline, original bytes | §6; Slices 3/4 | designed → gate |
| L36–43 | CONNECT accept/reject matrix, one request, 400/403/502/503/504 | Slice 3 | designed → gate |
| L45–50 | TLS 1.3-only profile, ECH rejection, inspection scope | Slice 4 | designed → gate |
| L52–58 | Config: 4 KiB TOML, mandatory keys, allowlist, allowance, EX_CONFIG 78 | Slice 1 | designed → gate |
| L60–62 | Listener; A-label names; resolver selection (first NS, port 53, numeric unicast) | Slice 1 | designed |
| L63 | Resolution before listener; requests never trigger lookups | Slice 2 | verified-local (runtime.rs turn; ucxi) |
| L64–65 | 90 s startup deadline; usable-iff-eligible; allowance; EX_TEMPFAIL 75 | Slices 1/2 | designed → gate |
| L66–67 | Degraded serving startup-only; no readiness endpoint; startup diagnostics | Slices 1/6 | designed → gate |
| L68–70 | TCP DNS transport, 1 conn/1 query, getrandom TIDs, control-plane never CONNECT-eligible | Slice 2 | designed → gate |
| L71–73 | Provenance A/AAAA, CNAME ≤8 rooted, no DNAME/follow-ups; unicast table; per-attempt validate | Slice 2 | designed → gate |
| L74–82 | Cache lifetime, stale retirement, refresh scheduling, negatives, backoff, incidents, reporting bounds, per-family counters | Slice 2/3/6 | designed → gate; L76/L78 verified-local (579b9ce driver; ucxi) |
| L84–97 | Validate-then-classify; negatives; outcome table; empty≠NODATA; no fallback | Slice 2 | designed → gate |
| L99–136 | Deployment boundary; confinement; image; operator; DNS assumptions; Cloud Run Direct VPC ≤1 Gbps target | arch §8; Slice 7 | designed → external |
| L138–150 | Rust single worker; compile-time/storage bounds; ownership; publication; scheduling; mio+epoll; panic=abort; runtime surface; prereqs | arch §2/§3/§5/§6/§7 | designed; L147/L150 verified-local |
| L152–185 | Initial resource profile (full row matrix §3) | arch §6 | artifact |
| L187–194 | Lifecycle: setup/connect/idle deadlines, closure drain, shutdown, capacity/logging | arch §4/§7 | designed → gate; L192 verified-local (e2e shutdown; ucxi) |
| L196–221 | Invariants I–IV (13) | arch §1 | designed → gate (§2) |
| L223–236 | Verification requirements (12 categories) | build-plan Slices 1–7 | gate (§4); measured in docs/harness-evaluation.md |
| L238–263 | rp2e tripwire/action/monitoring/pacing amendment: trigger/action catalog & attribution (AnyIllegal/early-upstream/EOF-reset), Block/Flare semantics, Tarpit **deferred** | arch §2 (`enforcement`) | designed → gate; Tarpit deferred |
| L265–281 | Mandatory `[any_illegal]`/`[actions]` config schema: index-aligned arrays, force-mandatory group, Tarpit-deferred rejection, 4 KiB capacity | arch §2 (`enforcement`); `src/config.rs` | verified-local (rp2e config surface) |
| L283–303 | Bounded stdout monitoring (per-ordinal/global correlated aggregates, drop+count/saturate, no new sink) & planned fixed control-storage bounds (~9–10 KiB) | arch §2 (`enforcement`)/§6 | designed → artifact → gate |
| L305–315 | Honest implementation status table: amendment/config/enforcement/monitoring implemented; Tarpit deferred; no pacing storage reserved | arch §2 (`enforcement`) | verified-local (rp2e) |

## 2. Invariant matrix (all 13)

| Invariant | Cited | Upheld by | Status |
|---|---|---|---|
| I-1 Destination-Binding | L200 | cache-only addresses; per-attempt revalidation; fixed peer | designed → gate |
| I-2 Authorization-Before-Forwarding | L32/L201 | Barriers A+B; D3 gate transition | designed → gate |
| I-3 Fail-Closed | L202 | no permissive fallback; bounded stale only | designed |
| II-1 Zero-Allocation | L206 | boot inventory; allocator witnesses rejecting alloc **or dealloc**; mio matrix | artifact → gate |
| II-2 Resource-Bounds | L207 | fixed limits; exhaustion rejects | artifact |
| III-1 Ownership | L211 | single worker owns tunnel/DNS/timers/cache; shared-readiness Runtime | designed |
| III-2 Generation-Isolation | L212 | G1–G4; anti-alias gates | artifact → gate |
| III-3 Bounded-Work | L213 | per-turn budgets; reschedule-without-loss | verified-local (this candidate, review re-work): strict-≤256 accept recheck + op-per-attempt count pinned by host unit tests (`listener_yield_at_recheck_rearms_for_queued_clients_without_new_connects` re-arm-on-yield; `preloaded_hold_drains_across_budget_splits_with_quiescent_sink_relying_on_rearm` + `preloaded_hold_drains_across_budget_splits_byte_exact_with_consuming_sink` sink-direction budget-split isolation; `hot_relay_turns_compose_with_bounded_stalled_dns` 17-slot owner-turn with work high-water within [200,256] and per-turn DNS advances within the 8-step cooperative loop bound — the counter is an observability aid, the 8-step `cooperative_dns_turn` loop is the bound itself); criterion-3 native Linux held-peer read-direction isolation via `read_direction_held_peer_drains_across_budget_splits_without_new_edges` (96 KiB peer preload fully queued, silent peer, real run_once polls, roomy sink; `reschedule`-rearm noop falsifier RED `linux_dispatch` exit 101 then restored-source GREEN exit 0); e2e relay `POS-RETAINED-EDGE-SILENT` + `POS-NO-NEW-EDGE-RETAINED` as blackbox smoke only (kernel-receipt isolation is not claimed from e2e; it lives in the serving-seam unit tests above); verdict pending review relay after adversarial round-2 gap closure |
| IV-1 State-Transition | L217 | exhaustive enum; every outcome has a transition | designed → gate |
| IV-2 Stream-Parsing | L218 | incremental parsers with residual state | designed → gate |
| IV-3 Non-Decrypting | L219 | metadata validator + bit-pipe; no keys | designed |
| IV-4 Byte-Conservation | L220 | ordered prefix; coalesced preserved | designed → gate |
| IV-5 Deadline | L221 | monotonic; earliest-enforced; no renewal after expiry | designed → gate |

## 3. Resource-row matrix (all `docs/alumina-proxy.md:158-182`, notes 183–185)

| Resource | Limit | Design home | Status |
|---|---|---|---|
| Config / allowlist | 4 KiB / 1–32 | Slice 1 | artifact |
| Worker threads | 1 | §2 III-1 | designed |
| Concurrent tunnels (incl. setup) / pending | 512 / 128 | Slice 3 | artifact (not 640) |
| Traffic buffers per tunnel | 2 × 128 KiB | Slice 3/5 | artifact |
| Total traffic storage | 128 MiB (512×2×128 KiB) | §6 | artifact |
| CONNECT headers | 8 KiB | Slice 3 | artifact |
| Buffered TLS pre-auth | ≤64 KiB | Slice 4 | artifact |
| DNS message / total RRs | 16 KiB / 128 | Slice 2 | artifact |
| Address candidates per name | 16 A + 16 AAAA | Slice 2 | artifact |
| CNAME chain | ≤8 links | Slice 2 | artifact |
| DNS conns / outstanding queries | 1 / 1 | Slice 2 | designed |
| Setup / connect deadlines | 10 s / 2 s | Slice 3 | artifact |
| Upstream attempts per tunnel | ≤4 | Slice 3 | artifact |
| DNS exchange deadline | 2 s | Slice 2 | artifact |
| Refresh / SOA negative interval | 30–300 s | Slice 2 | artifact |
| DNS retry backoff | 1,2,4,8,16,30 s | Slice 2 | artifact |
| Stale grace | 259200 s (72 h) | Slice 2 | artifact |
| Incident summary interval | 3600 s | Slice 6 | artifact |
| DNS reporting storage | 32/64/512 markers | Slice 6 | artifact |
| Log queue / entry | 256 / 8 KiB | Slice 6 | artifact |
| Log sink work per turn | 64 KiB or 16 ops | Slice 6 | artifact |
| Startup window | 90 s absolute | Slices 1/2 | artifact |
| Idle / drain / shutdown | 300 / 5 / 8 s | Slice 5 | artifact |

Notes 183–185: 128 MiB decomposition; buffer reuse without discarding;
outside-budget accounting (DNS storage, metadata, stacks, executable, kernel
buffers); throughput conditional per-direction — encoded in arch §6 / Slice 7.

## 4. Verification-requirement matrix (all `docs/alumina-proxy.md:225-236`)

| Spec verify requirement | Where planned | Owner | Status |
|---|---|---|---|
| Protocol + DNS (TLS1.3/fallback/ECH, fragmentation, binding, CNAME, startup failure, stale retention, negatives, isolation, TTL bounds, backoff, A/AAAA, admission edges, eligibility vectors, due-time/round-robin) | Slices 2/4 | cache+dns_parse+tunnel | gate |
| TLS forwarding gate (data/EOF/reset at named points, both barriers, combined readiness, gate-before-next-read, after-open fast responses, interop HRR/alerts) | Slice 4 (F2 1–3) | worker/tunnel | gate |
| Lifecycle deadlines (before/at/after, delayed, overlapping, clipped retries, idle reset by writes, second EOF/SIGTERM, drain vs forced) | Slice 5 (F2 4–5) | lifecycle/tunnel | gate |
| DNS classification (direct/CNAME/negatives, 8/9-link, loops, conflict, AA, SOA, malformed, trust region, pointers, RDLENGTH, QDCOUNT) | Slice 2 | dns_parse | gate |
| Parser fuzzing (owned corpus/inputs/evidence; CONNECT, ClientHello, DNS wire, log; determinism) | Gate F4, Slices 2/4 | parse/dns_parse/log | gate |
| DNS observability (first-failure warn, hourly summaries, incident recovery, exact-once accounting, window bounds, saturation, stalls) | Slice 6 | cache/log | gate |
| Resource profile (4096-B config, 128 MiB, bounded queues/timers, alloc-free, deadline, buffer preservation; process vs kernel split) | Slice 6; F1 | build-wide | gate |
| Logging (entry bounds, escaped text, whole-record drops, thresholds, one enqueue per rejection, partial writes/stall, alloc-free) | Slice 6 | log | gate |
| Startup readiness (allowance, all-ready early, exact-allowance degraded, 75/78, 90 s bounds, cancellation, diagnostics, no reapplication) | Slices 1/2/6 | config/lifecycle | gate |
| Deployment confinement; initial deployment; runtime surface+prereqs; performance | Slice 7 (release gates) | deployment | external |

## 5. Unresolved implementation-evidence ledger (explicit)

| # | Gap | Evidence needed (future) | Where tracked | Status |
|---|---|---|---|---|
| U1 | mio/transitive alloc-freedom | pinned version + op matrix + source review + Linux allocator witnesses | build-plan F3 | gate |
| U2 | Generation/window-id non-reuse | width/exhaustion design + construction-and-reuse proof | arch §5 (G1/G4) | artifact → gate |
| U3 | Gate-ordering online proof | F2 fault-injection runs on the real dispatcher (q28 schedule) | build-plan F2/Slice 4 | gate |
| U4 | Stack bound | measured worst-case parse-path stack on Linux | arch §6 G2 | artifact |
| U5 | Linux serving/refresh alloc evidence | allocation witnesses for all named phases on Linux (incl. serving completeness) | build-plan Slice 6; F1; F3 | gate |
| U6 | Throughput + confinement | conditional 1–10 Gbps benchmark; deployment confinement | build-plan Slice 7 | external |
| U7 | Boot allocation inventory sum (G1) | container-size accounting incl. outside-budget items; 128 MiB traffic-only + RSS split | arch §6 | artifact |
| U8 | Parser-fuzz corpus ownership | checked-in corpus/inputs/seed/hashes; crashes resolved before done-claim | build-plan F4 | gate |

## 6. Named decisions (pointers)

Design decisions D1–D7 and the state machine: `docs/architecture.md` §3/§4.
Gates F0–F4: `docs/build-plan.md` §2. Storage/boot and generation domains
(T1/T2/T3, G1–G4): `docs/architecture.md` §5/§6.

No ADR has been required: the documents restate the spec, no policy change.
The planning documents are committed and maintained alongside the
implementation; this matrix stays the single requirement→design→proof map, and
every `verified-local` status is scoped to the exact candidate it ran against
(exact-input identity receipts; never a blanket test-completion or production
claim). Canonical `docs/alumina-proxy.md` is unmodified.
