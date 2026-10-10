# Alumina — Requirement / Resource / Verification Traceability Matrix

**Status:** planning document. Canonical source: `alumina.md` (lines 1–236). This matrix is the single map from every specification section, invariant, resource row, and verification requirement to its design home ([architecture.md](architecture.md)), its execution plan ([build-plan.md](build-plan.md)), and its proof status. **Nothing is verified yet**: this is a planning-only mission, so every status below is `designed` (named design decision), `artifact` (bound/identity chosen, not measured), `gate` (future implementation-proof obligation), `external` (deployment-level release obligation), or `out-of-scope` (explicitly not implemented). No row claims runtime evidence.

Status vocabulary:
- **designed** — a named design decision D1–Dn or explicit architecture element exists.
- **artifact** — a number/identity (stack bound, width, pin) is chosen; not measured/proved.
- **gate** — a future acceptance/proof step named in a Slice; not yet demonstrated.
- **external** — deployment/operator obligation; cannot be established internally.
- **out-of-scope** — explicit non-goal (architecture.md §9 / build-plan.md §7).

## 1. Section matrix (all `alumina.md` sections)

| Spec ref | Section / requirement | Design home | Proof status | Notes |
|---|---|---|---|---|
| L1–7 | Overview: non-terminating forward proxy, HTTPS-over-TCP, FQDN allowlist, golden-path profile | [architecture.md §1, §9](architecture.md#1-governing-invariants-invariant-led-design) | designed | Priorities: integrity/bounded/low-latency/least-privilege/minimal |
| L9–15 | Threat model: compromised app in VPC; egress restriction goal; accepted limitation (no upstream auth, fronting risk) | [architecture.md §9](architecture.md#9-explicit-non-goals) | designed | Confinement analogy, not guarantee |
| L17–21 | Protocol contract: HTTPS-over-TCP only, fail-closed | §4 state machine (Barriers) | designed | I-3 (Fail-Closed) enforcement |
| L23–28 | Flow: Read CONNECT → authorize → connect → 200 → validate CH → forward → relay → drain/close | §4 transitions | designed | Maps to tunnel states |
| L30 | Response-begin vs complete; error policy before/after 200-begin; only complete 200 permits CH inspection | D1 | designed | T4 resolved as separate state facts |
| L32 | Gate opening on successful-write accounting, before next upstream read; no remote-receipt inference | D3 | designed → gate (Slice 4) | The core security transition |
| L34 | Incremental CONNECT/CH parsing, separate limits, absolute deadline; preserves original bytes | §6 buffers; Slice 3/4 | designed → gate | Stream-parsing invariant |
| L36–43 | CONNECT request: accept/reject matrix, one-request-per-connection, error codes 400/403/502/503/504, no input echo | Slice 3 | designed → gate | 8 KiB limit; status matrix |
| L45–50 | TLS ClientHello profile: TLS 1.3-only, identity/framing, ECH rejection, inspection scope | Slice 4 | designed → gate | Non-decrypting maintained |
| L52–58 | Configuration & DNS: 4 KiB TOML, mandatory keys, allowlist 1–32, allowance; EX_CONFIG 78 | Slice 1 | designed → gate | No runtime reconfig |
| L60 | Listener: address:port, wildcard allowed, bind failure prevents startup | Slice 1 | designed | |
| L61 | Names: A-label, case-insensitive compare, single trailing dot, absolute DNS, no search suffixes | Slice 2 | designed | |
| L62 | Resolver selection: first nameserver, port 53, numeric unicast no zone; fixed for process lifetime | Slice 1 | designed | |
| L63 | Resolution: bounded DNS stub; resolve before listener; requests never trigger lookups | Slice 2 | designed | |
| L64 | Startup deadline: fixed order; 90 s absolute post-storage-init; clipped exchanges; check before publication | Slice 1/2 | designed → gate | T1 boot/startup split |
| L65 | Startup readiness: usable iff eligible non-retired binding; early open; allowance; EX_TEMPFAIL 75 | Slice 1/2 | designed → gate | Startup readiness verification |
| L66 | Degraded serving: allowance only at startup; no readiness endpoint | Slice 1 | designed | |
| L67 | Startup diagnostics: one warn on first exchange failure; suppressed per-type first warnings; final result | Slice 6 | designed → gate | Logging rules |
| L68 | Transport: TCP only, 1 conn/1 query, getrandom TIDs, full validation, no fallback | Slice 2 | designed → gate | |
| L69 | Wire parsing: QDCOUNT 1, exact counts, RDLENGTH match, pointer rules, label/name limits | Slice 2 | designed → gate | |
| L70 | DNS control traffic: sockets reach only selected resolver; never CONNECT-eligible | Slice 2 | designed | |
| L71 | DNS provenance: A/AAAA only, CNAME ≤8 rooted chain, unambiguous target, no DNAME, no follow-ups | Slice 2 | designed → gate | |
| L72 | Service discovery: HTTPS/SVCB unsupported; never change target/port/transport | Slice 2 | designed | out-of-scope substitution |
| L73 | Addresses: global-routable unicast only; fixed boundary table; validate pre-publish + per attempt | Slice 2 | designed → gate | All IPv4/IPv6 ranges |
| L74 | Cache lifetime: per-name/type entry, generation, deadlines computed never stored, replacements | Slice 2 | designed → gate | G2 cache generation |
| L75 | Stale retirement: 259200 s stale grace; absolute retirement deadline; no extension; check per attempt | Slice 2 | designed → gate | |
| L76 | Refresh scheduling: min(300, max(30, TTL)); fixed due table; round-robin; one query per name/type | Slice 2 | designed → gate | |
| L77 | Negative refresh scheduling: SOA-based bounds; NXDOMAIN both types; NODATA queried type | Slice 2 | designed → gate | |
| L78 | Refresh failures: 1/2/4/8/16/30 backoff; per-type retry distinct; no monopolization | Slice 2 | designed → gate | |
| L79 | Incident notifications: per-type incidents, one warn, info recovery, hourly error summary | Slice 2/6 | designed → gate | |
| L80 | Incident summaries: full fields; activity definition; exact-once byte accounting; stale admission count | Slice 6 | designed → gate | |
| L81 | Reporting bounds: preallocate; window ids not reusable while live tunnel retains one; saturate counters | [architecture.md §5](architecture.md#5-generations-lifetimes-and-anti-alias-t7t1-merged-domains) | artifact → gate | G4 window-id domain |
| L82 | Bounds/retries: response profile bounds, 2 s DNS exchange, ≤4 connects × 2 s clipped, per-family attempt counts, revalidate, fixed peer | Slice 3 | designed → gate | |
| L84–86 | Response outcomes: validate-then-classify; AA irrelevant; malformed ⇒ exchange failure | Slice 2 | designed → gate | |
| L87–88 | Negative classification: covering SOA rule; terminal-name owner | Slice 2 | designed → gate | |
| L90–95 | Outcome table: Positive / NXDOMAIN / NODATA / Exchange failure actions | Slice 2 | designed → gate | |
| L97 | Empty answer ≠ NODATA; referral ≠ negative; no fallback transport | Slice 2 | designed | |
| L99–101 | Deployment boundary: egress responsibility; VPC isolation out of scope | [architecture.md §8](architecture.md#8-deployment-and-trust-boundary) | designed | |
| L103–115 | Typical deployment pattern: separate identities, private endpoint, default-deny | §8 | designed → external | |
| L116 | Confinement across all routes/families; no NAT64; no DNS64 | §8 | designed → external | |
| L118 | Production image: minimal Linux container, non-root, read-only rootfs, no creds | §8 | designed → external | Image contents gate |
| L120–122 | Operator responsibilities: private endpoint discovery, routing, firewall, NAT/LB; DNS-readiness≠reachability; CONNECT+TLS check | §8 | external | |
| L124–130 | DNS deployment assumptions: trust, third-party compatibility, freshness limitation | §8 | external | Qualification obligation |
| L132–136 | Initial test target: Cloud Run Direct VPC, ≤1 Gbps/instance; 10 Gbps needs fitting ceiling | [build-plan.md §3 Slice 7](build-plan.md#slice-7--release-gates--deployment-readiness) | external | Performance gating conditional |
| L138–141 | Architecture intro: Rust, single worker loop, TigerStyle-adapted, explicit responsibilities | §2 modules / §3 scheduling | designed | |
| L142 | Compile-Time Bounds statically fixed | §6 | designed | |
| L143 | Boot-Time Storage; stack bounded; not constant total memory | §6 (T3 reading) | designed/artifact | T3 resolved |
| L144 | Single Owner: worker owns tunnel/DNS/timers/cache | §2, III-1 | designed | |
| L145 | Cache Publication: preallocate, staging, generation advance, no tunnel cache refs | §5 G2/G3 | designed | |
| L146 | Scheduling: fair round-robin, budgets, timer recheck, dup-free queue | D6/D7 | designed → gate | T6 app-queue rule |
| L147 | I/O model: mio+epoll, no async runtime; gates on successful writes | D3; F3 | designed → gate | T2 mio seam |
| L148 | Failure handling: panic=abort; no unwrap/expect in production | §7 | designed | |
| L149 | Runtime surface: CONNECT listener only; SIGTERM only; stdout logs | §7/§8 | designed | |
| L150 | Runtime prerequisites: non-root, empty caps, no_new_privs; read once; storage before DNS; exit without dealloc | §7/§8; Slice 1 | designed → gate | |
| L152–185 | Initial resource profile: table rows (below) + sizing notes + throughput note | §6 | artifact | Full row matrix in §3 |
| L187–189 | Lifecycle setup: setup deadline, connect deadlines clipped | §4 | designed → gate | |
| L190 | Relay: idle deadline, reset on successful writes only | §4 | designed → gate | |
| L191 | Closure: first-EOF drain, drain deadline, reverse traffic, release exactly once | §4 | designed → gate | |
| L192 | Shutdown: SIGTERM grace, no extension, drain, exit | §4/§7 | designed → gate | |
| L193 | Capacity/logging: 503 no eviction; error entry when tunnel-slot/pending-setup/log-queue usage first exceeds 80% and again when it falls below 70%; reject warn; early-activity warn | Slice 6 | designed → gate | T5 metadata-only warn |
| L194 | Log delivery: best-effort, allocation-free, whole-record drop+count, nonblocking drain | Slice 6 | designed → gate | |
| L196–221 | Invariants I–IV (13) | [architecture.md §1](architecture.md#1-governing-invariants-invariant-led-design) | designed → gate | §4 matrix below |
| L223–236 | Verification requirements (12 categories) | build-plan Slices 1–7 | gate | §5 matrix below |

## 2. Invariant matrix (all 13)

| Invariant | Cited | Upheld by | Status |
|---|---|---|---|
| I-1 Destination-Binding | L200 | cache-only addresses; per-attempt revalidation; retirement check; fixed peer | designed → gate |
| I-2 Authorization-Before-Forwarding | L32/L201 | Barriers A+B; D3 gate transition | designed → gate |
| I-3 Fail-Closed | L202 | no permissive fallback anywhere; bounded stale only | designed |
| II-1 Zero-Allocation | L206 | boot inventory; allocator witnesses **rejecting either allocation or deallocation** after boot in every phase; mio op matrix | artifact → gate |
| II-2 Resource-Bounds | L207 | fixed limits; exhaustion rejects; never grows | artifact |
| III-1 Ownership | L211 | single worker owns tunnel/DNS/timers/cache | designed |
| III-2 Generation-Isolation | L212 | four domains G1–G4; anti-alias gates | artifact → gate |
| III-3 Bounded-Work | L213 | per-turn budgets; reschedule-without-loss | designed |
| IV-1 State-Transition | L217 | exhaustive enum; all outcomes have transitions | designed → gate |
| IV-2 Stream-Parsing | L218 | incremental parsers with residual state | designed → gate |
| IV-3 Non-Decrypting | L219 | metadata validator + bit-pipe; no keys | designed |
| IV-4 Byte-Conservation | L220 | ordered prefix; coalesced preserved | designed → gate |
| IV-5 Deadline | L221 | monotonic; earliest-enforced; no renew after expiry | designed → gate |

## 3. Resource-row matrix (all rows of `alumina.md:158-182`, plus notes 183–185)

| Resource | Limit | Design home | Accounting | Status |
|---|---|---|---|---|
| Config document / allowlist | 4 KiB / 1–32 | Slice 1 | 4096 B boot buffer | artifact |
| Worker threads | 1 | §2 III-1 | n/a | designed |
| Concurrent tunnels (incl. setup) / pending setups | 128 / 32 | Slice 3 | 128 slots; ≤32 pending; **not 160** | artifact (preflight-pinned) |
| Traffic buffers per tunnel slot | 2 × 512 KiB | Slice 3/5 | §6 inventory | artifact |
| Total preallocated tunnel traffic storage | 128 MiB | §6 | 128×2×512 KiB exactly | artifact |
| CONNECT headers | 8 KiB | Slice 3 | separate limit | artifact |
| Buffered TLS bytes pre-auth | ≤64 KiB | Slice 4 | separate limit; relay buffers don't enlarge setup | artifact |
| DNS response message / total RRs | 16 KiB / 128 | Slice 2 | staging buffer | artifact |
| Cached address candidates per name | 16 IPv4 + 16 IPv6 | Slice 2 | per-entry arrays | artifact |
| CNAME chain length | ≤8 links | Slice 2 | parse bound; loops rejected | artifact |
| DNS TCP connections / outstanding queries | 1 / 1 | Slice 2 | single transport owner | designed |
| Setup deadline / upstream connect deadline | 10 s / 2 s | Slice 3 | monotonic timers | artifact |
| Upstream attempts per tunnel | ≤4 | Slice 3 | per-family counts | artifact |
| DNS exchange deadline | 2 s | Slice 2 | monotonic | artifact |
| Normal refresh interval lower/upper | 30 / 300 s | Slice 2 | due table | artifact |
| SOA negative refresh lower/upper | 30 / 300 s | Slice 2 | due table | artifact |
| DNS retry backoff | 1,2,4,8,16,30 s | Slice 2 | per-type state | artifact |
| Stale grace | 259200 s (72 h) | Slice 2 | retirement deadline | artifact |
| Incident summary interval | 3600 s | Slice 6 | per-hostname | artifact |
| DNS reporting storage | 32 name/window, 64 incident, 128 tunnel markers | Slice 6 | §6 inventory | artifact |
| Log queue / max entry | 256 / 8 KiB | Slice 6 | §6 inventory | artifact |
| Log sink work per turn | 64 KiB or 16 ops | Slice 6 | scheduling budget | artifact |
| Startup resolution window | 90 s absolute | Slice 1/2 | includes DNS TCP establishment | artifact |
| Relay idle / EOF drain / shutdown grace | 300 / 5 / 8 s | Slice 5 | monotonic timers | artifact |

Notes 183–185 (`alumina.md`): 128 MiB derivation (128×2×512 KiB); buffer reuse without discarding; outside-budget accounting (DNS storage, metadata, stacks, executable, kernel buffers); throughput 1–10 Gbps conditional with per-direction/drain burst sizing — all encoded in [architecture.md §6](architecture.md#6-fixed-storage-and-the-zero-allocation-model) / build-plan Slice 7.

## 4. Verification-requirement matrix (all `alumina.md:225-236` categories)

| Spec verify requirement | Where planned | Owner | Status |
|---|---|---|---|
| Protocol and DNS (TLS1.3/fallback/ECH, fragmentation, DNS binding, CNAME, startup failure, stale retention, negative eviction, obsolete isolation, TTL refresh bounds, backoff, independent A/AAAA, admission at retirement edges, address eligibility vectors, due-time/round-robin) | Slice 2 / 4 | cache+dns_parse+tunnel | gate |
| TLS forwarding gate (data/EOF/reset at all named points; both barriers; WouldBlock; combined readiness; gate-open-before-next-read; fast-response-after-open not rejected; TLS1.3 interop incl. HRR/alerts) | Slice 4 (F2 script boundaries 1–3) | worker/tunnel | gate |
| Lifecycle deadlines (start/end/reset before/at/after, delayed, overlapping; connect retries clipped; idle resets by writes only; second EOF/SIGTERM; drain vs forced closure) | Slice 5 (F2 boundaries 4–5) | lifecycle/tunnel | gate |
| DNS classification (direct/CNAME/negatives, 8/9-link, loops, conflict, coexistence, AA both ways, SOA rules, malformed/contradictory rejection, trust region parsing, pointers, labels, RDLENGTH, trailing bytes, QDCOUNT≠1) | Slice 2 | dns_parse | gate |
| Parser fuzzing — separate acceptance with owned corpus/input/evidence (checked-in corpus + generated inputs + deterministic seed + minimized crash-input hashes; targets CONNECT headers, ClientHello/TLS framing, DNS wire parsing, log-record encoding; `alumina.md:225` focused tests + fuzzing) | Gate F4, exercised in Slice 2/4 | parse/dns_parse/log | gate |
| DNS observability (first-failure warn, hourly summaries, independent incident recovery, immediate no-eligible-binding, exact-once accounting, window boundaries, saturation, stalls) | Slice 6 | cache reporting/log | gate |
| Resource profile (4096-byte config, 128 MiB alloc, bounded queues/timers, allocation-free, deadline enforcement, buffer preservation; allocator instrumentation + dependency checks; process vs kernel memory split) | Slice 6; F1 harness | build-wide | gate |
| Logging (queue/entry bounds, escaped text, whole-record drops, thresholds, one enqueue per rejection, worst-case startup result fits limit, partial writes/backpressure/stall, allocation-free) | Slice 6 | log | gate |
| Startup readiness (allowance validation, all-ready early, exact-allowance degraded, EX_TEMPFAIL 75 / EX_CONFIG 78, not-yet-attempted, 90 s boundaries, cancellation, degraded diagnostics, no replay, no reapplication of allowance at runtime) | Slice 1/2/6 | config/lifecycle | gate |
| Deployment confinement (approved/unapproved calls; direct-path denial; proxy-ignore/bypass/unavailability; no alternative egress; cannot alter controls; unauthorized sources; upstream cert verification; repeat on change) | Slice 7 (security release gate) | deployment | external |
| Initial deployment (TCP DNS + CONNECT ingress on Cloud Run; qualify resolver responses; measure startup delay vs 90 s; operator CONNECT+TLS check; explicit revision on incompatibility) | Slice 7 (initial deployment) | deployment | external |
| Runtime surface + prerequisites (root/caps/no_new_privs failure; one listening socket; SIGTERM bounded; admin signals can't reload; image contents) | Slice 1/5/7 | lifecycle + deployment | designed → gate |
| Performance (aggregate payload measured once; 1–10 Gbps bursts conditional; per-metric report; slow-peer backpressure; DNS/deadline under load) | Slice 7 (performance release gate) | deployment/build | external |

## 5. Unresolved implementation-evidence ledger (explicit)

| # | Gap | Evidence needed (future) | Where tracked | Status |
|---|---|---|---|---|
| U1 | mio/transitive-dep alloc-freedom | pinned version + op matrix + source review + allocator witnesses on Linux | build-plan Gate F3; oracle G2/T2 | gate |
| U2 | Generation/window-id non-reuse | width/exhaustion design + construction-and-reuse proof | architecture §5 (G1/G4); oracle G3 | artifact → gate |
| U3 | Gate-ordering online proof | deterministic fault-injection runs on the real dispatcher (q28 schedule) | build-plan F2/Slice 4 | gate |
| U4 | Stack bound | measured worst-case parse-path stack usage on Linux | architecture §6 G2 | artifact |
| U5 | Linux epoll/serving/refresh/alloc evidence | allocation witnesses for all named phases on Linux | build-plan Slice 6; F1 | gate |
| U6 | Throughput + confinement | conditional 1–10 Gbps benchmark; deployment confinement | build-plan Slice 7 | external |
| U7 | Boot allocation inventory sum (G1) | container-size accounting breakdown incl. outside-budget items | architecture §6 | artifact |
| U8 | Parser-fuzz corpus/input/evidence ownership | checked-in corpus, generated input set, deterministic seed, minimized crash-input hashes recorded per run; resolving all crashes/hangs/timeouts before owning slice's done-claim | build-plan Gate F4 | gate |

## 6. Named design decisions (D1–D7) and resolved tensions

- **D1 response-begin boundary (T4)** — architecture §4.
- **D2 two barriers (T5/T4)** — architecture §4.
- **D3 gate-opening transition (L32 verbatim; crossing H forwards co-forwarded `X`; atomic open before subsequent upstream read)** — architecture §4.
- **D4 early-activity rule (pre-open upstream reads permitted; only observed data/EOF/reset terminate; WouldBlock/readiness not activity; T5 metadata-only warn)** — architecture §4.
- **D5 ordered successful-write accounting** — architecture §4.
- **D5a per-family storage arithmetic (2 counters/tunnel; addresses never stored)** — architecture §4.
- **D5b traffic-buffer reuse (coalesced bytes preserved, no re-encoding; relay buffers never enlarge setup limits)** — architecture §4.
- **D6 per-visit work budget (64 KiB / 16 ops)** — architecture §3.
- **D7 duplicate-free app ready queue (T6: spec prescribes no epoll trigger mode)** — architecture §3.
- **F0 exact static-Linux toolchain proof; F1 alloc+dealloc witness; F2 scripted fault injection; F3 mio op matrix before first DNS op; F4 parser fuzzing with owned corpus/inputs/evidence** — build-plan §2.
- **T1 boot boundary** — architecture §6 (single-owner boot/startup split).
- **T3 memory reading** — architecture §6 (128 MiB = tunnel traffic only).
- **T2/G4 mio dependency seam** — architecture §6 + build-plan F3.
- **G1/G2/G3/G5 artifact statuses** — §6 + rows above.

As of this planning-*refinement* mission: **no ADR was required** (spec restated, no policy change); **no application code, dependency, commit, push, or sync was performed**. The repository HEAD `4100a52201420aa84c874cf5af669b9f1602967d` is the `bd init` auto-commit created at mission setup, not an implementation commit; this refinement adds **no subsequent commit** — it changes only the three untracked planning documents in `docs/`. Canonical `alumina.md` and all committed bootstrap files are untouched, and the closed original planning mission (`alumina-b8a` records) is preserved unchanged.
