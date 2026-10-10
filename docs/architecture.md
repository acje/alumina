# Alumina — Architecture

**Status:** planning document (no application implementation). This document is a design statement, not runtime proof. Every claim about the target implementation is gated on a future Linux acceptance run per [build-plan.md](build-plan.md) and tracked in [traceability.md](traceability.md).

**Canonical source:** `alumina.md` (repository root) is the sole governing specification; there are no accepted ADRs in this repository. Where this document defines a boundary the specification leaves open, it is a **named design decision (lettered D1…Dn)**, never a policy change or silent security relaxation. This planning mission makes no policy decisions requiring an ADR.

## 1. Governing invariants (invariant-led design)

The architecture is derived from the specification's invariants; modules and transitions exist to uphold them. Each invariant names the design element that enforces it; the reverse mapping is in [traceability.md](traceability.md).

| Invariant | Canonical citation | Design element that upholds it |
|---|---|---|
| I-1 Destination-Binding | `alumina.md:200` (I. Security) | Tunnel setup reads addresses only from `cache` current entries; per-attempt revalidation; strict retirement check before every connect; fixed selected peer |
| I-2 Authorization-Before-Forwarding | `alumina.md:201`; `alumina.md:32` (Protocol contract) | Two forwarding barriers (Barrier A client→upstream, Barrier B upstream→client) implemented in the tunnel state machine; gate opens only via successful-write accounting |
| I-3 Fail-Closed | `alumina.md:202` | No permissive fallback anywhere: exhaustive error handling, no alternate resolver/transport/record-type fallback; only bounded stale grace tolerates DNS failure |
| II-1 Zero-Allocation | `alumina.md:206` | Boot allocation inventory (§6, T1); allocator instrumentation at build-time gates (build-plan F1); dependency (mio) operations scoped (§6 dependency seam, T2/G4) |
| II-2 Resource-Bounds | `alumina.md:207` | Fixed compile-time limits (allocation plan); exhaustion rejects work; never grows storage |
| III-1 Ownership | `alumina.md:211` | Single worker loop owns tunnel state, DNS sockets, timers, and the entire cache; no resolver thread, no shared mutable cache (L144) |
| III-2 Generation-Isolation | `alumina.md:212` | Four distinct generation/lifetime domains (G1–G4, §5); tunnel slot reuse is generation-scoped; stale work cannot re-validate |
| III-3 Bounded-Work | `alumina.md:213` | Per-turn scheduling budgets (D6); reschedule-without-loss; timer recheck every ≤256 ready-slot visits |
| IV-1 State-Transition | `alumina.md:217` | Exhaustive enum state machine; every I/O outcome has a permitted transition; readiness never implies success (§4) |
| IV-2 Stream-Parsing | `alumina.md:218` | Incremental parsers with explicit residual state; parse decisions independent of TCP read boundaries |
| IV-3 Non-Decrypting | `alumina.md:219` | No TLS private keys, no cert authority management; metadata validator + transparent bit-pipe |
| IV-4 Byte-Conservation | `alumina.md:220` | Ordered prefix forwarding from per-tunnel buffers; coalesced trailing bytes preserved, never reserialized or dropped |
| IV-5 Deadline | `alumina.md:221` | All deadlines monotonic; earliest deadline enforced even under delayed timer handling; expiry never renews a phase |

## 2. Module & ownership decomposition

Single binary crate, one worker thread, no async runtime (`alumina.md:140,147`). Modules below are crate-internal units; **all post-boot state is preallocated** per §7.

| Module | Owns (mutating authority) | Legal handoffs (what it hands to whom) | Citations |
|---|---|---|---|
| `config` | Parsed configuration, startup validation; EX_CONFIG exit 78 path | Validated config → `storage`/`cache`/`resolver` at boot only | `alumina.md:54,56,58,60` |
| `resolver` | Platform resolver config read (first nameserver, port 53); DNS TCP transport (1 conn, 1 outstanding query, getrandom transaction IDs) | Exchange results (validated) → `dns_parse` → `cache`; deadline state → `worker` | `alumina.md:62,68` |
| `dns_parse` | Wire parsing + staging classification (bounded CNAME chain, negatives, eligibility) | Classified outcome → `cache` publication | `alumina.md:69,71,73,86-97` |
| `cache` | Per-name×type entries (bindings, deadlines, generation); staging storage; refresh due table; retry/incident state; reporting windows | Hand-OUT read-only snapshots: addresses + attempt counts to `tunnel`; **tunnels never hold cache references** | `alumina.md:74-82,145` |
| `tunnel` | 128 tunnel slots; per-slot state machine, two 512 KiB directional buffers, per-family attempt counts | Ready/timer events → `worker`; no cache references retained | `alumina.md:82,145,160,183` |
| `parse` (CONNECT/ClientHello) | Incremental CONNECT headers (8 KiB) and ClientHello inspection (≤64 KiB incl. framing) parsers, residual state | Parsed frames + buffered original bytes → `tunnel` | `alumina.md:34,41,47-50,163-164` |
| `worker` | The single owner loop: readiness demux, fair round-robin scheduling, timer management, gate transitions, dispatch | (notional) I/O ops; is the sole owner per III-1 | `alumina.md:138,144,146,147,149` |
| `log` | 256×8 KiB preallocated queue; allocation-free format/encode; nonblocking sink; drop+count | Encoded entries → stdout sink | `alumina.md:149,178-179,193-194` |
| `lifecycle` | SIGTERM handling, shutdown grace, drain coordination; exit-without-deallocating | Shutdown sequence → `worker`/`tunnel`/`log` | `alumina.md:149,150,181,192` |

The worker is the only module permitted to touch I/O readiness, timers, and gate transitions; all state it touches is preallocated and single-owned (III-1).

## 3. Single-worker scheduling model

Per `alumina.md:146` and `alumina.md:147`:

- **Fair round-robin** across ready connections; per-visit budget = **64 KiB of I/O or 16 I/O operations, whichever is first** (D6).
- **Timer recheck** at most every **256 ready-slot visits** or I/O operations, even with more work pending.
- **Reschedule-without-loss:** unfinished work is re-enqueued without waiting for a new readiness edge; readiness is never mistaken for an operation's success (IV-1).
- **Ready queue:** sized from fixed slot counts; **one pending-work queue entry per slot** — the queue is duplicate-free by construction (D7). The queue is the application-owned one referenced by `alumina.md:146`; the specification does not prescribe a mio/epoll trigger mode, so readiness de-duplication is the application's responsibility regardless of how the OS re-presents events.
- **Deadlines** are checked against a monotonic clock before any completion transition; the earliest applicable deadline wins (IV-5, `alumina.md:221`).

## 4. Tunnel state machine and legal transitions

Tunnel state is a Rust enum; **illegal transitions are unrepresentable** (fleet priority 2), not merely rejected. Every I/O outcome (read completions, successful writes, `WouldBlock`, EOF, reset, timer expiry, budget exhaustion) has an explicit transition (IV-1).

```
ACCEPT
 └─> READ_CONNECT ──────────────── 400/403 (before 200 begins: HTTP error allowed)
       │                            └─> CLOSE (one request per connection)
       ├─> AUTHORIZED (hostname allowlisted, port 443)
       │     └─> CONNECTING_UPSTREAM (per-attempt: revalidate cache, ≤4 attempts,
       │         2s each, clipped to 10s setup deadline; 502/504 on failure)
       │            └─> SENT_200 (successful CONNECT response *completed*)
       │                  └─> VALIDATING_CLIENTHELLO (incremental, ≤64 KiB)
       │                        └─> GATE_OPENING (the write-accounting transition)
       │                              └─> RELAY_ACTIVE (both barriers open)
       │                                    ├─> DRAINING (first orderly EOF)
       │                                    └─> CLOSE (both EOF + drained, or deadline)
       └─> CLOSE (any error after 200 begins: no injected HTTP response, no TLS alert)
```

Named decisions:

- **D1 (response-begin boundary, T4).** `ResponseBegin` and `ResponseComplete` are separate state facts. Before the 200 begins, failures may send an HTTP error; once it begins, failures close with no injected response and no TLS alert (`alumina.md:30`). Only *completion* of a successful CONNECT response permits ClientHello inspection.
- **D2 (two barriers).** Barrier A (client→upstream): no client bytes, including ClientHello, are forwarded before complete validation with mandatory SNI normalized-equal to the approved CONNECT hostname. Barrier B (upstream→client): no upstream bytes are forwarded before the gate opens (`alumina.md:201`). A successful CONNECT response alone authorizes neither direction.
- **D3 (gate-opening transition).** Encodes `alumina.md:32` verbatim: the upstream→client gate **opens in the same worker transition whose successful local-write accounting reaches the end of the validated ClientHello (H), before any subsequent upstream read.** Successful write accounting uses the actual successful byte count, in order (§ Byte-Conservation). A single successful write may **cross H and include coalesced trailing bytes (`X`)** — those `X` bytes are already forwarded by that write. The gate opens **atomically** in that same transition, before any subsequent upstream read; `X` within the crossing write is relay traffic from the open point, and any still-unwritten buffered bytes remain in-order pending later writes. Local write success ≠ remote receipt (`send(2)`); arrival ordering is never inferred for activity first observed after open.
- **D4 (early-activity rule).** While Barrier B is closed the worker **may** perform upstream I/O observations — the spec permits actual pre-open I/O; it is *activity*, not observation, that terminates setup. Upstream data, EOF, or reset actually observed through real I/O while the gate is closed terminates setup: no forwarding, no logging of upstream bytes — only the prescribed metadata warn entry (hostname, peer, whether data/EOF/reset) (`alumina.md:201,193`; T5). `WouldBlock` or readiness alone is **not** activity (IV-1), so a WouldBlock read is neither forwarding nor termination.
- **D5 (accounting + storage footprint).** Forwarded-byte accounting advances only on successful writes; partial writes preserve ordered progress; a write that crosses H forwards its trailing `X` bytes as part of that successful write (D3) (`alumina.md:32,80,146-147,220`).
- **D5a (per-family storage arithmetic, `alumina.md:82`).** Each tunnel stores exactly two per-family attempt counters (A, AAAA) — never addresses and never cache references, so a replacement between attempts takes effect at the next attempt. Within a family the address at index `n` is used, `n` = number of earlier attempts in that family; the family is exhausted when `n` reaches the entry's current address count. Storage arithmetic: **2 counters per connecting/connected tunnel**, independent of family address counts.
- **D5b (traffic-buffer reuse, `alumina.md:142-143,183`).** The two 512 KiB directional buffers are preallocated once and reused across CONNECT parsing, ClientHello inspection, and relay **without discarding coalesced tunnel bytes** and without re-encoding; relay-buffer size never enlarges the separate CONNECT (8 KiB) / TLS (≤64 KiB) setup limits.

Lifetimes: the setup deadline starts at successful accept and is never reset; each upstream-connect deadline starts at its attempt and is clipped to the setup deadline (`alumina.md:189`). Idle deadline starts when the gate opens; reset only on successful tunnel-byte writes in either direction (`alumina.md:190`). Closure: first orderly EOF starts the 5 s drain deadline, never reset; reverse traffic may continue; close when both EOFs are drained or a deadline expires; resources released exactly once (`alumina.md:191`). Shutdown: first SIGTERM stops accepting and starts the 8 s grace; subsequent SIGTERM does not extend; drain, close sockets, exit without deallocating (`alumina.md:192,150`).

## 5. Generations, lifetimes, and anti-alias (T7/T1-merged domains)

Four domains must **not** be merged (`alumina.md:212`; oracle T7):

| Domain | Owner | Invalidation rule | Reuse proof status |
|---|---|---|---|
| G1 Tunnel-slot generation | `tunnel` | Connection-scoped events/timers/buffer bytes belong to one generation; slot reuse must never make stale work valid again (`alumina.md:212`) | Wrap/alias bound is a **design artifact** (width chosen so no wrap while a live slot can retain state); runtime nonreuse proof is an open build gate |
| G2 Cache-entry generation | `cache` | Advances on every replacement/eviction; rejects obsolete results (`alumina.md:145`) | Per-operation tag comparison; proof part of cache slice |
| G3 DNS non-connection lifetime | `cache` | Refresh results belong to cache state, **not** connection generations; tunnels never hold cache references (`alumina.md:74,145`) | Structural (no references out of `cache`), holds at design level |
| G4 Reporting window identifier | `cache` (reporting) | One last-counted window id per tunnel slot; ids not reusable while a live tunnel can retain one; reused slot resets its marker; counters saturate with overflow flag (`alumina.md:81`) | Width + exhaustion policy is a **design artifact**; reuse proof an open build gate |

A wide integer alone is not a nonreuse proof (`alumina.md:81,212`); the documents record width/exhaustion choices as artifacts and the construction-and-reuse proof as a future acceptance gate.

## 6. Fixed storage and the zero-allocation model

Scope readings the plan adopts (T1/T3; oracle q28):

- **T1 boot boundary:** *boot initialization* = privilege/prerequisite check + configuration read + resolver-config read + storage/singleton/dependency-facility initialization (+ authoritative parse of inputs). **Startup DNS resolution is post-boot** and must be allocation/deallocation-free (`alumina.md:64,150,206,230`).
- **T3 memory reading:** 128 MiB is **tunnel traffic storage only**. The invariant forbids heap alloc/dealloc during serving/refresh; it does **not** imply constant total memory use — kernel/RSS/virtual memory vary and are reported separately (`alumina.md:143,183,206`).

**Boot-time allocation inventory (artifact G1).** All application storage allocated before serving; stack usage bounded (`alumina.md:142-143,150`):

| Allocation | Size formula | Citations |
|---|---|---|
| Tunnel traffic buffers | 128 slots × 2 × 512 KiB = **128 MiB** | `alumina.md:160-162,183` |
| Config document buffer | 4096 B (reject oversized, no truncation) | `alumina.md:54,158` |
| CONNECT parse buffer | ≤8 KiB | `alumina.md:163` |
| TLS pre-auth buffer | ≤64 KiB incl. framing | `alumina.md:164` |
| DNS message/records | 16 KiB / 128 records staging | `alumina.md:165` |
| Cache entries | ≤32 names × 2 types; 16 IPv4 (A) + 16 IPv6 (AAAA) address slots per name, deadlines + generation per entry | `alumina.md:74,166` |
| Reporting storage | 32 name/window + 64 incident + 128 tunnel window markers | `alumina.md:177` |
| Log queue | 256 × 8 KiB | `alumina.md:178` |
| Ready/timer tables | Fixed slot counts (dup-free queue) | `alumina.md:146` |
| Stacks | Bounded; budget derived from worst-case parse path (16 KiB DNS, CNAME ≤8, label ≤63/name ≤255, **no recursion**) — numeric is a **design artifact** | `alumina.md:143,165,167,183` (G2) |
| mio Poll/Events | Preallocated at boot; operation matrix pinned | `alumina.md:147,206,230` (T2/G4) |

**Outside the 128 MiB budget** (accounted separately for container sizing): DNS storage, connection metadata, stacks, executable memory, kernel socket buffers (`alumina.md:183`).

**Dependency seam (T2/G4).** `mio` + Linux epoll is mandated (`alumina.md:147`); zero-alloc including dependencies (`alumina.md:206,230`) means the plan must pin the exact mio version, enumerate the operations used (Poll construction, registration/reregistration/deregistration, Events retrieval, error/close paths), and gate each on source review plus allocator instrumentation. This is an **early Linux feasibility gate** in [build-plan.md](build-plan.md); `mio`'s steady-state alloc-freedom is not assumed.

## 7. Startup, logging, shutdown

**Startup order** (`alumina.md:64`): privilege/caps/`no_new_privs` prerequisite → configuration + resolver reads → storage initialization → DNS startup window → listener open. After storage init, an absolute 90 s monotonic deadline is set before the first DNS connect; each exchange is clipped to it; only fully validated, published results strictly before the deadline count (`alumina.md:64-65`). Open early only when all names are usable; at the deadline evaluate once: serve if unresolved ≤ `startup_unresolved_allowance`, else EX_TEMPFAIL 75 (`alumina.md:56,65`). Degraded serving applies only at startup; no readiness endpoint (`alumina.md:66`). Startup diagnostics: exactly **one** warn enqueue attempt on first exchange failure across all names/types; per-type incidents tracked with suppressed first-failure warnings; one final result with full/degraded/failure status; suppressed warnings never replayed at serving (`alumina.md:67`).

**Logging** (`alumina.md:178-179,193-194`): structured allocation-free records with escaped text within 8 KiB; whole-record drop + count (never truncate); nonblocking sink drained under the per-turn budget with partial-write preservation; a stalled sink must not delay rejection, tunnel I/O, DNS, or deadlines. Threshold: attempt an error entry when tunnel slots, pending setups, or log queue usage **first exceeds 80%**, and again when usage **falls below 70%** (`alumina.md:193`); one warn per rejected connection (client address, reason, hostname when valid); one warn per early-upstream-activity close (hostname, peer, kind). Logs go to stdout only (`alumina.md:149`).

**Shutdown** (`alumina.md:150,192`): SIGTERM is the only handled signal; stop accepting, start 8 s grace, drain, close sockets, **exit without deallocating**. No reload of configuration; catchable administrative signals cannot change policy (IV + `alumina.md:149`). `panic = "abort"` with `unwrap()`/`expect()` excluded from production paths; expected I/O errors handled explicitly (`alumina.md:148`).

## 8. Deployment and trust boundary

Alumina is responsible for the egress it provides; VPC isolation is deployment-scoped (`alumina.md:99-101`). Runtime prerequisites: minimal Linux container holding only the statically linked binary + config + resolver config; no shell/package manager/other executables; non-root, empty caps sets, `no_new_privs`, read-only rootfs, no writable/secret volumes, no cloud permissions, no credentials (`alumina.md:118,150`). Confinement must default-deny application egress except Alumina + required platform/internal dependencies, with no alternate HTTPS path, across all routes and families (`alumina.md:116`). Exactly one listening socket; CONNECT listener is the only runtime surface; no control plane/health/metrics/debug/reconfig; configuration read once (`alumina.md:149,235`). Deployment supplies raw TCP and the platform resolver; no NAT64/DNS64 in the egress path (`alumina.md:101,116`).

## 9. Explicit non-goals

UDP/QUIC, HTTP/2 CONNECT to the proxy, plain HTTP forwarding, transparent interception, TLS <1.3, ECH support, HTTPS/SVCB endpoint substitution, DNS over TLS/HTTPS, local recursion or follow-up queries, multi-worker data paths, control plane or readiness/health/metrics surface, DNS64/NAT64 compatibility, upstream authentication or TLS certificate verification (clients verify), general compatibility negotiation or automatic fallback (`alumina.md:19,49,63,71,72,97,144,149`).

## 10. Unresolved proof obligations (explicit, honest)

1. **mio/dependency zero-alloc proof** — requires pinned version + operation matrix + allocator instrumentation on Linux (T2/G4); open gate.
2. **Generation/window-id alias + wrap nonreuse** — design artifact only; open gate (G3; `alumina.md:81,212`).
3. **Gate-ordering online proof** — the D3 transition must survive partial writes, budgets, combined readiness, and expiry under deterministic fault injection once the dispatcher exists (`alumina.md:226`). This document's transition model is paper-level orientation (q28 stress-test), not runtime confirmation.
4. **Stack bound** is derived, not measured (G2).
5. **Throughput 1–10 Gbps and all Linux epoll/alloc/confinement claims** are unverified on macOS and unverified at runtime until Linux release gates pass (`alumina.md:185,236`; deployment bounds `alumina.md:233-236`).

Cross-map: [build-plan.md](build-plan.md) for slice/gate execution, [traceability.md](traceability.md) for the complete section/invariant/resource/verification matrix.
