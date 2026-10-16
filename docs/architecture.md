# Alumina — Architecture

**Status:** design statement for the as-built implementation at HEAD `8934adb`
(foundation, boot, wired single-owner serving runtime; provisional parser
layer). This document is **not** runtime proof — qualification is gated on the
Linux acceptance gates in [build-plan.md](build-plan.md) and the proof matrix
in [traceability.md](traceability.md). **Canonical source:** `docs/alumina-proxy.md` is
the sole governing specification (no accepted ADRs). Where this document
defines a boundary the spec leaves open, it is a **named design decision
(D1…Dn)**, never a policy change or security relaxation.

## 1. Governing invariants (invariant-led design)

The fixed-profile invariants I-1…IV-5 name the design element each enforces;
the full invariant → design-element/proof-status matrix is owned by
[traceability.md §2](traceability.md#2-invariant-matrix-all-13).

## 2. Module & ownership decomposition

Single binary crate, one worker thread, no async runtime (`:140,147`); **all
post-boot state is preallocated** (§6).

| Module | Owns (mutating authority) | Citations |
|---|---|---|
| `config` | Parsed config, startup validation; EX_CONFIG 78 | `:54,56,58,60` |
| `resolver` | Resolver-config read (first NS, port 53); DNS TCP transport (1 conn/1 query, getrandom TIDs) | `:62,68` |
| `dns_parse` | Wire parsing + staging classification (bounded CNAME, negatives, eligibility) | `:69,71,73,86-97` |
| `cache` | Per-name×type entries, generations, staging, refresh due table, retry/incident, reporting; **tunnels never hold cache refs** | `:74-82,145` |
| `tunnel` | 128 slots; per-slot state machine; two 512 KiB buffers; per-family counts | `:82,145,160,183` |
| `parse` (CONNECT/CH) | Incremental CONNECT (8 KiB) + ClientHello (≤64 KiB) parsers, residual state, original bytes | `:34,41,47-50,163-164` |
| `worker` / `Runtime` | The single owner loop: readiness demux, scheduling, timers, gate transitions — realized as the shared-readiness `Runtime` | `:138,144,146,147,149` |
| `log` | 256×8 KiB preallocated queue; allocation-free encode; nonblocking sink; drop+count | `:149,178-179,193-194` |
| `lifecycle` | SIGTERM, shutdown grace, drain; exit without deallocating | `:149,150,181,192` |
| `enforcement` | rp2e tripwire/action/monitoring surface (`[any_illegal]`/`[actions]`), per-domain Action, bounded stdout monitoring, control state | `:238-315` (amendment) |

> **As-built realization.** `src/main.rs` is the single boot owner: preallocate
> serving workspaces → startup DNS window (`run_startup`) → on a Serve decision
> attach the listener and enter `Runtime::serve` (`src/runtime.rs`); one poll
> observes DNS freshness and traffic readiness, and the cooperative turn starts
> due DNS exchanges itself (`main.rs:80-91`; `starts_due_dns_if_idle`
> `runtime.rs:246-280`). Provisional parsers live in
> `src/{dns,connect,client_hello,startup_dns}.rs`; the rp2e tripwire/action/
> monitoring surface lives in `src/enforcement/{mod,action,monitor,policy,state}.rs`
> with the validated `[any_illegal]`/`[actions]` config schema enforced in
> `src/config.rs`. The serving owner is decomposed as `src/serving/{policy,reject,startup,tests}.rs`
> (fixed Refusal policy mapping, rejection effects, startup window, sibling
> test module) and the shared-readiness/runtime and startup-DNS test modules live
> at `src/runtime/tests.rs` and `src/startup_dns/tests.rs`. Buffer reuse is D5b.

## 3. Single-worker scheduling model

Fair round-robin with a **64 KiB-or-16-op per-visit budget** (D6); timer recheck
every ≤256 ready-slot visits; unfinished work reschedules without a new
readiness edge; ready queue duplicate-free by construction (D7) — the
application-owned queue of `:146`; deadlines checked against monotonic clock
before any completion transition (`:146,147`).

## 4. Tunnel state machine and legal transitions

Tunnel state is a Rust enum; **illegal transitions are unrepresentable**, not
merely rejected (IV-1).

```
ACCEPT → READ_CONNECT → (400/403 before 200 begins) → CLOSE
                 ↓ AUTHORIZED (allowlisted, 443)
        CONNECTING_UPSTREAM (revalidate per attempt, ≤4×2 s clipped to 10 s; 502/504)
                 ↓ SENT_200 (successful CONNECT completed)
        VALIDATING_CLIENTHELLO (≤64 KiB)
                 ↓ GATE_OPENING (write-accounting transition)
        RELAY_ACTIVE → DRAINING (first orderly EOF) → CLOSE
        (after 200 begins: any error closes, no injected response, no TLS alert)
```

Named decisions:

- **D1 response-begin.** `ResponseBegin` ≠ `ResponseComplete`; before 200
  begins failures may send HTTP error, once begun they close with no injected
  response/alert; only a *completed* 200 permits ClientHello inspection.
- **D2 two barriers.** A: no client bytes before full validation (SNI
  normalized-equal to approved hostname). B: no upstream bytes before the gate
  opens (`:201`).
- **D3 gate-opening.** The gate opens **in the same worker transition whose
  successful local-write accounting reaches the end of the validated
  ClientHello (H), before any subsequent upstream read** (`:32`); a crossing
  write forwards trailing `X` from the open point; local-write success ≠ remote
  receipt; arrival ordering never inferred after open.
- **D4 early-activity.** While B is closed the worker may do upstream I/O;
  actual data/EOF/reset terminates setup (metadata-only warn); WouldBlock/
  readiness is not activity.
- **D5 accounting.** Forwarded bytes advance only on successful writes; partial
  writes preserve order (`:32,80,146-147,220`). **D5a** exactly two per-family
  counters (A/AAAA) per connecting tunnel, never addresses/refs (`:82`).
  **D5b** two 512 KiB buffers reused across CONNECT/ClientHello/relay without
  discarding coalesced bytes; relay buffers never enlarge setup limits.

Lifetimes (`:189-192`): setup deadline starts at accept, never reset; connect
deadlines clipped to it; idle starts at gate open, reset only on successful
writes; first EOF starts the never-reset 5 s drain; SIGTERM stops accepting +
8 s grace (never extended); resources released exactly once; exit without
deallocating.

## 5. Generations, lifetimes, and anti-alias (T7/T1-merged domains)

Four domains must **not** be merged (`:212`):

| Domain | Owner | Invalidation rule | Reuse proof status |
|---|---|---|---|
| G1 Tunnel-slot generation | `tunnel` | Connection-scoped state; reuse must never make stale work valid | **design artifact**; nonreuse proof open gate |
| G2 Cache-entry generation | `cache` | Advances on replacement/eviction; rejects obsolete | per-op tag; part of cache slice |
| G3 DNS non-connection lifetime | `cache` | Refresh results not connection generations; no cache refs | structural |
| G4 Reporting window id | `cache` | Ids not reusable while a live tunnel retains one; counters saturate | **design artifact**; proof open gate |

A wide integer is not a nonreuse proof; width/exhaustion are recorded artifacts
with construction-and-reuse proof as a future gate.

## 6. Fixed storage and the zero-allocation model

- **T1 boot boundary:** boot init = privilege + config + resolver reads +
  storage/facility init; startup DNS is post-boot and allocation/deallocation-
  free (`:64,150,206,230`).
- **T3 memory reading:** 128 MiB is **tunnel traffic storage only**; the ban on
  heap alloc/dealloc during serving/refresh does not imply constant total
  memory — process/kernel memory reported separately (`:143,183,206`).

| Allocation | Size | Citations |
|---|---|---|
| Tunnel traffic buffers | 128 × 2 × 512 KiB = 128 MiB | `:160-162,183` |
| Config document buffer | 4096 B (reject oversized) | `:54,158` |
| CONNECT / TLS pre-auth | ≤8 KiB / ≤64 KiB | `:163-164` |
| DNS message/records staging | 16 KiB / 128 RRs | `:165` |
| Cache entries | ≤32 names × 2 types, 16 A + 16 AAAA per name | `:74,166` |
| Reporting storage | 32/64/128 markers | `:177` |
| Log queue | 256 × 8 KiB | `:178` |
| Ready/timer tables | Fixed slot counts (dup-free) | `:146` |
| Stacks | Bounded worst-case (no recursion); numeric a **design artifact** | `:143,165,183` |
| mio Poll/Events | Preallocated at boot; op matrix pinned | `:147,206,230` |

**Outside the 128 MiB budget** (separately accounted): DNS storage, metadata,
stacks, executable, kernel socket buffers (T3; traceability U7).
**Dependency seam (T2/G4):** `mio`+epoll mandated (`:147`); pin version,
enumerate operations, gate each on source review + allocator instrumentation
(build-plan F3) — mio steady-state alloc-freedom is not assumed.

## 7. Startup, logging, shutdown

**Startup** (`:64-67`): privilege → config+resolver → storage → 90 s startup
DNS window (exchanges clipped) → listener open; open early only when all names
usable; at deadline serve if unresolved ≤ allowance else EX_TEMPFAIL 75; no
readiness endpoint; one first-failure warn, suppressed per-type first warnings,
one final result. **Logging** (`:178-179,193-194`): allocation-free records ≤8
KiB escaped, whole-record drop+count (never truncate), nonblocking drain under
per-turn budget with partial-write preservation; a stalled sink must not delay
rejection/tunnel I/O/DNS/deadlines; one warn per rejection and per
early-activity close; stdout only. **Shutdown** (`:150,192`): SIGTERM only →
stop accepting, 8 s grace, drain, exit without deallocating; `panic="abort"`;
`unwrap()/expect()` excluded from production paths.

## 8. Deployment and trust boundary

Alumina is responsible for the egress it provides (`:99-101`); VPC isolation is
deployment-scoped. Runtime prerequisites (`:118,150`): minimal `FROM scratch`
container holding only `/alumina` (statically linked musl binary),
`/config.toml`, and `/resolv.conf`; non-root (`65534:65534`), empty caps
(`--cap-drop ALL`), `no_new_privs` (`--security-opt no-new-privileges`),
read-only rootfs (`--read-only`), no writable/secret volumes, and a dedicated
appliance identity holding no application secrets or credentials. Confinement
default-denies workload egress except to Alumina's private VPC endpoint
(`tcp:5353`) + explicitly required non-HTTPS platform dependencies across all
routes/families (`:116`), including removing default Private Google Access
(`199.36.153.8/30:443`) bypasses when unused; exactly one listening socket;
config read once; raw TCP + a TCP-capable recursive resolver supplied (`:68`);
no NAT64/DNS64 in the egress path (`:101,116`).

- **Separate VPC appliance vs same-pod sidecar:** Because serverless
  multi-container sidecar sandboxes share a single network namespace
  (`CLONE_NEWNET`), VPC firewall identity, and pod restart lifecycle without
  per-UID `CAP_NET_ADMIN` packet filtering, a same-pod sidecar cannot prevent an
  RCE-compromised workload container from bypassing `HTTPS_PROXY` via direct
  `connect(2)` syscalls or resetting in-memory `Block Domain` / `Block All`
  latches by crashing the pod. Positive locking under RCE requires hosting
  Alumina on a separate network-tagged VPC appliance (e.g. a locked-down
  Container-Optimized OS instance with `--network host` at a static internal
  VPC IP; see [README.md](../README.md#reference-vpc-appliance-deployment-pattern)).

## 9. Explicit non-goals

UDP/QUIC, HTTP/2 CONNECT, plain HTTP forwarding, transparent interception,
TLS<1.3, ECH, HTTPS/SVCB substitution, DNS over TLS/HTTPS, recursion/follow-up
queries, multi-worker data paths, control plane / readiness / metrics surface,
DNS64/NAT64 compatibility, upstream auth or cert verification, automatic
fallback (`:19,49,63,71,72,97,144,149`).

Cross-map: [build-plan.md](build-plan.md) for slice/gate execution and the
open qualification gates; [traceability.md](traceability.md) for the complete
matrix and unresolved-evidence ledger.
