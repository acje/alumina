# Alumina — Refinement Register

> Role and authority: this register is a normal versioned working document
> maintained for user review. It records issues and opportunities discovered
> during implementation, together with minimal clarification candidates. It is
> **not** canonical: [alumina.md](alumina.md) (repository root) remains the
> sole governing specification. Recommendations here never amend the canonical
> spec; canonical changes need an explicit design revision and user decision.
>
> Status: open working register. No runtime completion claim is made by this
> document; serving code qualification gates remain open (see `docs/build-plan.md`
> §2, checkout-local planning evidence).
>
> Authority: user directive 2026-10-10 (`bd alumina-01us`); carries reviewed
> diagnostics `bd alumina-bx9y`, `bd alumina-fpsd`, `bd alumina-lpbw` and
> evidence `bd alumina-6mt0`. Maintain this register when new material
> discoveries arise.

**Checkout-local evidence.** Citations to `docs/architecture.md` (D1–D7) and
`docs/build-plan.md` (gates F0–F4, slices) reference planning documents present
in this working tree but **not yet published** in the repository tree at the
time of writing; their text is consumed and verified as checkout-local evidence
only, not as published artifacts. The canonical root
[alumina.md](alumina.md) is the sole published specification. Any doc-only
publication of this register requires those planning documents to be published
first or their references re-qualified; this register must not carry
hyperlinks that resolve only against the working tree.

## KEEP policy

The following are intentional fixed-profile requirements. They are recorded
here for review completeness and are **not** open for weakening through this
register. Any change requires an explicit design revision and a user decision,
never a clarification comment.

| Reference | Intentional requirement (actual canonical text) |
|---|---|
| `alumina.md:5` | Golden-path profile only. "Environments whose complexity or technical debt prevents adopting this profile should use a more capable alternative, such as GCP Secure Web Proxy." **Protected servers must conform to Alumina or choose a different proxy.** |
| `alumina.md:19`,`:47` | HTTPS over TCP only; TLS 1.3-only profile (`0x0304`); "TLS 1.2 and earlier profiles, plain HTTP forwarding, HTTP/2 CONNECT to the proxy, UDP/QUIC, and transparent interception are unsupported." TLS 1.3-only is a golden-path profile requirement, not an added security control. |
| `alumina.md:48-49` | Exactly one `server_name` extension with one hostname entry matching the approved CONNECT hostname; "Reject the `encrypted_client_hello` extension, including ECH GREASE, regardless of outer SNI"; never strip or rewrite extensions. |
| `alumina.md:61`,`:71`,`:73` | Exact-name comparison; DNS public-IP/provenance: IN A/AAAA only, rooted CNAME ≤8 links, no DNAME, no follow-up queries; destinations must be globally routable unicast; table fixed at build time. |
| `alumina.md:206` | "While serving traffic or refreshing DNS, proxy execution paths, including dependencies, must not allocate or deallocate heap storage." |
| `alumina.md:152-185` | Fixed resource profile: 4 KiB config / 1 worker / 128 tunnels incl. ≤32 pending / two 512 KiB buffers per tunnel / 128 MiB total / 10s-2s-300s-5s-8s deadlines. |
| `alumina.md:149`,`:235` | No control plane, health, metrics, debug, or reconfiguration interface; one listening socket; SIGTERM is the only handled lifecycle signal. |

## Suppressed expansion proposals

The following were surfaced during diagnostics and are intentionally **not**
carried as register recommendations (per authority 2026-10-10). Recording them
here makes their absence an explicit decision, not an omission:

- TLS 1.2 (or broader) version-profile acceptance.
- ECH acceptance, real or GREASE.
- Additional configuration control surface / per-connection policy options.
- Health / readiness / metrics endpoint (runtime surface stays one listener).
- Multithreaded / multi-worker data path.

## Binding implementation defects

These are actual implementation findings against the current contract — review
friction driven by source violating satisfiable positive invariants, not spec
overconstraint (`bd alumina-fpsd` H1; `bd alumina-xz3f` N1–N8). They are
implementation work under the existing canonical profile, listed for
traceability so follow-up does not relitigate their binding. The rows are
deliberately heterogeneous and labeled per row: RF-001–RF-005 and RF-008 are
demonstrated defects/divergences with source witnesses; RF-006–RF-007 are
engineering guidance under binding invariants; RF-009–RF-010 record open
qualification and proof-scope gaps, not finished claims.

| ID | Category | Source witness | Current impact | Recommended minimal clarification | Owner | Status | Verification next step |
|---|---|---|---|---|---|---|---|
| RF-001 | Gate phase (Barrier B) | `alumina.md:32`,`:201`; `docs/architecture.md` D3/D4 (`:79-80`); `bd alumina-bx9y` | Upstream→client gate must open in the same trusted transition whose successful local-write accounting reaches end of validated ClientHello (H), before any subsequent upstream read; fast responses first observed after opening are **not** early activity; second ClientHello after HelloRetryRequest stays opaque (no second-CH validation expansion). | Restate D2–D4: gateway opens atomically in that write-accounting transition; classify actual upstream activity handled while closed without inferring arrival time after opening. | Engineering | Open (implementation + review) | `build-plan.md` Gate F2 deterministic fault injection of gate transitions (Slice 4); TLS 1.3 interop for fragmentation/HRR/fatal alerts (`alumina.md:226`). |
| RF-002 | Lifecycle / paused-source resume | `alumina.md:213` (Bounded-Work), `alumina.md:146`; `bd alumina-fpsd` H1/N3; `bd alumina-lpbw` A1 | Paused source is not resumed on sink drain: bytes stay in the source socket and progress stops, holding a graduated tunnel with no deadline. | Positively retain paused source work until sink space returns; resume without requiring a new readiness edge (engineering mechanism, not canonical change). | Engineering | Open | Host relay test pins N3 (sink-drain resumes source); F2-scripted `WouldBlock` then writable-only drain. |
| RF-003 | Closure / half-close | `alumina.md:191`,`:220`; `bd alumina-fpsd` N2; `bd alumina-lpbw` A2/C2 | Orderly EOF closes the whole slot instead of draining the direction and half-closing the peer write; reverse traffic must continue. Byte conservation on normal completion is binding. | First orderly EOF starts the 5 s drain deadline (never reset); drain that direction, `shutdown(Write)` the peer; close at both-EOF-drained or deadline; release exactly once. | Engineering | Open | Host relay test pins N2 (relay client FIN drains accepted bytes); Linux `read_closed`→EOF interpretation re-proven on native gate. |
| RF-004 | Timers / wakeup strategy | `alumina.md:221` (Deadline invariant), `alumina.md:146`; `docs/architecture.md:52` (trigger mode left open); `bd alumina-fpsd` CLARIFY-Timers (`bd alumina-lpbw` A4) | With zero readiness events on an established tunnel, timers must still fire: the earliest applicable deadline must trigger a wakeup (a capped poll timeout is one ordinary mechanism, not the only one); the current re-expiry path can zero-spin. | When no work is ready, arrange a wakeup by the earliest applicable deadline; a capped poll timeout is one ordinary mechanism, not the only one. | Engineering | Open | Deadline checks immediately before/at/after expiry incl. delayed timer delivery (Slice 5; `alumina.md:227`). |
| RF-005 | Response-expiry | `alumina.md:30`,`:190`; `bd alumina-xz3f` N5; `bd alumina-lpbw` A3 | Setup expiry can unconditionally rewrite an already-begun response from offset zero (spliced body); once a 200/body begins, failures must close without injecting another HTTP response or TLS alert. | An already-begun response is never replaced; expiry after successful-response begin closes. Gate `refuse()` on the response-begin boundary (D1). | acje + Engineering | Open | F2 expiry injected at/after 200-begin and 200-complete; assert no rewrites after begin. |
| RF-006 | RAII / fixed-slot release | `alumina.md:150`,`:192`,`:206`; `bd alumina-fpsd` CLARIFY (RAII) | Release must return sockets and fixed slots; it must not release heap storage. Heap-owned long-lived storage is retained through process exit; dropping owned errors must not violate the serving-phase alloca/dealloc ban. | Post-boot resource release may close sockets and return fixed slots; it must not release heap storage. RAII alone is not forbidden; verify dependency drop paths. | Engineering | Open | Gate F1 allocator witnesses for serving + shutdown phases (Slice 6); dependency operation/error inventory. |
| RF-007 | Test seams / runtime surface | `alumina.md:149`,`:235`; `bd alumina-fpsd` CLARIFY (QA) | Focused tests need private seams without exposing a runtime interface or smuggling public API changes in as testability. | Test-only private transport/clock seams are not runtime interfaces; no health endpoint is needed for operator assurance (operator check = CONNECT + authenticated TLS). | acje | Open | Runtime-surface gate (`alumina.md:235`): exactly one listening socket; no control/metrics surface. |
| RF-008 | Buffer profile / 128 MiB | `alumina.md:161-164`,`:183`; `bd alumina-lpbw` C1; `bd alumina-6mt0` | Current traffic storage is 72 KiB+64 KiB per slot (~17.4 MiB aggregate), not the mandated two 512 KiB buffers per tunnel (128 MiB). 128 MiB is tunnel traffic storage, not total RSS; shipping the mandated profile is a real container-footprint cost. | Implementing the mandated buffers is approved engineering; changing slots/buffers/limits is a user decision. Report process/kernel memory separately from the traffic budget. | acje (user decision) + Engineering | Open (divergence recorded) | Resource-profile gate (Slice 6): verify the 128 MiB allocation and buffer reuse; report traffic budget vs RSS separately. |
| RF-009 | Harness fitness / proof scope | `bd alumina-6mt0` §5-6; `bd alumina-fpsd` H4 | Focused parser/policy tests do not establish real socket-owner correctness; host proof must be exact-input for the current revision; `mio` debug-vs-release behavior is a separate harness concern. | Register exact-input gate evidence (build, workload, machine, date) at commit time; BOUNDARY = repo-native owner runs the complete stable-candidate gate (incl. native Linux dispatch; `flock-vm` connection reachability observed, dispatch/build unobserved as of 2026-10-10). | Engineering | Open | Exact-input INNER/MID/BOUNDARY evidence on the commit-time revision; `flock-vm` connection reachability observed via `podman --connection flock-vm info` only — verification dispatch and image/build success unobserved → BOUNDARY proof before any serving done-claim. |
| RF-010 | Native Linux proof | `bd alumina-lpbw` U-F1/U-F2; `bd alumina-6mt0` §4 | No native Linux runtime/allocator/epoll/RDHUP evidence exists for the current serving source; `main` exits `EX_SOFTWARE 70` ("serving loop not implemented in phase 1"). This register makes no runtime completion claim. | Serving code has no done-claim until build-plan gates F0–F4 + deployment/E2E pass on Linux; native feasibility stays a stated open gate, not a host-alt consequence. | Engineering | Open | Native Linux gates per `build-plan.md` §2/§7 + deployment confinement / initial deployment (Slices 7). |

## Specification ambiguities — minimal clarification candidates (no canonical edit)

These are surfaces where the binding text does not positively name the
mechanism (open rows) or where a candidate restates an already-explicit
boundary (restatement rows); each row states its status. The candidate wording
is offered for potential future clarification, never as a spec change in
itself.

| ID | Reference | Ambiguity | Minimal clarification candidate | Owner | Status |
|---|---|---|---|---|---|
| RF-011 | `alumina.md:146`,`:190`,`:213` (Bounded-Work/scheduling); `bd alumina-lpbw` A1 | No canonical sentence positively names the paused-source resume mechanism; liveness under edge-triggered readiness depends on it. Resume is a mechanism left to engineering under the existing Bounded-Work obligation, not an unresolved contract gap. | "Retain paused source work until sink space returns; resume without requiring a new source readiness edge." (`bd alumina-fpsd` CLARIFY-Progress) | Engineering | Open (mechanism owned by engineering) |
| RF-012 | `alumina.md:30`, `:221`; `docs/architecture.md:77` (D1); `bd alumina-lpbw` A3 | Canonical `alumina.md:30` and D1 already define the response-begin boundary (ResponseBegin vs ResponseComplete); the 504 splice is an implementation defect, not a missing normative ordering. Offered as an optional restatement of an explicit boundary, not as a spec gap. | "An already-begun response is never replaced; expiry after successful-response begin closes." (`bd alumina-fpsd` CLARIFY-Response) | acje | Restatement of explicit boundary (no ambiguity) |
| RF-013 | `alumina.md:82` | Alternation vs exact per-family counters (resolved permitting). | Lifecycle-family fact carried in the Connecting-phase transition input, never a stored attempt-record field; exactly two counters per tunnel, one for A and one for AAAA. (`bd alumina-ufrw`; `bd alumina-fpsd` H2) | Engineering | Accepted (permitting reading) |
| RF-014 | `alumina.md:146`,`:221` | Trigger mode for deadline wakeups is spec-open. | "When no work is ready, arrange a wakeup by the earliest applicable deadline." A capped poll timeout is one ordinary mechanism. (`bd alumina-fpsd` CLARIFY-Timers) | Engineering | Open |

## Factual confidence notes (open qualification)

These are cost/deployment/qualification items where confidence is recorded
factually and separately from the defect entries. A row citing a code witness
is a demonstrated defect under ordinary engineering, not a profile-cost
opinion. User decision gates any change to the listed profile choice.

| Reference | Item | Confidence note |
|---|---|---|
| `alumina.md:47` | TLS 1.3-only | Compatibility profile, not a security control; no measured client mismatch yet. Any relaxation is a user decision. |
| `alumina.md:206`,`:150` | Zero allocation AND deallocation post-boot | Stricter than merely bounded memory; excludes routine heap-owned drop paths. No measured impossibility supports relaxation. |
| `alumina.md:161-164`,`:183` | 128 MiB fixed traffic storage | Fixed storage, not measured throughput or total RSS; implementing mandated buffers is approved, changing limits is a user decision. |
| `alumina.md:62-82`,`:128-130` | DNS golden-path (TCP-only, stale grace 72 h, no NAT64/DNS64) | Explicit golden-path tradeoffs; change only against observed necessary compatibility/security/availability evidence. |
| `alumina.md:136` (deployment) | Cloud Run worker-pool raw-TCP / Direct VPC (≤1 Gbps) initial target | Platform network limits independent of CPU; no external Cloud guarantee established here. |
| xz3f N6 / `alumina.md:193` | accept() EMFILE / fd-exhaustion | Hot-loop accept witness (xz3f N6): avoiding the hot loop and bounding acceptance work are ordinary engineering under the current contract. A shed/backoff policy above that is a new design decision (needs a D-letter); user involvement is conditional on material availability, capacity, security, or cost effects (`bd alumina-bx9y`, `bd alumina-fpsd`). |

## Maintenance

On each new material discovery during implementation, add a register entry
(advance the RF-ID sequence), keep KEEP/suppressed blocks current, and cite the
actual text read. There is no per-tool bureaucracy: update in the same
increment that surfaces the discovery, and re-run the doc-native validator.
