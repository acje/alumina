# Alumina — Refinement Register

> Role and authority: a normal versioned working document for user review,
> recording **material potential normative choices** — canonical readings an
> implementer could contest that point toward a change to canonical
> [alumina.md](alumina.md) and need an explicit user decision. It is **not**
> canonical: `alumina.md` (repository root) is the sole governing
> specification. Recommendations here never amend the canonical spec;
> canonical changes need an explicit design revision and user decision.
>
> Status: open, kept concise. No runtime completion claim is made here;
> serving-code qualification gates remain open (build-plan §2/§7; traceability
> §5). Implementation defects, engineering mechanisms and qualification
> proof-scope are carried by their durable owners — `docs/architecture.md`
> (decisions D1–D7, §4) and `docs/build-plan.md` (gates F0–F4, Slices 1–7,
> §7) — and their original witnesses remain in bd history. The register does
> not duplicate them.
>
> Authority: user directive 2026-10-10 (`bd alumina-01us`); reviewed
> diagnostics `bd alumina-bx9y`, `bd alumina-fpsd`, `bd alumina-lpbw`,
> `bd alumina-xz3f`; evidence `bd alumina-6mt0`. Maintain this register when
> new material discoveries arise.

## KEEP policy (unchanged fixed profile)

Intentional fixed-profile requirements, **not** open for weakening through this
register; change requires an explicit design revision and user decision, never
a clarification comment.

| Reference | Intentional requirement (actual canonical text) |
|---|---|
| `alumina.md:5` | Golden-path profile only; protected servers must conform to Alumina or choose a different proxy. |
| `alumina.md:19`,`:47` | HTTPS over TCP only; TLS 1.3-only profile (`0x0304`); TLS 1.2-and-earlier, plain HTTP, HTTP/2 CONNECT, UDP/QUIC, transparent interception unsupported. TLS 1.3-only is a golden-path profile requirement, not an added security control. |
| `alumina.md:48-49` | Exactly one `server_name` with one hostname matching the approved CONNECT hostname; reject `encrypted_client_hello` incl. ECH GREASE regardless of outer SNI; never strip or rewrite extensions. |
| `alumina.md:61`,`:71`,`:73` | Exact-name comparison; DNS A/AAAA only, rooted CNAME ≤8, no DNAME, no follow-up queries; globally routable unicast destinations; table fixed at build time. |
| `alumina.md:206` | "While serving traffic or refreshing DNS, proxy execution paths, including dependencies, must not allocate or deallocate heap storage." |
| `alumina.md:152-185` | Fixed resource profile: 4 KiB config / 1 worker / 128 tunnels incl. ≤32 pending / two 512 KiB buffers per tunnel / 128 MiB total / 10s-2s-300s-5s-8s deadlines. |
| `alumina.md:149`,`:235` | No control plane, health, metrics, debug or reconfiguration interface; one listening socket; SIGTERM the only handled lifecycle signal. |

## Suppressed expansion proposals

Surfaced during diagnostics and intentionally **not** carried (per authority
2026-10-10); recorded so their absence is an explicit decision, not an omission:

- TLS 1.2 (or broader) version-profile acceptance.
- ECH acceptance, real or GREASE.
- Additional configuration control surface / per-connection policy options.
- Health / readiness / metrics endpoint (runtime surface stays one listener).
- Multithreaded / multi-worker data path.

## Material normative candidates

**None currently justified.** No evidenced material canonical change exists at
HEAD `8934adb`; each candidate that arose was either an explicit existing
requirement plus its qualification gap (e.g. the 128 MiB traffic-only reading
of `alumina.md:161-164,183` and separate process/kernel accounting,
`alumina.md:230` — proof tracked at build-plan Slice 6 and traceability
§5/U5,U7), or engineering proof-scope carried by build-plan/architecture.
A change is considered only when a concrete evidence condition in the table
below is met.

## Deferred material decisions (evidence conditions)

Acknowledged surfaces; **no change is currently justified**. Each needs an
explicit design revision and user decision when its trigger is met.

| Surface | Fixed baseline | Decision trigger (evidence condition) |
|---|---|---|
| TLS 1.3-only (`alumina.md:47`) | Compatibility profile, not a security control; no measured client mismatch yet. | A measured trusted-client mismatch that demands compatibility. |
| Zero allocation **and** deallocation post-boot (`alumina.md:206`,`:150`) | Stricter than bounded memory; excludes routine heap-owned drop paths; retained heap storage is not deallocated on exit. | Observed impossibility of the current reading or a material cost it imposes. |
| Cloud Run Direct VPC / raw-TCP ≤1 Gbps initial target (`alumina.md:136`) | Platform network limit independent of CPU; no external guarantee established here. | Measured deployment bounds that change the practical ceiling (build-plan §7). |
| accept-path fd-exhaustion (`alumina.md:193`) | Hot-loop avoidance and bounded acceptance work are ordinary engineering under the current contract. | A shed/backoff policy above that is a **new design decision** (needs a D-letter); revisit only on measured material fd-exhaustion with capacity/security/cost effects. |

## Prior items and their durable owners

Engineering-defect and proof-scope rows from earlier register revisions
(RF-001–RF-007, RF-009–RF-014) were removed from this register **without
evidence loss**: their substance and verification steps are carried by
`docs/architecture.md` (D1–D7, §4 state machine, §5 lifetimes), `docs/
build-plan.md` (F0–F4 gates, Slices 3–6, §7), and `docs/traceability.md`
(§4–5 matrices). Original source witnesses and dispositions remain in bd
history/beads: `alumina-bx9y`, `alumina-fpsd`, `alumina-lpbw`, `alumina-xz3f`
diagnostics; `alumina-6mt0` Q/A evidence; startup-DNS transport rounds
`alumina-4z6b` (round 1, NEEDS WORK — historical) and `alumina-c14m` (round 2,
APPROVED/closed); native candidate receipts `alumina-ucxi`, `alumina-z9m0`.

## Maintenance

On each new material discovery, add a register entry (advance the RF-ID
sequence), keep KEEP/suppressed blocks current, cite the actual text read, and
re-run the **eight-doc offline link check** (including this register):
`node scripts/docs_check/check.mjs README.md alumina.md alumina-refinement.md
docs/architecture.md docs/build-plan.md docs/traceability.md
docs/harness-evaluation.md qa-package/README.md`, plus the native gate
`sh scripts/verify.sh docs`.
