# Alumina — Refinement Register

Material potential normative choices — canonical readings an implementer could
contest that point toward a change to canonical [`docs/alumina-proxy.md`](docs/alumina-proxy.md) and
need an explicit user decision. Not canonical: `docs/alumina-proxy.md` is the sole
governing spec; nothing here amends it.

## Status

**None currently justified** — each candidate that arose was an explicit
requirement plus its qualification gap (e.g. the 128 MiB traffic-only reading
of `docs/alumina-proxy.md:161-164,183`; proof at build-plan Slice 6, traceability §5) or
engineering proof-scope carried by docs/build-plan.md / traceability.md;
witnesses stay in bd history.

## Deferred material decisions (evidence triggers)

Acknowledged surfaces; no change is currently justified. Each needs an
explicit design revision and user decision when its trigger is met.

| Surface | Fixed baseline | Decision trigger (evidence condition) |
|---|---|---|
| TLS 1.3-only (`docs/alumina-proxy.md:47`) | Compatibility profile, not a security control; no measured client mismatch yet. | A measured trusted-client mismatch that demands compatibility. |
| Zero allocation **and** deallocation post-boot (`docs/alumina-proxy.md:206`,`:150`) | Stricter than bounded memory; excludes routine heap-owned drop paths; retained heap storage is not deallocated on exit. | Observed impossibility of the current reading or a material cost it imposes. |
| Cloud Run Direct VPC / raw-TCP ≤1 Gbps initial target (`docs/alumina-proxy.md:136`) | Platform network limit independent of CPU; no external guarantee established here. | Measured deployment bounds that change the practical ceiling (build-plan §7). |
| accept-path fd-exhaustion (`docs/alumina-proxy.md:193`) | Hot-loop avoidance and bounded acceptance work are ordinary engineering under the current contract. | A shed/backoff policy above that is a **new design decision** (needs a D-letter); revisit only on measured material fd-exhaustion with capacity/security/cost effects. |

## Maintenance

On each new material discovery, add an entry (advance the RF-ID sequence)
citing the actual canonical text read; re-run the full affected-corpus offline
link check plus `sh scripts/verify.sh docs` (command set in
[docs/verification.md](docs/verification.md)).
