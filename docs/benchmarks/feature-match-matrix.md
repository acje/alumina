# Alumina baseline — selected-benchmark feature match matrix

Source-grounded, **selected-benchmark-config** comparison: Alumina (as-is baseline and proposed to-be) versus HAProxy and Envoy under the accepted 60 s / 100 Mbps TLS workload. This is **not** a product-capability matrix, a security-equivalence claim, or a runtime result. Every candidate cell is **source/manual/config-level positive evidence only**; no candidate configuration was executed for this document and no timed benchmark was run. Policy parity is explicitly **not** claimed (`alumina-et74` T1: wire parity ≠ policy parity; no generic HAProxy/Envoy config establishes Alumina's authorization gates). TLS client-certificate validation between client and endpoint is an endpoint application feature, not a proxy feature, and is not a row.

## Accepted workload boundary

Selected-parameters contract (details preserved in continuation bead `alumina-gjq4`; accepted from the harness contract record `alumina-ojxl` — cited here as a workload contract, not a tool safety or quality endorsement; the harness itself is unreviewed work-in-progress and was not published by this activity):

- 4096 B payload frames / 12 B header; 8 persistent connections; aggregate open-loop pacing 100 Mbps **decimal** client payload (12,500,000 B/s) plus echo; 5 s warmup; 60 s measurement window; setup outside the window; intended 750,000,000 B client payload with disclosed fixed-frame rounding.
- **Monotonic open-loop schedule** (offered rate independent of echo completion); distinct intended / offered / sent / echoed denominators plus `sched_to_echo`, `actual_send_to_echo`, `send_lag`; bounded retention/drain; **operational errors are never "clean"**; no invented 1.31 ms cutoff.
- One worker per proxy; total CPU and thread counts disclosed (auxiliary threads counted); common client/backend placement; no candidate run yet (smoke receipt only, see legend `Q`).

## Candidates

| Candidate | Evidence identity |
| --- | --- |
| **Alumina as-is** | Canonical spec [alumina.md](../../alumina.md) (sha256 `322b68eeb1…`); implementation `src/serving.rs`, `src/client_hello.rs`, `src/gate.rs`, `src/log.rs`, `src/worker.rs`; qualification owner `qa-package/README.md` + `scripts/verify.sh` |
| **Alumina to-be** | [reduced-copy-relay-plan.md](../../docs/reduced-copy-relay-plan.md) `:3-9` — proposed only, planned, not measured; preserves gates/limits (W2/W5/W6/W7) |
| **HAProxy** | Pinned **3.2.25** (LTS); haproxy.org 3.2 manual + sha256-verified tarball `d59a68d0…` (`alumina-722v`, `alumina-elyw`). Chosen comparable setup: TCP-mode near-direct TLS opaque relay — SNI allowlist, fixed backend, one configured thread, CONNECT stage skipped |
| **Envoy** | Selected **envoyproxy/envoy:v1.39.4** (arm64 digest `ce82b213…`); official `terminate_http1_connect.yaml` CONNECT-terminate, raw TCP upstream, `--concurrency 1` (`alumina-elyw`). Image/config/runtime unexecuted (intake only) |

## Legend

Alumina as-is column tags:

| Tag | Meaning |
| --- | --- |
| `R` | Required by canonical spec (`alumina.md:LINE`) |
| `I` | Implemented and enforced, cited to `src/` (`path:LINE`) or evidence bead |
| `Q` | **Narrow executed receipt recorded at current HEAD**: `alumina-ojxl` as-is smoke (`d6a476c`) — real CONNECT through the actual `alumina` binary, real endpoint TLS 1.3 negotiated, byte-exact echo `sent == echoed == offered` (6,103 frames, 2 s smoke). Receipt scope only — **not** full qualification; serving-phase/boundary/fuzz/F1–F3 and the 60 s timed benchmark remain open (`build-plan.md:19-30`; `qa-package/README.md` scoped-testQA status) |

Candidate columns (and to-be) use exactly one grade:

| Grade | Meaning |
| --- | --- |
| `✓ matched (source)` / `✓ matched (config intent)` | Positive source/manual/config evidence of the feature for the selected config; no runtime claim |
| `partial` | A related but altered/weaker form exists in the selected config, with the proven subset named |
| `different` | A materially different mechanism or policy is evidenced for the selected config |
| `unverified` | No positive evidence obtained in this pass; no capability-absence or runtime claim is made (absence ≠ negative) |
| `planned` | To-be proposal only; not measured |

## Matrix

| # | Feature (selected benchmark config) | Alumina as-is | Alumina to-be | HAProxy 3.2.25 | Envoy v1.39.4 |
| --- | --- | --- | --- | --- | --- |
| 1 | CONNECT wire entry (selected happy-path): completed 200 before ClientHello | `R` `I` `Q` | planned | different | ✓ matched (source) |
| 2 | Endpoint TLS 1.3 pass-through — non-terminating, proxy holds no keys | `R` `I` `Q` | planned | ✓ matched (source) | ✓ matched (source) |
| 3 | Proxy-side TLS 1.3-only ClientHello profile | `R` `I` | planned | different | different |
| 4 | Initial SNI inspection / matching CONNECT SNI | `R` `I` | planned | partial | different |
| 5 | Full ClientHello validation (framing, versions, exactly-one SNI, duplicates) | `R` `I` | planned | different | different |
| 6 | ECH rejection (incl. GREASE) | `R` `I` | planned | different | different |
| 7 | CONNECT-hostname allowlist / authorization | `R` `I` | planned | partial | different |
| 8 | Two forwarding barriers (client-before-validation, upstream-before-gate, early data/EOF/reset closed) | `R` `I` | planned | partial | different |
| 9 | DNS provenance / cache-life / destination-address policy | `R` `I` | planned | different | different |
| 10 | Original byte preservation (ordered unmodified prefix) | `R` `I` `Q` | planned | ✓ matched (source) | unverified |
| 11 | Partial-I/O, FIN, backpressure | `R` `I` | planned | unverified | unverified |
| 12 | Bounded resources (fixed limits, reject-on-exhaustion) | `R` | planned | unverified | unverified |
| 13 | No heap alloc/dealloc while serving | `R` | planned | unverified | unverified |
| 14 | Single worker | `R` `I` | planned | ✓ matched (config intent) | ✓ matched (source) |
| 15 | Logging (stdout-only best-effort allocation-free) | `R` `I` | planned | unverified | unverified |
| 16 | Shutdown (SIGTERM-only, bounded grace, no policy reload) | `R` | planned | unverified | unverified |

## By-row source notes

1. **CONNECT wire entry.** Wire-sequence row only; authority validation is row 7. Alumina: completed-200-before-CH required (`alumina.md:19,32`), implemented (`src/serving.rs:1532-1537` Connect→send 200→`Stage::ValidatingHello`, `:1702`), `Q` receipt (real CONNECT, `alumina-ojxl`). HAProxy: native HTTP CONNECT is a relay that enters tunnel only on a 2xx/101 parsed from the backend (`alumina-elyw`: `http_ana.c:2138,2195`; `mux_h1.c:1812-1815`), so no native 200-before-CH against a fixed TLS-only backend; chosen comparable setup skips the CONNECT stage. No broad impossibility claim — evidenced native-path consequence only. Envoy: early-200 synthesized on TCP-pool-ready, before upstream bytes (`upstream_request.cc:73-78`) — **wire-sequence** positive; no authority validation implied.
2. **Endpoint TLS pass-through.** Alumina non-decrypting, never holds keys (`alumina.md:219`); `Q` receipt = real endpoint TLS 1.3 negotiated through the actual binary at as-is smoke, `sent==echoed` byte-exact (`alumina-ojxl`). HAProxy opaque byte relay, no TLS termination, negotiated TLS identical end-to-end is an intent of the direct-TLS topology, not a measured outcome (`alumina-722v`). Envoy raw TCP upstream with no cluster `tls_context` (`alumina-elyw`). All candidates use an **intended common TLS 1.3 client/backend setup**; the actually negotiated endpoint parameters are **unverified** (no runs) and Alumina's CH check does not itself verify endpoint negotiation (`alumina.md:50`).
3. **TLS 1.3-only profile.** Alumina requires a TLS 1.3-only ClientHello (`alumina.md:47`; `src/client_hello.rs:26-27,435,552`). HAProxy `req.ssl_*` fetches parse a complete "SSL v3 or superior" hello with no TLS 1.3-only profile (`alumina-722v`). Envoy performs no CH inspection on the CONNECT path (`alumina-et74`, `alumina-w7y3`).
4. **Initial SNI inspection / matching CONNECT SNI.** Alumina requires exactly one `server_name` equal to the approved CONNECT hostname (`alumina.md:47-48`; `src/client_hello.rs:498,552`). HAProxy `req.ssl_sni` is an initial SNI filter in TCP mode — matches Alumina's initial-SNI filter only, plaintext parse of unverified client data, first-CH-only, ECH-unreliable (`alumina-722v`) → `partial`. Envoy has no CONNECT-SNI matching in the selected CONNECT-terminate path; `tls_inspector` SNI extraction is a separate listener filter disjoint from CONNECT parsing and is not claimed to enforce matching (`alumina-et74`, `alumina-w7y3`) → `different`.
5. **Full ClientHello validation.** Alumina validates framing and record bounds, TLS 1.3-only profile, exactly-one `server_name`, duplicate/ambiguous extension rejection, GREASE skip by length (`alumina.md:47-48`; `src/client_hello.rs` parsing/validation predicates `:345,435,476,498,552`, record limit `:9`). HAProxy: `req.ssl_sni` is a plaintext SNI parse, not full CH validation, with a reliability caveat (`alumina-722v`) → `different`. Envoy: no CH validation on the CONNECT path (`alumina-et74`, `alumina-w7y3`) → `different`.
6. **ECH rejection.** Alumina rejects `encrypted_client_hello` incl. GREASE (`alumina.md:49`; `src/client_hello.rs:59,156`). HAProxy: with ECH only the outer decoy CH is visible and must not be relied on for routing/access decisions (`alumina-722v`) — no ECH rejection. Envoy: no CH inspection, no ECH-reject claim.
7. **CONNECT-hostname allowlist.** Alumina authorizes by approved CONNECT hostname + DNS-bound destination, enforced before forwarding (`alumina.md:40-43,200-202`). HAProxy: TCP-mode SNI allowlist with deny-by-default exists (`alumina-722v` official example) but is not CONNECT-hostname authorization; HTTP-mode CONNECT performs no authority check (`alumina-elyw`, manual §H1) → `partial`. Envoy: CONNECT-terminate dials a configured fixed cluster — benchmark fixture destination, not per-request hostname authorization (`alumina-et74`, `alumina-w7y3`) → `different`.
8. **Two forwarding barriers.** Alumina: no client bytes (incl. CH) before validation and no upstream bytes before the gate opens (`alumina.md:32,201`; `:226` deterministic verification requirement); both barriers gated in `src/gate.rs` (barrier A = validated-hello release + `upstream_write` cumulative accounting, D3, `:195-236`; barrier B = `observe_upstream_activity` terminates on early data/EOF/reset, D4, `:238-249`; `is_open` only after both, `:252-256`) and serving closures (`src/serving.rs:1558-1595,1674-1694,1746-1785`). HAProxy: `tcp-request content inspect-delay` withholds client bytes pending a content verdict (`alumina-722v`) — a one-direction inspection hold only; no write-accounting gate and no upstream-before-gate barrier evidenced → `partial`. Envoy: CONNECT 200 synthesized on pool-ready with no validation barrier; raw configured destination → `different`. No barrier/cell implies policy equivalence.
9. **DNS provenance / address policy.** Alumina binds each upstream address to a positive, current, pre-retirement cache entry satisfying address policy (`alumina.md:200`; DNS publication `:145`; eligibility `:52-82`). HAProxy/Envoy resolve upstreams standardly (server line / cluster DNS) with no CONNECT-hostname-bound provenance or address-policy mechanism evidenced → `different` for both.
10. **Byte preservation.** Alumina: ordered unmodified prefix, no dup/replay, failures terminate the stream (`alumina.md:220`); `Q` receipt = byte-exact echo `sent==echoed` (`alumina-ojxl`). HAProxy: opaque TCP relay, inspected bytes forwarded verbatim (`alumina-722v`) → `✓ matched (source)`. Envoy: selected-config source for byte conservation was not inspected sufficiently in this pass; no positive claim → `unverified` (no runtime claim intended — this cell is a source-coverage gap, not a runtime requirement).
11. **Partial-I/O, FIN, backpressure.** Alumina preserves pending work across partial reads/writes and backpressure (`alumina.md:190`; `src/serving.rs:1348-1351,1722-1745`). HAProxy: inspect-delay describes inspection hold/release and the partial-verdict race only; it supplies no FIN drain/half-close or partial-successful-write/backpressure witness → `unverified` (not a runtime denial). Envoy: no source evidence inspected → `unverified`.
12. **Bounded resources.** Alumina: fixed build-time limits, exhaustion rejects, never grows (`alumina.md:154-166`; `:207` invariant). HAProxy/Envoy: no selected-config limit/exhaustion behavior inspected in this pass → `unverified` for both (absence ≠ negative; `--concurrency 1` is a worker count, not a resource-bound profile).
13. **Zero-alloc invariant.** Alumina requires no heap alloc/dealloc while serving incl. dependencies (`alumina.md:206`); `alloc-witness` is an opt-in separate build and serving-phase allocation-freedom remains an open gate (`alumina-et74` §4; `build-plan.md`); row therefore `R` only. HAProxy/Envoy: no allocation-path evidence inspected → `unverified`.
14. **Single worker.** Alumina fixes worker threads = 1 (`alumina.md:159`; `src/worker.rs` single loop). HAProxy `nbthread 1` one configured thread (`alumina-722v`) → `✓ matched (config intent)`; Envoy `--concurrency 1` forces one worker thread (`options_impl.cc:82-83`, `alumina-elyw`) → `✓ matched (source)`. Total CPU/thread disclosure is a benchmark condition for all candidates.
15. **Logging.** Alumina: stdout-only, best-effort allocation-free structured records, nonblocking drain (`alumina.md:192-194`; candidate model per `src/log.rs` implementation present). HAProxy/Envoy: no selected-config log-sink/allocation evidence inspected → `unverified` (product characterizations are not cited).
16. **Shutdown.** Alumina: SIGTERM-only, bounded grace never extended, no policy reload (`alumina.md:192`; runtime-surface verification `:235`); implementation and tests exist but no executed receipt is cited here → `R` only. HAProxy/Envoy: shutdown semantics not sourced or runtime-proven in this pass → `unverified` (absence ≠ negative).

## Key differences

- **HAProxy (closest approved native):** TCP/SNI-filtered direct-TLS opaque relay — pinned 3.2.25, fixed backend, one configured thread, CONNECT stage skipped. `req.ssl_sni` matches Alumina's initial-SNI filter only; no CH-profile validation, no ECH rejection (unreliable under ECH), no CONNECT-hostname authorization, no write-accounting barrier. Native HTTP CONNECT is a relay needing a backend 2xx, so it cannot produce the accepted 200-before-CH sequence against a fixed TLS-only backend.
- **Envoy:** native CONNECT-terminate with source-verified early-200 and raw TCP (no TLS termination) matches the accepted **wire sequence** at source level; it does not provide inner CH/SNI validation, ECH rejection, CONNECT-hostname authorization, or a validation barrier — the configured fixed destination is a benchmark fixture, not policy parity. Image/config/runtime unexecuted (`unverified` cells).
- **No policy parity claimed:** none of the candidate configurations establishes Alumina's authorization gates (`alumina.md:200-202`). Positive cells are `✓ matched (source)` / `✓ matched (config intent)` — source/match-at-config-level only, never runtime.

## References

- `alumina.md` (canonical spec, sha256 `322b68eeb1…`); `docs/architecture.md`; `docs/build-plan.md`; `docs/reduced-copy-relay-plan.md` (to-be, PROPOSED).
- Implementation: `src/serving.rs`, `src/client_hello.rs`, `src/gate.rs`, `src/log.rs`, `src/worker.rs`; qualification owner `qa-package/README.md`, `scripts/verify.sh`, `scripts/docs_check/check.mjs`.
- Evidence beads: `alumina-et74` (oracle, binding W1–W10), `alumina-722v` (HAProxy 3.2.25 manual/source + SNI-filter witness), `alumina-elyw` (HAProxy native-CONNECT path + Envoy v1.39.4 intake), `alumina-w7y3` (orientation), `alumina-ojxl` (harness contract/acceptance), `alumina-gjq4` (continuation: accepted workload boundary, Python/publication detail, verification evidence).
- External primary (stable): haproxy.org 3.2 Configuration Manual (`req.ssl_sni`, `tcp-request inspect-delay`, tunnel/timeout sections); `haproxy-3.2.25.tar.gz` sha256 `d59a68d0…`; envoyproxy/envoy v1.39.4 `terminate_http1_connect.yaml`, `source/extensions/upstreams/http/tcp/upstream_request.cc`, `source/server/options_impl.cc`.
