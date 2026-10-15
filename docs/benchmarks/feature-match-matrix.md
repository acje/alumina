# Alumina 8dbbec8 vs HAProxy 3.2.25 vs Envoy v1.39.4 — feature match matrix

## Candidates

| Candidate | Evidence identity |
| --- | --- |
| **Alumina 8dbbec8** | Canonical spec [docs/alumina-proxy.md](../../docs/alumina-proxy.md) (sha256 `322b68eeb1…` — **historical pre-rp2e spec digest**; current post-rp2e canonical sha256 `b5b1c9f…137d`); implementation `src/serving.rs`, `src/client_hello.rs`, `src/gate.rs`, `src/log.rs`, `src/worker.rs`; qualification owner `docs/qa-package/README.md` + `scripts/verify.sh`; 100 Mbps timed result in [`100mbps-comparison.md`](100mbps-comparison.md) |
| **HAProxy** | Pinned **3.2.25** (LTS); haproxy.org 3.2 manual + sha256-verified tarball `d59a68d0…` (`alumina-722v`, `alumina-elyw`). Chosen comparable setup: TCP-mode near-direct TLS opaque relay — SNI allowlist, fixed backend, one configured thread, CONNECT stage skipped |
| **Envoy** | Selected **envoyproxy/envoy:v1.39.4** (arm64 digest `ce82b213…`); official `terminate_http1_connect.yaml` CONNECT-terminate, raw TCP upstream, `--concurrency 1` (`alumina-elyw`). 100 Mbps timed result in [`100mbps-comparison.md`](100mbps-comparison.md) |

## Legend

Alumina 8dbbec8 column tags:

| Tag | Meaning |
| --- | --- |
| `R` | Required by canonical spec (`docs/alumina-proxy.md:LINE`) |
| `I` | Implemented and enforced, cited to `src/` (`path:LINE`) or evidence bead |

Candidate columns use exactly one grade:

| Grade | Meaning |
| --- | --- |
| `✓ matched (source)` / `✓ matched (config intent)` | Positive source/manual/config evidence of the feature for the selected config; no runtime claim |
| `partial` | A related but altered/weaker form exists in the selected config, with the proven subset named |
| `different` | A materially different mechanism or policy is evidenced for the selected config |
| `unverified` | No positive evidence obtained in this pass; no capability-absence or runtime claim is made (absence ≠ negative) |

## Matrix

| # | Feature (selected benchmark config) | Alumina 8dbbec8 | HAProxy 3.2.25 | Envoy v1.39.4 |
| --- | --- | --- | --- | --- |
| 1 | CONNECT wire entry (selected happy-path): completed 200 before ClientHello | `R` `I` | different | ✓ matched (source) |
| 2 | Endpoint TLS 1.3 pass-through — non-terminating, proxy holds no keys | `R` `I` | ✓ matched (source) | ✓ matched (source) |
| 3 | Proxy-side TLS 1.3-only ClientHello profile | `R` `I` | different | different |
| 4 | Initial SNI inspection / matching CONNECT SNI | `R` `I` | partial | different |
| 5 | Full ClientHello validation (framing, versions, exactly-one SNI, duplicates) | `R` `I` | different | different |
| 6 | ECH rejection (incl. GREASE) | `R` `I` | different | different |
| 7 | CONNECT-hostname allowlist / authorization | `R` `I` | partial | different |
| 8 | Two forwarding barriers (client-before-validation, upstream-before-gate, early data/EOF/reset closed) | `R` `I` | partial | different |
| 9 | DNS provenance / cache-life / destination-address policy | `R` `I` | different | different |
| 10 | Original byte preservation (ordered unmodified prefix) | `R` `I` | ✓ matched (source) | unverified |
| 11 | Partial-I/O, FIN, backpressure | `R` `I` | unverified | unverified |
| 12 | Bounded resources (fixed limits, reject-on-exhaustion) | `R` | unverified | unverified |
| 13 | No heap alloc/dealloc while serving | `R` | unverified | unverified |
| 14 | Single worker | `R` `I` | ✓ matched (config intent) | ✓ matched (source) |
| 15 | Logging (stdout-only best-effort allocation-free) | `R` `I` | unverified | unverified |
| 16 | Shutdown (SIGTERM-only, bounded grace, no policy reload) | `R` | unverified | unverified |
