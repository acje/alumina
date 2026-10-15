# Alumina Proxy — Domain filtering TLS proxy

Allowlist TLS egress in your cloud environments.

Alumina is an **HTTPS-on-TCP/443 explicit HTTP CONNECT forward proxy**: per
connection it terminates two independent TCP sessions, validates the TLS 1.3
ClientHello (version offer, SNI against the allowlist, ECH rejection), and
relays end-to-end TLS upstream **without decryption**. Cloud Run validation
targets Cloud Run Worker Pools with Direct VPC (`listen = '0.0.0.0:<port>'`) or
a multi-container sidecar (`listen = '127.0.0.1:<port>'`).

Alumina can be deployed as a light weight explicit forward proxy to protect the egress
for your servers or containers by allowlisting which domains are eligible for
egress traffic. The idiomatic use case is to deploy Alumina Proxy with one container
or workload type in a VPC that limits egress to be exclusively through the
Alumina Proxy. In case of component compromise the attacker will have limited
opportunities for establishing egress; policy violations and early-upstream-data
events trigger configurable tripwire actions (`flare_only` / `block`) with
bounded stdout monitoring (`docs/alumina-proxy.md:238-315`, rp2e amendment).

## Documents

| Document | Role |
| --- | --- |
| [alumina-proxy.md](docs/alumina-proxy.md) | **Canonical spec** — sole governing requirements |
| [docs/architecture.md](docs/architecture.md) | Conceptual design + as-built single-owner mapping (decisions D1–D7) |
| [docs/build-plan.md](docs/build-plan.md) | Qualification owner — gates F0–F4, seven slices, current status |
| [docs/traceability.md](docs/traceability.md) | Requirement → design → proof matrix + unresolved-evidence ledger |
| [alumina-refinement.md](alumina-refinement.md) | Material normative candidates for user review only |
| [docs/harness-evaluation.md](docs/harness-evaluation.md) | Measured harness fitness (dated, scoped) |
| [docs/qa-package/README.md](docs/qa-package/README.md) | Local testQA run/validation instructions |
| [docs/verification.md](docs/verification.md) | Verification instructions, command set + offline link checker |
| [docs/benchmarks/100mbps-comparison.md](docs/benchmarks/100mbps-comparison.md) | 100 Mbps matched comparison — Alumina 8dbbec8 vs HAProxy 3.2.25 vs Envoy 1.39.4 (tables-only; workload parameters + durable receipts) |
| [docs/benchmarks/feature-match-matrix.md](docs/benchmarks/feature-match-matrix.md) | Feature match matrix across the three benchmark candidates |
| [docs/repository-layout-review.md](docs/repository-layout-review.md) | Advisory repository layout review (Layout A recommendation, dated at 59ad255) |
| [docs/tripwire-architecture-review.md](docs/tripwire-architecture-review.md) | Advisory post-Layout-A architecture review (tripwire/action domain) |

## Runtime surface and fixed inputs

- `./config.toml` (≤ 4096 B, mandatory keys, no defaults) and `./resolv.conf`
  (first nameserver, numeric unicast, port 53); no CLI args, no env overrides;
  one listening socket; **SIGTERM the only handled lifecycle signal**
  (`docs/alumina-proxy.md:149`).
- Privilege preflight (non-root, empty caps, `no_new_privs`): unmet → EX_CONFIG
  78; unresolved beyond allowance → EX_TEMPFAIL 75.

## Repository layout

`src/main.rs` boot owner → `src/runtime.rs` shared-readiness serving loop;
`src/{serve,boot,config,resolver,preflight,inventory}.rs` boot path;
`src/enforcement/{mod,action,monitor,policy,state}.rs` tripwire/action/monitoring
surface (rp2e amendment); `src/{dns,connect,client_hello,startup_dns,cache,schedule,worker,gate,serving,eligibility,log}.rs`
serving/parser core; `src/serving/{policy,reject,startup,tests}.rs`,
`src/runtime/tests.rs`, `src/startup_dns/tests.rs` serving/startup decomposition
and sibling test modules; `src/{alloc,fault,fuzz}.rs` F1/F2/F4 scaffolds;
`scripts/` verification owners; `tests/` integration corpus.

## Known limitations / not implemented (honest)

- Deployment confinement, initial deployment, remaining native E2E profiles,
  fuzz campaign receipts, platform/confinement/performance qualification —
  **open** (build-plan §7; traceability §5).
- F3 serving completeness witness and full BOUNDARY remain open; exact
  candidates above are proven for relay/shutdown, never a blanket claim.
- `getrandom` intake complete; `cargo deny`/`cargo audit` clean; no
  product-wide zero-alloc claim is made.
