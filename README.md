# Alumina Proxy — Domain filtering TLS proxy

Allowlist TLS egress in your cloud environments.

Alumina can be deployed as a light weight explicit forward proxy to protect the egress
for your servers or containers by allowlisting which domains are eligible for
egress traffic. The idiomatic use case is to deploy Alumina Proxy with one container
or workload type in a VPC that limits egress to be exclusively through the
Alumina Proxy. In case of component compromise the attacker will have limited
opportunities for establishing egress (TODO: and risk setting off tripwires with configurable actions.)

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
`src/{dns,connect,client_hello,startup_dns,cache,schedule,worker,gate,serving,eligibility,log}.rs`
serving/parser core; `src/{alloc,fault,fuzz}.rs` F1/F2/F4 scaffolds;
`scripts/` verification owners; `tests/` integration corpus.

## Known limitations / not implemented (honest)

- Deployment confinement, initial deployment, remaining native E2E profiles,
  fuzz campaign receipts, platform/confinement/performance qualification —
  **open** (build-plan §7; traceability §5).
- F3 serving completeness witness and full BOUNDARY remain open; exact
  candidates above are proven for relay/shutdown, never a blanket claim.
- `getrandom` intake complete; `cargo deny`/`cargo audit` clean; no
  product-wide zero-alloc claim is made.
