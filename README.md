# Alumina Proxy — Domain filtering TLS proxy

Allowlist TLS egress in your cloud environments.

Alumina is an **HTTPS-on-TCP explicit HTTP CONNECT forward proxy**: each
allowlist entry declares its destination port (e.g. `api.github.com:443`,
`example.com:443`). Per connection it terminates two independent TCP sessions,
validates the TLS 1.3 ClientHello (version offer, SNI against the allowlist,
ECH rejection), and relays end-to-end TLS upstream **without decryption**.
For hard network-level isolation under workload RCE, deploy Alumina on a
separate VPC appliance identity (`listen = '0.0.0.0:<port>'`); a same-pod
multi-container sidecar (`listen = '127.0.0.1:<port>'`) is cooperative only
(see [Reference VPC appliance deployment pattern](#reference-vpc-appliance-deployment-pattern)).

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
- Example config: `docs/qa-package/config.example.toml` (≤ 4096 B) shows the
  mandatory `[any_illegal]` + index-aligned `[actions]` tripwire tables with
  `<fqdn>:<port>` allowlist entries — a real-world HTTPS target
  (`api.github.com:443`) and illustrative domains (`example.com:443`,
  `www.example.net:443`); illustrative only, executed by no gate.

## Workload & protocol compatibility (zero proxy code changes)

Alumina's wire contract (`docs/alumina-proxy.md:17-50,200-202`) is: an explicit
plaintext `HTTP/1.1`/`HTTP/1.0` `CONNECT <fqdn>:<port>` (the port must exactly
match the allowlisted entry, e.g. `443`); then — after `200
Connection established` — the **client speaks first** with a TLS 1.3
`ClientHello` whose SNI equals `<fqdn>` (Barrier A); and the upstream server
sends **zero bytes before the validated `ClientHello` is flushed upstream**
(Barrier B — `EarlyUpstreamData` closes the tunnel if the server speaks
first). Once the gate opens, encrypted application bytes are relayed opaquely,
with no ALPN or application-protocol inspection (`docs/alumina-proxy.md:19-21,48-50`).

| Workload | Transport | Compatible? |
| --- | --- | --- |
| HTTPS REST/API (`https://api.github.com:443`, e.g. `reqwest` with `HTTPS_PROXY=http://<proxy>:5353`, TLS 1.3) | TLS 1.3 `ClientHello` (SNI) immediately after `200` | **Yes** — works out of the box |
| NATS Mode 1 — standard NATS (`nats://` / `tls://` server-first StartTLS) | server-speaks-first plaintext `INFO {...}` before any TLS upgrade | **No** — even when the CONNECT port is authorized, the server-first plaintext `INFO` trips Barrier B (`EarlyUpstreamData`) and Barrier A (non-TLS client bytes) |
| NATS Mode 2 — NATS `tls_first` (`handshake_first: true`; `async_nats::ConnectOptions::tls_first()`) | client TLS 1.3 `ClientHello` (SNI) right after `200`; `INFO` inside the encrypted TLS 1.3 stream | **Yes** — wire-compatible, zero `alumina-proxy` changes |
| NATS Mode 3 — NATS over WebSockets (`wss://<nats-fqdn>:443`) | TLS 1.3 `ClientHello` (SNI) right after `200`; HTTP `Upgrade: websocket` + NATS frames inside the encrypted tunnel | **Yes** — wire-compatible, zero `alumina-proxy` changes |

`alumina-proxy` needs **zero code changes** for NATS workloads: the NATS
**client/workload** must (a) establish the TCP tunnel via
`HTTP CONNECT <nats-fqdn>:<allowlisted-port>` to Alumina and (b) match the
allowlisted entry's port and speak a TLS 1.3 `ClientHello` first (`wss://` or
`tls_first`).

## Reference VPC appliance deployment pattern

To enforce positive locking (`docs/alumina-proxy.md:7,103-122`), the protected
workload and Alumina must run under **separate network-policy and runtime
identities** so a compromised workload (RCE) cannot bypass `HTTPS_PROXY` via
direct `connect(2)` syscalls or reset latched `Block Domain` / `Block All`
tripwire state by crashing its own container.

### 1. Topology and VPC firewall confinement

```text
[Protected Serverless / Container Workload (tag: app-workload)]
   │  Direct VPC egress: all-traffic
   │  HTTPS_PROXY = http://<alumina-internal-ip>:5353
   ▼
[VPC Egress Firewall on app-workload]
   ├── ALLOW tcp:5353 -> <alumina-internal-ip>/32 (Alumina listener)
   ├── ALLOW link-local platform metadata if required by platform runtime
   └── DENY  all      -> 0.0.0.0/0 (blocks direct TCP/443, UDP/QUIC, and Private Google Access VIPs)
   │
   ▼
[Dedicated Alumina Appliance VM (tag: alumina-proxy, static internal IP, no public IP)]
   ├── INGRESS: ALLOW tcp:5353 from VPC subnet CIDR only (+ host iptables INPUT rule)
   ├── EGRESS:  ALLOW tcp:53   -> TCP-capable recursive resolver (via Cloud NAT or VPC resolver)
   ├── EGRESS:  ALLOW tcp:443  -> 0.0.0.0/0 via Cloud NAT (approved allowlist destinations)
   └── EGRESS:  DENY  all      -> 0.0.0.0/0 (all other ports and protocols denied)
```

- **Why a separate VPC appliance beats a same-pod sidecar under RCE:**
  - In serverless multi-container sidecar platforms (such as Cloud Run
    multi-container services), all containers in a revision share one network
    namespace (`CLONE_NEWNET`), one VPC IP/tag, and one pod lifecycle, and do
    not grant `CAP_NET_ADMIN` for per-UID `iptables` owner matching. Any
    firewall rule permitting the sidecar to reach `0.0.0.0/0:443` also permits
    an RCE payload in the application container to dial `:443` directly, and
    crashing the application container respawns the pod and clears in-memory
    tripwire latches.
  - Standard serverless HTTP ingress proxies (such as GFE / Cloud Run Services)
    terminate HTTP and reject raw `HTTP CONNECT` tunneling, and serverless
    Worker Pools do not accept unsolicited inbound TCP `SYN` connections on
    Direct VPC IPs. Hosting Alumina on a dedicated minimal VM appliance (e.g.
    Container-Optimized OS `e2-micro` with a static internal VPC IP) provides
    raw TCP `CONNECT` ingress and hard VPC firewall separation.

### 2. Minimal `FROM scratch` container image

Matches `docs/alumina-proxy.md:118` — three files in the root filesystem
(`/alumina`, `/config.toml`, `/resolv.conf`), zero shell or OS utilities:

```dockerfile
FROM --platform=linux/amd64 rust:1.99.0-alpine AS builder
WORKDIR /build
RUN apk add --no-cache musl-dev && rustup target add x86_64-unknown-linux-musl
COPY Cargo.toml Cargo.lock ./
COPY src ./src
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --target x86_64-unknown-linux-musl --bin alumina

FROM scratch
WORKDIR /
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/alumina /alumina
COPY config.toml /config.toml
COPY resolv.conf /resolv.conf
USER 65534:65534
EXPOSE 5353
ENTRYPOINT ["/alumina"]
```

### 3. Appliance runtime invocation and TCP DNS requirement

- **Container-Optimized OS host invocation (`--network host`):** use the
  idiomatic `#cloud-config` (`metadata.user-data`) with a declarative systemd
  unit (`alumina-proxy.service`) instead of imperative shell. The unit writes a
  TCP-capable resolver file, configures the registry credential helper, opens
  the narrow VPC ingress rule, pins the image by digest, and runs the container
  with the hardened profile:
  ```yaml
  #cloud-config
  write_files:
    - path: /var/lib/docker/alumina-resolv.conf
      permissions: "0644"
      owner: root
      content: |
        nameserver <tcp-dns-resolver-ip>
    - path: /etc/systemd/system/alumina-proxy.service
      permissions: "0644"
      owner: root
      content: |
        [Unit]
        Description=Alumina CONNECT Egress Proxy
        Wants=gcr-online.target docker.service
        After=gcr-online.target docker.service

        [Service]
        Environment="HOME=/var/lib/docker"
        Environment="DOCKER_CONFIG=/var/lib/docker/.docker"
        ExecStartPre=/usr/bin/docker-credential-gcr configure-docker --registries=<registry-host>
        ExecStartPre=/sbin/iptables -w -I INPUT -p tcp -s <vpc-subnet-cidr> --dport 5353 -j ACCEPT
        ExecStartPre=-/usr/bin/docker rm -f alumina-proxy
        ExecStartPre=/usr/bin/docker pull <registry-host>/<project>/<repo>/alumina-proxy@sha256:<digest>
        ExecStart=/usr/bin/docker run --rm --name alumina-proxy --network host --log-driver=gcplogs --workdir / --read-only -v /var/lib/docker/alumina-resolv.conf:/resolv.conf:ro --tmpfs /tmp:size=64m --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges <registry-host>/<project>/<repo>/alumina-proxy@sha256:<digest>
        ExecStop=-/usr/bin/docker stop -t 8 alumina-proxy
        Restart=always
        RestartSec=2s
        TimeoutStopSec=10s

        [Install]
        WantedBy=multi-user.target
  runcmd:
    - systemctl daemon-reload
    - systemctl enable --now alumina-proxy.service
  ```
  `--user 65534:65534`, `--cap-drop ALL`, and `--security-opt no-new-privileges`
  satisfy `src/preflight.rs` (`UID != 0`, `CapEff == CapPrm == CapAmb == 0`,
  `no_new_privs == 1`); `--network host` binds `0.0.0.0:5353` directly on the
  internal VPC interface without bridge NAT overhead; `--read-only` plus the
  `--tmpfs /tmp:size=64m` scratch mount and the `:ro` resolver bind keep the
  root filesystem immutable at runtime.
- **TCP-capable DNS resolver (`alumina-resolv.conf` → `/resolv.conf`):** Alumina
  performs DNS over TCP exclusively (`docs/alumina-proxy.md:68`). Where a cloud
  provider's link-local metadata DNS (`169.254.169.254:53`) answers UDP only for
  external records, `write_files` provisions the resolver file with a
  TCP-capable recursive resolver reachable over a narrow `tcp:53` firewall rule,
  and the unit mounts it read-only into the container
  (`-v /var/lib/docker/alumina-resolv.conf:/resolv.conf:ro`).
- **Client TLS 1.3 requirement:** Client HTTPS stacks using `HTTPS_PROXY` must
  offer TLS 1.3 (`0x0304`) as their minimum protocol version so `ClientHello`
  `supported_versions` does not advertise TLS 1.2 (`0x0303`), which Alumina
  rejects by design (`docs/alumina-proxy.md:47`).

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

## License

Dual-licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
