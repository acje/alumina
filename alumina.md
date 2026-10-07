# Alumina Proxy - Domain-level filtering for HTTPS egress

## Overview

Alumina is a non-terminating forward proxy for HTTPS over TCP, admitting connections to a configured FQDN allowlist. Its priorities are integrity, bounded resources, low latency, least privilege, and a minimal feature set. It supports a single golden-path profile: a simple, known-good, cloud-platform-agnostic configuration, rather than general compatibility or automatic negotiation between proxy operating modes. Environments whose complexity or technical debt prevents adopting this profile should use a more capable alternative, such as GCP Secure Web Proxy. Application-protocol verification is not a goal.

## Threat model

Alumina must resist attempts by a compromised application in the same VPC to alter its integrity, control, or destination enforcement. It restricts the egress it provides to reduce opportunities for data exfiltration and command and control (C2), not to provide comprehensive prevention.

DoS resistance is a design goal, but availability cannot be guaranteed within fixed resource limits. In the idiomatic deployment, the assumed availability blast radius is the HTTPS egress path of the VPC containing the compromised application. In typical deployments the unavailability of egress from a compromised VPC will not be the critical issue.

**Accepted limitation:** Alumina restricts CONNECT hostnames and DNS-derived network destinations, and requires matching SNI. It does not authenticate the upstream server or enforce the origin named inside encrypted application requests. An approved endpoint may expose attacker-controlled resources or permit access to other origins through domain fronting or connection coalescing. A compromised application may abuse these capabilities for data exfiltration or command and control, including by supplying its own credentials. These activities are outside Alumina's enforcement scope. Allowlisting a domain therefore accepts the risk of capabilities reachable through its admitted endpoints, not merely the application's intended use of that domain.

## Protocol contract

Alumina supports HTTPS over TCP to limit its protocol surface, not to verify that admitted tunnels carry HTTPS. Clients use explicit proxy configuration and plaintext HTTP/1.1 or HTTP/1.0 CONNECT with an FQDN and port 443, followed by a TLS 1.3-only ClientHello with SNI. TLS 1.2 and earlier profiles, plain HTTP forwarding, HTTP/2 CONNECT to the proxy, UDP/QUIC, and transparent interception are unsupported. HTTP versions inside the encrypted tunnel are opaque to Alumina.

Fail-closed behavior applies to unsupported or invalid input observable in CONNECT and ClientHello, and to internal failures. Once admitted, tunnel contents are relayed without application-protocol verification; Alumina cannot detect unsupported behavior hidden inside the encrypted stream.

```text
Read CONNECT -> Authorize hostname -> Select cached address
-> Connect upstream -> Send 200 -> Read and validate ClientHello
-> Forward buffered bytes -> Relay -> Drain/close
```

The [security invariants](#i-security--authorization-invariants) govern upstream connection establishment and release of buffered tunnel bytes. Before a successful CONNECT response begins, failures may receive an HTTP error response; once it begins, failures close the connection without injecting another HTTP response. Only completion of a successful response permits ClientHello inspection; buffered tunnel bytes remain gated by authorization.

CONNECT headers and ClientHello are parsed incrementally with separate byte limits and an absolute setup deadline. ClientHello may span TCP reads and TLS records; inspection preserves the original bytes for forwarding. Reject malformed framing and duplicate or ambiguous SNI.

### CONNECT request

Alumina's own configuration is strict; client input is accepted where variants have a single meaning and rejected where interpretation could differ.

- **Accept:** any hostname case, compared in lowercase; `Content-Length: 0`. Ignore all other headers, including `Host` and `Proxy-Authorization`.
- **Reject:** a port other than exactly `443`, nonzero `Content-Length`, any `Transfer-Encoding`, bare LF line endings, and obs-fold.
- **One request per connection:** close after any error response.
- **Errors:** `400` malformed request, `403` hostname not allowlisted, `502` upstream connection failed, `503` no capacity, `504` setup deadline expired. Each error response carries a fixed plain-text body stating the reason; client input is never echoed.

### TLS ClientHello profile

- **Version offer:** Require the `supported_versions` extension with TLS 1.3 (`0x0304`) as its only non-GREASE version. Reject missing extensions, TLS 1.2 fallback offers, and other non-GREASE versions. TLS 1.3-only is a golden-path profile requirement, not a security control: clients must be configured with TLS 1.3 as their minimum version. Require the TLS 1.3 ClientHello `legacy_version` value `0x0303` and the single null legacy compression method. Accept handshake record legacy versions `0x0301` and `0x0303` for the initial ClientHello; these compatibility fields do not enable a TLS 1.2 parsing path. Reject SSLv2 framing and non-handshake records before the initial ClientHello is complete; bound each plaintext record payload to 16 KiB.
- **Identity and framing:** Require exactly one `server_name` extension containing exactly one hostname entry, matching the approved CONNECT hostname. Validate enclosing lengths, vectors, and extension boundaries; reject duplicate extensions and malformed or ambiguous identity. Well-framed unknown extensions and GREASE values may be skipped by length; do not introduce cipher-suite or ALPN policy.
- **ECH:** Reject the `encrypted_client_hello` extension, including ECH GREASE, regardless of outer SNI. Golden-path clients must not send ECH. Never strip or rewrite extensions.
- **Inspection scope:** Inspect only the initial ClientHello, preserving fragmentation and all buffered bytes. Later handshake messages and encrypted application traffic remain opaque. A second ClientHello following a HelloRetryRequest is not inspected; it adds no capability beyond the accepted domain-fronting limitation. The version check constrains the client's advertised profile; it does not authenticate the upstream server or independently verify the version actually negotiated by the endpoints.

## Configuration & DNS

Configuration is a single TOML document of at most 4 KiB (4096 bytes), including comments and whitespace, with a required `allowlist` array of at most 32 exact FQDN strings and a required `listen` key. Both limits apply: 32 maximum-length DNS names need not fit. A compact configuration with 32 names of 100 ASCII bytes each and a listener fits within the document limit. Bound the configuration read and reject oversized input without truncating it. Load and fully validate configuration and local prerequisites before opening listeners or issuing DNS queries. There is no runtime policy update interface.

Missing or unreadable configuration, invalid TOML (including duplicate keys or invalid table redefinitions), missing required fields, unknown keys or tables, incorrect types, out-of-range values, conflicting settings, and unmet local prerequisites cause immediate startup failure with a nonzero exit status and a diagnostic identifying the field or source location where available. Reject duplicate allowlist names after normalization. Do not coerce types, discard invalid entries, or supply missing required values from defaults, environment variables, or command-line overrides. After startup resolution, DNS timeouts, negative answers, and other network failures are expected runtime outcomes governed by the cache rules below, not configuration errors.

- **Listener:** `listen` is a required string of the form `address:port`, with a numeric IPv4 or bracketed IPv6 address and a port from 1 through 65535. Wildcard addresses are allowed. A bind failure prevents startup.
- **Names:** Configuration uses lowercase ASCII DNS hostnames, with IDNs supplied in A-label form; CONNECT and SNI hostnames compare case-insensitively. Configuration and CONNECT may normalize a single trailing dot; SNI must satisfy TLS hostname syntax. Compare canonical names and issue absolute DNS queries without search suffixes.
- **Resolver selection:** Read the platform-provided resolver configuration once at startup and select its first declared nameserver address, using port 53. The address must be a numeric unicast IPv4 or IPv6 address without a zone identifier. An unreadable configuration, missing nameserver, or invalid selected address prevents startup; do not skip it in favor of another nameserver. The resolver endpoint is fixed for the process lifetime. Ignore platform search suffixes and resolver tuning options; do not use general OS hostname-resolution APIs, hosts-file lookup, runtime rediscovery, or fallback to another resolver. The platform configuration is a trusted deployment input.
- **Resolution:** Alumina implements a bounded DNS stub, not a recursive resolver or a client-facing DNS service. At startup, before opening the listener, every allowlisted name must obtain at least one positive address binding within the startup resolution window, retrying with the refresh backoff; otherwise startup fails. Afterwards, refresh through the selected recursive resolver independently of connection requests. Requests use cached results only; they neither trigger nor wait for DNS lookups. The resolver integration must not block worker loops and must satisfy the same allocation and resource bounds as the proxy. Local DNSSEC validation and DNS over TLS or HTTPS are outside the initial scope.
- **Transport:** Use plain DNS over TCP only, with one reusable connection and one outstanding query. There is no UDP or alternate-resolver fallback. Validate the response flag, opcode, transaction ID, and question name, type, and class against the outstanding query. Close the DNS connection on timeout, malformed or mismatched responses, truncation, or an oversized message; do not publish partial results. TCP is not cryptographic authentication of the resolver or DNS data.
- **DNS control traffic:** DNS sockets may reach only the selected resolver endpoint. This control traffic is separate from tunnel destination authorization and may use a private, loopback, or link-local resolver address; it never makes that address eligible as a CONNECT destination.
- **DNS provenance:** Use A/AAAA queries without follow-up queries. A response must contain any CNAME chain rooted at the queried hostname together with the terminal name's addresses; an incomplete chain is an exchange failure. Every candidate address must belong to the queried allowlisted hostname or the terminal name of a valid CNAME chain rooted at that hostname. Unrelated records in answer or additional sections must never become candidates. CNAME targets need not be allowlisted or share a DNS suffix; they locate an approved name's addresses but never authorize additional CONNECT names.
- **Service discovery:** HTTPS/SVCB endpoint substitution is unsupported. These records must not change the CONNECT target, destination port, or transport. Clients must use the origin hostname on port 443 as the CONNECT target and supply matching SNI, rather than substitute an alternative endpoint.
- **Addresses:** As defense-in-depth against resolver or zone misconfiguration, only globally routable unicast destinations are eligible. A fixed built-in list rejects IANA special-use and non-public ranges, including private, shared address space, loopback, link-local (including metadata endpoints), unique-local, multicast, and reserved ranges, along with equivalent IPv4-mapped IPv6 forms. Validate every A/AAAA candidate before use.
- **Cache lifetime:** A binding's TTL is the earliest TTL of any supporting CNAME or address record, measured from receipt with a monotonic clock. A successful positive answer replaces the cached addresses for its record type. An authoritative negative answer evicts them: NXDOMAIN is name-wide; NODATA is specific to the queried record type and must not evict addresses of another type. Exchange failures, including timeouts, SERVFAIL, and malformed responses, leave cached addresses in place; a binding whose TTL has elapsed remains usable until a later answer replaces or evicts it. Missing or evicted bindings cannot authorize a new upstream connection. DNS queries and refresh results belong to cache state, not connection generations; obsolete results cannot overwrite newer cache state.
- **Refresh scheduling:** Refresh each name when its binding TTL elapses, capped at five minutes; retry evicted bindings using the failure backoff. Start at most one refresh round per configured name per second; a round resolves both A and AAAA. An exchange failure ends the affected resolution attempt; later attempts use 1, 2, 4, 8, 16, then 30-second capped backoff, reset by a successful resolution. Service due names fairly so a failing name cannot monopolize DNS work. Client requests cannot accelerate refresh or retries.
- **Bounds and retries:** Enforce the initial resource profile for DNS messages, record counts, CNAME chain length, and outstanding queries. Reject loops and results exceeding capacity rather than retaining an arbitrary truncated subset. Each DNS exchange has a 2-second deadline. Upstream connection attempts use cached candidates sequentially, alternating IPv4 and IPv6 candidates starting with IPv4 when both exist, at most four attempts with a 2-second per-attempt deadline within the absolute setup deadline. Revalidate eligibility before each attempt. Commit the peer at the first successful TCP connection; retry only failed connection establishment and never replace a connected peer. Cache updates do not change the peer of an established tunnel.

## Deployment boundary

Alumina is responsible for the egress it provides. VPC isolation mechanisms and prevention of alternative egress paths are outside its scope. Deployment supplies raw TCP connectivity and access to the platform-provided DNS resolver.

**DNS trust:** Alumina relies on the platform-provided recursive resolver for correct name-to-address bindings. Deployment must protect the resolver, its configuration, and communication between Alumina and the resolver from modification or impersonation by compromised applications. Resolver responses must still pass all parsing, provenance, cache-lifetime, and destination-address checks.

The initial GCP test target is a Cloud Run worker pool with Direct VPC connectivity, providing private TCP ingress and continuously allocated CPU, rather than ordinary Cloud Run service HTTP ingress. Platform network limits remain independent of CPU speed: the [Cloud Run Direct VPC documentation](https://docs.cloud.google.com/run/docs/configuring/vpc-direct-vpc#limitations) currently specifies up to 1 Gbps per instance. Testing the 10 Gbps end of the target requires a deployment whose network ceiling permits it.

## Architecture

Alumina uses Rust and a single `mio` worker loop in the first iteration, following TigerStyle principles adapted to Rust. State transitions and scheduling are explicit.

- **Compile-Time Bounds:** Max concurrent connections and buffer sizes are statically fixed.
- **Boot-Time Storage:** Application storage is allocated before serving traffic; stack usage is bounded. This does not imply constant total memory use or immunity to resource exhaustion.
- **Single Owner:** The worker owns tunnel state, DNS sockets, timers, and the entire DNS cache. There is no resolver thread, blocking system resolver, shared mutable cache, or cross-thread publication. Additional workers are outside the initial profile; any future worker must own its own connection and DNS state without cross-worker data-path coordination.
- **Cache Publication:** Preallocate cache entries and staging storage. Validate a complete result in staging, then replace the relevant cache state in one worker transition without merging obsolete records. Keep A and AAAA state distinct; a name-wide negative result invalidates both and supersedes older pending work. Generation identifiers reject obsolete results.
- **Scheduling:** Use fair round-robin scheduling with at most 64 KiB of I/O or 16 I/O operations per connection visit, whichever comes first. Recheck timers after at most 256 ready-slot visits or I/O operations, even if more work is pending. Reschedule unfinished work without waiting for a new readiness edge; DNS work receives bounded turns alongside tunnel traffic. Size ready queues and timer storage from fixed slot counts, with no duplicate queue entry per slot.
- **No async/await:** Use explicit `mio` event handling rather than an async runtime.
- **Failure Handling:** Expected input and I/O failures are handled explicitly. `panic = "abort"` is a fail-stop policy, not proof of panic freedom; `unwrap()` and `expect()` are excluded from production paths.

## Initial resource profile

These are fixed build-time limits, not optional TOML settings or measured capacity claims. Limit exhaustion rejects work; it never enlarges storage or relaxes validation.

| Resource | Limit |
| --- | --- |
| Configuration document / allowlist entries | 4 KiB / 32 |
| Worker threads | 1 |
| Concurrent tunnels, including setup / pending setups | 128 / 32 |
| Traffic buffers per tunnel slot | Two 512 KiB buffers, one per direction |
| Total preallocated tunnel traffic storage | 128 MiB |
| CONNECT headers | 8 KiB |
| Buffered TLS bytes before authorization, including record framing | 64 KiB |
| DNS response message / total resource records | 16 KiB / 128 |
| Cached address candidates per configured name | 16 IPv4 and 16 IPv6 |
| CNAME chain length | 8 links; loops rejected |
| DNS TCP connections / outstanding queries | 1 / 1 |
| Setup deadline / individual upstream connect deadline | 10 seconds / 2 seconds |
| Upstream connection attempts per tunnel | 4, within the setup deadline |
| DNS exchange deadline | 2 seconds |
| Startup resolution window | 60 seconds |
| Relay idle deadline / EOF drain deadline / shutdown grace period | 300 seconds / 5 seconds / 8 seconds |

Preallocate 128 tunnel slots with two 512 KiB directional buffers each: `128 * 2 * 512 KiB = 128 MiB`. Reuse these buffers across CONNECT parsing, ClientHello inspection, and relay without discarding coalesced tunnel bytes. The separate CONNECT and ClientHello limits still apply; larger relay buffers do not permit larger setup messages. DNS storage, connection metadata, stacks, executable memory, and kernel socket buffers are outside this traffic-storage budget and must be accounted for separately when sizing the container.

The first-iteration target is 1-10 Gbps aggregate relayed payload throughput across both directions, subject to CPU speed, workload, and network limits. At these rates, 128 MiB represents approximately 1.07 seconds to 107 milliseconds of aggregate payload, not a throughput guarantee. Storage is partitioned by tunnel and direction and cannot all absorb a burst on one connection; a 512 KiB directional buffer represents approximately 4.19 milliseconds at 1 Gbps or 0.42 milliseconds at 10 Gbps. Use socket backpressure rather than buffer growth. Benchmark sustained relay and bursts separately; application buffer capacity is not a substitute for TCP window sizing or a measured CPU budget.

## Lifecycle

- **Relay:** Handle partial reads and writes, backpressure, and spurious readiness without losing pending work.
- **Closure:** On orderly EOF in either direction, drain that direction and shut down the peer's write direction; reverse traffic may continue, but the whole tunnel closes when the EOF drain deadline expires. Release connection resources exactly once.
- **Shutdown:** Stop accepting connections and drain within a bounded grace period before closing remaining sockets and performing final cleanup.
- **Capacity and logging:** When tunnel or setup capacity is exhausted, reject new connections with a best-effort static `503` and close; never evict established tunnels. Log an error when tunnel slots, pending setups, or log buffer usage first exceeds 80%, and again when usage falls below 70%. Logging never blocks the worker; when the log buffer is full, drop new entries and count the drops. Log every rejected connection at warn level with the client address, the reason, and the requested hostname when it is valid.

## Invariants

### I. Security & Authorization Invariants

- **The Destination-Binding Invariant:** An upstream tunnel connection may be opened only for an approved CONNECT hostname that is a valid FQDN, not an IPv4/IPv6 literal, on TCP port 443. The destination address must come from a positive entry in Alumina's DNS cache for that hostname that no later answer has replaced or evicted, and must satisfy the destination-address policy. The selected peer remains fixed for that tunnel.
- **The Authorization-Before-Forwarding Invariant:** No client tunnel bytes, including ClientHello, are forwarded until the complete ClientHello passes validation and its mandatory SNI contains a valid, nonempty FQDN whose normalized value equals the approved CONNECT hostname's normalized value. A successful CONNECT response alone does not authorize forwarding.
- **The Fail-Closed Invariant:** Malformed or unsupported input, ambiguous identity, DNS failure, and resource exhaustion cannot skip authorization checks or enable permissive fallback.

### II. Memory & Resource Invariants

- **The Zero-Allocation Invariant:** While serving traffic or refreshing DNS, proxy execution paths, including dependencies, must not allocate or deallocate heap storage. Boot initialization and final shutdown cleanup after these activities stop are exempt.
- **The Resource-Bounds Invariant:** Connections, buffers, queues, DNS requests, timers, and logs have explicit capacity limits. Exhaustion rejects work rather than expanding storage without bound.

### III. Execution & Concurrency Invariants

- **The Ownership Invariant:** Each live connection's mutable state belongs to exactly one worker.
- **The Generation-Isolation Invariant:** Connection-scoped events, timers, and buffered bytes belong to one connection generation. Stale work cannot affect reused connection storage; generation reuse must not make stale work valid again. DNS refresh and other non-connection work have independent lifetimes.
- **The Bounded-Work Invariant:** Each scheduling turn has a finite work budget. Pending work is rescheduled without losing readiness or starving other connections and deadlines.

### IV. Protocol & State Machine Invariants

- **The State-Transition Invariant:** Every I/O outcome has an explicit permitted transition. Invalid protocol transitions close the connection; readiness alone is not evidence that an operation succeeded.
- **The Stream-Parsing Invariant:** For the same byte stream within the specified size and time limits, parsing decisions are independent of TCP read boundaries. Parsing incomplete input never authorizes forwarding.
- **The Non-Decrypting Invariant:** The proxy shall never possess TLS private keys, manage authority certificates, or decrypt payload traffic. It acts strictly as a metadata validator and a transparent bit-pipe.
- **The Byte-Conservation Invariant:** Forwarded tunnel bytes are an ordered, unmodified prefix of the received tunnel stream in each direction, without duplication or replay. Normal completion drains accepted tunnel bytes; failures terminate the stream rather than silently skipping data and continuing.
- **The Deadline Invariant:** Setup has an absolute deadline that incremental traffic cannot extend. Relay idle time and draining have separate finite limits, measured with a monotonic clock.

## Verification requirements

- **Protocol and DNS:** Verify TLS 1.3-only acceptance, TLS 1.2 fallback and ECH rejection, fragmented ClientHello handling, DNS response binding, CNAME provenance, startup resolution failure, stale retention on refresh failure, negative-answer eviction, and obsolete-result isolation. Exercise malformed input and configured bounds with focused tests and parser fuzzing.
- **Resource profile:** Verify the 4096-byte configuration boundary, the 128 MiB traffic-buffer allocation, bounded queues and timers, allocation-free operation, deadline enforcement, and preservation of buffered bytes across setup and relay. Report process and kernel memory separately from the traffic-buffer budget.
- **Initial deployment:** Demonstrate TCP DNS resolution and end-to-end CONNECT ingress on the selected Cloud Run worker-pool deployment. Compatibility failure requires an explicit deployment or design revision, never automatic protocol or resolver fallback.
- **Performance:** Measure aggregate forwarded payload bytes once, not once on read and again on write. Benchmark 1-10 Gbps bursts where CPU and network capacity permit, and report burst duration, concurrency, payload sizes, CPU utilization, queueing, and sustained throughput separately. Include slow-peer backpressure and verify DNS and deadline progress under load. These targets and deployment behaviors are unverified until measured.
