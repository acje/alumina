# Alumina Proxy - Domain-level filtering for HTTPS egress

## Overview

Alumina is a non-terminating forward proxy for HTTPS over TCP, admitting connections to a configured FQDN allowlist. Its priorities are integrity, bounded resources, low latency, least privilege, and a minimal feature set. Application-protocol verification is not a goal.

## Threat model

Alumina must resist attempts by a compromised application in the same VPC to alter its availability, integrity, control, or destination enforcement. It restricts the egress it provides to reduce opportunities for data exfiltration and command and control (C2), not to provide comprehensive prevention.

DoS resistance is a design goal, but availability against a resource-asymmetric attacker cannot be guaranteed within arbitrary deployment limits. In the idiomatic deployment, the assumed availability blast radius is the HTTPS egress path of the VPC containing the compromised application. In typical deployments the unavailability of egress from a compromised VPC will not be the critical issue.

**Accepted limitation:** Alumina restricts egress destinations, not the activities performed through approved destinations. A compromised application may use attacker-controlled resources hosted at a whitelisted domain for data exfiltration or command and control, including by supplying its own credentials. Such traffic is outside Alumina's enforcement scope and is an inherent limitation of the mechanism, not a capability Alumina intends to add. Whitelisting a domain therefore accepts the risk of abuse of capabilities accessible through that domain, not merely the application's intended use of it.

## Protocol contract

Alumina supports HTTPS over TCP to limit its protocol surface, not to verify that admitted tunnels carry HTTPS. Clients use explicit proxy configuration and plaintext HTTP/1.1 CONNECT with an FQDN and port 443, followed by TLS ClientHello with SNI. Plain HTTP forwarding, HTTP/2 CONNECT to the proxy, UDP/QUIC, and transparent interception are unsupported. HTTP versions inside the encrypted tunnel are opaque to Alumina. **NOTE for next review: HTTP/2 should be considdered supported as it has very similar mechanism as 1.1. the design space would probably not expand by much.**

Fail-closed behavior applies to unsupported or invalid input observable in CONNECT and ClientHello, and to internal failures. Once admitted, tunnel contents are relayed without application-protocol verification; Alumina cannot detect unsupported behavior hidden inside the encrypted stream.

```text
Read CONNECT -> Authorize hostname -> Select valid cached address
-> Connect upstream -> Send 200 -> Read and validate ClientHello
-> Forward buffered bytes -> Relay -> Drain/close
```

The [security invariants](#i-security--authorization-invariants) govern upstream connection establishment and release of buffered tunnel bytes. Before a successful CONNECT response begins, failures may receive an HTTP error response; once it begins, failures close the connection without injecting another HTTP response. Only completion of a successful response permits ClientHello inspection; buffered tunnel bytes remain gated by authorization.

CONNECT headers and ClientHello are parsed incrementally with separate byte limits and an absolute setup deadline. ClientHello may span TCP reads and TLS records; inspection preserves the original bytes for forwarding. Reject malformed framing and duplicate or ambiguous SNI.

## Configuration & DNS

Configuration is TOML with at most 32 exact FQDN entries loaded before startup. There is no runtime policy update interface. Invalid configuration or unmet local prerequisites prevent startup; network failures remain expected runtime outcomes.

- **Names:** Use lowercase ASCII DNS hostnames, with IDNs supplied in A-label form. Configuration and CONNECT may normalize a single trailing dot; SNI must satisfy TLS hostname syntax. Compare canonical names and issue absolute DNS queries without search suffixes.
- **Resolution:** Initialize a bounded DNS cache for configured allowlist names at startup and refresh periodically through an operator-configured resolver, independently of connection requests. Requests use cached results only; they neither trigger nor wait for DNS lookups. The resolver integration must not block worker loops. CNAME chains may locate an approved name's addresses but never authorize additional CONNECT names. **Note for next review: are we missing some invariants here? can we be more strict and remain usefull? the usecase is strictly machine to machine api and webpage consumption**
- **Addresses:** Only public unicast destinations are eligible. Reject special-use, VPC/internal, metadata, and proxy addresses, including equivalent IPv4-mapped IPv6 forms. Validate every A/AAAA candidate before use and reject unsupported address families.
- **Cache lifetime:** Honor positive and negative DNS cache lifetimes. Missing, negative, or expired entries reject new requests. Refresh failure does not extend validity; still-valid cached results remain usable. DNS queries and refresh results belong to cache lifetimes, not connection generations; obsolete results cannot overwrite newer cache state.
- **Bounds and retries:** Bound answer counts, CNAME depth, outstanding queries, and refresh retries. Upstream connection attempts use valid cached candidates sequentially before forwarding begins. Cache updates do not change the peer of an established tunnel.

## Deployment boundary

Alumina is responsible for the egress it provides. VPC isolation mechanisms and prevention of alternative egress paths are outside its scope. Deployment supplies raw TCP connectivity and access to the configured DNS resolver. **note for next review: what do we mean by "and access to the configured DNS resolver" should we take on DNS responsibilities? do we have to the solve the common case? could we provide a DNS response for the configured FQDN only to solve our usecase? would the application even need to resolve the domains behind alumina when forward proxy is configured?**

## Architecture

Alumina uses Rust and single-threaded `mio` worker loops, following TigerStyle principles adapted to Rust. State transitions and scheduling are explicit.

- **Compile-Time Bounds:** Max concurrent connections and buffer sizes are statically fixed.
- **Boot-Time Storage:** Application storage is allocated before serving traffic; stack usage is bounded. This does not imply constant total memory use or immunity to resource exhaustion.
- **Shared-Nothing Workers:** Each worker owns its connection state without cross-worker coordination in the data path.
- **No async/await:** Use explicit `mio` event handling rather than an async runtime.
- **Failure Handling:** Expected input and I/O failures are handled explicitly. `panic = "abort"` is a fail-stop policy, not proof of panic freedom; `unwrap()` and `expect()` are excluded from production paths.

## Lifecycle

- **Relay:** Handle partial reads and writes, backpressure, and spurious readiness without losing pending work.
- **Closure:** On orderly EOF, drain that direction before shutting down the peer's write direction; reverse traffic may continue until EOF or deadline. Release connection resources exactly once.
- **Shutdown:** Stop accepting connections and drain within a bounded grace period before closing remaining sockets and performing final cleanup.
- **Health:** A separate health listener has no forwarding capability.

## Invariants

### I. Security & Authorization Invariants

- **The Destination-Binding Invariant:** An upstream connection may be opened only for an approved CONNECT hostname that is a valid FQDN, not an IPv4/IPv6 literal, on TCP port 443. The destination address must come from a valid entry in Alumina's DNS cache for that hostname and satisfy the destination-address policy. The selected peer remains fixed for that tunnel.
- **The Authorization-Before-Forwarding Invariant:** No client tunnel bytes, including ClientHello, are forwarded until the complete ClientHello passes validation and its mandatory SNI contains a valid, nonempty FQDN whose normalized value equals the approved CONNECT hostname's normalized value. A successful CONNECT response alone does not authorize forwarding.
- **The Fail-Closed Invariant:** Malformed or unsupported input, ambiguous identity, DNS failure, and resource exhaustion cannot skip authorization checks or enable permissive fallback.

### II. Memory & Resource Invariants

- **The Zero-Allocation Invariant:** While serving traffic or refreshing DNS, proxy execution paths, including dependencies, must not allocate or deallocate heap storage. Boot initialization and final shutdown cleanup after these activities stop are exempt.
- **The Resource-Bounds Invariant:** Connections, buffers, queues, DNS requests, timers, and telemetry have explicit capacity limits. Exhaustion rejects work rather than expanding storage without bound.

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

## Open decisions

- Supported TLS ClientHello profile, including ECH handling.
- Numerical resource limits, deadlines, and DNS refresh cadence.
- Resolver integration and DNS cache ownership consistent with the worker model.
