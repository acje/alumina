# Alumina — phase-1 foundations + boot + wired serving runtime

Statically-linked, single-binary HTTP CONNECT egress proxy for constrained
servers. This repository currently contains the phase-1 foundations slice
(exact toolchain pin F0, allocation-counter witness F1, deterministic scripted
I/O outcomes F2, parser-target/corpus ownership scaffolding F4), the boot
increment: strict config/resolver validated types, Linux startup privilege
preflight, the fixed boot-storage inventory, and a boot-owned startup DNS
window that resolves the allowlist within the 90 s window — and the serving
runtime increment: one cooperative/shared-readiness owner continues that same
startup listener/cache/clock into actual CONNECT/ClientHello gate relay on a
serving decision, with the retained serving workspaces preallocated before
the DNS window. Logging, schedule-driven DNS refresh, SIGTERM shutdown, and
deployment remain later slices and are **not** implemented. See
[Checkpoint status and limitations](#checkpoint-status-and-limitations).

Alongside the boot scaffold, the **protocol-serving parsers** are present as
provisional, instrument-free implementations: DNS response classification
(`dns.rs`), CONNECT request-head parsing (`connect.rs`), TLS 1.3 ClientHello
inspection/framing (`client_hello.rs`), plus shared normalized-hostname types
(`config.rs` `FixedHostname`). "Provisional" is deliberate — they are
correct-by-construction, fixed-storage inputs to later slices, **not**
qualified serving components. See [Provisional protocol-parser status](#provisional-protocol-parser-status).


## Provisional protocol-parser status

A subset of the protocol-serving parser layer was implemented product-first,
before the qualification gates in `docs/build-plan.md` (§0). These hold **no**
servable-status claim and have not passed those gates:

| Component | Provisionally implemented | Deferred qualification |
| --- | --- | --- |
| DNS response classification (`src/dns.rs`) | covering-SOA rule, bounded CNAME ≤8, NODATA/NXDOMAIN, unknown-RR skip, case-insensitive owners, ≤128 RR bound, fixed reusable parse workspace + fixed binding storage (0 heap in parse under `alloc-witness`), authority-only SOA negative provenance, per-owner candidate cap | F2 scripted malformed/timeout outcomes, F4 wire-parser fuzzing, Linux MID/BOUNDARY |
| CONNECT request-head parse (`src/connect.rs`) | exact HTTP/1.x version, first-CRLFCRLF boundary (byte-conservation via `head_len`), tchar headers, fixed 8 KiB head | F1 serving-phase witness, F2 boundary/deadline scripts, F4 framing fuzzing |
| TLS 1.3 ClientHello gate (`src/client_hello.rs`) | record/handshake reassembly, fixed storage, ECH rejection, SNI normalization, duplicate-extension and length-integrity rejection | F1 serving-phase witness, F2 gate-transition scripts (D3/Boundary A/B, early activity), F4 fuzzing, TLS 1.3 endpoint interop |
| Normalized hostname (`src/config.rs` `FixedHostname`) | shared fixed `[u8; FQDN_MAX_LEN]` lowercase type feeding the two gates | — (no gate beyond the parsers that use it) |
| Startup-DNS transport (`src/startup_dns.rs`) | one reusable mio poll/event connection, fixed 512 B query + 16386 B response buffers, typed non-allocating errors separated into counted per-exchange network failures vs fatal storage/entropy/lifecycle/token-exhaustion, monotonic poll-token generation that refuses (rather than wraps) on exhaustion, explicit register/deregister lifecycle (state reset even when deregister errors), every counted failure advanced in the schedule backoff, half-open exchange deadline clipped to the startup window | serving integration, connecting route, F4 fuzzing, BOUNDARY (the transport itself was independently reviewed: `bd alumina-4z6b`/`alumina-c14m`; read-outcome classification/connectedness approved in the read-triage cycle `bd alumina-vl6d`) |

Each parser core carries focused falsifier/positive tests per repaired defect
(review report `alumina-p4ot`, repair directives `alumina-26l1.1` and
`alumina-26l1.2`), verified
single-crate with `cargo +1.99.0 atest -p alumina --locked`
(all green), `cargo +1.99.0 fmt --all --check`, `cargo +1.99.0 aclippy -p
alumina --locked --all-targets -- -D warnings`. The endpoint parser cores
(DNS/CONNECT/ClientHello) still have no serving-phase allocation witness,
fault-injection script, or fuzz corpus; the startup-DNS transport (below) is
the one component with independent review and native Linux proof to date. No
product-wide zero-alloc claim is made.

The `getrandom` 0.3.4 dependency intake is complete (recorded in bead
`alumina-zjwk`, duplicate `alumina-z50j` closed; `build.rs` source-reviewed
benign; `cargo deny check advisories` and `cargo audit` clean), and the
startup-DNS transport draft now carries focused actual-DNS runtime tests
(success incl. AAAA, mismatched-TID rejection, fragmented partial reads,
exchange timeout and deadline reconnect, token-generation exhaustion, plus
review-requested falsifiers: a schedule-storage refusal escaping `resolve`
as a fatal error, and a connect-refused nameserver counting a failure and
still advancing the schedule backoff) and an `alloc-witness`
allocation-free-including-reconnect witness. Those transport tests were
verified on the macOS host (`cargo +1.99.0 atest -p alumina --locked` and
the `--features alloc-witness` variant, all green; fmt and `aclippy -D
warnings` clean) and on native Linux arm64 inside the pinned builder image
(release, `--features alloc-witness`): `tests/mio_matrix.rs` 8/8 and the
startup-DNS unit set 12/12 including the reconnect allocation witness. The
transport itself has been independently reviewed (`bd alumina-c14m` /
`alumina-4z6b`; DNS read-outcome classification additionally `alumina-vl6d`);
it remains provisional pending the serving-phase gates and BOUNDARY, and is
not a servable component yet.

## Toolchain

- Pinned in `rust-toolchain.toml`: Rust `1.99.0` (edition 2024).
- Static target: `aarch64-unknown-linux-musl`.
- Linux builder image: `rust:1.99.0-alpine` (arm64), verified official digest
  `docker.io/library/rust@sha256:484dce463db97ee3b9c3dbeb82ac48408091573ec2da1ce9ccd84c823642779a`
  (matches `scripts/verify.sh` IMAGE). The former 1.98.1 digest
  (`400acfd2e044747555ff87ead291c3c480b7a02ba54bc7ac1a1bbce927b862cc`) is not
  carried forward.
- **Verification prerequisites.**
  - Linux MID gates (`sh scripts/verify.sh mid foundations`, `sh scripts/verify.sh mid boot`) run
    inside the Linux builder with `git`, `readelf`, `cargo` 1.99.0 and the actual checkout visible
    (its `.git/HEAD` must be present). The whitespace gate fails closed if `git` or `.git/HEAD` is
    missing — no host proof receipt is consumed.
  - The boundary (`sh scripts/verify.sh boundary phase1`) runs on the **host** as sole coordinator
    and dispatches those Linux MID children through the existing live `flock-vm` Podman connection
    with the pinned builder image (`--pull=never`); it never invokes Linux-only functions directly
    on a non-Linux host. The host additionally requires `podman` with reachable `flock-vm` (and
    `flock-vm-root` for the caps-effective fixture), the pinned builder image present, `cargo-audit`
    and `cargo-deny` installed, `sha256sum`/`shasum` for its before/after source-identity
    capture, and `python3` (host stdlib only, no dependencies) for the authoritative
    cargo-config-candidate observation that distinguishes verified absence from
    permission/traversal/non-regular errors. Absent tools or any failed child stop the boundary non-zero (e.g.
    `LINUX-DISPATCH-BLOCKED`, `AUDIT-DENY-BLOCKED`, `SOURCE-IDENTITY-CHANGED FAIL`) — never a green
    skip; the before/after snapshots must be byte-identical or completion markers are refused.

## Boot inputs (fixed, documented)

The production binary reads two fixed files from the working directory. It
reads **no** CLI arguments, configuration keys, or environment variables as
policy (no CLI/env overrides):

| Input | Path | Contract |
| --- | --- | --- |
| Config | `./config.toml` | Single TOML doc <= 4096 B (reject oversized, no truncation); all keys mandatory, no defaults/coercion; `allowlist` 1..=32 exact FQDN, `listen` `addr:port`, `startup_unresolved_allowance` 0..=allowlist_len-1 |
| Resolver | `./resolv.conf` | First `nameserver` entry only; numeric unicast IPv4/IPv6, no zone id, port 53; missing/unreadable/invalid prevents startup (never skips) |

Boot order (`alumina.md:64`): privilege check -> config + resolver reads ->
storage initialization (128 MiB traffic store + retained serving workspaces)
-> startup DNS window (allowlist resolution within the 90 s window) -> serving
decision. On a Serve decision the listener is bound and `main` continues the
same owner into the shared-readiness `Runtime` serving loop for the process
lifetime; an unresolved count beyond the allowance exits `EX_TEMPFAIL` (75);
any boot/startup failure exits `EX_CONFIG` (78) with a field/source
diagnostic. The serving-loop runtime route is exercised by host integration
tests (mirroring `main`'s exact preallocate -> startup -> attach order) and natively
by `sh scripts/verify.sh e2e relay`, which rebuilds the production binary from
the exact candidate and runs an isolated real-IO CONNECT/SNI opaque-relay gate
against the actual static binary under the privilege profile (see
[Checkpoint status and limitations](#checkpoint-status-and-limitations)).

## Linux startup privileges

At startup the binary requires (checked from `/proc/self/status`, never set by
the binary): a non-root UID, empty effective/permitted/ambient capability sets,
and `no_new_privs`. Unmet prerequisites fail as EX_CONFIG 78. The kernel-
grounded real fixtures run host-side:

```
sh scripts/verify.sh fixtures boot
```

**Checkpoint caveat.** The positive fixture's expected banner
(`PHASE1-BOOT-OK (non-serving scaffold; DNS and listener are later slices)`)
predates both the wired startup DNS window/listener and the now-serving
runtime: against the current binary a Serve decision enters the serving loop
(no 0-exit banner) and an unresolved-exceeds-allowance run exits 75, so the
fixture contract as written is stale for the serving binary, and re-deriving
it (a bounded-stop expectation for the serving loop, with guard-bite proofs)
is a tracked harness-migration item under mission `alumina-26l1.21`. This
checkpoint does not claim that fixture green; its applicable checkpoint gates
(host MID, native Linux dispatch, deny/audit, docs) are the verified evidence
recorded with it.

(`PODMAN_CONNECTION` selects the builder; default `flock-vm`.) Each fixture
runs the actually-built static binary from its fixed `config.toml`/`resolv.conf`
working directory under a different kernel-grounded process-attribute profile.
The executed artifact is the proof-only `fixture-facts` feature build (a
clearly-separate variant under `target/fixture-facts`; the default production
release under `target/release` is untouched) so the binary prints its own
kernel facts (`read_kernel_facts`, `/proc/self/status`) to stderr at actual
entry. Every fixture asserts that binary-entry facts line exactly, the exact
stderr diagnostic, and the expected exit (0 / EX_CONFIG 78):

1. non-root + empty caps + `no_new_privs` — phase-1 OK, exit 0, entry facts all-zero;
2. root (euid 0, any UID axis) — rejected, exit 78;
3. non-root, empty caps, `no_new_privs` missing — rejected, exit 78;
4. non-root with a raised capability set (rootful builder raises
   `cap_net_admin` via inheritable+ambient), `no_new_privs` set — rejected on
   the non-empty effective set, exit 78, with the binary observing all three
   capability sets non-empty (effective-first refusal, not per-axis isolation).

After the fixtures, an authoritative metadata probe (xattr filesystem API via
`scripts/fixture_metadata_probe.py`, run inside the builder) proves the
`security.capability` xattr is absent on the exact executed variant, recording
file mode and sha256, keeping probe errors (stat/listxattr/getxattr failure,
non-regular file) distinct from verified absence.

Permitted-only applicability (authoritative kernel rule `alumina-5zn`): for a
non-root exec of this ordinary non-setid executable — which the metadata proof
confirms carries no file capabilities — the kernel execve rule gives
`P'(permitted) = P'(effective) = P(ambient)` (capabilities(7); commoncap.c
v6.6). A non-root exec clears pre-existing permitted/effective, so a profile
with `CapEff=0` and `CapPrm` non-zero is **not reachable at this binary
entry**; with empty ambient all sets are empty, with non-empty ambient all
three are non-empty together (fixture 4 observes exactly that), and
ambient-only is likewise unreachable because ambient always feeds both
permitted and effective. It is therefore recorded as a proven-applicability
disposition, never asserted native green; the kernel nonempty-permitted and
nonempty-ambient refusal policy is unchanged and the decision-table unit test
(`preflight_rejects_each_unmet_prerequisite_independently`) asserts each
synthetic axis independently. Earlier `PR_SET_KEEPCAPS`/`SECBIT_KEEP_CAPS`
VM-user-namespace claims in this section are corrected: `SECBIT_KEEP_CAPS` is
cleared on execve and is not a permitted-retention mechanism.

## Features

- `alloc-witness` (non-default, opt-in): installs a counting global allocator
  (delegating to the system allocator) so the integration-test harness can
  assert allocation behaviour in named phases. Normal production releases are
  built WITHOUT this feature, so they are never instrumented.
- `fixture-facts` (non-default, opt-in): proof-only diagnostic used by the
  kernel fixtures. The built binary prints its own kernel facts to stderr at
  entry so fixtures assert facts at the exact executable entry. Compile-time
  gated; no policy effect, no privileged bypass, no runtime env/CLI override;
  never part of `default`.

## Commands

- Production release (clean, un-instrumented, static):
  `cargo +1.99.0 build --release --locked`
- Foundation witness tests (F1 + F2 + F4):
  `cargo +1.99.0 atest -p alumina --locked --features alloc-witness --test foundations`
- Foundation tests without the witness (F2 + F4 subset):
  `cargo +1.99.0 atest -p alumina --locked --test foundations`
- Boot tests (strict config/resolver corpus, preflight decision table,
  storage inventory; cross-platform, no kernel dependence):
  `cargo +1.99.0 atest -p alumina --locked --test boot`
- Middle-verification gates (Linux; static-ELF proof + witness tests + fmt +
  clippy + whitespace):
  `sh scripts/verify.sh mid foundations`
  `sh scripts/verify.sh mid boot`
- Native CONNECT/SNI opaque-relay E2E (rebuilds the production binary from the
  exact candidate, then runs the isolated real-IO gate against it; hard exit 0,
  guard-bite tested):
  `sh scripts/verify.sh e2e relay`
- Full phase-1 boundary (sole host owner: coordinates foreground Linux MID,
  boot fixtures, source identity, doc-link and audit/deny gates — every
  missing or failed child blocks completion and returns non-zero; no
  hardcoded success claims; final phase-1 completion stays BLOCKED pending
  fixture/doc/Rust repairs and review approval, no E2E equivalence claimed):
  `sh scripts/verify.sh boundary phase1`

The `atest` / `aclippy` aliases are owned by the fleet user Cargo config on the
host; each Linux MID dispatch writes the identical alias block into a fresh,
throwaway `/cargo-home/config.toml` inside the container (no reusable volume is
mounted for that config), so both owners define the same bytes. The repository
does not duplicate the aliases.

## Repository layout

- `src/alloc.rs` — F1 phase-scoped allocation witness (feature-gated).
- `src/fault.rs` — F2 deterministic scripted I/O outcomes + explicit
  exhaustion and clock semantics.
- `src/fuzz.rs` — F4 parser-target/corpus/seed ownership scaffold with honest
  64-bit FNV-1a input hashing and seed-derived deterministic generation.
- `src/config.rs` — strict TOML config validated internal types (EX_CONFIG 78).
- `src/resolver.rs` — first-nameserver resolver-config parse (numeric unicast,
  no zone, port 53, read once).
- `src/preflight.rs` — Linux kernel prerequisite facts + decision table.
- `src/inventory.rs` — fixed boot-storage inventory (128 MiB traffic +
  per-slot serving workspaces + DNS named buffers, separately accounted as a
  constant-derived lower bound; reserved-future = deferred log queue) +
  actual traffic-storage allocation.
- `src/boot.rs` — boot harness (fixed startup order, EX_CONFIG mapping).
- `src/main.rs` — fixed documented `config.toml` / `resolv.conf` entry: boot ->
  serving-workspace preallocation (before the DNS window) -> startup DNS
  window -> on a Serve decision attach the startup listener and enter the
  shared-readiness `Runtime` serving loop.
- `src/serve.rs` — boot-owned `ServeStorage` (cache/schedules/dns/config/worker/
  origin clock) + the 90 s startup window (`run_startup`).
- `src/dns.rs` — provisional DNS response classification core (see Provisional
  protocol-parser status).
- `src/connect.rs` — provisional CONNECT request-head parser.
- `src/client_hello.rs` — provisional TLS 1.3 ClientHello inspection gate.
- `src/cache.rs`, `src/schedule.rs` — cache/schedule state used by the DNS
  outcome pipeline (provisional).
- `src/eligibility.rs` — address/provenance eligibility ranges.
- `src/worker.rs` — worker decision core: slots/clock/deadlines/connect-phase,
  decrement core only (no event loop).
- `src/gate.rs`, `src/serving.rs` — forwarding gate + mio event dispatcher
  (setup/relay/closures/drain). Wired through `main` via the shared-readiness
  `Runtime` (`src/runtime.rs`): the retained serving workspaces (parser/
  inspector/gate/cursors per slot) and the event buffer are preallocated
  before the startup DNS window, and `Serving::attach_listener` registers the
  listener the startup decision opened.
- `src/runtime.rs` — shared-readiness owner: attaches the retained DNS
  transport to the serving poll so one wait observes DNS freshness and
  traffic readiness, advances the cooperative exchange in bounded turns, and
  folds the DNS deadline into the serving timeout authority; `main` enters it
  via `Runtime::serve`.
- `src/startup_dns.rs` — provisional startup-DNS transport over mio
  (see Provisional protocol-parser status); wired into `main` (via
  `ServeStorage::run_startup`).
- `scripts/verify.sh` — repo-native verification gate owner.
- `scripts/e2e_relay.sh` — native Linux real-IO CONNECT/SNI opaque-relay gate
  runner: network-isolated (`--network none`) container from the pinned-base
  harness image, NNP + uid-65534 drop, foreground supervisor that reaps the
  binary/upstream processes with real waits.
- `scripts/e2e_relay.py` — the driver inside that container: DNS-over-TCP
  responder, raw-echo/TLS/counting upstream fixtures, real TCP/TLS clients and
  full-stream byte-exact + upstream-effect + distinct-timeout assertions.
- `scripts/fixture_metadata_probe.py` — authoritative Linux-xattr metadata probe
  (mode + `security.capability` absence + sha256) used by the boot fixtures.
- `scripts/cargo_config_probe.py` — authoritative filesystem observation of
  Cargo config candidates for the boundary source-identity record.
- `scripts/docs_check/` — offline AST/literal docs-link checker (`check.mjs`).
- `tests/foundations.rs` — foundations integration tests.
- `tests/boot.rs` — boot increment integration tests (TDD corpus).
- `tests/eligibility.rs`, `tests/mio_matrix.rs` — eligibility classification and
  native Linux mio operation matrix (feature-gated `alloc-witness`) tests.

## Checkpoint status and limitations

This repository state is published as a **checkpoint of an incomplete,
expressly non-serving implementation**, not a deployable or servable candidate.
The root register
[`alumina-refinement.md`](alumina-refinement.md) (RF-009/RF-010) and the
canonical spec `alumina.md` remain the governing status/qualification record; a
runtime completion claim requires the build-plan gates plus deployment
qualification, which are not done.

Verified checkpoint evidence for this snapshot (exact file inventory, sha256
identity at `HEAD da2b150`, and every raw command with exit code) is recorded
in the durable bd evidence bead for the checkpoint publication increment, and
in the handoff records for the `alumina-kzar` checkpoint agenda; the commands
in this file re-derive it in the actual checkout with a recorded exit. Native
Linux dispatch used the existing foreground `flock-vm` podman connection with
the pinned builder image (exit observed, not merely probed). Reproducible
checkpoint verification:

```
cargo +1.99.0 fmt --check
cargo +1.99.0 atest -p alumina --locked
cargo +1.99.0 atest -p alumina --locked --features alloc-witness
cargo +1.99.0 aclippy -p alumina --locked --all-targets -- -D warnings
cargo +1.99.0 deny check
cargo +1.99.0 audit
sh scripts/verify.sh docs
```

plus the native Linux dispatch (`sh scripts/verify.sh mid foundations` and
`mid boot`, then the full suite in the pinned `flock-vm` image: default and
`alloc-witness`).

**Known limitations / not implemented (honest inventory):**

- **Serving loop wired; the actual static binary relays a real native
  CONNECT/SNI tunnel.** `main` preallocates the retained serving workspaces
  before the DNS window and enters the shared-readiness `Runtime` loop, which
  attaches the startup-opened listener and relays CONNECT/ClientHello
  traffic. The native production route is proven by `sh scripts/verify.sh
  e2e relay` (guard-bite tested): a freshly rebuilt static binary, dropped to
  uid 65534 with empty caps and NNP, in a fully network-isolated
  (`--network none`) container drives an authentic TLS 1.3 reverse-echo
  round-trip through an allowlisted matching-SNI tunnel, byte-exact
  fragmented/coalesced/partial/FIN/4 MiB echoed streams, and the negative
  vector (disallowed CONNECT 403, SNI mismatch/ECH/malformed hello rejected
  with zero forwarded bytes, dial-refused 502 pre-hello).
- **No post-startup DNS refresh.** The startup window resolves the allowlist
  once; schedule-driven refresh/retirement/alternation is implemented in
  `schedule.rs`/`worker.rs` and the shared-registration seam exists in
  `runtime.rs`/`startup_dns.rs`, but no schedule-driven post-boot refresh
  driver is wired.
- **No structured logging queue.** The canonical 256 x 8 KiB alloc-free log
  queue is reserved in the inventory (reserved-future) but not allocated or
  implemented; `main` uses `print!`/`eprintln!` diagnostics only.
- **No SIGTERM handler.** No signal code exists under `src/`; the canonical
  8 s grace shutdown is not implemented, so the serving loop has no graceful
  stop path yet.
- **Native Linux proofs are scoped, not blanket.** Recorded native evidence is
  confined to the exact candidate it ran against: `mid foundations`/`mid boot`
  (static ELF + whitespace gates), the 8 MiB main-thread accept/reset stack
  run, and `e2e relay` (real static binary under the privilege profile: TLS 1.3
  matching-SNI relay + byte-conservation + negative/effect proofs), all on the
  pinned rust image lineage. Still pending for the production candidate: the
  production-profile allocator witness, post-build harness/gh-report
  assessment, and the E2E scope's remaining native profiles. No claim of those
  pending gates is made.
- **`scripts/verify.sh` phase-1 harness is stale** relative to the now-serving
  startup path (`fixtures boot` positive banner; `boundary phase1`
  NotImplemented lines) as documented above; the phase-1 boundary remains
  BLOCKED, and harness migration with guard-bite proofs is tracked under
  mission `alumina-26l1.21`.
- **Deferred/Unknown:** deployment confinement, E2E, fuzz corpora,
  platform/confinement/performance qualification. No external deployment claim
  is made; security scanning push protection is active on the GitHub remote.
