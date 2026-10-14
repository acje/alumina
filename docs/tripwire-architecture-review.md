# Alumina — Post-Layout-A Architecture Review (advisory proposal)

**Status:** advisory. No restructuring, feature, refactor or specification change is
implemented or authorized by this document. It separates what is **observed today**
(§2) from what a future contract **could** choose to do (increments §4, typed feature
sketches §6), and ends with material questions a later approval step must answer
(§8). The historical alternatives analysis is preserved in the prior review —
[`repository-layout-review.md`](repository-layout-review.md) — and is not restated here.

- **Repo / branch / HEAD:** `acje/alumina-proxy`, `main`, commit
  `4c29c2c8da58d5225029cabb9e149408dafd4ab4` (short `4c29c2c`); every source link in this
  document is pinned to this identity (resolved against the actual checkout at assessment).
- **Canonical spec** `docs/alumina-proxy.md`, sha256
  `322b68eeb112f95960a67843ebafcd65b92da90ca0024f3422fdb95a5395b836` — the **binding
  requirement**, never edited; documents only restate or cite it (not a claim it is fully
  implemented as code; see §9).
- **Working tree at assessment:** only three untracked user bench drafts
  (`scripts/bench_frame_echo.{py,sh}`, `scripts/bench_frame_echo.py.new`); README and canonical
  spec untouched.

## 1. What changed since the prior review (Layout A landed)

The prior review (HEAD `59ad255…`) recommended **Layout A**: extract the two largest inline
`cfg(test)` tails into sibling `tests.rs` child modules. That recommendation has since
landed on `main` as two tidy commits:

| Commit | Effect | Status |
|---|---|---|
| `9903db4` | serving: manufacture `src/serving/tests.rs` (−3,657 in-file, +3,648 sibling) | landed (source-present) |
| `248f132` | runtime: manufacture `src/runtime/tests.rs` (−1,698 in-file, +1,694 sibling) | landed (source-present) |

Both tails end with `#[cfg(test)] mod tests;` and the sibling files open with `use super::*;`
— private fields stay reachable, no visibility widening. Layout B (a production child for the
startup window) was **not** executed; it reappears below as increment **I2**, now informed by
the post-A tree. The mandatory four-folder `controlplane/dataplane/monitoring/runner` boundary
remains rejected exactly as before: it organizes across the single shared scheduler without
hiding information.

## 2. Observed current state (as-built at 4c29c2c)

Counts are **navigation evidence, not complexity scores**. Method is disclosed per bucket:
top-level `src/*.rs`, sibling test files and external `tests/` are exact `wc -l` totals and are
**additive**; inline `cfg(test)` mass is a **subset of the top-level total**, estimated by a
brace-tracked heuristic (non-additive at row level, disclosed as a heuristic, never treated as
a compiler fact). Production columns are **census estimates**, not `wc -l`.

| Additive bucket | Lines | Method |
|---|---|---|
| top-level `src/*.rs` files (production + inline tests, no sibling files) | 18,018 | `wc -l`, exact |
| sibling test files `serving/tests.rs 3,648 + runtime/tests.rs 1,694` | 5,342 | `wc -l`, exact |
| **all-src total** | 23,360 | 18,018 + 5,342 |
| external `tests/` | 2,005 | `wc -l`, exact |
| **grand total (with external)** | 25,365 | 23,360 + 2,005 |

Inline `cfg(test)` mass ≈6,263 is a **subset of the 18,018 top-level lines** (also
brace-tracked heuristic), not an additive fourth bucket.

Largest modules (total `wc -l` / inline census / **estimated production-by-census** /
sibling test file):

| Module | Total | Inline (heuristic) | Est. production | Sibling tests |
|---|---|---|---|---|
| `src/serving.rs` | 2,563 | 120 | 2,443 | 3,648 |
| `src/startup_dns.rs` | 3,024 | 1,338 | 1,686 | — |
| `src/log.rs` | 1,594 | 575 | 1,019 | — |
| `src/dns.rs` | 1,576 | 573 | 1,003 | — |
| `src/worker.rs` | 1,400 | 745 | 655 | — |
| `src/serve.rs` | 1,234 | 642 | 592 | — |
| `src/cache.rs` | 1,155 | 754 | 401 | — |
| `src/schedule.rs` | 877 | 454 | 423 | — |
| `src/runtime.rs` | 376 | 20 | 356 | 1,694 |

`log.rs` is a **deep-module witness**, not "the deepest by census": its only `pub` (non-`pub(crate)`)
top-level item is `LogStoreError` ([log.rs:513](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/log.rs#L513));
the draining sink is private (`sink_fd`, [log.rs:988](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/log.rs#L988)),
hiding roughly 1,019 production lines behind a one-item surface.

### 2.1 Owner map (unchanged fixed profile)

Single binary, one shared poll, one boot owner + one serving owner (`docs/alumina-proxy.md`;
`docs/architecture.md` §2). Pinned source links:
[main](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/main.rs),
[serve](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/serve.rs),
[runtime](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/runtime.rs),
[serving](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/serving.rs),
[gate](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/gate.rs),
[startup_dns](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/startup_dns.rs).

```
src/main.rs          process composition (boot owner) → ServeStorage::boot →
                     Preallocated::preallocate → prepare_stdout_log_sink →
                     run_startup (startup DNS window) → attach(listener) consumes
                     Preallocated → Runtime::serve
src/serve.rs         ServeStorage (private: cache, schedules, StartupDns, config,
                     worker, origin, now0, LogStore); boot() is the only construction path
src/runtime.rs       Preallocated{serving, dns_token} consumed by attach
                     (compile_fail E0599 doctest at runtime.rs:34); DNS_ADVANCE_BOUND=8
src/serving.rs       Serving owns Vec<SlotWorkspace>; SlotWorkspace (435-469) private:
                     parser, inspector, gate, approved, stage, buf/down Box<[u8]>
src/gate.rs          TunnelGate (95) pure per-tunnel state machine; ValidatedHello
                     minted only via pub(crate) new(_accepted: HelloAccepted, end) (126)
src/startup_dns.rs   StartupDns (508) single construction path StartupDns::new(); window ledger
```

### 2.2 One-origin decision facts (the seam an action design must not duplicate)

The code already keeps refusal → wire body → log reason as **one decision** (pinned links):

- CONNECT authorization sets `slot.approved` from the allowlist decision
  ([serving.rs:1825](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/serving.rs#L1825)).
- `buffer_and_validate` feeds `ChInspector`; `hello_complete` calls
  `client_hello::validate(hello, &approved)` and mints `ValidatedHello::new(accepted, end)`
  ([serving.rs:2011-2031](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/serving.rs#L2011-L2031)).
- `serving::Refusal{BadRequest,Forbidden,DialFailed,SetupTimeout}`
  ([serving.rs:203-228](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/serving.rs#L203-L228))
  maps 1:1 to `BODY_400/403/502/504` **and** `log::RejectReason`; `Capacity` and
  `TlsValidation` are emitted separately at the decision site
  ([serving.rs:1477](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/serving.rs#L1477),
  [serving.rs:2398-2406](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/serving.rs#L2398-L2406)).
- Post-200 hello rejection is a **distinct phase path**: `reject_hello` → `gate.on_hello_rejected`
  → best-effort `TlsValidation` warn → `close_slot` — never an injected HTTP body/TLS alert
  (lawful after 200 begins: `docs/alumina-proxy.md:30`).

**Consequence for any action design:** a control fact is captured once, where the decision is
made, from the existing typed `Reason`/`Refusal`/`ChError` values. An action/notification stage
may be a **projection** of that fact, never a second decision re-inferred from raw bytes, logs,
or guard/match flag combinations.

### 2.3 Typed operational errors vs violations; and a separate invariant-breach class

Three classes must stay distinct in any future classification:

- **Operational (ordinary, expected, never a control fact):** `WouldBlock`/`Interrupted`
  (not activity — [gate.rs:20-23](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/gate.rs#L20-L23),
  [serving.rs:238-249](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/serving.rs#L238-L249)),
  `ConnectionReset` as early activity, startup-DNS
  `FailureReason{Connect,Send,Receive,Timeout}`
  ([startup_dns.rs:252-269](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/startup_dns.rs#L252-L269)),
  dial-failure / setup-deadline (`502/504`), capacity (`503`), exchange timeouts, DNS refresh
  incidents, shutdown, overload. These are "expected input and I/O failures handled explicitly"
  (`docs/alumina-proxy.md:148`).
- **Hostile-input violation candidates (the only ordinary control-fact class):** unauthorized
  CONNECT hostname (403), malformed/ambiguous identity or duplicate SNI, ECH present (incl. ECH
  GREASE), non-TLS1.3 version offer, address-policy ineligible destination, malformed DNS
  response / mismatched query binding, obs-fold / Transfer-Encoding / bare-LF in CONNECT. The
  fixed spec labels this class "policy violations, which indicate misconfiguration or
  compromise" (`docs/alumina-proxy.md:43`). This class is where a future, authored violation
  classification could define Control facts — no catalog is assumed here (§6, Q1).
- **Internal invariant breach (separate, not a hostile-input Control):** a closed gate is
  ordinary gate state (`gate.rs` `AwaitConnect`/`Connecting`/`AwaitResponse`/`Validating`;
  `upstream_write` returns `BlockedByBarrierA`); observed early upstream activity has the
  distinct typed path `TerminateReason::EarlyUpstream(Activity)`
  ([gate.rs:63-71](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/gate.rs#L63-L71)).
  Actually forwarding forbidden bytes while barrier B is closed would violate the canonical
  authorization invariant (`docs/alumina-proxy.md:201`) — an internal enforcement failure
  modeled separately, never projected into an optional hostile-input Control. A tripwire may
  never fire on WouldBlock/reset/closed-gate state, and `Unknown` in any evaluator is never a
  violation.

## 3. Fixed-profile constraints every increment and sketch must keep

Binding and unchanged; any **contract change** these conflict with requires explicit later
approval, which is exactly what §8 surfaces:

- Zero-allocation invariant while serving/refreshing, including dependencies
  (`docs/alumina-proxy.md:206`); exhaustion rejects rather than expands storage (`:207`).
- Exactly one worker owns each connection's mutable state (`:211`); no multi-worker data path.
- Fixed configuration read once; no hot reload; no new listening/runtime surface (`:54,149,235`).
- Logs are stdout-only, in-band, best-effort, whole-record drop+count (`:149,194`).
- Before 200 begins a failure may emit a phase-lawful fixed HTTP error; once 200 begins a
  failure closes with no injected response or TLS alert (`:30`).
- No new egress beyond approved-upstream-443 + fixed resolver-53 under deployment
  default-deny confinement (`:116`). TLS capability stays fixed (TLS1.3 / SNI / ECH-reject).

## 4. Recommended minimal increments (unimplemented; each reversible, one axis)

These are the smallest next restructuring steps consistent with Layout A's trajectory. They
are proposals, each owned by a later contract and each with a kill criterion. Feature
behavior (Tripwire/Tarpit/Flare/Portcullis) is **not** a prerequisite for any of them.

### I1 — startup_dns terminal test-module extraction (same pattern as A)

- **Tree change**
  ```
  src/startup_dns.rs        production body + small retained cfg(test) owner hooks
  src/startup_dns/tests.rs  the terminal #[cfg(test)] mod tests (today :1774-:3024)
                            relocated via super::*
  ```
  Scope disclosure: the extractable mass is the **terminal test module** (≈1.25k physical
  lines, `startup_dns.rs:1774-3024`), not the entire ≈1,338 heuristic inline census — earlier
  `cfg(test)` seams (e.g. `startup_dns.rs:481,539,541`) stay in the owner as hooks. The
  execution owner determines the exact extraction range in a later mission.
- **Interface / private ownership:** identical to Layout A — sibling child module, no visibility
  widening, module path `alumina::startup_dns` unchanged.
- **Test ownership:** window-ledger, transport and deadline units stay beside the owner; the
  `NotAttemptedReason::WindowClosed` / `NameOutcome` semantic coupling to the `log` formatter is
  preserved (relocating spellings into a new vocabulary module only if a real second consumer
  appears — never to cure import aesthetics).
- **Benefit:** exposes the terminal test mass, leaving the transport/ledger face-up; same
  navigation gain Layout A proved for serving/runtime.
- **Cost:** one more source hop when reading inline seams; low.
- **Kill criterion:** if the tail's helpers are themselves entangled with the production body,
  prefer a smaller documented seam — do not force the split for symmetry. `dns.rs`/`log.rs`
  follow this pattern only if I1 reads well.

### I2 — serving startup as a private same-owner child (Layout B, re-derived post-A)

- **Tree change**
  ```
  src/serving.rs          Sole Serving type: poll/dispatch, slots, tunnel lifecycle
  src/serving/startup.rs  impl Serving { run_startup_window, StartupTallies }
  src/serving/tests.rs    serving tests incl. the startup coupling
  ```
- **Interface / private ownership:** move the **whole** startup method (≈194 raw lines,
  [serving.rs:894-1087](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/serving.rs#L894-L1087)
  at assessment) plus its small `StartupTallies` type into a child `impl` block that keeps
  private field access. No field widens, **no pass-through state wrapper**, no DNS-owned wait,
  no independent runner; `pub(crate)` method visibility unchanged so `Runtime` still calls it.
  Startup stays time-located with its owner (see §5 temporal-decomposition note).
- **Test ownership:** the startup-window + SIGTERM settlement trace stays as the acceptance
  story; native real-TLS/SIGTERM/timer fixtures remain the proof surface (not boolean
  action-flag guards).
- **Benefit:** a smaller tunnel-reading face; deep-module encapsulation retained.
- **Cost:** one extra production hop during lifecycle reasoning; must read well end-to-end.
- **Kill criterion (F3):** walk the SIGTERM settlement trace (startup_final → shutdown_final,
  drained, reaped exit 0) after the move; if the split fragments that trace or the shared poll
  ownership, revert — relocation alone is not a win.

### I3 — optional owner-local rejection grouping (same owner; F4-tested)

A third increment only if its **own** navigation benefit survives its kill test; two increments
(I1+I2) are a complete minimal plan.

- **Tree change (optional; owner-local, no new policy owner)**
  ```
  src/serving.rs             Serving keeps ownership of the whole rejection path
  src/serving/rejection.rs   OPTIONAL same-owner grouping: impl Serving { refuse, emit_reject,
                             reject_hello, close_slot } + the private Refusal type
                             (today serving.rs:203-228; refuse paths ~2251-2277; reject_hello
                             ~2398-2406) — same owner, private fields, no new ownership
  ```
- **Interface / private ownership:** `Refusal`, `refuse`, `emit_reject`, `reject_hello` and
  `close_slot` remain **Serving's own** mechanism (one-origin refusal→body→log projection kept
  intact, §2.2). A child module is purely a grouping for navigation; it must not create a new
  policy owner, a pass-through wrapper, or split the refusal decision from its log projection.
- **Test ownership:** refusal-mapping and phase-specific close units stay with the owner; the
  post-200 distinct `reject_hello` close remains a first-class negative-effect case.
- **Benefit:** groups the rejection vocabulary in one reading site without widening scope.
- **Cost:** one more hop if the grouping is read back and forth with the phases that emit it.
- **Kill criterion (F4):** measure whether the grouping reduces or merely relocates reading; if
  a maintainer still must jump between the grouping and the phase sites, do **not** land it.

### H2 — conditional competitor: a deep pure shared-policy module (only if a real shared decision appears)

Kept **separate** from I3. This is a different boundary with its own precondition and falsifier:

- **Shape (hypothetical; nothing proposed today):** a deep pure module (e.g. a future
  `src/enforcement.rs`) hiding a classification that **two independent owners demonstrably
  need to share** — private policy types, no sockets, no allocation, tests on a private pure
  fact → enforcement outcome branch.
- **Precondition / falsifier (F2):** only a demonstrated shared-decision consumer promotes H2.
  A future Portcullis attribution surface is **not** by itself proof of a second owner needing
  the same decision. If the only shared thing is the same words in two log lines, there is no
  shared decision — reject H2 as speculative generality (§5).

## 5. Three structural options compared (Ousterhout applied to the actual seams)

Primary sources actually read (author-owned; §9): Stanford book page, CS190 "Modular
Design", and the author's `aposd-vs-clean-code` README. The application below is
**inference grounded in those sources**, not new quotation:

| Option | Depth / interface | Cost | Verdict |
|---|---|---|---|
| **Keep the deep owner** (I1+I2, optional owner-local I3) | Owner already hides the decision machine behind few pub items (serving pub 11 / pub(crate) 24); phase and startup stay under one implementation | Smallest responsibility change; preserves phase owner | **Recommended.** Simplest interface wins; no new layer, no pass-through |
| **Deep pure shared-policy module** (H2) | A small pure interface hiding a real shared classification | New contract + boundary; justified only by a demonstrated shared decision (F2) | Conditional only — see H2 above |
| **Extensible event framework / generic control catalog** | Pass-through surface over one scheduler; generic-flag framing | Inverts depth (interface bigger than the hidden state); speculative generality | **Rejected.** Ousterhout: "don't get carried away"; generic framework flags do not hide information in a single-owner system |

Concrete application to the actual seams under review (attributed as inference):

- **Information hiding:** `Serving` already hides refusal/read/connect/write stages behind a
  few pub items; I2's child `impl` keeps that hiding while grouping the startup method —
  the private phase state is not leaked (Layout A already demonstrated the sibling-module
  seam does not widen visibility).
- **Temporal decomposition warning:** the startup window is deliberately time-located with the
  serving owner (startup → attach → serve compose in `main.rs`, one worker). I2 groups what is
  temporally coupled, and explicitly forbids a DNS-owned waiting runner — splitting by execution
  order across modules is precisely the information leakage Ousterhout warns about.
- **Depth and pass-through:** I2 and I3 both forbid a pass-through state wrapper; a string of
  shallow accessors would be the red flag. The `log.rs` one-item surface is treated as a
  deep-module **witness** (candidate), not a depth ranking.
- **Generality / error handling:** no generic control/action framework is introduced (§6);
  operational errors (WouldBlock/timeout/capacity) are handled locally and never promoted to
  violation facts (§2.3) — "solve, don't punt" applied by keeping refusal→log projection in
  one place so callers never re-derive a reason.

No numeric line budget is proposed anywhere (file length alone is not a seam; the
over-decomposition warning applies). The house-style comments tension is inherited unchanged:
durable rationale lives in documents/beads, not prose attached to code.

## 6. Typed conceptual feature domain (unimplemented, not a catalog, no public API)

These preserve the user-named typed concepts (Tripwire/Tarpit/Flare/Portcullis) as an
**unimplemented conceptual domain** so the information-hiding question is concrete and the
approval boundaries are explicit. Nothing here is a compiling implementation, a public API
decision, or authorization; each later step lists its contract boundary in §8.

```text
// Conceptual sketch only. Control is intentionally UNDEFINED/opaque: a later
// approval decides whether any fixed set is ratified and which facts define one
// (Q1). The facts below are ILLUSTRATIVE, NON-EXHAUSTIVE hostile-input refusal
// classes an authored violation classification MIGHT define — NOT a catalog.
facts-of-hostile-input-refusals = {
    unauthorized CONNECT hostname (403),
    ClientHello identity mismatch / duplicate SNI / ECH present / non-TLS1.3 offer,
    address-policy-ineligible destination,
}   // intentionally partial; internal invariant breach and observed early
    // activity are modeled SEPARATELY (§2.3), never folded into these facts

// Conceptual sketch only. User-named concepts preserved; whether the public
// shape is "one enforceable outcome + independent notification" or "a bounded
// ordered instruction set" is undecided (Q2). Evaluators never allocate, never
// set severity from Unknown, and consume the existing per-visit budget.
Tarpit      = bounded timer-driven terminal pacing / paced refusal    (meaning Q3)
Flare       = best-effort notification (structured stdout; outbound = Q4)
Portcullis  = block/close (current-connection now; global scope = Q5)
```

Lawful ordered composition (one illustrative bounded case, retaining phase owner and ordered
release): **block-now** (Portcullis, current connection) takes effect at the forward barrier
immediately; an approved **terminal pacing** interval (Tarpit) may govern the paced close on a
phase-lawful path — it can never **postpone the blocking decision** while bytes flow; an
independent best-effort **notification** (Flare, via the existing stdout substrate) is
attempted without waiting on its delivery; the owner clears resources exactly once
(release-once), and close-now can never be followed by operations on a released slot. Pre-200,
only fixed error responses are lawful and any paced/denied terminal effect lives inside that
phase's typed refusal path; post-200-begins, close-with-no-injected-bytes is the current
contract and the immediate close stays unless a later contract changes it (Q3).

No runtime activation is sketched: any future activation is a fixed, startup-validated config
table (no hot reload, no pointer-option magic defaults, no new numeric resource limits —
the constants are qualitative unknowns a later approval bounds, never invented here).

## 7. Test-layout direction for any adopted sketch

- Policy domain: pure fact → action/enforcement-outcome unit tests on the private branch
  (no sockets), with operational/violation/Unknown classes kept distinct (§2.3).
- Data-plane lifecycle: negative effect tests at the real transitions (pre/post-200), with
  native real-TLS/SIGTERM/timer fixtures, not boolean action-flag guards.
- Identity/attribution source (only if a global Portcullis scope is ever approved): its own
  validated-source manifest; future changes are separate work, not performed here.

## 8. Unresolved decisions before any feature/refactor contract

Recorded here so an approval step can answer them; none are decided by this proposal. The four
material question areas from the mission frame are covered; the Controls area is split into
**two independent questions** (taxonomy and composition) because they are orthogonal and had
been falsely opposed to each other (review B3).

1. **Controls taxonomy.** What facts define a Control? Is a fixed, ratified Control set ever
   justified, or does the domain keep Control **opaque/not-defined** with an **authored,
   approved violation classification** at each validation site? Which hostile-input refusal
   classes (§2.3) qualify, and how is the internal invariant-breach class kept separate from
   ordinary hostile-input Control facts? No catalog is assumed.
2. **Action composition (independent of taxonomy).** Do terminal enforcement and
   best-effort notification stay independent instructions, share a fixed small ordered set, or
   both? Is a single enforceable outcome plus an independent notification the shape (block-now
   + Flare), or must ordered multi-step terminal sequences be representable (block-now, then a
   phase-lawful paced close)? The owner already performs refusing-plus-notification and
   close-plus-notification in one place (§2.2) without a new representation; no
   mutually-exclusive user-Action sum is assumed.
3. **Tarpit meaning and resources.** Does Tarpit mean bounded timer-driven pacing of a
   phase-lawful **refusal/terminal** effect, or pacing of previously-authorized established
   traffic — or are both excluded under the fixed profile? Under any meaning: never forward
   unauthorized bytes and never postpone the blocking/refusal decision while bytes flow; the
   current immediate post-200 close stays unless a later contract changes it. Timing/capacity/
   admission/expiry budgets are qualitative unknowns for a future approval — never invented
   here.
4. **Flare transport.** Is Flare the existing bounded best-effort **structured stdout** event
   (in-band, no delivery guarantee), or is an outbound alert transport (secret endpoint,
   DNS/TLS deps, egress permissions) actually required despite being a contract/security/
   deployment change?
5. **Portcullis scope.** Is blocking **current-connection** only (fits existing typed
   refusal/close), or must it be **domain or cross-connection client** scope — which needs a
   validated trusted identity source, attribution, false-blocking and resource decisions, all
   explicit later approvals?

## 9. Sources and status (researched vs implemented, accurately labeled)

| Source | Reference | Status |
|---|---|---|
| Canonical spec | `docs/alumina-proxy.md` sha256 `322b68ee…5b836` (full `322b68eeb112f95960a67843ebafcd65b92da90ca0024f3422fdb95a5395b836`), pinned [alumina-proxy.md](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/docs/alumina-proxy.md) | **binding requirement**, never edited — **not** a blanket "implemented" claim; some spec provisions differ from current source (see note below) |
| Design statement | `docs/architecture.md` (D1–D7), pinned [architecture.md](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/docs/architecture.md) | **historical design statement** pinned at HEAD `8934adb`; design context, **not runtime evidence** |
| Prior layout review | `docs/repository-layout-review.md` | preserved history; Layout A **landed** (commits `9903db4`, `248f132`, source-present); Layout B not only unimplemented but a proposed future increment (I2) |
| Current source modules | pinned blob links in §2–§5 (serving/gate/client_hello/startup_dns/log/etc. at 4c29c2c) | resolved against the actual checkout; mechanisms named there are source-present |
| Working tree | `git status`: 3 untracked bench drafts only; README preserved | observed |
| Ousterhout (primary, author-owned) | [book.php](https://web.stanford.edu/~ouster/cgi-bin/book.php), [aposd.php](https://web.stanford.edu/~ouster/cgi-bin/aposd.php), [CS190 Modular Design](https://web.stanford.edu/~ouster/cgi-bin/cs190-winter18/lecture.php?topic=modularDesign), [aposd-vs-clean-code](https://github.com/johnousterhout/aposd-vs-clean-code/raw/main/README.md) | researched (actually read in the observe pass, per evidence alumina-5n9v); not re-fetched here |

**Honest spec/source delta (cited to avoid overstating implementation):** the repository is a
scoped local testQA candidate with open serving-qualification gates (`docs/build-plan.md`); the
canonical spec as a whole is therefore never marked "implemented." A concrete example within
the reviewed path: spec `:43` requires runtime-condition failures (`502/503/504`) to send a
**fixed plain-text body stating the reason**, while the current source defines
zero-content-length bodies for those statuses
([serving.rs:193-197](https://github.com/acje/alumina-proxy/blob/4c29c2c8da58d5225029cabb9e149408dafd4ab4/src/serving.rs#L193-L197)).
That difference is cited only to falsify a blanket implementation claim, not assigned as
remediation in this doc-only mission.

## 10. Method disclosures and coverage limits

- Buckets are **additive and labeled**: top-level `src` 18,018 + sibling tests 5,342 =
  all-src 23,360; + external 2,005 = grand 25,365. The inline `cfg(test)` census (≈6,263) is a
  **subset of the top-level total**, disclosed as a heuristic; production columns are
  census estimates, not `wc -l` (§2). The sibling-test figure (5,342) is exact `wc -l`.
- The four Ousterhout sources are the ones actually read by the observe pass (author's own
  pages/discussion); the full APOSD 2nd-edition chapter text is paywalled/image-only and was
  not read — attribution never extends past what was read. §5's application is labeled
  inference grounded in those sources.
- No runtime builds/tests were run to produce this document (advisory only). The `docs` gate
  (`sh scripts/verify.sh docs`) checks offline document links over the fixed gate roots;
  source-line citations in §2 were re-pinned at HEAD `4c29c2c` and blob links point to that
  identity.
- Everything future-looking in §4/§6/§8 is unimplemented and unauthorized; implemented status
  is stated per row in §9 (landed commits and named source-present mechanisms only).
