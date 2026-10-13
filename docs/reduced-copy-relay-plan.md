# Alumina — Reduced-Copy Single-Owner Relay Plan (Proposed)

> **STATUS: PROPOSED DESIGN — NOT IMPLEMENTED.** This is a document-only plan.
> It changes no runtime code, no dependency, and no line of the canonical
> specification `alumina.md` (sha256 `322b68ee…5b836`, byte-unchanged at HEAD
> `1096832`). Every proposed edit listed here is a *seam-level proposal* cited
> against the current checkout; none has been applied, and no implementation or
> benchmark execution is claimed. Diagrams labelled **PROPOSED** describe the
> target design, not the running system.
>
> This plan was produced in offline (fallback) mode: the requested `showme`
> skill is **not available in the active skill list** of this session (a disk-
> directory `~/.config/opencode/skills/show-me/` is present on disk, but the
> active skill registry exposes no loadable `showme`/`show-me` entry), so no
> `showme` invocation is claimed. Diagrams below are self-contained
> Mermaid + ASCII fallbacks. No graph exists in the repository
> (`graphify-out` absent) and none was generated; all statements are grounded
> in direct local source reads at HEAD `1096832`.

## 1. Objective, scope, and out-of-scope

**Objective (one line).** Remove the per-direction *retained-buffer* copy in the
single-owner relay by reading socket bytes directly into the already-initialized
unused tail of the existing retained per-direction buffer — and committing only
the returned write count — while leaving every fixed limit, cursor, gate
accounting rule, and outcome unchanged.

**Scope.** The two read sites in `src/serving.rs` that currently read into a
stack `scratch` and then `memcpy` into the retained buffer:

- client → upstream (`client_readable`): `src/serving.rs:1363-1380` (read) → the
  `append_client_bytes` copy at `src/serving.rs:1405-1413`.
- upstream → client (`relay_upstream_to_client`): `src/serving.rs:1846-1865`
  (read → `down` copy).

**Out of scope (unchanged behaviour, not part of this plan).**

- Ring buffers, kernel zero-copy (`splice`/`sendfile`/`io_uring`/`MSG_ZEROCOPY`),
  multi-worker, new libraries, features, or unsafe uninitialized I/O. Direction
  A was endorsed and kernel zero-copy deferred in user decision `alumina-3xjr.4`
  (evidence `alumina-cub9`).
- The parser-owned fixed-array copies that remain in the path (see §3 and §7):
  direct-tail reads remove the scratch → retained `memcpy` **only**; it does not
  make the pipeline copy-free.
- The reverse (`down`) retained-buffer semantics: reset, backpressure, refusal
  bodies, and FIN half-close change **where** upstream bytes land, never the
  stored profile.
- The fixed resource profile: 128 slots × 2 × 512 KiB retained buffers =
  128 MiB traffic storage (`src/inventory.rs:9-12`; `alumina.md:183`), max
  64 KiB or 16 I/O operations per direction per visit (`src/serving.rs:96-100`;
  `alumina.md:146`), zero heap alloc/dealloc post-boot (`alumina.md:206`).
- Canonical spec, runtime code, dependencies, `docs/architecture.md` decisions,
  managed instructions and doctrine: none edited by this plan.

The user brief for this plan (`alumina-izep`) and the oracle constraints it
depends on (`alumina-bqtc`, itself built on `alumina-ynwp` plus the copy-location
observation pass `alumina-lcj9` and ranked orientation `alumina-cub9`) are the
authoritative inputs; this document restates, never overrides, any of them.

## 2. Current state (as-built at HEAD 1096832)

The relay is a single-owner, single-threaded event loop (`src/serving.rs`;
`alumina.md:140,146,147`), with per-slot state in `SlotWorkspace`
(`src/serving.rs:312-340`). Each tunnel slot owns two boot-retained 512 KiB
buffers transferred in by value from the boot store (`src/serving.rs:343-373`,
`494-500`):

| Buffer | Direction | Capacity | Cursor model |
|---|---|---|---|
| `buf` | client → upstream | `HOLD_CAP` 512 KiB (`:69`; `inventory.rs:11`) | `buf_base`, `buf_len`, `fwd`, `parse_rel`, `insp_rel`, `head_len`, `hello_end`, `hello_consumed` (`:323-331`) |
| `down` | upstream → client | `DOWN_CAP` 512 KiB (`:73`) | `down_len`, `down_off` only — no base, no compaction (`:332-334`) |

### 2.1 Copy inventory — client → upstream (per byte, current)

1. **Read** client socket into stack `scratch: [0u8; CHUNK]`
   (`src/serving.rs:1363-1366`; `CHUNK = 4096` at `:100`; `MAX_OPS = 16` at
   `:96`). Nonblocking; `WouldBlock` returns without progress; `Ok(0)` is
   classified as `Activity::Eof` by `classify_read` (`src/serving.rs:222-225`).
2. **Appendix copy** `append_client_bytes`: `copy_from_slice(&scratch[..n])`
   into the retained tail `buf[buf_len..]`, then `buf_len += n`
   (`src/serving.rs:1405-1413`). This is the copy this plan removes.
3. **Occasional compaction** `compact()`: `copy_within(fwd..buf_len, 0)` moving
   the live tail to the front, with `buf_base` advanced in lockstep
   (`src/serving.rs:379-388`). Not a per-byte `memmove`; runs only when
   `fwd > 0` (relay phase only) and the tail is near cap (`buf_room`,
   `src/serving.rs:1319-1325`).
 4. **Parser/inspector internal copies** (remain, out of scope): the CONNECT
    parser copies the fed segment into its own fixed `head: [u8; CONNECT_LIMIT]`
    (`src/connect.rs:99`, copy at `:133-139`); the ClientHello inspector copies
    into its own fixed `buf: [u8; MAX_CLIENT_HELLO]` (`src/client_hello.rs:192`,
    copy at `:232-243`), then **flattens** each fully-buffered leading record
    into its second fixed 64 KiB `scratch: [u8; MAX_CLIENT_HELLO]` (`:196`); the
    flatten copy is `src/client_hello.rs:304` (`copy_from_slice` of the record
    payload), with each record payload bounded by the 16 KiB per-record
    `RECORD_PAYLOAD_LIMIT` (`src/client_hello.rs:9,288-290`) and the flattened
    buffer bounded by `MAX_CLIENT_HELLO` (`:301-302`); `parse_body` reads the
    flattened slice at `:252`. Both 64 KiB arrays are accounted in
    `SLOT_WORKSPACE_BYTES` (`src/inventory.rs:15-18`). Feeding happens from
    `&ws.buf[parse_rel..buf_len]` / `&ws.buf[insp_rel..buf_len]`
    (`buffer_and_parse` `src/serving.rs:1415-1446`; `buffer_and_validate`
    `src/serving.rs:1648-1672`).
5. **Syscall write** upstream: `up.write(&ws.buf[fwd..buf_len])`, advancing
   `fwd += n` only on `Ok(n)` (`drain_to_upstream` `src/serving.rs:1710-1744`,
   `fwd += n` at `:1721-1722`).

### 2.2 Copy inventory — upstream → client (per byte, current)

1. **Read** upstream socket into stack `scratch: [0u8; CHUNK]`
   (`src/serving.rs:1846-1854`), blocked at `down_len + CHUNK > DOWN_CAP`
   (`:1842`).
2. **Retained copy** `down[down_len..down_len + n].copy_from_slice(&scratch[..n])`
   then `down_len += n` (`src/serving.rs:1861-1865`). This is the copy this plan
   removes.
3. **Syscall write** client: `client.write(&ws.down[down_off..down_len])`,
   advancing `down_off += n` only on `Ok(n)` (`flush_down`
   `src/serving.rs:1791-1831`, `:1800-1802`); on full drain both `down_len` and
   `down_off` reset to 0 (`:1826-1830`).

### 2.3 Gate and D3 write accounting (current)

Forwarded-byte accounting advances **only on successful writes**, cumulative
and non-decreasing (`gate.rs:208-240`, `debug_assert` `:214`). The committed
client→upstream projection is `committed = buf_base + fwd − head_len`
(`src/serving.rs:1758`). `drain_to_upstream` may perform several successful
socket writes in one burst before returning (`src/serving.rs:1710-1744`);
`flush_client_upstream` then reports the cumulative projection ONCE per drain
burst via `gate.upstream_write(committed)` (`:1746-1760`). D3 therefore locates
the gate opening in this **worker accounting transition — before any subsequent
upstream read — not inside a single write syscall** (`docs/architecture.md:75-79`;
`alumina.md:147`). A crossing burst whose cumulative reaches the end of the
validated ClientHello `H` forwards the coalesced tail `X` from the open point;
`X` here means the **accepted** trailing bytes (`cumulative − hello_len`,
`src/gate.rs:228-229`), not necessarily all retained `X`. A partial successful
write stays ordered (`WritingHello { total }`, `gate.rs:36-38,226`); the
`WritingHello` entry sets `fwd = head_len − buf_base`
(`src/serving.rs:1693`), leaving hello+X pending.

## 3. Cursor and gate picture — current

ASCII legend for one slot, both directions. `buf_base` is the **absolute**
stream position of `buf[0]`; `fwd` is an **in-buffer** offset, so the absolute
forwarded prefix is `[buf_base .. buf_base + fwd)`; the gate cumulative is
`buf_base + fwd − head_len`.

```
UP (client->upstream)
  held        absolute  [buf_base .. buf_base + buf_len)
  forwarded   absolute  [buf_base .. buf_base + fwd)     (fwd = in-buffer offset)
  forwardable-on-writable: in-buffer [fwd .. buf_len)
  gate        upstream_committed = buf_base + fwd - head_len

  buf_base            buf_base+fwd         buf_base+buf_len
    |-------------------|---------------------|----------------------|
    | forwarded         | pending             | empty tail (init,     |
    | (write-ok)        | hello+X coalesced   | reusable)            |
    | abs base..+fwd    | in-buffer fwd..len  | today: scratch->memcpy lands here

DOWN (upstream->client)
  held [.. down_len)   written [.. down_off)

    |--------|----------------------------------|---------------------|
    | written| pending                          | empty tail (init)   |
    down_off                                  down_len                DOWN_CAP
```

Fragmented ClientHello crossing (current behaviour, `gate.rs:213-240`;
`flush_client_upstream` `src/serving.rs:1746-1789`):

- hello fragment 1 (1536) + fragment 2 (2560) are fully retained in `buf`;
  validation completes at `hello_end = head_len + hello_consumed`
  (`src/serving.rs:1688-1691`), so `H` ends at `hello_end`
  (`head_len + 4096`).
- `WritingHello` entry: `fwd = head_len − buf_base` (validated hello+X pending).
- `drain_to_upstream` may perform several successful socket writes in one burst
  (`src/serving.rs:1710-1744`); `flush_client_upstream` then reports ONE
  cumulative `gate.upstream_write(committed)` (`:1746-1760`). D3 promises the
  gate opens within this **worker accounting transition — before any
  subsequent upstream read — not inside each write syscall**
  (`docs/architecture.md:75-79`).
- Concrete H=4096 example: the first successful write lifts cumulative to 1536
  (still below `H` → `WritingHello { total: 4096 }`); the next advances it to
  4500, crossing `H` by 404 → `GateOpened { crossing: 4500,
  relay_from_open: 404 }` (`gate.rs:228-235`). `relay_from_open =
  cumulative − hello_len` counts **accepted** trailing bytes only; with 1000
  coalesced `X` retained, 404 are accepted by the crossing burst and
  **residual X = 596** remain not yet forwarded.
- Residual client→upstream `X` is re-flushed on the upstream-writable relay
  arm (`src/serving.rs:1543-1552`) and on the client_readable relay re-flush
  before its next client read (`:1356-1361`). `client_writable`'s relay arm
  (`src/serving.rs:1924-1938`) flushes the **down** buffer and resumes upstream
  reads; it does **not** re-flush residual client→upstream `X`.

## 4. Proposed minimal change (PROPOSED — NOT IMPLEMENTED)

The seam is *reading directly into the initialized unused retained tail* and
committing only the returned count, dropping the stack `scratch` and its
`memcpy` into the retained buffer for both directions. This mirrors the
reserve/commit/drain idiom already used by the fixed-buffer DNS path
(`src/startup_dns.rs:513,1221` per `alumina-lcj9`) and reuses the existing
field-disjoint borrow pattern already present in this file.

### 4.1 Up direction (client → upstream)

**PROPOSED** replace `src/serving.rs:1363-1380` + `:1405-1413` with a direct
tail read of bounded length:

1. Existing `buf_room` guard runs first (`:1319-1325`, `:1348-1355`): it compacts
   when `fwd > 0 && HOLD_CAP − buf_len < CHUNK`, and refuses/rejects/returns when
   `buf_room < CHUNK`, so **no zero-length tail is ever presented to the
   nonblocking read** (a zero-length read would return `Ok(0)` = false `Eof`, per
   `classify_read` `:222-225`).
2. Read into a bounded tail slice `&mut ws.buf[buf_len .. buf_len + CHUNK]`
   (length `CHUNK`, sound because the guard guarantees `HOLD_CAP − buf_len ≥
   CHUNK`). Reading at most `CHUNK` per op preserves the 64 KiB / 16-op-per-visit
   bound exactly (`:96-100`, `alumina.md:146`) — an unclamped full-tail read
   would change that bound, so the clamp is part of the minimal proposal.
3. **Commit only the returned `n`**: `buf_len += n`. `WouldBlock` commits
   nothing and returns without progress, exactly as today.
4. Feed the parser/inspector from the already-retained bytes
   `&ws.buf[parse_rel..buf_len]` / `&ws.buf[insp_rel..buf_len]` via a
   feed-without-append step (the validate path already skips appending on an
   empty slice, `src/serving.rs:1649-1651`; the parse path gains the same
   guard). This is the "split current read\`append_ingest` so receive vs commit
   parse no second copy" requirement (`alumina-izep`): receive = direct tail read
   + `buf_len` commit; commit-parse = feed existing retained bytes.
5. **Borrow ordering and seams:** the tail borrow lives only across `read`;
   `buf_len` is mutated and any capacity-check/compact happens **after** the
   borrow ends (compact while a live tail slice exists is an aliasing defect).
   The existing `buf_room` compact-trigger already completes before the read
   borrow begins, so the natural loop ordering preserves this. The PROPOSED up
   read is a **direct field-read** — `(slot.client, &mut slot.buf[buf_len..])`
   borrowed as disjoint fields in one scope (mirroring `drain_to_upstream`
   `:1714-1737` and `append` `:1405-1413`) — **not** a call through the
   whole-owner `read_upstream(&mut self, index, buf)` helper (`:1637`), whose
   `&mut self` receiver overlaps a tail borrowed from the same `SlotWorkspace`.
   The borrow-clean shape is argued by construction here; compile/behavior
   proof remains producer-owned and planned (§7), never claimed as a review
   result.

**Removed copy:** item 2 of §2.1 (scratch → `buf` `memcpy`). **Unchanged:** the
`fwd`/`compact()`/`buf_base` invariant — compaction stays relay-only
(pre-gate `fwd == 0` no-op, `src/serving.rs:379-382,375-378`).

### 4.2 Down direction (upstream → client)

**PROPOSED** replace `src/serving.rs:1846-1865`:

1. Keep the existing block-at-`down_len + CHUNK > DOWN_CAP` guard
   (`:1842`) — it is exactly the guarantee that the tail slice is not
   zero-length and the backpressure/refusal capacity policy is unchanged.
2. Read upstream directly into `&mut ws.down[down_len .. down_len + CHUNK]`.
3. Commit only the returned `n`: `down_len += n`; `WouldBlock` returns without
   mutation (`:1854` today).
4. `flush_down` (`:1866`, `:1791-1831`) and the full-drain reset
   (`:1826-1830`) are untouched; `down_off` advances only on successful client
   writes, refusal bodies (`BODY_200` etc. `:1525-1526,1877-1879`) flow into the
   same `down` store unchanged.

**Removed copy:** item 2 of §2.2 (scratch → `down` `memcpy`). **Unchanged:** the
down `[down_len, down_off]`-only cursor model, drain reset, and FIN half-close
(`finish_drain` `:1985-2009`, `maybe_close_drained` `:2013-2022`).

### 4.3 Test seams (PROPOSED seam shape, not a runtime claim)

`read_upstream(&mut self, index, buf: &mut [u8])` (`src/serving.rs:1637`) borrows
the **whole owner**, so it cannot receive a mutable tail borrowed from
`self.slots[index]` — the existing relay read already bypasses that helper and
reads `up` directly (`:1847-1849`). Two distinct facts follow:

- The **relay payload read** (down) is proposed as the direct field-disjoint
  read `(slot.upstream, &mut slot.down[down_len..])` in one scope (see §4.2) —
  no whole-owner call, tail borrow scoped to `read`, `down_len += n` committed
  after it drops. That shape compiles by the same disjoint-field rule the file
  already relies on (`drain_to_upstream` `:1714-1737`); the compile proof is a
  planned producer step, not claimed here.
- The **pre-open activity read** (`observe_upstream_read` `:1591-1635` via
  `read_upstream`) keeps a stack `scratch` today and its `test_reads` hook
  (`:339,371,1639-1641`) stores only `io::Result<usize>` counts — payload is
  irrelevant there because any observed activity terminates setup
  (`gate.rs:245-252`). That count-only semantics is preserved.

For the relay payload read to gain a deterministic injection route without an
incompatible receiver borrow, a **minimal field-level sibling** is needed — a
free or static-seam function taking the disjoint fields explicitly, e.g.
`read_upstream_direct(up: &mut Option<TcpStream>, test_reads:
&mut Vec<io::Result<usize>>, tail: &mut [u8]) -> io::Result<usize>`, invoked as
a single borrow `(…upstream, …test_reads, &mut slot.down[down_len..])`. If
injection is extended to the payload read, an injected `Ok(n)` must
**materialize bounded bytes into the provided tail** (a count alone does not
place data); the TDD cycle may instead drive real upstream sockets, which the
current relay tests already do. Real client sockets remain a valid
deterministic route for the up read; adding a client injection API is **not
mandatory**.

## 5. Proposed diagrams (PROPOSED — NOT IMPLEMENTED)

### 5.1 Data-path before/after, both directions

```mermaid
flowchart LR
    subgraph UpCurrent["UP — CURRENT (client -> upstream)"]
        C1[client socket] -- "read 4KiB" --> S1[/stack scratch 4KiB/]
        S1 -- "memcpy into retained tail" --> B1[(retained buf 512KiB)]
        B1 -- "feed slice (parser CH copies)" --> P1[CONNECT/CH workspaces]
        B1 -- "write ok -> fwd+=n" --> U1[upstream socket]
    end
    subgraph UpProposed["UP — PROPOSED (client -> upstream)"]
        C2[client socket] -- "read up to CHUNK direct into retained tail" --> B2[(retained buf 512KiB)]
        B2 -- "feed slice (parser CH copies)" --> P2[CONNECT/CH workspaces]
        B2 -- "write ok -> fwd+=n" --> U2[upstream socket]
    end
    subgraph DownCurrent["DOWN — CURRENT (upstream -> client)"]
        U3[upstream socket] -- "read 4KiB" --> S3[/stack scratch 4KiB/]
        S3 -- "memcpy into retained tail" --> B3[(retained down 512KiB)]
        B3 -- "write ok -> down_off+=n" --> C3[client socket]
    end
    subgraph DownProposed["DOWN — PROPOSED (upstream -> client)"]
        U4[upstream socket] -- "read up to CHUNK direct into retained tail" --> B4[(retained down 512KiB)]
        B4 -- "write ok -> down_off+=n" --> C4[client socket]
    end
```

```text
CURRENT  client -> upstream : read->scratch  memcpy(scratch->buf)  feed(parse)  write(fwd)
                             [1 read+1 copy+workspace copies+1 write]
PROPOSED client -> upstream : read -> buf tail (direct)           feed(parse)  write(fwd)
                             [1 read+workspace copies+1 write]   (scratch + memcpy removed)

CURRENT  upstream -> client : read->scratch  memcpy(scratch->down)  write(down_off)
                             [1 read+1 copy+1 write]
PROPOSED upstream -> client : read -> down tail (direct)           write(down_off)
                             [1 read+1 write]                     (scratch + memcpy removed)

Workspace copies that REMAIN (not copy-free):
  CONNECT head 8KiB copy (src/connect.rs:133-139)
  ClientHello 64KiB input copy (src/client_hello.rs:232-243)
    + flatten into 64KiB scratch, each record <= 16KiB cap (src/client_hello.rs:304,252,9)
  compaction copy_within (src/serving.rs:379-388)  [relay phase only]
```

### 5.2 Proposed cursor/held picture per direction

```text
UP    held       absolute [buf_base .. buf_base + buf_len)
      forwarded  absolute [buf_base .. buf_base + fwd)     (fwd = in-buffer offset)
      forwardable in-buffer {fwd .. buf_len}   gate committed abs = buf_base + fwd - head_len
      PROPOSED tail read: &buf[buf_len .. buf_len+CHUNK], then buf_len += n

  buf_base            buf_base+fwd         buf_base+buf_len
  |-------------------|---------------------|----------------------|
  | forwarded         | pending (accepted,  | empty tail (init,     |
  | (write-ok)        | forwardable)        | reusable)            |
  | abs base..+fwd    | in-buffer fwd..len  | PROPOSED direct read  |
  |                   |<- write ok advances fwd ->|               |
  |                   |<- compact() moves (fwd..buf_len)->0, buf_base+=fwd -- relay only

DOWN  held [.. down_len)   written [.. down_off)
      PROPOSED tail read: &down[down_len .. down_len+CHUNK], then down_len += n
  |--------|----------------------------------|---------------------|
  | written| pending                          | empty tail (init,   |
  down_off|                                  down_len     reusable) |
```

### 5.3 Gate crossing with fragmented ClientHello + partial write (unchanged semantics, retained by this plan)

```text
buf (ABS bytes vs stream base, rel to head_len):
   [head_len ..... H (4096) .....][X retained (1000) ][.. later bytes ..]
   0                            hello_end           hello_end+1000       buf_len'
   head_len  ^ H ends at hello_end = head_len + hello_consumed

1. Fragmented H: fragment1 (1536) + fragment2 (2560) fully retained -> H=4096,
   coalesced X=1000 retained after hello_end => validated.
2. WritingHello entry: fwd = head_len - buf_base  (hello+X pending).
3. drain burst writes: cumulative 1536 (below H) -> gate WritingHello{total:4096}.
4. Next write advances cumulative to 4500, crossing H by 404 ->
   gate GateOpened{crossing: 4500, relay_from_open: 404}
   (gate.rs:228-235) --- a worker accounting transition BEFORE any subsequent
   upstream read; 404 accepted X forwarded, residual X=596 retained not yet
   accepted by that crossing.
5. Residual X drains on later writable/read edges
   (upstream_writable :1543-1552; client_readable relay re-flush :1356-1361);
   ordered, never duplicated (gate.rs:357 test).
```

## 6. What stays fixed (limits, invariants, accounting) — PROPOSED target

| Element | Value / rule | Source |
|---|---|---|
| Retained per-slot store | 2 × 512 KiB (`buf` + `down`), 128 slots, 128 MiB | `inventory.rs:9-12`; `alumina.md:161-164,183` |
| Boot ownership | single boot owner, buffers moved in by value, no post-boot heap alloc/dealloc | `serving.rs:343-373,494-500`; `alumina.md:206,150` |
| Per-visit IO budget | ≤ 64 KiB or 16 ops per direction (direct tail read clamped to `CHUNK`) | `serving.rs:96-100`; `alumina.md:146,213` |
| Setup caps | CONNECT 8 KiB `TooLong`; ClientHello ≤ 64 KiB `TooLarge`, record payload 16 KiB; serving 512 KiB is only the coarser backstop | `connect.rs:8,131-152`; `client_hello.rs:6-9,238-249`; `alumina.md:163-164` (D5b) |
| Gate accounting | `committed = buf_base + fwd − head_len`; advance only on successful writes; **no second byte count** (duplicate offset fact rejected) | `serving.rs:1756-1759`; `gate.rs:208-240`; `alumina.md:147,220` |
| Gate open | one `gate.upstream_write` per drain burst; opens in the worker accounting transition crossing `H`, before subsequent upstream read; coalesced `X` retained, never duplicated | `gate.rs:213-240`; `serving.rs:1710-1760`; D3 |
| Barriers | A/B as today: no client bytes before full validation; no upstream bytes before gate open; pre-open upstream activity terminates | `gate.rs:245-252`; `alumina.md:201` |
| Down reset/backpressure | full-drain reset `down_len=down_off=0`; full tail → no read, stall/re-arm; fixed 200/refusal bodies | `serving.rs:1826-1830,1842,1525-1526,1877-1879` |
| Drain/closure | first EOF starts never-reset 5 s drain; directional half-close only when that direction drains; both-EOF+drained closes exactly once | `serving.rs:1985-2022`; `alumina.md:190-191` |
| Parser workspace copies | CONNECT 8 KiB + ClientHello 64 KiB input copy → 64 KiB flatten workspace (per-record payload cap 16 KiB) **remain** (not copy-free) | §5.1; `serving.rs:1415-1472`; `alumina.md:206` |
| Compaction | `compact()` relay-only (pre-gate `fwd == 0`), `buf_base` in lockstep, cumulative invariant preserved | `serving.rs:379-388`; D5 |

## 7. Native future verification plan (PLANNED, NOT RUN)

No direct-tail execution witness exists; the oracle `alumina-bqtc` names this
GAP explicitly. Before any implementation claim the following native cases are
required; the plan below is **planned**, none of it has been executed for this
document.

### 7.1 Expected TDD cases (narrow, phased, Tidy First)

Planned red → green steps (behavioural changes only; structural tidyings land in
separate commits per Tidy First):

1. full-buffer residual read (tail clamped to `CHUNK`; residual handled on next
   edge),
2. fragmented ClientHello crossing `H` with coalesced tail retained/ordered,
3. compaction-vs-live-tail-slice borrow (compact only after borrow dropped),
4. `WouldBlock` no-progress and no offset advance (up and down),
5. zero-EOF guard (empty tail never handed to a nonblocking read),
6. per-visit budget limit (64 KiB / 16-op unchanged),
7. partial successful write ordering (gate `WritingHello{total}`, then
   `GateOpened{crossing, relay_from_open}`),
8. successful-write gate-counter zero-effect (committed projection identical;
   no second byte count),
9. down reset/backpressure and FIN half-close unchanged.

### 7.2 Affected current tests (actual names, qualify CURRENT candidate only)

These green tests pin the invariant the change must preserve. They qualify the
**current** candidate (`alumina-bqtc`; reuse cannot qualify a changed future
candidate):

- `relay_pending_tail_then_fresh_bytes_preserve_order_and_count`
  (`src/serving.rs:3180`)
- `relay_client_fin_drains_pending_bytes_then_half_closes_and_releases`
  (`src/serving.rs:3229`)
- `sink_drain_of_client_upstream_resumes_paused_client_source`
  (`src/serving.rs:3345`)
- `sink_drain_of_client_writes_resumes_paused_upstream_source`
  (`src/serving.rs:3402`)
- `directional_buffer_profile_matches_the_128_mib_mandate`
  (`src/serving.rs:3850`)
- gate units `gate_opens_in_the_same_write_that_crosses_h` (`src/gate.rs:336`)
  and `relay_and_coalesced_bytes_are_ordered_and_never_duplicated`
  (`src/gate.rs:357`); gate unit suite `src/gate.rs:315-471`.
- E2E `relay 11/11`, `shutdown 10/10` at the current candidate (qa-package
  README; harness `localhost/alumina-e2e:e2e-20261011`) — evidence for the
  **current** candidate only.

### 7.3 Named verification commands

Owners and prerequisites: `README.md:61-89` (Verification) and
`qa-package/README.md:75-118` (selector host context — the sole owner:
`mid` Linux-only via `boundary phase1` dispatch on Darwin; `fixtures boot`
host-Podman; `e2e` selectors directly host-runnable with immutable harness ID;
`boundary phase1` requires podman/flock-vm, Node, git, hashers, python3, and
`cargo-audit`/`cargo-deny`, never invokes E2E). Docs gate per `AGENTS.md`:
doc-only changes → `sh scripts/verify.sh docs`.

Base suite (matches `README.md:66-70`):

```
cargo +1.99.0 atest -p alumina --locked
cargo +1.99.0 atest -p alumina --locked --features alloc-witness
cargo +1.99.0 fmt --check
cargo +1.99.0 aclippy -p alumina --locked --all-targets -- -D warnings
```

Narrow filters for directly-affected invariants during TDD. The named tests
below are crate unit tests (`#[cfg(test)]` modules in `src/serving.rs` and
`src/gate.rs`), selected on `-p alumina` by libtest name filters (e.g.
`cargo +1.99.0 atest -p alumina --locked -- relay_pending_tail_then_fresh_bytes_preserve_order_and_count`);
the exact filter spelling is producer-verified when executed, not asserted now.
Affected invariants: `relay_pending_tail_then_fresh_bytes_preserve_order_and_count`
(`serving.rs:3180`), `relay_client_fin_drains_pending_bytes_then_half_closes_and_releases`
(`:3229`), `sink_drain_of_client_upstream_resumes_paused_client_source` (`:3345`),
`sink_drain_of_client_writes_resumes_paused_upstream_source` (`:3402`),
`directional_buffer_profile_matches_the_128_mib_mandate` (`:3850`);
gate units `gate_opens_in_the_same_write_that_crosses_h` (`gate.rs:336`) and
`relay_and_coalesced_bytes_are_ordered_and_never_duplicated` (`:357`); gate unit
suite `gate.rs:315-471`.

Changed-candidate host/native selectors (run against the implemented future
candidate, not this plan):

```
sh scripts/verify.sh docs                       # native 4-doc offline link gate
node scripts/docs_check/check.mjs README.md AGENTS.md alumina.md \
  alumina-refinement.md docs/architecture.md docs/build-plan.md \
  docs/traceability.md docs/harness-evaluation.md qa-package/README.md \
  docs/reduced-copy-relay-plan.md               # explicit set INCLUDING this plan
sh scripts/verify.sh boundary phase1            # host coordinator: MID union + fixtures + docs + audit/deny + identity; never E2E
sh scripts/verify.sh e2e relay                  # directly host-runnable; rebuilds exact-source production in-run
sh scripts/verify.sh e2e shutdown               # directly host-runnable (rootful harness)
```

`boundary phase1` / `e2e relay` / `e2e shutdown` are the changed-candidate
native gates the current `alumina-bqtc` GAP defers; executing them is future
producer work, not part of this document.

### 7.4 Measurement plan (PLANNED — NOT RUN; comparable, not universal)

The full native 4 MiB bidirectional echo exists as the functional
`POS-LARGE-ECHO` case (`scripts/e2e_relay.py:995-1000`:
`case_raw_echo(…, 4 * 1024 * 1024, "POS-LARGE-ECHO", coalesce_hello=True)`),
reached by the whole `sh scripts/verify.sh e2e relay` selector. That selector is
a **functional relay** pass, not itself a CPU / copy / stack / allocator
benchmark — no automatic instrumentation route for those metrics exists.

Planned before/after measurements on that 4 MiB echo, both directions:
CPU, wall-elapsed, per-byte copy count, stack peak, allocator — every figure
carrying build, workload, concurrency, machine image, cache state, and date; no
universal gain asserted. Allocator delivery uses the existing witness contract:
`src/alloc.rs` `run_phase` phase scopes (`:96-110`) accumulate `Counts` per named
phase (`:67-70`), and capturing a measurement requires BOTH a declared phase
scope AND a witness-enabled build (`--features alloc-witness`) — enabling the
feature alone is not a measurement receipt (`alloc.rs:67-109,135-137`). A
CPU/copy/stack-peak capture has **no existing native command**: that is the
named **unresolved** instrumentation seam and planned producer work, not a
runnable command in this plan. No measurement has been executed and none is
claimed; the production-only `e2e relay` selector is not claimed to test both
allocator variants.

## 8. Material risks and cheap falsifiers

| Risk | Cheap falsifier (read-level / design check) |
|---|---|
| Borrow alias / cursor stale: invalid slice length or aliased tail | direct slice length is derived from the same `buf_len`/guard the code mutates; confirm only disjoint fields are borrowed and the borrow spans only `read`. |
| Parser retained slice vs compaction resets `H` offset | compaction is pre-relay no-op (`fwd == 0`), and `parse_rel`/`insp_rel` are reset only on slot reset (`:399-400`); confirm no compact between a tail read and its feed. |
| Gate bug / wrong committed projection | `committed = buf_base + fwd − head_len` unchanged; **no second byte count** added; gate unit tests must stay green. |
| Zero-length tail → false `Ok(0)` EOF | keep `buf_room` guard + `< CHUNK` refusal; assert the tail slice is never empty at the read site. |
| Weird CPU regression / per-visit bound drift | clamp direct read to `CHUNK`; measurement §7.4 planned to bound any residual. |
| `WouldBlock`/failure offsets | no offset advances on failure; `down_off`/`fwd` mutate only on `Ok(n)` (existing). |

None of these have been executed for this plan; they are the named falsifiers
the independent review and the future TDD cycle check (§9 points to routing).

## 9. Discussion points (few, material)

1. **Test seam for the payload reads.** The up/client read has no `test_reads`
   seam today (tests drive real client sockets). For the down/upstream relay
   payload read, the direct field-disjoint read is the proven seam; a
   deterministic injection route needs the minimal field-level sibling named in
   §4.3 (borrowing only `(upstream, test_reads, &mut down[down_len..])`, with an
   injected `Ok(n)` materializing bounded bytes into the tail), OR real
   upstream sockets as the current relay tests already use. The pre-open
   activity path keeps its count-only `test_reads` semantics (payload
   irrelevant — any observed activity terminates setup). Which route the relay
   TDD cycle takes is a genuine test-story decision; either is consistent with
   this plan's unchanged-scope bounds.
2. **Implement now vs measure first.** The change is optimization-motivated with
   no measured throughput gate; the retained-buffers mandate (`alumina.md:183`)
   binds storage, not CPU. The before/after measurement (§7.4) should run before
   committing to the borrow-risk surface; if it shows negligible CPU delta, the
   plan can be closed as not-worth-implementing with the evidence retained.

## 10. Deliverable scope, tracking, and rollback

- **This session produces only this document** (`docs/reduced-copy-relay-plan.md`).
  No runtime/canonical/dependency edits; canonical `alumina.md` sha256
  `322b68ee…5b836` is byte-unchanged; HEAD `1096832` clean-main identity.
- **Review gate.** An independent generic (non-Rust) read-level review of this
  plan against actual source, oracle constraints, and the exact native commands
  runs **before** any authorized commit/push. On approval, only an ordinary
  linear `git push origin main` with the doc-only diff is authorized
  (no force push, no reset of shared main).
- **Rollback.** Remove the mission-created document before publication if
  needed; after commit, ordinary reviewed revert only.
- **Beads / evidence.** Source/input identity, raw verification output and
  exits, and publication state are recorded to the mission evidence bead
  `alumina-asq3` (parent user task `alumina-izep`), which stays open until
  commander verification; gardener closes it.

## 11. References

- `alumina.md` (canonical, sha256 `322b68ee…5b836`): §Scheduling/I-O model
  (`:146-147`), runtime prerequisites (`:150`), fixed limits (`:154,160-164`),
  traffic storage / reuse / backpressure (`:183,185`), lifecycle (`:190-191`),
  invariants (`:198,201,206,213,220`), verification (`:223`).
- `docs/architecture.md`: D2 two barriers, D3 gate opening, D4 early activity,
  D5/D5a/D5b accounting and buffer reuse, §4 state machine, §6 fixed storage.
- Source seams cited in §2–§6 (all read at HEAD `1096832`).
- Evidence beads: `alumina-bqtc` (oracle summary), `alumina-ynwp` (binding
  constraints), `alumina-cub9` (ranked orientation), `alumina-lcj9` (copy
  inventory), `alumina-3xjr.4` (user decision: direction A endorsed).
