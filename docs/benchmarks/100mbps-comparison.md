# Alumina as-is vs to-be — 100 Mbps matched measurement

Measured comparison of the retained AS-IS Alumina binary against the retained
TO-BE reduced-copy binary under the accepted fixed workload (contract
`alumina-gjq4`; mission `alumina-qryg.7`). AS-IS ran **first**, then TO-BE
(approved chronological order), same setup, same supervised container
(`localhost/alumina-e2e:e2e-20261011`, id `9191d288…`, connection
`flock-vm-root`). No candidate binary was rebuilt. No competitor (HAProxy /
Envoy) was **executed**; their source-level intake and selected semantics are
accepted (`alumina-gjq4`, `alumina-elyw`), but route-timeout/config/probe gaps
remain before any runtime (see `Limits`).

**Status:** durable measurement record (measurement HEAD `54a34ce`, measured
2026-10-13) of the retained AS-IS/TO-BE matched pair, corrected per the
independent source-only review `alumina-rqne` (blocking findings B1–B7).
Correction/supersession history is recorded in evidence bead `alumina-76fv`.
Reviewed seam tools (`52e28b87…` / `2b2ecd16…`) and the byte-exact raw
reports referenced under `docs/benchmarks/results/` are listed in `Identity`
and `Raw evidence`.

## Workload and setup (accepted, unchanged)

- 8 persistent connections; 4096 B payload frames + 12 B header counted
  separately; aggregate **open-loop** pacing at 100 decimal Mbps client
  payload (12 500 000 B/s) plus echo; 5 s warmup; 60 s measurement window;
  5 s setup/drain; nominal target 750 000 000 B client payload across
  183 105 planned **whole** frames. The scheduled whole frames carry
  749 998 080 B; the remaining 1 920 B
  (`params.measure_remainder_bytes=1920` in both reports) is deliberately
  **not** scheduled — accepted fixed-frame floor rounding (`alumina-gjq4`).
- Monotonic scheduled open-loop rate (independent of echo completion);
  outstanding cap 1024 frames / 4 194 304 B; exhaustion produces explicit
  unsent (backpressure), never catch-up after the window.
- Real TLS 1.3 byte-exact framed echo backend, genuine CA + SAN
  (`example.com`), endpoint negotiated and validated by the client; proxy acts
  as opaque CONNECT relay (no decryption).
- Host: arm64 Apple-VM, 4 CPU / 14 GiB; native `aarch64-unknown-linux-musl`
  candidates; Python 3.14.8 / OpenSSL 3.5.9 harness image; `--network none`,
  loopback global-unicast alias; candidate dropped to uid 65534.

## Identity and provenance (all verified at run time)

| Item | Value |
| --- | --- |
| Measurement checkout HEAD | `54a34ceeff4aad701f6ce3c2f65ef6965144f30c` (`identity.source_head` in both JSON, filled by the supervisor from the run-time checkout) |
| `seam_echo.py` (tool, reviewed seam) | sha256 `52e28b8784fc7f9b14b017885a7f1d84f739163aabbcba25ec73e6f006b97eeb` (`tool_sha256` in every JSON; matches approval `alumina-9ej1`) |
| `seam_echo.sh` (supervisor) | sha256 `2b2ecd1674bf851b8fdfe66548b2126459f3508f0948628f1843ea73d81494e0` (matches approval `alumina-9ej1`) |
| AS-IS binary (retained, reused) | `.ooda/alumina-vdpi.2/baseline/alumina-musl` sha256 `170fae6c1dbfce1907bb2b2ec02599808c4d9404b243ccd24b8834490d3ab72f` (`executed_binary_sha256` == `retained_binary_sha256` in every JSON) |
| TO-BE binary (retained, reused) | `.ooda/alumina-vdpi/tobe/baseline/alumina-musl` sha256 `8a9f1f5b288abc1ec649e9a98302caa8e088d1f5e55c432950a59167d869dec8` |
| Config (identical for both) | `config_sha256` `a0b505295bac82a10270d66a74a38c5723f6cd120c7d04d71daad5b22e5122bb` (allowlist `example.com`, listen `127.0.0.1:8080`) |
| Harness image / OS | `9191d288353391e4751525e83196e8127884d73daa395ced6fafc4a96d71564f` (parent `ad70ceb90f563e9fe2ef7064b92dc1347aeaeb71e5369ba8b242498ba030a6f8`), OpenSSL 3.5.9, Python 3.14.8, target `aarch64-unknown-linux-musl` |
| AS-IS raw report | `.ooda/benchmarks/54a34ce-seam-as-is-timed-20261013T234349Z.json` sha256 `d75156f7006aae40741e47a565bad5508de67d7e6536907d1d5ba939e53f46b1` |
| TO-BE raw report | `.ooda/benchmarks/54a34ce-seam-to-be-timed-20261013T234500Z.json` sha256 `f6fe021b1fbff8b5aa597a102f8158d179904ad81993defb3672f59e4f456a49` |
| Durable exact copies (this document's references) | `results/54a34ce-seam-as-is-timed-20261013T234349Z.json` and `results/54a34ce-seam-to-be-timed-20261013T234500Z.json` under `docs/benchmarks/`, byte-identical to the raw reports above |

The measurement HEAD is the **run-time checkout revision**, not a source
receipt of either retained binary. Binary build provenance is bound by build
receipts:

- **AS-IS `170fae6c…`** ← `alumina-hkp6`: built on `e6e5385a` + the exact
  candidate dirty diff (whole-diff sha256 `1d3558d1c3d4…`), e2e relay
  `binhash` == shutdown `binhash` == `170fae6c…`; that gated tree was
  published identity-only as commit `8dbbec8984c07bd5ba72e4d4456170e9d720b091`.
- **TO-BE `8a9f1f5b…`** ← `alumina-x36s`: built on `8dbbec8` + the direct-tail
  candidate diff (whole-diff sha256 `9e16327e2856…`); the direct-tail
  mechanism later landed in commit `54a34ceeff4aad…` with
  `Cargo.toml`/`Cargo.lock`/`rust-toolchain.toml`/`deny.toml` unchanged in
  that commit diff. Binary sha256 equality establishes **reuse of the same
  artifact**; it does not make the retained binary reproducible from HEAD
  alone.

The exact seam bytes (`seam_echo.py` / `seam_echo.sh`) are **reviewed tools**
(approval `alumina-9ej1`), **untracked at measurement time, absent from
measurement HEAD `54a34ce`**; their full sha256 hashes above identify the exact
approved bytes and they are the reproducibility entry point below. No rebuild
occurred and none is claimed from HEAD alone.

**Compact reproducibility (from repository root, after accepted qualification
and on a host with the prerequisites below):**

```
sh scripts/seam_echo.sh proxyless smoke   # qualification smoke, SESSION_EXIT=0 SEAM-OK
sh scripts/seam_echo.sh as-is smoke       # qualification smoke, exec==retained==170fae6c
sh scripts/seam_echo.sh as-is timed       # AS-IS first (approved chronological order)
sh scripts/seam_echo.sh to-be timed       # TO-BE second
```

Prerequisites: rootful podman connection `flock-vm-root` with pinned harness
image `9191d288…` (`--pull=never`); retained binaries present under
`.ooda/alumina-vdpi.2/baseline/alumina-musl` and
`.ooda/alumina-vdpi/tobe/baseline/alumina-musl`; exact seam bytes with the
hashes above.

Raw exits: AS-IS timed `SESSION_EXIT=0` `SEAM-OK`, TO-BE timed `SESSION_EXIT=0`
`SEAM-OK`; all owned children reaped (backend/dns via TERM status 143,
alumina via TERM status 0, `shutdown_final status="drained"`). Both reports
`valid=true`, `workload_fulfilled=false`, `reasons=[]` — the instrument is
**valid** (trustworthy measurement) and the load was **not fully fulfilled**
(see counters below); the two are kept separate by contract.

The pre-approval accidental TO-BE smoke
(`54a34ce-seam-to-be-smoke-20261013T233250Z.json`) is **excluded** — it is not
qualification and is not reused as evidence here.

## Matched results (60 s window, AS-IS first then TO-BE)

| Metric | AS-IS | TO-BE |
| --- | --- | --- |
| Verdict | valid | valid |
| Workload fulfilled | no | no |
| Achieved client payload | 99.996 Mbps | 99.817 Mbps |
| Planned frames / admitted | 183 105 / 183 102 | 183 105 / 182 770 |
| Sent / echoed (total) | 183 100 / 183 100 | 182 770 / 182 770 |
| In-window sent / drain-completed sent | 183 099 / 1 | 182 770 / 0 |
| In-window echoed / drain echoed | 183 031 / 69 | 182 703 / 67 |
| Interval deficit (planned − in-window sent) | 6 (5 never-sent + 1 drain-completed) | 335 (all never-sent) |
| Measurement-cohort never-sent slots | 5 (offered_unsent 2 + backpressure 3) | 335 (backpressure 333 + missed_at_end 2) |
| Offered unsent / backpressure / missed_at_end | 2 / 3 / 0 | 0 / 333 / 2 |
| Errors (timeout / send_failed / conn_errors / protocol) | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| **latency `actual_send_to_echo`** (in-window cohort) | p50 23.95 ms, p95 40.85 ms, p99 42.15 ms, max 82.6 ms (n=183 031) | p50 23.95 ms, p95 40.95 ms, p99 42.35 ms, max 92.5 ms (n=182 703) |
| **latency `sched_to_echo`** | p50 24.55 ms, p95 41.45 ms, p99 42.85 ms, max 83.7 ms | p50 24.55 ms, p95 41.55 ms, p99 43.05 ms, max 94.5 ms |
| **`send_lag`** (distinct population, n=in-window-sent) | p50 0.55 ms, p95 1.25 ms, p99 1.35 ms, max 3.8 ms (n=in-window-sent 183 099) | p50 0.55 ms, p95 1.25 ms, p99 1.35 ms, max 40.5 ms (n=in-window-sent 182 770) |
| **Proxy CPU** (observed aperture) | mean 0.0365 cores, peak 0.080 (240 core samples) | mean 0.0398 cores, peak 0.080 (240 core samples) |
| Client CPU | mean 0.179 cores, peak 1.22 | mean 0.206 cores, peak 0.32 |
| Backend CPU | mean 0.0955 cores, peak 0.199 | mean 0.1095 cores, peak 1.024 |
| **Proxy RSS** (sampled VmRSS) | mean 153 532 KB, peak 153 532 KB; VmHWM 153 532 KB | mean 153 532 KB, peak 153 532 KB; VmHWM 153 532 KB |
| Client / backend RSS (VmRSS sample scope) | 26 585 / 25 945 KB mean | 26 512 / 26 009 KB mean |
| Worst observed `send_lag` | 3.8 ms | 40.5 ms |

Latency histograms contain **only measurement-cohort echoes that completed
in-window** (candidate counts above; drain tails are excluded from
percentiles). `send_lag` is the distinct population whose denominator is the
in-window **sent** count (`n=in-window-sent`), not the total-sent total — it
is not a whole-cohort latency tail. Completion timestamps are captured after
the successful send/recv return; frames returned in one recv chunk share a
single post-recv completion time.

**Histogram resolution:** all latency percentiles are **100 µs-bin midpoint
estimates** (`bin_us=100` in both raw reports), not exact order-statistic
values; the exact maxima are recorded separately and rounded in the table.
Reported between-run differences of 0.10–0.20 ms sit at or near this bin
granularity.

CPU means use an explicit **observed aperture** (start/end boundary tick
observations with observed timestamps and disclosed boundary lag:
~0.0011 s start / ~0.0000–0.0002 s end for AS-IS, ~0.0007 s / ~0.0002 s for
TO-BE); this is not an exact scheduled-window or atomic isolation claim, and
the periodic `core_samples` omit the final boundary slice while the mean
includes the final tick delta. RSS is an arithmetic mean of sampled current
VmRSS with sampled peak kept separate from the lifetime high-water mark
VmHWM; kernel-buffer / TCP memory is not folded into any figure. Single pair,
no repeats ⇒ no noise/inter-run variance estimate.

## Fulfilment accounting (why both are `workload_fulfilled=false`)

Conservation holds in both runs: `admitted + backpressure + missed_end =
planned`; `admitted = sent + send_failed + offered_unsent`;
`sent = echoed + unechoed`. Three populations must be kept distinct: (1)
**in-window sent** (`interval_vs_cohort.in_window_sent_frames`: 183 099 AS-IS,
182 770 TO-BE), (2) **drain-completed sent** (`drain_sent_frames`: 1 AS-IS, 0
TO-BE — a frame admitted before the window end whose send completed during
drain), and (3) **measurement-cohort never-sent slots** — planned frames with
no send at all (AS-IS 5 = offered_unsent 2 + backpressure 3; TO-BE 335 =
backpressure 333 + missed_at_end 2). The **interval deficit** — planned minus
in-window sent — is therefore 6 for AS-IS (5 never-sent + 1 drain-completed)
and 335 for TO-BE (all never-sent; no drain-completed send). The earlier
draft's "5/335 frames unsent **in-window**" mislabelled these as a single
in-window loss population; the corrected split keeps cohort conservation
(phase `sent` = in-window + drain) and interval accounting separate.

**Backpressure cause split is not recorded.** The harness increments a single
backpressure counter for *either* "selected connection busy/closed" *or*
"aggregate outstanding ≥ 1024 frames / 4 MiB" (one shared counter in the
tool). The combined AS-IS 3 / TO-BE 333 backpressure admission skips cannot
therefore be attributed specifically — or exclusively — to reaching the
aggregate cap; the exact cause split is unrecorded by the raw reports. These
are **unfulfilled workload** (valid instrument, unfulfilled load), not
instrument invalid; neither run was retried, per the standing rule that an
existing intermittent fulfilment failure is workload, not a harness defect.

## Honest reading (single-pair observations, no universal gain)

Observed per-pair facts (reported as observations, not inferential claims):

- **CPU:** no lower proxy CPU was observed for TO-BE in this pair. Proxy mean
  CPU increased by approximately **0.0033 cores** (AS-IS 0.0365 → TO-BE 0.0398
  cores); client (0.179 → 0.206) and backend (0.0955 → 0.1095) means are also
  higher. Single pair, no repeats ⇒ **no noise/inter-run variance estimate**;
  the delta is reported as observed, not attributed with confidence.
- **Latency:** p50 is equal **at histogram resolution** for
  `actual_send_to_echo` (23.95 ms) and `sched_to_echo` (24.55 ms); p95 and p99
  are 0.10 ms and 0.20 ms higher in TO-BE; maxima are higher (e.g.
  `actual_send_to_echo` max 92.5 vs 82.6 ms) and TO-BE shows a 40.5 ms
  `send_lag` max spike vs 3.8 ms (`send_lag` p50/p95/p99 identical at 0.55 /
  1.25 / 1.35 ms). **No statistical-equivalence and no significance conclusion
  is drawn** — differences are within-pair observations near the 100 µs-histogram
  granularity, with no repeated-run variance.
- **Backpressure:** TO-BE shows more backpressure admission skips (333 vs 3);
  the cause split (busy/unavailable selected connection vs aggregate cap) is
  not recorded, so "reached the cap more often" is **not** claimed.
- **Mechanism fact:** the direct initialized-tail read seam
  ([reduced-copy-relay-plan.md](../../docs/reduced-copy-relay-plan.md) §4)
  removes the scratch→retained copies that the AS-IS binary performs. This
  document measures the end-to-end effect of that mechanism on this pair only;
  it does not decompose component costs.
- **Interpretation:** no lower proxy CPU was observed (one-pair outcome), and
  H2 ("fixed setup/syscall costs dominate, copy removal has little end-to-end
  benefit") is a **possible explanation** — component costs (time at
  retained-copy sites, TLS cost, loopback waits, backend contribution, syscall
  counts) and the dominant cause are **unmeasured** by this experiment. H1
  (copy-limited CPU) is neither confirmed nor refuted.
- Neither run claims a universal-gain or universal-regression; numbers are
  scoped to this workload, machine, single pair, and observed aperture.

## Limits

- Single matched pair; no repeats, so no noise/inter-run variance estimate.
- CPU is observed-aperture, not exact-window or all-cores-total; `cores` are
  per-process CPU normalized to one core. RSS/VmHWM exclude kernel/TCP buffers.
- Percentiles exclude drain tails and are conditioned on in-window
  completions; `send_lag` population is separate and conditioned on in-window
  sends.
- Proxy resource figures include the process only; candidate ran inside the
  harness container, common to both, so the comparison is matched.
- No competitor was executed: HAProxy 3.2.25 and Envoy v1.39.4 remain
  **source-level intake accepted, not executed**
  ([feature-match-matrix.md](../../docs/benchmarks/feature-match-matrix.md)).
  Source/registry intake and selected semantics were accepted (`alumina-gjq4`,
  `alumina-elyw`); the wire-parity-vs-policy-parity boundary applies
  (`alumina-et74`). Route-timeout/config/probe gaps remain before any runtime,
  so source acceptance is a pin/receipt status — not operational authorization
  and not execution of competitor images/source.
- Serving/QA qualification gates stay per
  [build-plan.md](../../docs/build-plan.md); this document reports a
  measurement only and does not alter status.

## Raw evidence

Durable byte-exact AB pair — this document's references (published as part of
this correction; provenance in `Identity`):

- [AS-IS](results/54a34ce-seam-as-is-timed-20261013T234349Z.json) —
  `results/54a34ce-seam-as-is-timed-20261013T234349Z.json`, sha256
  `d75156f7006aae40741e47a565bad5508de67d7e6536907d1d5ba939e53f46b1`
- [TO-BE](results/54a34ce-seam-to-be-timed-20261013T234500Z.json) —
  `results/54a34ce-seam-to-be-timed-20261013T234500Z.json`, sha256
  `f6fe021b1fbff8b5aa597a102f8158d179904ad81993defb3672f59e4f456a49`

These are **exact, unchanged** copies of the original reports. Sample-record
volume is modest — the largest field is the 240 per-process `core_samples`
interval array plus histogram summaries (~101 KB per file) — so the full JSON
is retained as-is; nothing was projected, filtered or excluded.

Original unfiltered reports remain at `.ooda/benchmarks/`:

- `.ooda/benchmarks/54a34ce-seam-as-is-timed-20261013T234349Z.json`
- `.ooda/benchmarks/54a34ce-seam-to-be-timed-20261013T234500Z.json`

Both under measurement HEAD `54a34ce`, tool `52e28b87…`, supervisor
`2b2ecd16…`, with full byte hashes recorded in `Identity`. Qualification smokes
(proxyless + as-is, `SESSION_EXIT=0`, `SEAM-OK`, clean reap) are recorded in
`54a34ce-seam-proxyless-smoke-20261013T234315Z.json` and
`54a34ce-seam-as-is-smoke-20261013T234337Z.json` under `.ooda/benchmarks/`;
they qualify the seam and are not part of the durable AB pair.
