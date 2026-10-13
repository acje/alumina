# Alumina as-is vs to-be vs HAProxy vs Envoy — 100 Mbps matched comparison

Measured comparison of the retained AS-IS Alumina binary against the retained
TO-BE reduced-copy binary, extended with the actual native competitor pair
(HAProxy 3.2.25, then Envoy 1.39.4) — the full four-candidate comparison under
the accepted fixed workload (contract `alumina-gjq4`; mission `alumina-qryg.7`
→ `alumina-qryg.10`). AS-IS ran **first**, then TO-BE (approved chronological
order); the native pair ran under qryg.9/p0on after independent source review
APPROVE (`alumina-r69v`), HAProxy **first** then Envoy. Same supervised
container (`localhost/alumina-e2e:e2e-20261011`, id `9191d288…`), connection
`flock-vm-root`, same fixture and matched placement for every run. No candidate
binary was rebuilt: competitor binaries ran from pinned official images
(identity below), never from rebuilt source.

**Status:** durable measurement record of the four-candidate comparison under
one accepted workload. The retained AS-IS/TO-BE Alumina pair was measured at
measurement HEAD `54a34ce` (2026-10-13) and corrected per the independent
source-only review `alumina-rqne` (blocking findings B1–B7;
`alumina-76fv`). The native competitor pair (HAProxy 3.2.25 direct TLS/SNI
passthrough, Envoy 1.39.4 CONNECT-terminate) was measured 2026-10-14 at HEAD
`031ee10` after independent source review APPROVE `alumina-r69v`, using the
same reviewed seam extended with route-neutral direct-proxy accounting
(`seam_echo.py` sha256 `347a0b8b…`) and the reviewed native supervisor
(`qryg_runner.sh` `c6d4aab6…` / `harness_native.sh` `57b4acd0…`; identity in
the native section and the byte-exact raw + native-JSON reports under
`docs/benchmarks/results/`). The historical AB pair receipts
(tool `52e28b87…`) are unchanged; the newer reviewed tool `347a0b8b…` was used
for the native runs.

## Workload and setup (accepted, unchanged — shared across all four candidates)

The workload, host, harness image and placement below are **shared** across
the historical AS-IS/TO-BE (AB) pair and the native competitor pair. Entry and
identity attributes that differ per candidate (route label, libc/build, user,
seam tool, supervisor, config) are scoped in the four-candidate matrix in the
native section and are **not** restated as blanket properties here.

- 8 persistent connections; 4096 B payload frames + 12 B header counted
  separately; aggregate **open-loop** pacing at 100 decimal Mbps client
  payload (12 500 000 B/s) plus echo; 5 s warmup; 60 s measurement window;
  5 s setup/drain; nominal target 750 000 000 B client payload across
  183 105 planned **whole** frames. The scheduled whole frames carry
  749 998 080 B; the remaining 1 920 B
  (`params.measure_remainder_bytes=1920` in the seam reports) is deliberately
  **not** scheduled — accepted fixed-frame floor rounding (`alumina-gjq4`).
- Monotonic scheduled open-loop rate (independent of echo completion);
  outstanding cap 1024 frames / 4 194 304 B; exhaustion produces explicit
  unsent (backpressure), never catch-up after the window.
- Real TLS 1.3 byte-exact framed echo backend, genuine CA + SAN
  (`example.com`), endpoint negotiated and validated by the client.
- Host (shared): arm64 Apple-VM, 4 CPU / 14 GiB; Python 3.14.8 / OpenSSL 3.5.9
  harness image; `--network none`, loopback global-unicast alias; matched
  client/backend placement in the shared supervised container.
- **AB pair only (Alumina AS-IS/TO-BE):** the retained proxy acts as an
  opaque **CONNECT relay** (no decryption); its candidates are native
  `aarch64-unknown-linux-musl` builds, dropped to uid 65534. The native
  competitors are **not** musl opaque CONNECT relays: HAProxy is a glibc
  official-image direct TLS/SNI passthrough with no CONNECT, Envoy is a
  BoringSSL official-image CONNECT-terminating tunnel (`--user 65534`) —
  entry semantics labelled, never equivalent (native section, matrix).

## Identity and provenance — historical Alumina AB pair (all verified at run time)

This identity/provenance table and the build receipts below describe the
**historical AS-IS/TO-BE Alumina pair only** (seam tool `52e28b87…`,
supervisor `2b2ecd16…`, measurement HEAD `54a34ce`). The native competitor
pair has separate identity (tool `347a0b8b…`, supervisor `qryg_runner.sh`
`c6d4aab6…` / `harness_native.sh` `57b4acd0…`, images/configs), recorded in
the Native section and its raw-evidence block.

| Item | Value |
| --- | --- |
| Measurement checkout HEAD | `54a34ceeff4aad701f6ce3c2f65ef6965144f30c` (`identity.source_head` in both AB JSON, filled by the supervisor from the run-time checkout) |
| `seam_echo.py` (tool, reviewed seam) | sha256 `52e28b8784fc7f9b14b017885a7f1d84f739163aabbcba25ec73e6f006b97eeb` (`tool_sha256` in both AB JSON; matches approval `alumina-9ej1`) |
| `seam_echo.sh` (supervisor) | sha256 `2b2ecd1674bf851b8fdfe66548b2126459f3508f0948628f1843ea73d81494e0` (matches approval `alumina-9ej1`) |
| AS-IS binary (retained, reused) | `.ooda/alumina-vdpi.2/baseline/alumina-musl` sha256 `170fae6c1dbfce1907bb2b2ec02599808c4d9404b243ccd24b8834490d3ab72f` (`executed_binary_sha256` == `retained_binary_sha256` in both AB JSON) |
| TO-BE binary (retained, reused) | `.ooda/alumina-vdpi/tobe/baseline/alumina-musl` sha256 `8a9f1f5b288abc1ec649e9a98302caa8e088d1f5e55c432950a59167d869dec8` |
| Config (identical for both) | `config_sha256` `a0b505295bac82a10270d66a74a38c5723f6cd120c7d04d71daad5b22e5122bb` (allowlist `example.com`, listen `127.0.0.1:8080`) |
| Harness image / OS (shared) | `9191d288353391e4751525e83196e8127884d73daa395ced6fafc4a96d71564f` (parent `ad70ceb90f563e9fe2ef7064b92dc1347aeaeb71e5369ba8b242498ba030a6f8`), OpenSSL 3.5.9, Python 3.14.8; AB candidate rust-target `aarch64-unknown-linux-musl` |
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

The exact seam bytes for the **AB pair** (`seam_echo.py` `52e28b87…` /
`seam_echo.sh` `2b2ecd16…`) are **reviewed tools** (approval `alumina-9ej1`),
**untracked at measurement time, absent from measurement HEAD `54a34ce`**;
their full sha256 hashes above identify the exact approved bytes and they are
the AB reproducibility entry point below. No rebuild occurred and none is
claimed from HEAD alone.

**Compact AB reproducibility (historical AS-IS/TO-BE pair only):** the
commands below reproduce the AB pair with the historical `52e28b87…` seam and
`2b2ecd16…` supervisor. They are **not** the native-run reproduction: the
native competitor runs used the newer reviewed seam `347a0b8b…` under the
`qryg_runner.sh` supervisor (command in the Native section); the current
`347a0b8b…` seam does **not** recreate the historical `52e28b87…` AB receipts,
and the historical seam does not reproduce the native runs. AB receipts are
retained unchanged.

```
sh scripts/seam_echo.sh proxyless smoke   # qualification smoke, SESSION_EXIT=0 SEAM-OK
sh scripts/seam_echo.sh as-is smoke       # qualification smoke, exec==retained==170fae6c
sh scripts/seam_echo.sh as-is timed       # AS-IS first (approved chronological order)
sh scripts/seam_echo.sh to-be timed       # TO-BE second
```

AB prerequisites: rootful podman connection `flock-vm-root` with pinned harness
image `9191d288…` (`--pull=never`); retained AB binaries present under
`.ooda/alumina-vdpi.2/baseline/alumina-musl` and
`.ooda/alumina-vdpi/tobe/baseline/alumina-musl`; exact AB seam bytes with the
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

## Native competitor pair — HAProxy 3.2.25 then Envoy 1.39.4 (60 s window)

Actual native competitor pair executed after independent source review
APPROVE (`alumina-r69v`) under the qryg.9/p0on approved topology: HAProxy ran
**first**, then Envoy (approved chronological order), each through the same
reviewed seam (`seam_echo.py` sha256 `347a0b8b…`) driven by the reviewed
native supervisor (`qryg_runner.sh` sha256 `c6d4aab6…` with
`harness_native.sh` sha256 `57b4acd0…`) inside the shared disposable
network-none harness container (`9191d288…`) net+PID namespace — same
fixture, matched client/backend placement, 5 s setup/drain / 5 s warmup /
60 s window / 8 conns / 4096 B + 12 B / 100 decimal Mbps. Both supervisor
sessions exited 0 (`session_exit=0`, candidate `classify=ok`, candidate
stop/wait rc 0, then full supervisor-owned container cleanup — see advisory
below). Positive version/config validation
preceded the runs: HAProxy `3.2.25-70469d3` + `haproxy -c` exit 0; Envoy
`1.39.4/Clean/RELEASE/BoringSSL` + `envoy --mode validate … OK` exit 0.

**Reap advisory (no failure):** each retained timed `harness.log` shows a
Podman automatic-removal warning at container exit (the candidate container
still existed when the harness's `--rm` auto-removal ran, so the harness
auto-removal was deferred). The supervisor then explicitly waited and removed
the candidate before the harness (`qryg_runner.sh` stop/wait + owned
`rm -f` teardown, rc 0), so the warning is an **expected teardown-order
diagnostic**, not a residual-container failure: `session_exit=0`,
`harness_job_rc=0`, owned-cleanup rc 0, and the VM was left with zero
containers. No converted failure claim is made from the warning alone.

| Metric | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- |
| Route label (`native.json client_mode`) | `direct-proxy` | `via-proxy` |
| Verdict | valid | valid |
| Workload fulfilled | no | no |
| Achieved client payload | 99.998 Mbps | 99.994 Mbps |
| Planned / admitted | 183 105 / 183 102 | 183 105 / 183 095 |
| Sent / echoed (total) | 183 102 / 183 102 | 183 095 / 183 095 |
| In-window sent / drain-completed sent | 183 102 / 0 | 183 095 / 0 |
| In-window echoed / drain echoed | 183 094 / 8 | 183 087 / 8 |
| Interval deficit (planned − in-window sent) | 3 | 10 |
| Measurement-cohort never-sent slots | 3 (backpressure 3) | 10 (backpressure 8 + missed_at_end 2) |
| Errors (timeout / send_failed / conn_errors / protocol) | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| **latency `actual_send_to_echo`** | p50 2.55 ms, p95 4.05 ms, p99 4.25 ms, max 7.38 ms (n=183 094) | p50 2.75 ms, p95 4.05 ms, p99 4.35 ms, max 9.21 ms (n=183 087) |
| **latency `sched_to_echo`** | p50 3.35 ms, p95 4.25 ms, p99 4.45 ms, max 7.68 ms | p50 3.35 ms, p95 4.35 ms, p99 4.55 ms, max 9.28 ms |
| **`send_lag`** | p50 0.55 ms, p95 1.45 ms, p99 1.65 ms, max 4.35 ms (n=183 102) | p50 0.45 ms, p95 1.45 ms, p99 1.65 ms, max 4.30 ms (n=183 095) |
| **Proxy CPU** (observed aperture, process-total incl. all proxy threads) | mean 0.0501 cores, peak 0.120 (240 periodic core intervals) | mean 0.0783 cores, peak 0.120 (240 periodic core intervals) |
| Proxy thread count (in-namespace PID task dir, positive-only) | 1 (`nbthread 1`) | 7 (`--concurrency 1`; 7 tasks disclosed) |
| Client CPU | mean 0.261 cores, peak 0.440 | mean 0.299 cores, peak 0.440 |
| Backend CPU | mean 0.181 cores, peak 0.280 | mean 0.186 cores, peak 0.280 |
| **Proxy RSS** (sampled VmRSS) / VmHWM | mean=peak 84 180 KB; VmHWM 84 180 KB | mean 61 834 KB / peak 61 840 KB; VmHWM 61 840 KB |

**Sample count and boundary lag disclosure:** the proxy CPU figures are
computed over the **240 periodic core intervals** contained in the observed
measurement aperture (`core_samples=240` in each native seam report's
`sampling.proxy`), not over the 263 whole-run observations. The whole-run
`samples=263` counts every successful per-period sample across setup/warmup/
window/drain combined (seam `window_summary` sets `samples` to the full sample
list and `core_samples` to only the contained in-window periodic intervals); it
is a different population and is **not** the CPU denominator. Boundary lags of
the observed aperture vs the scheduled window are recorded in each report's
`sampling.proxy.boundary_lag_s`: HAProxy start 0.0002 s / end 0.0413 s
(`sampled_from` `386982.614263006` → `sampled_to` `387042.655331893`, observed
span 60.0411 s); Envoy start 0.0006 s / end 0.0007 s (`sampled_from`
`387053.081477253` → `sampled_to` `387113.081507489`, observed span
60.0000 s). These are measured-lag values, not exact scheduled-window
isolation; `core_samples` omit the final boundary slice while the mean includes
the final tick delta, agreeing with the AB CPU-aperture note above.

### Entry / policy semantics (labelled, never equivalence)

- **HAProxy 3.2.25** ran as a direct TLS/SNI TCP-mode **passthrough** (`mode
  tcp`, `tcp-request content` on ClientHello, `use_backend` on SNI
  `example.com`, fixed backend `8.8.8.8:443`, `nbthread 1`; direct binary
  `-db`, no `-W`). Client route `--mode direct-proxy` — **direct TLS to the
  proxy, no CONNECT handshake**. HAProxy inspects the ClientHello SNI and
  relays bytes; it does not terminate TLS, has no CONNECT method, and
  terminates inside its HTTP/TCP path only per the accepted config.
- **Envoy 1.39.4** ran as a **CONNECT-terminating** proxy (HCM
  `connect_matcher` route to fixed backend `8.8.8.8:443`, route `timeout: 0s`,
  `--concurrency 1`, uid 65534). Client route `--mode via-proxy` (authentic
  HTTP CONNECT). Envoy terminates the CONNECT request and then tunnels raw
  TCP; it does not decrypt the tunnel payload.
- The two are **not policy-equivalent**: different entry semantics (direct SNI
  passthrough vs CONNECT termination), process architecture (1 vs 7 threads),
  users, runtimes and memory profiles. Each run's `native.json` records
  `client_mode`, image/manifest digests, config sha256, in-namespace proxy PID
  and a positive-only thread count (producer-zero/absent would be explicit
  Unknown). Single pair per candidate ⇒ no noise/inter-run variance estimate,
  and no statistical-equivalence, causal or universal-gain claim is drawn.

Observation notes: both candidates saturated the offered 100 Mbps with tiny
explicit unfilled admission deficits (3 / 10 planned frames of 183 105) —
`valid=true` while `workload_fulfilled=false` are reported separately, per
contract, and no run was retried (unfulfilled = workload, not harness defect).
HAProxy observed-aperture CPU mean ≈ 0.050 cores (1 thread) vs Envoy ≈ 0.078
(7 threads); latency p50/p95/p99 sit in the same 100 µs-bin histogram
granularity used for the AB pair, with Envoy maxima ~1.6–1.8 ms higher. Proxy
RSS figures cover the proxy process only (HAProxy 84 180 KB mean vs Envoy
61 834 KB mean at this workload); kernel/TCP buffers are excluded. Base-image
CVE/SBOM/attestation completeness remains scoped intake **Unknown**
(`alumina-aztk`/`raa7`) — no universal security/production claim.

### Four-candidate scope matrix (shared vs per-candidate identity)

The four candidates are **not** claimed equivalent; this matrix labels what is
shared (workload, host, harness image, placement) separately from what is
per-candidate (route, libc/build, user, tool, supervisor, config) so no
candidate's attribute is inherited by another without saying so.

| Attribute (shared) | AS-IS | TO-BE | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- | --- |
| Workload | same fixed 100 decimal Mbps workload for all four (see Workload) | same | same | same |
| Harness image / placement | `9191d288…` net+PID ns, `flock-vm-root`, loopback alias | same | same | same |
| Host | arm64 Apple-VM, 4 CPU / 14 GiB | same | same | same |

| Attribute (per-candidate) | AS-IS | TO-BE | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- | --- |
| Route label / client mode (seam report `mode`) | `via-proxy` (CONNECT) | `via-proxy` (CONNECT) | `direct-proxy` (direct TLS/SNI, no CONNECT) | `via-proxy` (CONNECT-terminate) |
| Libc / build | `aarch64-unknown-linux-musl` | `aarch64-unknown-linux-musl` | glibc (official image; libssl/libcrypto/liblua5.4/libpcre2/libz/libzstd) | BoringSSL RELEASE (libc/libm/libdl/librt/libpthread) |
| User | uid 65534 | uid 65534 | image default (no user flag) | uid 65534 (`--user 65534:65534`) |
| Seam tool (`tool_sha256`) | `52e28b87…` | `52e28b87…` | `347a0b8b…` | `347a0b8b…` |
| Supervisor | `seam_echo.sh` `2b2ecd16…` | `seam_echo.sh` `2b2ecd16…` | `qryg_runner.sh` `c6d4aab6…` + `harness_native.sh` `57b4acd0…` | `qryg_runner.sh` `c6d4aab6…` + `harness_native.sh` `57b4acd0…` |
| Config | allowlist + listen (`config_sha256` `a0b50529…`) | same as AS-IS | `haproxy.cfg` `35cf35df…` (TCP/SNI passthrough) | `envoy_connect.yaml` `e6fb9ef7…` (CONNECT-terminate) |
| Candidate image / binary | retained `170fae6c…` (musl) | retained `8a9f1f5b…` (musl) | image `d483b789…` / manifest `3947a542…`, binary `8c8791be…` | image `a084f595…` / manifest `ce82b213…`, binary `6b064069…` |
| Threads (positive-only task count) | n/r (AB pair not thread-probed) | n/r | 1 (`nbthread 1`) | 7 (`--concurrency 1`) |
| Measurement HEAD | `54a34ce` | `54a34ce` | `031ee10` | `031ee10` |
| Raw + companion evidence | AS-IS report `d75156f7…` | TO-BE report `f6fe021b…` | seam `ffa5ee4a…` + native `96b341de…` | seam `770de863…` + native `5256d337…` |

Every per-candidate cell is labelled from that candidate's own raw report /
native companion; a shared row applies to all four only as stated here.
Consistent with every other row in this document: single pair per candidate,
no noise/inter-run variance estimate, no statistical-equivalence, causal or
universal-gain claim.

## Limits

- Single matched pair; no repeats, so no noise/inter-run variance estimate.
- CPU is observed-aperture, not exact-window or all-cores-total; `cores` are
  per-process CPU normalized to one core. RSS/VmHWM exclude kernel/TCP buffers.
- Percentiles exclude drain tails and are conditioned on in-window
  completions; `send_lag` population is separate and conditioned on in-window
  sends.
- Proxy resource figures include the process only; candidate ran inside the
  harness container, common to both, so the comparison is matched.
- Competitors were executed only as pinned official-image binaries after
  review APPROVE (`alumina-r69v`), under the qryg.9/p0on topology; their
  entry semantics and architecture differ and are **not policy-equivalent**
  (see the native section). The wire-parity-vs-policy-parity boundary applies
  (`alumina-et74`). Base-image CVE/SBOM/attestation completeness is scoped
  intake **Unknown** (`alumina-aztk`/`raa7`) — retained, no universal
  security/production claim. Competitor binaries were **not rebuilt** from
  source; the source-level pin/receipt record stands in
  ([feature-match-matrix.md](../../docs/benchmarks/feature-match-matrix.md)).
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

### Native pair (durable byte-exact copies, this document's references)

Durable byte-exact native pair under measurement HEAD `031ee10`, reviewed tool
`347a0b8b…`, reviewed native supervisor (`qryg_runner.sh` `c6d4aab6…`,
`harness_native.sh` `57b4acd0…`), seam reports + native companions — sha256:

- [HAProxy seam report](results/qryg-haproxy-timed-20261014T012232Z-66396.json) —
  `results/qryg-haproxy-timed-20261014T012232Z-66396.json`, sha256
  `ffa5ee4a8e7184fb93df8d5aaefdea80b44493573ffaa27229213a407f23dd08`
- [HAProxy native companion](results/qryg-haproxy-timed-20261014T012232Z-66396.native.json) —
  sha256 `96b341deafdea95405c027418488fc2b0f7d9c673e0b5c30da012422a8ab5cd2`
- [Envoy seam report](results/qryg-envoy-timed-20261014T012343Z-66851.json) —
  `results/qryg-envoy-timed-20261014T012343Z-66851.json`, sha256
  `770de86332f35f8793c6944cde7afad639cd6028b6e8cc5c806d5ca96d14f5b2`
- [Envoy native companion](results/qryg-envoy-timed-20261014T012343Z-66851.native.json) —
  sha256 `5256d337d67744ca196a0658dc72efe3d8fe9d0265929f62455c7a798c990dfd`

Original unfiltered reports + companions (byte-identical to the above) and
the qualification smokes remain at `.ooda/benchmarks/qryg-native/`:

- `qryg-haproxy-timed-20261014T012232Z-66396.json` /
  `…-66396.native.json` (valid, unfulfilled 3)
- `qryg-envoy-timed-20261014T012343Z-66851.json` /
  `…-66851.native.json` (valid, unfulfilled 10)
- smokes: `qryg-haproxy-smoke-20261014T012202Z-65743{,.native}.json`
  (valid, fulfilled) and `qryg-envoy-smoke-20261014T012215Z-66118{,.native}.json`
  (valid, unfulfilled 3 × `missed_at_end`).

Candidate identity recorded per run (seam `identity` + `native.json`):
HAProxy image `d483b789…` / manifest `sha256:3947a542…`, binary
`/usr/local/sbin/haproxy` sha256 `8c8791be66ec97399e949752afddb5210e6223e2bf67eaa9e43ac1d92afb59b7`
(glibc build: libssl/libcrypto/liblua5.4/libpcre2/libz/libzstd), config
`haproxy.cfg` sha256 `35cf35df…`; Envoy image `a084f595…` /
manifest `sha256:ce82b213…`, binary `/usr/local/bin/envoy` sha256
`6b0640696b20c1faeb5cf725d1c73c0dc35ce824febe9e4326e7083f0f411b45`
(BoringSSL RELEASE; ld shows only libc/libm/libdl/librt/libpthread), config
`envoy_connect.yaml` sha256 `e6fb9ef7…`. Config validation and version strings
(`3.2.25-70469d3` / `1.39.4/Clean/RELEASE/BoringSSL`) were verified raw exit 0
before the smokes.
