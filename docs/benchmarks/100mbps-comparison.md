# Alumina e3a9ff1 vs HAProxy 3.2.25 vs Envoy 1.39.4 — 100 Mbps matched comparison

## Matched results (60 s window)

| Metric | Alumina e3a9ff1 | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- |
| Route label (client mode) | via-proxy (CONNECT) | direct-proxy (direct TLS/SNI, no CONNECT) | via-proxy (CONNECT-terminate) |
| Verdict | valid | valid | valid |
| Workload fulfilled | no | no | no |
| Achieved client payload | 99.999 Mbps | 99.998 Mbps | 99.994 Mbps |
| Planned frames / admitted | 183 105 / 183 103 | 183 105 / 183 102 | 183 105 / 183 095 |
| Sent / echoed (total) | 183 103 / 183 103 | 183 102 / 183 102 | 183 095 / 183 095 |
| In-window sent / drain-completed sent | 183 103 / 0 | 183 102 / 0 | 183 095 / 0 |
| In-window echoed / drain echoed | 183 095 / 8 | 183 094 / 8 | 183 087 / 8 |
| Interval deficit (planned − in-window sent) | 2 (backpressure 2) | 3 | 10 |
| Measurement-cohort never-sent slots | 2 (backpressure 2) | 3 (backpressure 3) | 10 (backpressure 8 + missed_at_end 2) |
| Errors (timeout / send_failed / conn_errors / protocol) | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| latency `actual_send_to_echo` (in-window cohort) | p50 2.95 ms, p95 3.35 ms, p99 3.55 ms, max 9.05 ms (n=183 095) | p50 2.55 ms, p95 4.05 ms, p99 4.25 ms, max 7.38 ms (n=183 094) | p50 2.75 ms, p95 4.05 ms, p99 4.35 ms, max 9.21 ms (n=183 087) |
| latency `sched_to_echo` | p50 3.35 ms, p95 3.95 ms, p99 4.05 ms, max 9.55 ms | p50 3.35 ms, p95 4.25 ms, p99 4.45 ms, max 7.68 ms | p50 3.35 ms, p95 4.35 ms, p99 4.55 ms, max 9.28 ms |
| `send_lag` (distinct population, n=in-window sent) | p50 0.55 ms, p95 1.25 ms, p99 1.35 ms, max 4.17 ms (n=183 103) | p50 0.55 ms, p95 1.45 ms, p99 1.65 ms, max 4.35 ms (n=183 102) | p50 0.45 ms, p95 1.45 ms, p99 1.65 ms, max 4.30 ms (n=183 095) |
| Proxy CPU (observed aperture) | mean 0.0376 cores, peak 0.811 (240 core samples) | mean 0.0501 cores, peak 0.120 (240 periodic core intervals) | mean 0.0783 cores, peak 0.120 (240 periodic core intervals) |
| Proxy thread count (positive-only task count) | 1 (single-worker) | 1 (`nbthread 1`) | 7 (`--concurrency 1`) |
| Client CPU | mean 0.172 cores, peak 0.239 | mean 0.261 cores, peak 0.440 | mean 0.299 cores, peak 0.440 |
| Backend CPU | mean 0.121 cores, peak 0.160 | mean 0.181 cores, peak 0.280 | mean 0.186 cores, peak 0.280 |
| Proxy RSS (sampled VmRSS) / VmHWM | mean=peak 153 620 KB; VmHWM 153 620 KB | mean=peak 84 180 KB; VmHWM 84 180 KB | mean 61 834 KB / peak 61 840 KB; VmHWM 61 840 KB |

## Relay optimization progression (Alumina 100 Mbps / 60 s)

| Attribute | Alumina 8dbbec8 (baseline) | Alumina 54a34ce (copy-only removal) | Alumina e3a9ff1 |
| --- | --- | --- | --- |
| Read / buffer mechanism | 4 KiB stack scratch bounce `CHUNK = 4096` + `append_client_bytes` memcpy into 512 KiB slab | 4 KiB direct-into-slab read `CHUNK = 4096` (copy-only removal; no stack bounce memcpy) | 32 KiB direct-into-slab read `READ_CHUNK = 32 KiB`, `MIN_BUF_ROOM = 4096`, half-visit read room reservation in `Stage::Relay` |
| Poll batch & dispatch mechanism | 64-event `mio::Events`, sequential per-token dispatch | 64-event `mio::Events`, sequential per-token dispatch | 512-event `POLL_EVENTS_CAP` two-pass per-slot readiness coalescing (`CoalescedBatch`), duplicate-free app reschedule queue; eliminates false `!live_here` reschedules and redundant `epoll_ctl(EPOLL_CTL_MOD)` syscalls |
| Syscall & visit-budget mechanics (`VISIT_OPS = 16` / `VISIT_BYTES = 64 KiB`) | 4 KiB read syscalls + interleaved client/upstream tokens exhaust the per-visit op budget → reschedules; memcpy bounce adds no read size, latency governed by syscall/visit granularity | 4 KiB read syscalls; per-4 KiB token interleave still exhausts `VISIT_OPS` → frequent reschedules; copy removal alone does not change granularity | 32 KiB reads amortize `read(2)`; two-pass per-slot coalescing amortizes `epoll_wait(2)`/`epoll_ctl(2)` across the visit budget — syscall/visit granularity, not user-space 4 KiB memcpy, governs latency |
| Achieved payload / deficit | 99.996 Mbps / deficit 6 (offered_unsent 2 + backpressure 3 + drain 1) | 99.817 Mbps / deficit 335 (backpressure 333 + missed_at_end 2) | 99.999 Mbps / deficit 2 (backpressure 2) |
| `actual_send_to_echo` (p50 / p95 / p99 / max) | 23.95 / 40.85 / 42.15 / 82.6 ms | 23.95 / 40.95 / 42.35 / 92.5 ms | 2.95 / 3.35 / 3.55 / 9.05 ms |
| `sched_to_echo` (p50 / p95 / p99 / max) | 24.55 / 41.45 / 42.85 / 83.7 ms | 24.55 / 41.55 / 43.05 / 94.5 ms | 3.35 / 3.95 / 4.05 / 9.55 ms |
| `send_lag` (p50 / p95 / p99 / max) | 0.55 / 1.25 / 1.35 / 3.78 ms | 0.55 / 1.25 / 1.35 / 40.5 ms | 0.55 / 1.25 / 1.35 / 4.17 ms |
| Proxy CPU (mean / peak) | 0.037 / 0.080 | 0.040 / 0.080 | 0.038 / 0.811 |
| Proxy RSS (VmRSS) / VmHWM | 153 532 / 153 532 KB | 153 532 / 153 532 KB | 153 620 / 153 620 KB |
| Raw JSON receipt | [results/54a34ce-seam-as-is-timed-20261013T234349Z.json](results/54a34ce-seam-as-is-timed-20261013T234349Z.json) | [results/54a34ce-seam-to-be-timed-20261013T234500Z.json](results/54a34ce-seam-to-be-timed-20261013T234500Z.json) | [results/e3a9ff1-seam-timed-20261015T135816Z.json](results/e3a9ff1-seam-timed-20261015T135816Z.json) |

## Workload & measurement parameters

| Parameter | Value |
| --- | --- |
| Persistent connections | 8 |
| Payload frame | 4096 B payload + 12 B framing header (counted separately) |
| Aggregate open-loop client payload rate | 100 decimal Mbps = 12 500 000 B/s + echo |
| Warmup / window / setup+drain | 5 s / 60 s / 5 s |
| Planned whole frames | 183 105 scheduled frames = 749 998 080 B + 1 920 B unscheduled floor remainder |
| Outstanding cap | 1024 frames / 4 194 304 B (exhaustion = explicit unsent, never catch-up) |
| Endpoint | Real TLS 1.3 byte-exact framed-echo backend, `example.com` (genuine CA + SAN) |
| E2E latency histogram resolution | `bin_us=100` (100 us bin midpoint resolution) |
| Proxy CPU sample resolution | `core_samples=240` periodic in-window intervals over the 60 s observed aperture |

## Candidate scope / identity

| Attribute (shared) | Alumina e3a9ff1 | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- |
| Workload | same fixed 100 decimal Mbps workload for all three (8 persistent connections, 4096 B payload frames + 12 B header, aggregate open-loop pacing, 5 s warmup / 60 s window / 5 s setup+drain) | same | same |
| Harness image / placement | `9191d288…` net+PID ns, `flock-vm-root`, loopback alias | same | same |
| Host | arm64 Apple-VM, 4 CPU / 14 GiB | same | same |

| Attribute (per-candidate) | Alumina e3a9ff1 | HAProxy 3.2.25 | Envoy 1.39.4 |
| --- | --- | --- | --- |
| Route label / client mode | via-proxy (CONNECT) | direct-proxy (direct TLS/SNI, no CONNECT) | via-proxy (CONNECT-terminate) |
| Binary commit | e3a9ff1 (fresh musl binary `1c0d0f3b…`) | official pinned image 3.2.25 | official pinned image v1.39.4 |
| Measurement HEAD | 78e878a (Rust code e3a9ff1; receipt `source_head` `e3a9ff1e…`) | 031ee10 | 031ee10 |
| Libc / build | `aarch64-unknown-linux-musl` | glibc (official image; libssl/libcrypto/liblua5.4/libpcre2/libz/libzstd) | BoringSSL RELEASE (libc/libm/libdl/librt/libpthread) |
| User | uid 65534 | image default (no user flag) | uid 65534 (`--user 65534:65534`) |
| Seam tool (`tool_sha256`) | `347a0b8b…` | `347a0b8b…` | `347a0b8b…` |
| Supervisor | `seam_echo.sh` `1fb1fe63…` | `qryg_runner.sh` `c6d4aab6…` + `harness_native.sh` `57b4acd0…` | `qryg_runner.sh` `c6d4aab6…` + `harness_native.sh` `57b4acd0…` |
| Config | allowlist + listen + `[any_illegal]` `scope=connection` + `[actions]` `kind=[flare_only]` `scope=[connection]` (`config_sha256` `6f41d28e…`) | `haproxy.cfg` `35cf35df…` (TCP/SNI passthrough: `mode tcp`, `tcp-request content` on ClientHello, `use_backend` on SNI `example.com`, fixed backend `8.8.8.8:443`, `nbthread 1`, no CONNECT method) | `envoy_connect.yaml` `e6fb9ef7…` (CONNECT-terminate: HCM `connect_matcher` route to fixed backend `8.8.8.8:443`, route `timeout: 0s`, `--concurrency 1`, uid 65534) |
| Candidate image / binary | retained `1c0d0f3b…` (musl) | image `d483b789…` / manifest `3947a542…`, binary `8c8791be…` | image `a084f595…` / manifest `ce82b213…`, binary `6b064069…` |
| Raw + companion evidence | seam report `3b30e542…` — [results/e3a9ff1-seam-timed-20261015T135816Z.json](results/e3a9ff1-seam-timed-20261015T135816Z.json) | seam `ffa5ee4a…` — [results/qryg-haproxy-timed-20261014T012232Z-66396.json](results/qryg-haproxy-timed-20261014T012232Z-66396.json) + native `96b341de…` — [results/qryg-haproxy-timed-20261014T012232Z-66396.native.json](results/qryg-haproxy-timed-20261014T012232Z-66396.native.json) | seam `770de863…` — [results/qryg-envoy-timed-20261014T012343Z-66851.json](results/qryg-envoy-timed-20261014T012343Z-66851.json) + native `5256d337…` — [results/qryg-envoy-timed-20261014T012343Z-66851.native.json](results/qryg-envoy-timed-20261014T012343Z-66851.native.json) |
