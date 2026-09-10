# Bounded end-to-end baseline

Date: 2026-09-10. Node source: `8e13d14`; Xray fork 26.9.9. Both
client and node used this fork, Linux amd64, Go 1.27.0.

## Setup

Shared six-vCPU AMD EPYC VPS, with production services left unchanged.
Independent Laravel development panel, temporary hidden nodes and dedicated user;
UniProxy served through the isolated temporary entrypoint described in
`panel-runtime-fixes.md` (traffic jobs run synchronously).

- Node: Docker CPU quota 1, memory limit 256 MiB.
- Client: Docker CPU quota 1, memory limit 256 MiB.
- Private Nginx HTTPS origin: CPU quota 0.5, memory limit 96 MiB.
- No proxy ports published to host; source and destination stayed inside Docker
  networking. Client curl processes used the client's network namespace.
- TCP+TLS versus TCP+REALITY+Vision; HTTPS payload ensures TLS traffic inside
  Vision. Certificates were verified using the ephemeral test certificate.
- Sniffing disabled, private outbound explicitly allowed, user speed unlimited.
- Warmup followed by 8 requests per cell, concurrency 1/4, two repetitions.
  Each request fetched and SHA-256 checked a random 4 MiB file.
- Curl `--limit-rate 2m` per request, timeout 12s; overall script timeout 240s.
  This is bounded functional/load characterization, **not saturation throughput**.
- CPU measured from node `/proc/PID/stat` deltas (100% = one core); RSS sampled
  from node `/proc/PID/status` every 200ms. Excludes origin/client/panel CPU and
  is not container-wide peak memory. Sampling can miss short-lived peaks.

## Results

All 64 measured requests succeeded with matching payload hashes.

| Case | Concurrency | Payload MiB/s, run 1 / 2 | Node CPU %, run 1 / 2 | Peak RSS MiB, run 1 / 2 | Max request seconds, run 1 / 2 |
| --- | ---: | --- | --- | --- | --- |
| TCP+TLS | 1 | 2.134 / 2.415 | 5.87 / 9.81 | 33.7 / 33.7 | 1.908 / 1.767 |
| TCP+TLS | 4 | 8.476 / 8.752 | 8.21 / 11.76 | 34.4 / 34.4 | 1.861 / 1.928 |
| REALITY+Vision | 1 | 2.288 / 2.022 | 12.73 / 10.36 | 36.9 / 36.9 | 1.808 / 1.992 |
| REALITY+Vision | 4 | 8.281 / 7.230 | 11.13 / 31.40 | 37.5 / 39.1 | 1.994 / 2.021 |

Request medians ranged from 1.589 to 1.886 seconds. Median TTFB per cell ranged
from 0.042 to 0.111 seconds; observed maximum TTFB was 0.342 seconds.
With only eight requests per cell, the script's nearest-rank p95 equals the
maximum; it is **not** a statistically robust estimate of production tail latency.
Short transfers and curl's rate-limiter burst behavior explain measured payload
rates slightly above the nominal per-request cap. Do not infer sustained
bandwidth capacity or compare protocols as a controlled A/B result from this run.
Shared-host contention and per-process CPU attribution limit comparisons.

## Setup failures and cleanup

An SSH interruption occurred before uploading the load script; no load ran then.
Subsequent warmup initially failed: sniffing rewrote the private destination to
`test.example.invalid` from the inner TLS SNI, which cannot resolve. The benchmark
explicitly disabled sniffing to preserve the intended private test route. This
run therefore does not establish performance/correctness with sniffing enabled.

Test node/client containers were removed after each case. Temporary origin,
PHP listener, panel nodes/user/group/statistics and secret files/binaries were
removed at completion. The production `stao-us` PID (572502) and 443 listener
were unchanged. This did not deploy a new production node image.

## Interpretation and next work

- No correctness failure or runaway RSS was observed at these bounded loads.
- There is no basis here to enable raw splice or introduce lock sharding.
- No CPU/mutex/heap profile was collected. Before further runtime optimization,
  use a dedicated test host or agreed resource window for a longer steady-state
  workload and profiles, including client/origin utilization and quota throttling.
- Add a reproducible checked-in orchestration harness with automatic cleanup,
  fixed warmup/duration, sufficiently large latency samples and versioned raw
  results before treating this as a release performance gate. Current remote
  orchestration is an ad-hoc test script, not a maintained load-testing framework.
