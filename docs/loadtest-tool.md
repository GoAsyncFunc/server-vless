# Reproducible bounded load driver

`scripts/loadtest.py` uses Python 3.9+ and curl. It operates on an **already
provisioned isolated SOCKS client and HTTPS origin**; it never edits panel data,
starts/stops containers or deploys a node. Provisioning is intentionally separate
from the driver to avoid automatically mutating an administrator's panel.

## Preconditions

- Dedicated test node/user and client, no production user credentials.
- Node/client containers limited to 1 CPU and 256 MiB each; origin limited to
  0.5 CPU and 96 MiB. No public port publication.
- HTTPS origin serves a fixed file <=16 MiB with known size and SHA-256.
- Test CA is trusted explicitly; TLS verification is never disabled.
- SOCKS client listens on loopback in the namespace executing the script.
- Set private outbound opt-in only on the dedicated test node. Disable sniffing
  when using an unresolvable test SNI so it cannot replace the fixed private IP.

## Example (run inside client network namespace)

```sh
# Compute these on the test origin, not from the downloaded response.
sha256sum payload.bin
wc -c < payload.bin

nice -n 15 timeout --signal=TERM 150s python3 scripts/loadtest.py \
  --socks 127.0.0.1:25443 \
  --url https://test.example.invalid:8443/payload.bin \
  --target-ip 172.20.0.6 --ca /path/to/test-ca.crt \
  --sha256 REPLACE_WITH_64_HEX_DIGITS --size 4194304 \
  --duration 60 --warmup 2 --concurrency 4 --rate-kib 1024 \
  --timeout 15 --label reality-vision-commit-SHA-run1 \
  --output /path/to/results/run1.json
```

On Linux, optionally pass `--node-pid` when the node's /proc entry is visible.
The driver samples node CPU/RSS every 200ms and rejects PID reuse. CPU is measured
as a percentage of **one core**, not the whole host. It excludes client/origin CPU.
`--resolve` fixes the private target while retaining TLS hostname verification.
Curl configuration files are disabled and proxy bypass is cleared explicitly.

## Workload and safety

Warmup requests are excluded. Each worker starts requests until the fixed duration
expires; the last requests may finish up to the request timeout later. The driver
fails fast on transport/integrity errors, stops launching work on SIGINT/SIGTERM,
kills active curl children, and removes payload files using a temporary directory.
It writes versioned JSON containing individual latency samples, success counts,
aggregate payload throughput, nearest-rank percentiles and optional node metrics.
No URL, proxy credentials or curl error body is written to results.

Hard limits: 8 workers, 300s duration, 30s request timeout, 2 MiB/s per worker,
16 MiB payload. These are not a substitute for Docker/cgroup limits. Use at least
100 completed requests before interpreting p95; even then repeat tests and record
host contention. Short-transfer rate-limit bursts are not sustained throughput.

The driver's cleanup covers **its children and temporary payloads only**. The
operator must remove provisioned nodes/users, certificates, containers and panel
caches afterward, including if the outer process is SIGKILLed. Do not describe
this as a complete one-command provisioning/cleanup framework.

## Profiling and longer runs

Do not add unauthenticated public pprof endpoints to production. Next use an
isolated instrumented test build on an agreed resource window; record CPU, heap,
mutex profiles together with client/origin utilization and cgroup throttling.
This change does not enable runtime profiling or claim that a long steady-state
profile run has been completed.

Run driver tests with:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```
