# Performance baseline: phase 1

Date: 2026-09-10. Go 1.27.0. Baseline runtime: `0d9f34b`.

## Method

- Local: darwin/amd64, CPU reported as Genuine Intel 1.70 GHz.
- VPS: linux/amd64, AMD EPYC virtual CPU. Shared machine with running services;
  benchmarks ran at nice 15, with a timeout, GOMAXPROCS capped at 1 or 2.
  No production service was restarted, modified or used as a traffic target.
- Fast microbenchmarks: 300ms, three repeats, local CPU=1,4 and VPS CPU=1,2.
- Limited waits: 100 operations, three repeats, 32 KiB per operation, 8 Mbps
  configured limit. One-second bucket burst/refill affects the average; this is
  not an end-to-end network throughput measurement.
- Writer wrappers use an in-memory no-op sink, without socket copies or TLS.
- Fixed existing service benchmarks to exclude fixture generation from timing
  and allocation reporting. Compare future service results only against the
  corrected baseline, not the old setup-inclusive numbers.

## Implemented optimization

Reuse a lazily allocated timer within each blocked `limiter.Wait` instead of
allocating one for every 10ms polling tick. Reservation size, cancellation,
dynamic updates, accounting and the decision to disable raw splice are unchanged.

| Limited wait, VPS | Before | After |
| --- | --- | --- |
| Time/op (3 runs) | 30.05–30.18 ms | 30.02–30.12 ms |
| Bytes allocated/op | 510–642 B | 7–8 B |
| Reported allocs/op | 6–7 | 0 (integer-rounded average) |

Local runs showed about 691–704 B/op before and 7 B/op after, with approximately
30ms/op in both. The measured allocation reduction is about 98%; this does **not**
mean 98% less total process memory or zero timer allocations. Short fixed runs
and Go's timer implementation affect averaged allocation counts.

## Other observations (not optimized yet)

- VPS device acquire/release: 64 B and 2 allocations per operation. Timing varied
  substantially (~336–843 ns/op at CPU=2 for the same user). The release closure
  and idempotent release state are candidates for profiling, not grounds to
  remove lifetime safety or immediately introduce lock sharding.
- Local 4-worker device acquire/release median: ~243 ns/op for one user and
  ~275 ns/op for a 1024-user fixture. Each worker sticks to one fixture user;
  this is not a 1024-simultaneous-client test.
- Local writer median: bare ~1.85 ns/op, stats ~12.1 ns/op, stats+unlimited dynamic
  wrapper ~41.9 ns/op, all 0 heap allocations. Compiler optimization and a no-op
  sink limit the usefulness of these numbers for real transport costs.
- Corrected service batch selection at 10k/100k users: ~24 us/op, 81,920 B/op,
  1 allocation (2048-user snapshot). User diff at 10k users: ~1.55–1.63 ms/op,
  ~1.84 MB/op. These are polling costs, not per-packet costs.
- Unlimited Wait and bucket lookup allocate no memory. Any synthetic MB/s shown
  by the benchmark's SetBytes is bookkeeping, not physical network bandwidth.

## Reproduction

```sh
go test ./internal/pkg/limiter -run '^$' \
  -bench 'Benchmark(DeviceAdmission|WaitUnlimited|BucketLookup)$' \
  -benchmem -benchtime=300ms -count=3 -cpu=1,4

go test ./internal/pkg/limiter -run '^$' \
  -bench '^BenchmarkWaitLimited$' -benchmem -benchtime=100x -count=3

go test ./internal/pkg/dispatcher -run '^$' \
  -bench BenchmarkWriterWrappers -benchmem -benchtime=300ms -count=3

go test ./internal/pkg/service -run '^$' -bench . -benchmem -benchtime=200ms -count=3
```

Keep race tests separate from timing runs. The full race suite must pass before
accepting a performance change.

## Next stage

1. Dedicated/capped end-to-end TCP and REALITY/Vision workloads with fixed client
   counts, duration and payloads; record CPU, RSS, throughput and tail latency.
2. Collect mutex and allocation profiles before considering registry sharding,
   reusable admission handles or snapshot reuse.
3. Benchmark configuration building and actual report/user-update work; current
   service benchmarks only cover slice selection and diffing.
4. Do not restore splice until custom traffic accounting and live policy updates
   can be proven correct on the bypass path. No claim about splice throughput
   improvement/regression is established by this microbenchmark phase.
