# Cloudflare split download / extra matrix / bounded soak

2026-09-10, node source `e5c9115`, clients 26.9.9 and 26.6.1 fork CLI.
Same resource-limited isolated Laravel/node/origin topology as
`cloudflare-cdn-test.md`. Two newly created proxied hostnames in the authorized
test Zone selected separate upload and download entrypoints; both ultimately
reached the same node/session backend through Nginx. This is not independent
backend clustering.

## Matrix (all passed)

Each combination used packet-up and explicit downloadSettings with the second
CDN hostname. Both client versions passed three 64 KiB byte-checked downloads
and 32/512/1200-byte UDP echo in each case:

1. Split CDN upload/download, client ALPN h2 on both legs.
2. Split CDN upload/download, client ALPN h3 on both legs.
3. Split h2 plus noGRPCHeader=true, noSSEHeader=true.
4. Split h2 plus xmux.maxConnections=2, hMaxRequestTimes=4,
   hMaxReusableSecs=10, scMaxEachPostBytes=65536, scMinPostsIntervalMs=10.

Four current-client wrong-UUID checks rejected traffic with working positives.
These extra values were applied to client configurations; the panel node retained
its compatible auto-mode settings. This is not validation of every panel-side
extra field or every client/server cross-product. In particular, the short matrix
alone does not prove that every xmux reuse limit was reached.

## 15-minute low-load observation (passed)

Current client, split CDN h2, same node and client processes:

- Elapsed 905.48 seconds, 162 exact-byte-checked 64 KiB downloads, all successful.
- 14 UDP check rounds, all successful (three payload sizes per round).
- About five seconds between requests; not continuous bulk saturation.
- Node PID unchanged.
- Sampled node RSS 33,784–38,012 KiB; final sample 37,804 KiB.
- No failure or runaway RSS observed in this window. GC/steady-state convergence
  cannot be established from RSS alone; this is not a memory-leak proof.

This keeps the processes running while issuing repeated connections; it does not
prove that one application TCP connection or one CDN HTTP stream survived for
15 minutes. It is not hours/days of production stability, a high-concurrency soak,
packet-loss/reconnect testing, or ticket-resumption instrumentation.

## Scope and cleanup

No finite run can enumerate all extra combinations (ranges, addresses, nesting,
versions and provider settings). This is a representative feature matrix, not
"all extra options certified". H3 concerns the client-to-Cloudflare leg; the
origin still uses TLS/TCP. Existing Zone Full SSL mode was unchanged, so strict
CF-to-origin identity verification was not established by the test.

Both dedicated DNS records were deleted and the Origin CA certificate revoked
(API success confirmed). Test panel records, containers, private keys, config
files and binaries were removed, and temporary host port 8443 closed. Existing
stao-us PID 572502 and port 443 were unchanged. Account API credentials were not
stored in the repository; the owner should rotate/revoke the provided Global Key.
