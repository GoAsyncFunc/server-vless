# V2Board VLESS branch audit

Date: 2026-09-10. Node source: `19da6c2` (runtime unchanged since `4cbd44a`).
Panel examined: isolated `v2board-legacy-dev` installation, specifically
`app/Http/Controllers/V1/Admin/Server/VlessController.php`,
`app/Utils/Helper.php` and the UniProxy controller. This is not a claim about
all V2Board forks/versions.

## Actual panel branches

The URI generator explicitly handles tcp, ws, grpc, kcp, httpupgrade and xhttp.
The admin validator only requires `network` rather than enumerating allowed
values: being able to save an arbitrary string does not establish support.
Security accepts 0/1/2; Vision is cleared for non-tcp network values. ML-KEM
settings, ECH client configuration and XHTTP extra settings add more combinations.

Historical tests in `protocol-compatibility.md` cover the six transport families,
TLS/REALITY/Vision, XHTTP packet-up/stream-up and three ML-KEM modes. This run
supplemented them with ten specific subbranches, not the full cross-product.

## Additional remote tests

Each case passed a 64 KiB exact-byte download plus 32/512/1200-byte SOCKS UDP echo
with both 26.9.9 and 26.6.1 fork clients:

| Case | Result |
| --- | --- |
| TCP HTTP header (no TLS, isolated network only) | Pass both |
| XHTTP stream-one + TLS | Pass both |
| XHTTP packet-up + TLS, noGRPCHeader/noSSEHeader/scMaxBufferedPosts=20 | Pass both |
| KCP header none, no seed | Pass both |
| KCP seed only | Pass both |
| KCP SRTP + seed | Pass both |
| KCP UTP + seed | Pass both |
| KCP wechat-video + seed | Pass both |
| KCP DTLS + seed | Pass both |
| KCP WireGuard header + seed | Pass both |

Ten wrong-UUID tests with the current client also failed as expected with working
positive controls. These are 20 successful client/config combinations and ten
negative controls. KCP clients used version-appropriate explicit Finalmask order,
not a real application's URI-import transformation. A WireGuard KCP header test
is not a test of the WireGuard VPN protocol.

TLS certificate validation remained enabled. Test records were created directly
as dedicated hidden node models; this did not exercise the admin save middleware
or import generated subscriptions into real apps. The Laravel UniProxy endpoint
used the temporary in-memory-token/synchronous-job entrypoint described in prior
reports. No production services were modified. Temporary nodes/users/statistics,
containers, listeners, keys and binaries were removed.

## Not an "all options supported" verdict

- ECH: the panel URI generator emits ECH client parameters, but the pinned
  UniProxy TLS model and node builder do not expose corresponding server ECH
  configuration. Do not claim direct-node ECH support; CDN termination is a
  different deployment and has not been tested here.
- XHTTP split downloadSettings, HTTP/3, proxy/CDN deployments and all extra
  parameter combinations remain untested.
- ML-KEM 0-RTT/ticket resumption, padding combinations, wrong-key cases remain
  untested. The panel auto-generates X25519 keys via Sodium when fields are absent;
  previous tests used explicitly generated ML-KEM keys. These key paths must not
  be conflated.
- REALITY ML-DSA handshakes passed with a suitable target, but the examined
  generic URI generator does not emit a corresponding verification parameter.
  Manual client config tests do not prove subscription delivery of that option.
- Actual client-app import/export, public IPv6 proxy paths, uploads at scale and
  all security/transport cross-products remain acceptance tasks.

Verdict: six main transport families have real interoperability evidence and all
20 newly tested subbranch/client combinations passed. Arbitrary panel settings,
subscription clients and every possible combination have not been certified.
