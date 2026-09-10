# V2Board -> Mihomo subscription report

2026-09-10. Node source `a8a43a5`; Xray 26.9.9. Mihomo official release
v1.19.30, linux-amd64-compatible, Go 1.26.6. Downloaded release gzip SHA-256
matched GitHub's asset digest:
`db214c7a2517e63c150d123178d16d102e03a241ccdae4e5e07ffbe9cf56c6f9`.

## Method

Dedicated user/group and nine test nodes on the legacy development panel.
Initially generated the full YAML through the real ClashMeta::handle method.
Then fetched `/api/v1/client/subscribe?flag=meta` with the dedicated user's token
via an isolated loopback Laravel HTTP entrypoint using the real kernel/routes
and client middleware. HTTP 200; all nine proxy objects exactly matched the
initial export. Explicit flag=meta was used; User-Agent auto-selection was not
validated. Only dedicated-group nodes were made visible to that subscription.

Mihomo `-t` accepted the complete subscription. To prevent template routing from
bypassing the test node, each connection test copied one emitted proxy object
unchanged into a minimal envelope with MATCH to that proxy, a loopback mixed port
and no external controller. No transport/security fields were repaired. The
process SSL_CERT_FILE trusted the ephemeral test CA; skip-cert-verify remained
false. This is runtime testing of subscription proxy objects, not acceptance of
the original template's entire DNS/routing behavior.

## Results

| Panel node | Full YAML parses | 64 KiB exact download | UDP 32/512/1200 bytes |
| --- | --- | --- | --- |
| TCP | Yes | Pass | Pass |
| TCP+TLS | Yes | Pass | Pass |
| TLS+Vision | Yes | Pass | Pass |
| REALITY+Vision | Yes | Fail: REALITY authentication failed | Not run |
| WS+TLS | Yes | Pass | Pass |
| gRPC+TLS | Yes | Pass | Pass |
| XHTTP packet-up+TLS | Yes | Pass | Pass |
| HTTPUpgrade+TLS | Yes | Fail | Not run |
| KCP SRTP+seed | Yes | Fail | Not run |

## Findings and attribution

1. Confirmed panel serialization gap: ClashMeta::buildVless has no HTTPUpgrade
   or KCP branch. Both emitted proxies lack network and transport options, so
   Mihomo defaults to TCP. Config parsing success does not detect this loss.
   Whether the specific Mihomo version supports a correctly encoded transport
   must be checked separately before choosing serialization versus filtering.
2. **Resolved in follow-up:** see `mihomo-reality-compatibility.md`. Setting
   `reality-opts.support-x25519mlkem768: true` for the tested new server made
   downloads and UDP pass; a wrong short ID remained rejected. The original
   subscription test below is retained as the before-correction result.
   REALITY emits public-key, short-id, servername, fingerprint and flow, but
   Mihomo logged REALITY authentication failed against the private Nginx TLS1.3
   target. Cause not isolated (target/client/core interaction). Previous Xray CLI
   tests are not a positive Mihomo control. Do not claim this is a panel-field bug
   or that Mihomo REALITY universally fails.
3. XHTTP extra is explicitly omitted in ClashMeta::buildVless. Prior manually
   configured CDN/split-download tests do not establish subscription delivery of
   those options. This run used basic packet-up only.
4. Advanced encryption, ECH, ML-DSA, UA dispatch, CDN, other XHTTP modes, negative
   credentials and GUI import were not covered by this nine-node run.

No production panel/node or generator source was modified. Dedicated records,
statistics, containers, local subscription tokens/configs, certs, binaries and
listeners were cleaned up. Production stao-us PID 572502 and port 443 unchanged.

## Recommended follow-up

First resolve panel HTTPUpgrade/KCP serialization or explicitly omit unsupported
nodes for Mihomo with an actionable indication. Then isolate REALITY with a
controlled working Mihomo baseline and compare clients/target characteristics.
Finally add generated-subscription fixtures and runtime smoke tests as a separate
release gate; do not use core CLI interoperability as a substitute.
