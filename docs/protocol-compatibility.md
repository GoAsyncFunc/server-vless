# Protocol compatibility and release acceptance

Compatibility has three separate gates: panel JSON -> config fidelity, successful
core configuration build, and real client interoperability. Passing one does not
establish the others. Re-run the matrix on one frozen candidate commit after any
runtime/dispatcher change; historical results apply only to their recorded builds.

## Latest configuration fixes

- Normalize case/whitespace and Xray aliases: raw/tcp, websocket/ws,
  splithttp/xhttp, mkcp/kcp. Parse transport-specific settings using the canonical
  name instead of silently leaving defaults for aliases.
- REALITY destination uses JoinHostPort, preserving bare or bracketed IPv6.
- An empty panel short ID becomes the explicit Xray `shortIds: [""]`, not an
  invalid empty list. This intentionally permits an empty short ID; operators
  wanting a nonempty ID should configure it in the panel.
- Forward the panel's `mldsa65Seed` to Xray instead of discarding it. The core
  remains responsible for validating key length and encoding.

Tests compare alias/canonical configuration and build transport settings. REALITY
field tests verify forwarding/address formatting, not a post-quantum handshake.

## Candidate acceptance matrix

For both the previous supported client and current client, test at minimum:

| Area | Required cases |
| --- | --- |
| TCP | none (isolated only), TLS, TLS+Vision, REALITY+Vision |
| HTTP transports | WS+TLS, gRPC+TLS, HTTPUpgrade+TLS, XHTTP modes |
| mKCP | seed only, header only, header+seed, representative supported headers |
| REALITY | nonempty/empty short ID, IPv4/IPv6 target, ML-DSA verification |
| VLESS encryption | none, supported ML-KEM mode and invalid key rejection |
| Data | TCP upload/download, UDP relay, IPv4/IPv6, long-lived connection |
| Runtime | user revoke/restore, UUID/limit change, successful/failed reload |
| Negative | wrong UUID, wrong key/short ID/SNI, invalid config, unsupported transport |

Record exact node/client commits, panel version, OS, certificates, relevant flags,
expected failures and cleanup. Real client app coverage needs explicit versions
(e.g. an app embedding a different core is not covered by testing our fork CLI).

## Current evidence and limits

See `xray-26.9.9-validation.md` for historical remote protocol tests and
`panel-runtime-fixes.md` for subsequent lifecycle changes. The four config fixes passed the full local race suite and vet.

A follow-up remote run (2026-09-10) tested source based on `cb141de` plus these
config fixes, using the isolated Laravel entrypoint and resource-limited temporary
nodes. Both 26.9.9 and 26.6.1 fork clients passed byte-checked 256 KiB downloads
and 32/512/1200-byte SOCKS UDP echo for:

- raw + TLS;
- websocket alias + TLS with a non-default path;
- gRPC + TLS;
- HTTPUpgrade + TLS;
- splithttp alias, packet-up + TLS;
- XHTTP stream-up + TLS;
- REALITY/Vision with an explicitly empty short ID.

All seven wrong-UUID negative tests using the new client rejected transfers while
the client stayed running. A wrong, nonempty short ID also failed against the
empty-short-ID REALITY node. These negatives had working positive controls.
Certificates were verified; production services were unchanged. Temporary panel
records, containers, certificates, keys and binaries were cleaned up.

**ML-DSA remains blocked:** adding an ephemeral seed and matching client Verify
key caused handshake failure for both client versions against the private Nginx
TLS 1.3 target. Server log: handshake did not complete successfully. The cause
(target prerequisites versus core compatibility) has not been isolated. Negative
results from this failing setup are not valid authentication acceptance evidence.
Do not advertise ML-DSA interoperability based on field forwarding alone.

IPv6 destination formatting is unit-tested, but actual IPv6 connectivity and
VLESS ML-KEM encryption were not exercised in this run. The full matrix above
remains incomplete.

Do not silently map removed h2/quic transports to a different protocol, disable
TLS verification, or drop encryption settings to make a configuration appear to
work. Prefer actionable errors and explicit migration guidance.
