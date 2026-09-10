# Advanced XHTTP and encryption tests

2026-09-10; node source `082fafd`, Xray 26.9.9; clients 26.9.9 and
26.6.1 fork CLI. Isolated legacy Laravel panel, hidden nodes, dedicated user,
private origin, limited Docker containers. Production services unchanged.

## Encryption: real panel default-key generation

Invoked the actual VlessController::save method in the Laravel console, omitting
private_key/password so the panel generated them through Sodium's X25519 keypair
path. This tests save defaults, not admin middleware authentication. Modes native,
xorpub and random used rtt=0rtt, ticket=60s, server/client padding `100-64-64`.
Both clients passed four sequential 64 KiB byte-checked downloads in the same
client process plus 32/512/1200-byte UDP echo, for every mode. Wrong UUID was
rejected in each mode with a working positive control.

This verifies the panel-generated key path and this legal padding combination.
Despite the protocol name mlkem768x25519plus, these default non-forward-secret
keys are X25519 keys, not the explicitly generated ML-KEM public keys tested
previously. Do not conflate the paths.

0-RTT is configured and repeated connections work, but no ticket-hit observation,
packet-level flight analysis or instrumentation was collected. Actual resumption,
ticket expiry/rejection, server restart fallback, replay properties and arbitrary
padding combinations are **not proven** by repeated successful requests.

## XHTTP

Both clients passed downloads and UDP in these scenarios, with correct/wrong UUID
controls and full certificate validation:

1. Explicit downloadSettings pointing to the same TLS node (separate logical
   download configuration, not a physically different backend).
2. Nginx TLS/HTTP2 reverse proxy -> TLS node, buffering disabled and upstream
   certificate verification enabled.
3. Upload through the Nginx TLS/HTTP2 port 18444, downloadSettings pointing directly
   to the node's TLS port 24446. These are different entrypoints, same backend.

Initial proxy tests failed because the test Nginx listener did not enable HTTP/2
and returned 400 to the HTTP2 preface. Enabling `http2 on` made both scenarios
pass. This was a test proxy prerequisite, not a server-vless patch.

HTTP/3 **did not pass**. Setting client ALPN=h3 cannot make the server listen on
QUIC. Xray's splithttp listener requires server TLS ALPN to be exactly ["h3"],
whereas this project's TLS builder only supplies certificates and does not expose
that selection through the panel TLS model. The direct-node H3 configuration path
is therefore incomplete. Failed H3 negatives are not acceptance evidence.

No actual CDN deployment was exercised. CDN certificate management, HTTP version
support, streaming timeouts, buffering and upload limits require provider-specific
validation; local Nginx success is not a substitute.

## Cleanup and remaining work

Dedicated panel records/statistics, test proxy/origin/node containers, listeners,
credentials and binaries were removed. No runtime changes were needed for the
passing cases. Next tasks: design explicit server H3/ALPN configuration without
silently changing existing TLS behavior; add instrumented ticket-resumption tests;
provision a controlled CDN hostname before claiming CDN support.
