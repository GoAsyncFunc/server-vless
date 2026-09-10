# Real Cloudflare XHTTP validation

2026-09-10; node source `23b327e` (runtime unchanged from prior tests).
Dedicated proxied subdomain in the owner's authorized test Zone; no existing DNS
records, Zone settings or production node were modified. API credentials were
not stored in the repository or test scripts.

## Topology and result

Client -> Cloudflare proxied hostname:8443 -> temporary Nginx:8443 -> private
node TLS:24446 -> private HTTP payload origin. The panel was the isolated legacy
Laravel test installation with dedicated records and temporary UniProxy entrypoint.

Both 26.9.9 and 26.6.1 fork clients passed 64 KiB exact-byte downloads and
32/512/1200-byte SOCKS UDP echo in these configurations:

- XHTTP with client TLS ALPN restricted to h2.
- XHTTP with client TLS ALPN restricted to h3.

Wrong UUID tests failed with working positive controls in each configuration.
Cloudflare response headers included a CF-Ray and advertised h3; origin access
logs recorded Cloudflare source addresses and HTTP/2 requests. Client H3 config
selects Xray's HTTP/3 transport; no packet capture was collected. HTTP/3 here is
the client-to-edge leg, **not** a direct-node QUIC listener or H3 origin connection.
UDP payloads are carried inside VLESS/XHTTP, not arbitrary Cloudflare UDP proxying.

## TLS/security details

Public client certificate validation remained enabled. A temporary Cloudflare
Origin CA certificate was issued for this subdomain and installed on Nginx.
The Zone's pre-existing SSL mode was Full, not Full (strict), and was deliberately
left unchanged. Thus this run does not establish strict CF-to-origin identity
validation. Nginx-to-node TLS used explicit trusted certificate verification.
Nginx request/response buffering was disabled. Production would need a separate
review of Full (strict), origin access restrictions and streaming/provider limits.

## Scope and cleanup

This was a short functional test of default XHTTP settings over Cloudflare, not a
long-lived CDN stability/load test, split download over CDN, or all extra/WAF/cache
combinations. Earlier split-download tests were local Nginx tests, not this CDN run.

Deleted the dedicated proxied DNS record and revoked its Origin CA certificate
through Cloudflare API (both returned success). Removed test containers, panel
user/group/nodes/statistics, PHP listener, secrets, certificates and binaries.
The temporary 8443 listener disappeared; production stao-us retained PID 572502
and its 443 listener. The operator should rotate/revoke the supplied Global API
Key after testing; revoking that account credential was not performed here.
