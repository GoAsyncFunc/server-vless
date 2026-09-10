# Mihomo REALITY compatibility correction

Scope: server-vless with Xray fork 26.9.9 / REALITY dependency
`8cdf7bf9c7f0`, tested against official Mihomo v1.19.30.

## Root cause

Mihomo's `adapter/outbound/reality.go` exposes
`reality-opts.support-x25519mlkem768` and defaults it to false. In
`component/tls/reality.go`, false calls
`BuildRemovedX25519MLKEM768HandshakeState` for compatibility with old servers.
The pinned REALITY server now requires an X25519MLKEM768 key share ahead of the
optional X25519 share. Therefore the default client behavior is rejected even
with correct public key, short ID, SNI and fingerprint.

A temporary transparent test relay inspected only ClientHello key-share group
IDs and lengths (not application payload or key material). Unmodified Mihomo
emitted GREASE plus X25519 (29,32 bytes), with no X25519MLKEM768. Server logged
authentication/validation failure. This establishes a specific default-mode
mismatch, not a generic inability of Mihomo to use REALITY.

## Minimal client correction

For nodes running the tested new REALITY version:

```yaml
reality-opts:
  public-key: <existing-public-key>
  short-id: <existing-short-id>
  support-x25519mlkem768: true
```

Keep the existing `client-fingerprint: chrome`, servername, UUID and flow.
Do not disable certificate verification or weaken server key-share requirements.
Do not blindly apply to old REALITY servers: the Mihomo switch exists specifically
because some older servers do not handle this mode correctly.

On the same test node and private TLS1.3 target, copying the emitted subscription
proxy and adding only this option changed Mihomo v1.19.30 from authentication
failure to a byte-checked 64 KiB download plus 32/512/1200-byte UDP echo success.
Changing short-id to an incorrect value with the switch still enabled rejected
the connection. Dedicated test resources and credentials were cleaned up.

The override fragment in `scripts/mihomo-reality-override.yaml` must be merged
only into known-new REALITY proxies, preserving the other reality-opts fields.
It is not an automatic panel patch or a standalone configuration.
No production panel or missing HTTPUpgrade/KCP/XHTTP-extra serialization is changed.
This is a subscription/client correction: server-vless has no ability to set a
client's ClientHello policy after the connection arrives.
