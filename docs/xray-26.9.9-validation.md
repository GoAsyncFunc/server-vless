# Xray 26.9.9 upgrade validation

## Dependency

- Fork: `GoAsyncFunc/Xray-core`
- Commit: `52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120`
- Go: 1.27

## Compatibility changes

- Statistics registration now uses `stats.Manager.GetOrRegisterCounter` and
  `GetOrRegisterOnlineMap` methods instead of package-level helpers.
- Freedom applies an implicit private-IP block for VLESS inbounds even without
  configured final rules. `ALLOW_PRIVATE_OUTBOUND=true` therefore needs an
  explicit allow rule for the project's private CIDRs. Default blocking remains
  unchanged.
- Invalid panel API configuration now returns a constructor error via
  `api.NewWithError`, rather than allowing startup with a nil API client.
- The default freedom outbound now sets `sockopt.domainStrategy` directly,
  removing the deprecated `freedom.domainStrategy` setting. Tests assert the
  resulting sender socket settings.
- Panel-provided freedom/direct outbounds may not specify `finalRules` when
  private outbound is disabled, matching the existing `ipsBlocked` restriction
  and preventing explicit allow rules from overriding the private-IP policy.
  These final two changes were checked locally after the remote test run.

## Remote integration test (2026-09-10)

Used a separate legacy V2Board development installation and temporary hidden
nodes, dedicated group and user. The production panel and existing node were
not restarted or modified. No test proxy ports were published to the host.

The development panel had no server API token. A temporary PHP HTTP entrypoint
loaded its existing Laravel/UniProxy routes and supplied a random token in memory,
restricted requests to the dedicated VLESS node IDs, and ran traffic jobs
synchronously. This validates the controller and database path, **not** the normal
Nginx/TLS ingress or asynchronous queue workers. Nodes reached that entrypoint
through loopback in the development container's network namespace.

With a client built from the same Xray commit, all of these VLESS transports
successfully fetched a 1 MiB random file from a temporary private-network HTTP
origin through a loopback SOCKS proxy; received bytes matched the source exactly:

- TCP
- WebSocket
- gRPC
- XHTTP
- HTTPUpgrade

All five cases used `security=none`, VLESS `encryption=none`, and the explicit
private-outbound opt-in. Database readback showed 5,244,180 downloaded bytes and
1,020 uploaded bytes across the validation activity, plus traffic-report timestamps
for all five nodes. Panel cache contained online-IP reports from all five nodes.
Panel online entries have a TTL, so these observations do not establish immediate
panel-side removal when a connection closes.

A separate negative TCP test with private outbound disabled received no response
and the node log explicitly confirmed the target was blocked.

Temporary containers, PHP listener, test user/group/nodes/statistics, per-node
cache, credentials and binaries were removed. Production node PID and listener
were unchanged after testing.

## Local checks

- `go test -race ./...`
- `go vet ./...`
- `go build ./...`
- Linux amd64 runtime tested remotely; Linux arm64 cross-compilation checked.
- Regression tests cover concurrent counter registration, online-IP cleanup,
  private-outbound configuration and invalid API configuration.

## Additional remote validation

A second isolated run used the pushed `b385f89` node build, followed by the mKCP
compatibility fix below. Both clients were built from the project's pinned fork:

- New client: 26.9.9 (`52a412d9e2f5`).
- Old client: 26.6.1 (`fdb9b616fc0e`, the pre-upgrade dependency).

The following combinations passed with both clients:

| Transport/security | TCP file transfer | SOCKS5 UDP relay |
| --- | --- | --- |
| TCP + TLS | Pass | Pass |
| TCP + TLS + Vision | Pass | Pass |
| TCP + REALITY + Vision | Pass | Pass |
| WebSocket + TLS | Pass | Pass |
| gRPC + TLS | Pass | Pass |
| XHTTP + TLS | Pass | Pass |
| mKCP + SRTP header + seed | Pass after fix | Pass after fix |

Each file transfer compared a 256 KiB random payload byte-for-byte. UDP used a
private-network echo endpoint with 32-, 512- and 1200-byte random payloads. TLS
clients explicitly trusted the ephemeral test certificate; certificate checking
was not disabled. REALITY used ephemeral X25519 keys and a private TLS 1.3 target.
The initial REALITY test had an empty client key due to the test script parsing
an outdated key-output label; correcting that test setup made both clients pass.

### mKCP compatibility issue and fix

The new Finalmask manager reverses its configured mask chain before wrapping,
unlike the old manager. Consequently, simply keeping the previous generated
header/seed array broke old-client interoperability when both masks were present.
The project now reverses its legacy KCP translation to preserve the pre-upgrade
wire format. The old client retains its old explicit Finalmask order; a new
client using explicit Finalmask JSON must reverse that order. Both then passed
TCP file transfer and UDP relay. A single header or seed is unaffected.

### Hot reload

On a running WS+TLS test node, without changing its process PID/start time:

- Banning the dedicated user rejected new connections; restoring it allowed them.
- Rotating its UUID rejected the old UUID and accepted the new UUID.
- Changing its WS path rejected the old path and accepted the new path.

The panel recorded traffic reports for all seven dedicated nodes. Test nodes,
user/group/statistics, listeners, temporary credentials and binaries were cleaned
up again; the production node PID and 443 listener remained unchanged.

## Remaining coverage gaps

VLESS post-quantum encryption, HTTPUpgrade+TLS, other mKCP masks, UDP loss/MTU
stress, real-world client apps other than these two fork builds, production queue
workers, prolonged load and live production deployment remain untested. The
GitHub Docker workflow passed after `b385f89`; this integration run mounted the
tested binary in an existing runtime image rather than deploying that new image.
