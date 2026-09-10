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

## Not covered

TLS/REALITY, Vision, mKCP, UDP relay, VLESS post-quantum encryption, older clients,
user/config hot reload, production queue workers, full Docker image build,
long-running load and live production deployment were not validated by this run.
