# server-vless

`server-vless` builds the `vless-node` binary for serving VLESS nodes backed by the UniProxy server API.

## Runtime configuration

Required flags can also be supplied as environment variables:

| Flag | Environment | Description |
| --- | --- | --- |
| `--api` | `API` | UniProxy/V2Board API base URL. |
| `--token` | `TOKEN` | Server API token. |
| `--node` | `NODE` | Node ID. |

Optional runtime controls:

| Flag | Environment | Default | Description |
| --- | --- | --- | --- |
| `--fetch-users-interval` | `FETCH_USER_INTERVAL` | `60s` | User sync interval. |
| `--report-traffics-interval` | `REPORT_TRAFFICS_INTERVAL` | `80s` | Traffic report interval (capped at 120s for panel health; idle cycles send an empty push). |
| `--heartbeat-interval` | `HEARTBEAT_INTERVAL` | `60s` | Online-user heartbeat interval. |
| `--check-node-interval` | `CHECK_NODE_INTERVAL` | fetch interval | Node config polling interval. |
| `--dns` | `DNS` | UniProxy/default DNS | Comma-separated DNS override. |
| `--asset-dir` | `ASSET_DIR`, `SERVER_VLESS_ASSET_DIR` | empty | Directory containing `geoip.dat` and `geosite.dat`. |
| `--disable-sniffing` | `DISABLE_SNIFFING` | `false` | Disable inbound sniffing. |
| `--allow-private-outbound` | `ALLOW_PRIVATE_OUTBOUND` | `false` | Let the built-in direct egress and panel-provided `freedom`/`direct` outbounds reach private and loopback destinations. Not a complete fence around panel egress — see [private destination policy](#private-destination-policy). |
| `--domain-strategy` | `DOMAIN_STRATEGY` | `UseIPv4v6` | Freedom outbound domain strategy. |

Every flag also accepts its older `snake_case` spelling, and the interval and strategy flags the short aliases `fui`, `rti`, `hbi`, `cni` and `ds`.

`geoip.dat` is required: the direct egress blocks private destinations with Xray's `geoip:private` attribute, so the node refuses to start when the file cannot be read. `geosite.dat` is only needed when a route or the panel DNS uses a `geosite:` attribute, and its absence is reported when such a route is built. Both files are resolved from `--asset-dir` (or, when that flag is unset, the executable's own directory), then `/usr/local/share/xray/`, `/usr/share/xray/`, and `/opt/share/xray/`; release archives ship both beside the binary.

`configs/conf.yaml` is an example-only file. The current `cmd/server` entrypoint does not load it; runtime settings come from CLI/env flags and UniProxy panel data.

## UniProxy compatibility

The module currently pins `github.com/GoAsyncFunc/uniproxy v0.1.4`. Local or upstream UniProxy structure changes do not affect this repository until the dependency version or a local `replace` directive is changed.

The code imports the UniProxy public facade at `github.com/GoAsyncFunc/uniproxy/pkg`. If a future UniProxy release removes that facade or renames exported models, update the imports and API model references together.

## Reload behavior

User list changes and supported inbound-only node changes are refreshed by runtime polling. UniProxy route, DNS, and custom outbound changes require a process restart so the Xray core config is rebuilt consistently. Private-destination blocking is baked into the core config when it is built, so flipping `ALLOW_PRIVATE_OUTBOUND` also needs a restart. See [private destination policy](#private-destination-policy).

Device limits are enforced per source IP for new connections, using local reservations and the panel's periodically refreshed `alivelist`. Cross-node counts are eventually consistent, not an atomic global quota. Speed changes apply to existing connections. See [runtime compatibility fixes and test boundaries](docs/panel-runtime-fixes.md).

For systemd installs, the unit at `scripts/server-vless.service` starts `/usr/local/bin/vless-node`, matching the Docker and release artifacts, and reads every setting from `/etc/server-vless/env`: the unit refuses to start while that file is missing. Copy `scripts/server-vless.env.example` there with `install -D -m 0600`, fill in `API`, `TOKEN` and `NODE`, then enable the unit. Because the unit hides `/root`, TLS certificates have to live outside the home directories, for example under `/etc/server-vless/certs`, with `CERT_FILE` and `KEY_FILE` pointing at them.

## Shutdown

On SIGINT or SIGTERM the node stops its background tasks and waits up to 10 s for them, removes the listener, sends one final traffic report inside that same 10 s budget, then closes the Xray core with another 10 s cap. Give the process at least 30 s before SIGKILL, or the final report, and with it up to one report interval of traffic, is lost. Docker's default stop grace period is only 10 s, so use `docker stop -t 30` or set `stop_grace_period: 30s` in Compose. Kubernetes' default `terminationGracePeriodSeconds` of 30 s and systemd's default `TimeoutStopSec` of 90 s already cover it. A second SIGINT or SIGTERM during the shutdown ends the process immediately, without the final report.

## Private destination policy

By default the node keeps proxy users off the server's own private and loopback addresses. `--allow-private-outbound` relaxes two things:

- The built-in `direct` egress stops blocking `geoip:private`. The node emits that rule explicitly rather than leaning on Xray's implicit default, and the flag flips its action from `block` to `allow`.
- A panel-provided `freedom` or `direct` outbound may set `ipsBlocked` or `finalRules`. With the flag off, such a route is rejected; with it on, the node appends an allow rule for `geoip:private` to the outbound's `finalRules`.

The flag does not cover every outbound the panel can configure, so do not read it as a complete fence:

- It only inspects `freedom` and `direct`. A `socks`, `http`, `shadowsocks`, or any other outbound the panel points at an internal address is built as given.
- It only inspects `settings`. A freedom outbound that sets `sockopt.dialerProxy` in its `streamSettings` bypasses both its own `finalRules` and Xray's default private-IP rule, because Xray skips those checks entirely for a dialer-proxied freedom outbound.

Both gaps need someone able to edit the panel's route configuration. If that access is not fully trusted, review panel outbounds yourself rather than relying on the flag.

## Release artifacts

Each tag publishes `vless-node-<os>-<arch>.tar.gz`, which contains `vless-node`, `geoip.dat`, and `geosite.dat` — unpack it into one directory and the node finds its assets without extra flags. The bare `vless-node-<os>-<arch>` binary is published alongside it for existing install scripts; those installs must supply `geoip.dat` themselves (see `--asset-dir` above). The Docker image already carries both files under `/usr/local/share/xray/`.

Both geo files are downloaded and sha256-verified at build time by `build/package/fetch-geo-assets.sh`, which the release workflow and the Dockerfile share.

Every artifact is built with the Go toolchain pinned in `go.mod` (`toolchain go1.27.3`). CI and the release workflow read it through `go-version-file`, and the Dockerfile's builder image is the matching `golang:1.27.3-alpine` digest, so the three cannot drift apart.
