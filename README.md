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
| `--fetch_users_interval` | `FETCH_USER_INTERVAL` | `60s` | User sync interval. |
| `--report_traffics_interval` | `REPORT_TRAFFICS_INTERVAL` | `80s` | Traffic report interval. |
| `--heartbeat_interval` | `HEARTBEAT_INTERVAL` | `60s` | Online-user heartbeat interval. |
| `--check_node_interval` | `CHECK_NODE_INTERVAL` | fetch interval | Node config polling interval. |
| `--dns` | `DNS` | UniProxy/default DNS | Comma-separated DNS override. |
| `--asset-dir` | `ASSET_DIR`, `SERVER_VLESS_ASSET_DIR` | empty | Directory containing `geoip.dat` and `geosite.dat`. |
| `--disable_sniffing` | `DISABLE_SNIFFING` | `false` | Disable inbound sniffing. |
| `--allow-private-outbound` | `ALLOW_PRIVATE_OUTBOUND` | `false` | Allow outbound access to private and loopback destinations. |
| `--domain_strategy` | `DOMAIN_STRATEGY` | `UseIPv4v6` | Freedom outbound domain strategy. |

`configs/conf.yaml` is an example-only file. The current `cmd/server` entrypoint does not load it; runtime settings come from CLI/env flags and UniProxy panel data.

## UniProxy compatibility

The module currently pins `github.com/GoAsyncFunc/uniproxy v0.0.9`. Local or upstream UniProxy structure changes do not affect this repository until the dependency version or a local `replace` directive is changed.

The code imports the UniProxy public facade at `github.com/GoAsyncFunc/uniproxy/pkg`. If a future UniProxy release removes that facade or renames exported models, update the imports and API model references together.

## Reload behavior

User list changes and supported inbound-only node changes are refreshed by runtime polling. UniProxy route, DNS, and custom outbound changes require a process restart so the Xray core config is rebuilt consistently. When `ALLOW_PRIVATE_OUTBOUND=false`, panel-provided freedom outbounds may not override the node's private IP blocking policy with `ipsBlocked`.

For systemd installs, the service starts `/usr/local/bin/vless-node`, matching Docker and release artifacts.

