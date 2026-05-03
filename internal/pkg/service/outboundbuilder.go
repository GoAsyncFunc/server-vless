package service

import (
	"encoding/json"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// privateOutboundCIDRs lists CIDR ranges treated as "private" for outbound
// blocking. Equivalent to xray-core's "geoip:private" alias but expressed
// inline so we do not depend on geoip.dat being available when freedom config
// is parsed. Covers RFC1918, loopback, link-local, CGN, ULA, multicast,
// reserved, documentation, and unspecified ranges. IPv4-mapped IPv6
// (::ffff:0:0/96) is intentionally omitted because xray-core unwraps
// IPv4-mapped addresses to native IPv4, so the IPv4 entries already match.
var privateOutboundCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::/128",
	"::1/128",
	"2001:db8::/32",
	"fc00::/7",
	"fe80::/10",
}

// OutboundBuilder builds the freedom outbound handler used as the "direct"
// egress. nodeInfo is reserved for future per-node outbound customization
// (e.g., bind address from node metadata) and is currently unused.
func OutboundBuilder(config *Config, _ *api.NodeInfo) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = "direct"

	domainStrategy := ""
	if config != nil {
		domainStrategy = config.DomainStrategy
	}
	if domainStrategy == "" {
		domainStrategy = "UseIPv4v6"
	}

	settings := map[string]interface{}{
		"domainStrategy": domainStrategy,
	}
	if config == nil || !config.AllowPrivateOutbound {
		settings["finalRules"] = []map[string]interface{}{
			{
				"action": "block",
				"ip":     privateOutboundCIDRs,
			},
		}
	}
	settingsBytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	raw := json.RawMessage(settingsBytes)
	outboundDetourConfig.Settings = &raw

	return outboundDetourConfig.Build()
}
