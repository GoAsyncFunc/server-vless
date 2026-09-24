package service

import (
	"encoding/json"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// privateIPRule gates private and loopback destinations on the direct egress.
// It is Xray's own "geoip:private" attribute, resolved from geoip.dat rather
// than from a list maintained here.
//
// An inline CIDR list used to live here. It had drifted from the ranges Xray
// treats as private, so under --allow-private-outbound destinations in
// 192.88.99.0/24 and ff00::/8 stayed blocked: our allow rule did not match
// them and Xray's implicit defaultBlockPrivateRule took over. Multicast was
// also narrower (224.0.0.0/4 against Xray's /3). The one range the old list
// blocked that geoip:private does not is the IPv6 documentation prefix
// 2001:db8::/32, which is not routable. The trade is that geoip.dat is now a
// hard runtime requirement; the release archives and the Docker image ship it.
const privateIPRule = "geoip:private"

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

	outboundDetourConfig.StreamSetting = &conf.StreamConfig{
		SocketSettings: &conf.SocketConfig{DomainStrategy: domainStrategy},
	}
	settings := map[string]interface{}{}
	// Emit the rule explicitly instead of leaning on Xray's implicit
	// defaultBlockPrivateRule, so the block is not silently lost if upstream
	// ever changes which inbounds receive it. Only --allow-private-outbound
	// flips the action; the default stays blocking.
	action := "block"
	if config != nil && config.AllowPrivateOutbound {
		action = "allow"
	}
	settings["finalRules"] = []map[string]interface{}{
		{"action": action, "ip": []string{privateIPRule}},
	}
	settingsBytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	raw := json.RawMessage(settingsBytes)
	outboundDetourConfig.Settings = &raw

	return outboundDetourConfig.Build()
}
