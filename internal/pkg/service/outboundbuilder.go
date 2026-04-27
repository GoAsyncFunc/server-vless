package service

import (
	"encoding/json"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

func OutboundBuilder(config *Config, nodeInfo *api.NodeInfo) (*core.OutboundHandlerConfig, error) {
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
	if config != nil && config.AllowPrivateOutbound {
		settings["ipsBlocked"] = []string{}
	}
	settingsBytes, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	raw := json.RawMessage(settingsBytes)
	outboundDetourConfig.Settings = &raw

	return outboundDetourConfig.Build()
}
