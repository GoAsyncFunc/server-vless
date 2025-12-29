package service

import (
	"encoding/json"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

func OutboundBuilder(config *Config, nodeInfo *api.NodeInfo, extConf []byte) (*core.OutboundHandlerConfig, error) {
	// If external config is provided, can load it.
	// Use default "freedom" outbound.

	// Example: parse extFileBytes if you have complex routing rules.

	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = "direct"

	// Freedom Protocol setting
	// Default to "AsIs" (System DNS) matching V2bX behavior when internal DNS is not configured.
	// Default to "UseIPv4" to fix partial connections
	domainStrategy := "UseIPv4"

	// Future-proofing: If we support internal DNS (EnableDNS), we would set logic here.
	// if config.EnableDNS { domainStrategy = "UseIP" }

	settings := map[string]interface{}{
		"domainStrategy": domainStrategy,
	}
	settingsBytes, _ := json.Marshal(settings)
	outboundDetourConfig.Settings = (*json.RawMessage)(&settingsBytes)

	return outboundDetourConfig.Build()
}
