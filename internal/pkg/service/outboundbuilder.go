package service

import (
	"encoding/json"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

func OutboundBuilder(config *Config, nodeInfo *api.NodeInfo, extConf []byte) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = "direct"

	domainStrategy := "UseIPv4"

	settings := map[string]interface{}{
		"domainStrategy": domainStrategy,
	}
	settingsBytes, _ := json.Marshal(settings)
	outboundDetourConfig.Settings = (*json.RawMessage)(&settingsBytes)

	return outboundDetourConfig.Build()
}
