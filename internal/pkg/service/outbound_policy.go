package service

import (
	"encoding/json"
	"strings"

	"github.com/xtls/xray-core/infra/conf"
)

// ApplyPrivateOutboundOptIn supplies the same explicit private-IP allow rule to
// panel freedom outbounds as to the built-in direct outbound. Explicit panel
// final rules retain their order and take precedence over this fallback.
func ApplyPrivateOutboundOptIn(outbound *conf.OutboundDetourConfig) error {
	protocol := strings.ToLower(strings.TrimSpace(outbound.Protocol))
	if protocol != "freedom" && protocol != "direct" {
		return nil
	}
	settings := make(map[string]json.RawMessage)
	if outbound.Settings != nil {
		if err := json.Unmarshal(*outbound.Settings, &settings); err != nil {
			return err
		}
	}
	if settings == nil {
		settings = make(map[string]json.RawMessage)
	}
	var rules []json.RawMessage
	for key, value := range settings {
		if strings.EqualFold(key, "finalRules") {
			if err := json.Unmarshal(value, &rules); err != nil {
				return err
			}
			delete(settings, key)
		}
	}
	rule, err := json.Marshal(map[string]any{"action": "allow", "ip": privateOutboundCIDRs})
	if err != nil {
		return err
	}
	rules = append(rules, rule)
	encoded, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	settings["finalRules"] = encoded
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	raw := json.RawMessage(data)
	outbound.Settings = &raw
	return nil
}
