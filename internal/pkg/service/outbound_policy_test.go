package service

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/freedom"
)

func TestPanelFreedomOptInPreservesExplicitRules(t *testing.T) {
	for _, settings := range []string{`{}`, `{"finalRules":[{"action":"block","ip":["10.0.0.0/8"]}]}`} {
		raw := json.RawMessage(settings)
		out := &conf.OutboundDetourConfig{Protocol: "freedom", Settings: &raw}
		if err := ApplyPrivateOutboundOptIn(out); err != nil {
			t.Fatal(err)
		}
		built, err := out.Build()
		if err != nil {
			t.Fatal(err)
		}
		message, err := built.ProxySettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		rules := message.(*freedom.Config).FinalRules
		if len(rules) == 0 || rules[len(rules)-1].Action != freedom.RuleAction_Allow {
			t.Fatal("missing private allow fallback")
		}
		if settings != `{}` && (len(rules) != 2 || rules[0].Action != freedom.RuleAction_Block) {
			t.Fatal("overrode explicit administrator rule")
		}
	}
}
