package service

import (
	"testing"

	freedom "github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
)

func TestOutboundBuilderDefaultsIPv4FirstDualStack(t *testing.T) {
	outbound, err := OutboundBuilder(&Config{}, nil)
	if err != nil {
		t.Fatalf("OutboundBuilder returned error: %v", err)
	}
	message, err := outbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatalf("GetInstance returned error: %v", err)
	}
	config, ok := message.(*freedom.Config)
	if !ok {
		t.Fatalf("proxy settings type = %T, want *freedom.Config", message)
	}
	if got, want := config.DomainStrategy, internet.DomainStrategy_USE_IP46; got != want {
		t.Fatalf("domain strategy = %v, want %v", got, want)
	}
	if len(config.FinalRules) != 1 {
		t.Fatalf("finalRules count = %d, want 1", len(config.FinalRules))
	}
	if got := config.FinalRules[0].Action; got != freedom.RuleAction_Block {
		t.Fatalf("finalRules[0].Action = %v, want Block", got)
	}
	if got, want := len(config.FinalRules[0].Ip), len(privateOutboundCIDRs); got != want {
		t.Fatalf("finalRules[0].Ip count = %d, want %d", got, want)
	}
}

func TestOutboundBuilderNilConfigUsesDefaultDomainStrategy(t *testing.T) {
	outbound, err := OutboundBuilder(nil, nil)
	if err != nil {
		t.Fatalf("OutboundBuilder returned error: %v", err)
	}
	message, err := outbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatalf("GetInstance returned error: %v", err)
	}
	config, ok := message.(*freedom.Config)
	if !ok {
		t.Fatalf("proxy settings type = %T, want *freedom.Config", message)
	}
	if got, want := config.DomainStrategy, internet.DomainStrategy_USE_IP46; got != want {
		t.Fatalf("domain strategy = %v, want %v", got, want)
	}
	if len(config.FinalRules) != 1 {
		t.Fatalf("finalRules count = %d, want 1 for nil config", len(config.FinalRules))
	}
	if got := config.FinalRules[0].Action; got != freedom.RuleAction_Block {
		t.Fatalf("finalRules[0].Action = %v, want Block", got)
	}
}

func TestOutboundBuilderAllowsPrivateOutboundWhenEnabled(t *testing.T) {
	outbound, err := OutboundBuilder(&Config{AllowPrivateOutbound: true}, nil)
	if err != nil {
		t.Fatalf("OutboundBuilder returned error: %v", err)
	}
	message, err := outbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatalf("GetInstance returned error: %v", err)
	}
	config, ok := message.(*freedom.Config)
	if !ok {
		t.Fatalf("proxy settings type = %T, want *freedom.Config", message)
	}
	if len(config.FinalRules) != 0 {
		t.Fatalf("finalRules count = %d, want 0 when private outbound allowed", len(config.FinalRules))
	}
}
