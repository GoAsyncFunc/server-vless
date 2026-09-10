package service

import (
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/core"
	freedom "github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
)

func assertOutboundDomainStrategy(t *testing.T, outbound *core.OutboundHandlerConfig, config *freedom.Config, want internet.DomainStrategy) {
	t.Helper()
	if config.DomainStrategy != internet.DomainStrategy_AS_IS {
		t.Fatal("deprecated freedom.domainStrategy must not be set")
	}
	message, err := outbound.SenderSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	sender := message.(*proxyman.SenderConfig)
	if sender.StreamSettings == nil || sender.StreamSettings.SocketSettings == nil {
		t.Fatal("missing outbound sockopt settings")
	}
	if got := sender.StreamSettings.SocketSettings.DomainStrategy; got != want {
		t.Fatalf("sockopt domain strategy = %v, want %v", got, want)
	}
}

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
	assertOutboundDomainStrategy(t, outbound, config, internet.DomainStrategy_USE_IP46)
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
	assertOutboundDomainStrategy(t, outbound, config, internet.DomainStrategy_USE_IP46)
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
	if len(config.FinalRules) != 1 {
		t.Fatalf("finalRules count = %d, want 1 explicit allow rule", len(config.FinalRules))
	}
	if config.FinalRules[0].Action != freedom.RuleAction_Allow {
		t.Fatal("private outbound opt-in must override Xray's implicit block")
	}
	if got := len(config.FinalRules[0].Ip); got != len(privateOutboundCIDRs) {
		t.Fatalf("allow rule IP count = %d, want %d", got, len(privateOutboundCIDRs))
	}
}
