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
}
