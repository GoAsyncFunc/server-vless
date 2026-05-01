package server

import (
	"encoding/json"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/infra/conf"
)

func TestBuildRouteConfigDNSActionIsIgnored(t *testing.T) {
	result, err := buildRouteConfig([]api.Route{
		{Id: 1, Action: api.RouteActionDNS, Match: []string{"domain:dns.example.com"}},
	}, api.Rules{})
	if err != nil {
		t.Fatalf("buildRouteConfig returned error: %v", err)
	}
	if result.needsBlock {
		t.Fatal("DNS action should not allocate block outbound")
	}
	if result.router != nil {
		t.Fatal("DNS action should not produce router rules")
	}
	if len(result.outbounds) != 0 {
		t.Fatalf("DNS action should not produce outbounds, got %d", len(result.outbounds))
	}
}

func TestBuildRouteConfigUnknownActionIsSkipped(t *testing.T) {
	// Unknown action falls through to the default branch and is logged-then-skipped.
	result, err := buildRouteConfig([]api.Route{
		{Id: 99, Action: "totally-made-up", Match: []string{"domain:example.com"}},
	}, api.Rules{})
	if err != nil {
		t.Fatalf("buildRouteConfig returned error: %v", err)
	}
	if result.router != nil || result.needsBlock || len(result.outbounds) != 0 {
		t.Fatalf("unknown action should produce empty result, got %+v", result)
	}
}

func TestBuildRouteConfigRouteWithEmptyMatchesIsSkipped(t *testing.T) {
	// route/route_ip with no matches must not add outbounds or rules.
	result, err := buildRouteConfig([]api.Route{
		{Id: 1, Action: api.RouteActionRoute, Match: []string{}, ActionValue: `{"protocol":"freedom"}`},
		{Id: 2, Action: api.RouteActionRouteIP, Match: nil, ActionValue: `{"protocol":"freedom"}`},
	}, api.Rules{})
	if err != nil {
		t.Fatalf("buildRouteConfig returned error: %v", err)
	}
	if len(result.outbounds) != 0 {
		t.Fatalf("expected no outbounds for empty matches, got %d", len(result.outbounds))
	}
	if result.router != nil {
		t.Fatal("expected no router rules for empty matches")
	}
}

func TestBuildRouteConfigBlockActionsWithEmptyMatchesDoNotAllocateBlock(t *testing.T) {
	// block-family actions with no matches should be no-ops.
	result, err := buildRouteConfig([]api.Route{
		{Id: 1, Action: api.RouteActionBlock, Match: []string{}},
		{Id: 2, Action: api.RouteActionBlockIP, Match: nil},
		{Id: 3, Action: api.RouteActionBlockPort, Match: []string{}},
		{Id: 4, Action: api.RouteActionProtocol, Match: nil},
	}, api.Rules{})
	if err != nil {
		t.Fatalf("buildRouteConfig returned error: %v", err)
	}
	if result.needsBlock {
		t.Fatal("empty-match block actions should not allocate block outbound")
	}
}

func TestBuildRouteConfigPolicyAllowsIpsBlockedWhenPrivateOutboundEnabled(t *testing.T) {
	// When private outbound is allowed, ipsBlocked freedom config must pass.
	_, err := buildRouteConfigWithPolicy([]api.Route{
		{Id: 1, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"direct-private","protocol":"freedom","settings":{"ipsBlocked":[]}}`},
	}, api.Rules{}, true)
	if err != nil {
		t.Fatalf("expected ipsBlocked accepted when allowPrivateOutbound=true, got %v", err)
	}
}

func TestValidateRouteOutboundPolicySkipsNonFreedomProtocols(t *testing.T) {
	// Protocols other than freedom/direct skip the ipsBlocked policy check entirely.
	settings := json.RawMessage(`{"ipsBlocked":[]}`)
	out := conf.OutboundDetourConfig{
		Protocol: "socks",
		Tag:      "socks-out",
		Settings: &settings,
	}
	if err := validateRouteOutboundPolicy(api.Route{Id: 1}, out, false); err != nil {
		t.Fatalf("non-freedom outbound should bypass ipsBlocked check, got %v", err)
	}
}

func TestValidateRouteOutboundPolicyAllowsIpsBlockedWhenPrivateOutboundEnabled(t *testing.T) {
	// allowPrivateOutbound=true takes the early-return branch.
	settings := json.RawMessage(`{"ipsBlocked":[]}`)
	out := conf.OutboundDetourConfig{
		Protocol: "freedom",
		Tag:      "direct-private",
		Settings: &settings,
	}
	if err := validateRouteOutboundPolicy(api.Route{Id: 2}, out, true); err != nil {
		t.Fatalf("ipsBlocked must be accepted when allowPrivateOutbound=true, got %v", err)
	}
}

func TestValidateRouteOutboundPolicyAcceptsFreedomWithoutSettings(t *testing.T) {
	// Freedom outbound with no settings block must pass even when private outbound is disabled.
	out := conf.OutboundDetourConfig{
		Protocol: "freedom",
		Tag:      "plain-freedom",
		Settings: nil,
	}
	if err := validateRouteOutboundPolicy(api.Route{Id: 3}, out, false); err != nil {
		t.Fatalf("freedom without settings should be accepted, got %v", err)
	}
}

func TestValidateRouteOutboundPolicyRejectsMalformedSettings(t *testing.T) {
	// Malformed settings JSON in a freedom outbound triggers the parse-error path.
	settings := json.RawMessage(`{not json`)
	out := conf.OutboundDetourConfig{
		Protocol: "freedom",
		Settings: &settings,
	}
	err := validateRouteOutboundPolicy(api.Route{Id: 4}, out, false)
	if err == nil {
		t.Fatal("expected parse error for malformed settings")
	}
}

func TestBuildRouteConfigPolicyAcceptsFreedomWithoutSettings(t *testing.T) {
	// Freedom outbound with no settings block must pass even when private outbound is disabled.
	_, err := buildRouteConfigWithPolicy([]api.Route{
		{Id: 1, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"plain-freedom","protocol":"freedom"}`},
	}, api.Rules{}, false)
	if err != nil {
		t.Fatalf("freedom without settings should be accepted, got %v", err)
	}
}

func TestBuildRouteOutboundRequiresActionValue(t *testing.T) {
	// route/route_ip with empty action_value must error before any tag work.
	_, err := buildRouteConfig([]api.Route{
		{Id: 7, Action: api.RouteActionRoute, Match: []string{"domain:example.com"}, ActionValue: ""},
	}, api.Rules{})
	if err == nil {
		t.Fatal("expected error for empty action_value")
	}
}
