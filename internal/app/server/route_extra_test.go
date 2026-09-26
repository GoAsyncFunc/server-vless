package server

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	log "github.com/sirupsen/logrus"
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
	useGeoAssets(t)
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

// The private-outbound policy only reaches freedom/direct outbounds and only
// looks at their settings. Anything else the panel points at an internal
// address is dialed as given, so the node says so at startup instead of leaving
// the operator to infer it from a README section.
func TestUncoveredOutboundReasonFlagsNonFreedomProtocol(t *testing.T) {
	reason := uncoveredOutboundReason(conf.OutboundDetourConfig{Protocol: "socks"})
	if reason == "" {
		t.Fatal("a socks outbound is outside the private-outbound policy and must be reported")
	}
}

func TestUncoveredOutboundReasonFlagsDialerProxy(t *testing.T) {
	// Xray skips finalRules and its default private-IP rule for a
	// dialer-proxied freedom outbound, and dialerProxy lives in streamSettings
	// rather than in the settings this policy inspects.
	out := conf.OutboundDetourConfig{
		Protocol: "freedom",
		StreamSetting: &conf.StreamConfig{
			SocketSettings: &conf.SocketConfig{DialerProxy: "proxy-tag"},
		},
	}
	if reason := uncoveredOutboundReason(out); reason == "" {
		t.Fatal("a dialer-proxied freedom outbound must be reported")
	}
}

func TestUncoveredOutboundReasonAcceptsCoveredOutbounds(t *testing.T) {
	for _, protocol := range []string{"freedom", "direct", "Freedom", " direct "} {
		out := conf.OutboundDetourConfig{
			Protocol:      protocol,
			StreamSetting: &conf.StreamConfig{SocketSettings: &conf.SocketConfig{DomainStrategy: "UseIPv4"}},
		}
		if reason := uncoveredOutboundReason(out); reason != "" {
			t.Errorf("protocol %q should be covered, got reason %q", protocol, reason)
		}
	}
}

func TestUncoveredOutboundReasonToleratesMissingStreamSettings(t *testing.T) {
	for name, out := range map[string]conf.OutboundDetourConfig{
		"no stream settings": {Protocol: "freedom"},
		"no socket settings": {Protocol: "freedom", StreamSetting: &conf.StreamConfig{}},
		"blank dialer proxy": {Protocol: "freedom", StreamSetting: &conf.StreamConfig{SocketSettings: &conf.SocketConfig{DialerProxy: "  "}}},
	} {
		if reason := uncoveredOutboundReason(out); reason != "" {
			t.Errorf("%s: expected no reason, got %q", name, reason)
		}
	}
}

func TestBuildRouteOutboundWarnsAboutOutboundOutsidePrivatePolicy(t *testing.T) {
	useGeoAssets(t)
	var logs bytes.Buffer
	originalOutput := log.StandardLogger().Out
	log.SetOutput(&logs)
	defer log.SetOutput(originalOutput)

	if _, err := buildRouteConfigWithPolicy([]api.Route{
		{Id: 11, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"socks-out","protocol":"socks","settings":{"servers":[{"address":"10.0.0.1","port":1080}]}}`},
	}, api.Rules{}, false); err != nil {
		t.Fatalf("a socks outbound should build: %v", err)
	}
	got := logs.String()
	if !strings.Contains(got, "route 11") || !strings.Contains(got, "--allow-private-outbound's scope") {
		t.Fatalf("uncovered outbound was not named in a warning: %q", got)
	}
}

func TestBuildRouteOutboundStaysQuietWhenPrivateOutboundIsAllowed(t *testing.T) {
	useGeoAssets(t)
	var logs bytes.Buffer
	originalOutput := log.StandardLogger().Out
	log.SetOutput(&logs)
	defer log.SetOutput(originalOutput)

	if _, err := buildRouteConfigWithPolicy([]api.Route{
		{Id: 12, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"socks-out","protocol":"socks","settings":{"servers":[{"address":"10.0.0.1","port":1080}]}}`},
	}, api.Rules{}, true); err != nil {
		t.Fatalf("a socks outbound should build: %v", err)
	}
	if got := logs.String(); strings.Contains(got, "--allow-private-outbound's scope") {
		t.Fatalf("scope warning must not fire once the flag is on: %q", got)
	}
}
