package server

import (
	"os"
	"strings"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/common/platform"
)

func TestApplyAssetDir(t *testing.T) {
	t.Setenv(platform.AssetLocation, "")
	if err := applyAssetDir(" /tmp/server-vless-assets "); err != nil {
		t.Fatalf("applyAssetDir returned error: %v", err)
	}
	if got := os.Getenv(platform.AssetLocation); got != "/tmp/server-vless-assets" {
		t.Fatalf("asset dir env = %q", got)
	}
}

func TestApplyAssetDirEmptyKeepsExistingValue(t *testing.T) {
	t.Setenv(platform.AssetLocation, "/tmp/existing-assets")
	if err := applyAssetDir("  "); err != nil {
		t.Fatalf("applyAssetDir returned error: %v", err)
	}
	if got := os.Getenv(platform.AssetLocation); got != "/tmp/existing-assets" {
		t.Fatalf("asset dir env = %q", got)
	}
}

func TestBuildRouteConfigBlockActions(t *testing.T) {
	result, err := buildRouteConfig([]api.Route{
		{Id: 1, Action: api.RouteActionBlock, Match: []string{"domain:ads.example.com", "regexp:.*\\.tracker", "protocol:quic"}},
		{Id: 2, Action: api.RouteActionBlockIP, Match: []string{"10.0.0.0/8"}},
		{Id: 3, Action: api.RouteActionBlockPort, Match: []string{"53", "1000-2000"}},
		{Id: 4, Action: api.RouteActionProtocol, Match: []string{"bittorrent"}},
	}, api.Rules{})
	if err != nil {
		t.Fatalf("buildRouteConfig returned error: %v", err)
	}
	if !result.needsBlock {
		t.Fatal("expected block outbound")
	}
	if result.router == nil {
		t.Fatal("expected router config")
	}
	rules := result.router.GetRule()
	if len(rules) != 5 {
		t.Fatalf("rule count = %d, want 5", len(rules))
	}
	if got := rules[0].GetTag(); got != "block" {
		t.Fatalf("domain rule outbound = %q", got)
	}
	if got := len(rules[0].GetDomain()); got != 2 {
		t.Fatalf("domain rule count = %d, want 2", got)
	}
	if got := rules[1].GetProtocol(); len(got) != 1 || got[0] != "quic" {
		t.Fatalf("block protocol rule = %#v", got)
	}
	if got := rules[2].GetTag(); got != "block" {
		t.Fatalf("ip rule outbound = %q", got)
	}
	if got := len(rules[2].GetIp()); got != 1 {
		t.Fatalf("ip rule count = %d, want 1", got)
	}
	if rules[3].GetPortList() == nil {
		t.Fatal("expected port rule")
	}
	if got := rules[4].GetProtocol(); len(got) != 1 || got[0] != "bittorrent" {
		t.Fatalf("protocol rule = %#v", got)
	}
}

func TestBuildRouteConfigCustomRoutes(t *testing.T) {
	result, err := buildRouteConfig([]api.Route{
		{Id: 10, Action: api.RouteActionRoute, Match: []string{"domain:proxy.example.com"}, ActionValue: `{"protocol":"freedom"}`},
		{Id: 11, Action: api.RouteActionRouteIP, Match: []string{"192.168.0.0/16"}, ActionValue: `{"tag":"ip-proxy","protocol":"freedom"}`},
	}, api.Rules{})
	if err != nil {
		t.Fatalf("buildRouteConfig returned error: %v", err)
	}
	if len(result.outbounds) != 2 {
		t.Fatalf("custom outbound count = %d, want 2", len(result.outbounds))
	}
	if result.outbounds[0].Tag != "route_10" {
		t.Fatalf("generated tag = %q, want route_10", result.outbounds[0].Tag)
	}
	if result.outbounds[1].Tag != "ip-proxy" {
		t.Fatalf("custom tag = %q, want ip-proxy", result.outbounds[1].Tag)
	}
	rules := result.router.GetRule()
	if got := rules[0].GetTag(); got != "route_10" {
		t.Fatalf("route rule tag = %q", got)
	}
	if got := rules[1].GetTag(); got != "ip-proxy" {
		t.Fatalf("route_ip rule tag = %q", got)
	}
}

func TestBuildRouteConfigDefaultOutLastWins(t *testing.T) {
	result, err := buildRouteConfig([]api.Route{
		{Id: 1, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"first","protocol":"freedom"}`},
		{Id: 2, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"second","protocol":"freedom"}`},
	}, api.Rules{})
	if err != nil {
		t.Fatalf("buildRouteConfig returned error: %v", err)
	}
	if result.defaultOutbound == nil {
		t.Fatal("expected default outbound")
	}
	if result.defaultOutbound.Tag != "second" {
		t.Fatalf("default outbound tag = %q, want second", result.defaultOutbound.Tag)
	}
	if result.router != nil {
		t.Fatal("default_out should not create router rules")
	}
}

func TestBuildRouteConfigDefaultOutCanReplaceDirect(t *testing.T) {
	result, err := buildRouteConfig([]api.Route{
		{Id: 1, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"direct","protocol":"freedom"}`},
	}, api.Rules{})
	if err != nil {
		t.Fatalf("buildRouteConfig returned error: %v", err)
	}
	if result.defaultOutbound == nil {
		t.Fatal("expected default outbound")
	}
	if result.defaultOutbound.Tag != "direct" {
		t.Fatalf("default outbound tag = %q, want direct", result.defaultOutbound.Tag)
	}
}

func TestBuildRouteConfigDefaultOutCanReusePreviousDefaultTag(t *testing.T) {
	result, err := buildRouteConfig([]api.Route{
		{Id: 1, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"same","protocol":"freedom"}`},
		{Id: 2, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"same","protocol":"freedom"}`},
	}, api.Rules{})
	if err != nil {
		t.Fatalf("buildRouteConfig returned error: %v", err)
	}
	if result.defaultOutbound == nil {
		t.Fatal("expected default outbound")
	}
	if result.defaultOutbound.Tag != "same" {
		t.Fatalf("default outbound tag = %q, want same", result.defaultOutbound.Tag)
	}
}

func TestBuildRouteConfigDefaultOutCanSwitchBackToDirect(t *testing.T) {
	result, err := buildRouteConfig([]api.Route{
		{Id: 1, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"first","protocol":"freedom"}`},
		{Id: 2, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"direct","protocol":"freedom"}`},
	}, api.Rules{})
	if err != nil {
		t.Fatalf("buildRouteConfig returned error: %v", err)
	}
	if result.defaultOutbound == nil {
		t.Fatal("expected default outbound")
	}
	if result.defaultOutbound.Tag != "direct" {
		t.Fatalf("default outbound tag = %q, want direct", result.defaultOutbound.Tag)
	}
}

func TestBuildRouteConfigRejectsRouteReusingCurrentDefaultOutTag(t *testing.T) {
	_, err := buildRouteConfig([]api.Route{
		{Id: 1, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"panel","protocol":"freedom"}`},
		{Id: 2, Action: api.RouteActionRoute, Match: []string{"domain:example.com"}, ActionValue: `{"tag":"panel","protocol":"freedom"}`},
	}, api.Rules{})
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestBuildRouteConfigRejectsPrivateBypassWhenPrivateOutboundDisabled(t *testing.T) {
	tests := []struct {
		name     string
		settings string
	}{
		{name: "camel case", settings: `{"ipsBlocked":[]}`},
		{name: "pascal case", settings: `{"IpsBlocked":[]}`},
		{name: "lowercase", settings: `{"ipsblocked":[]}`},
		{name: "mixed acronym", settings: `{"IPsBlocked":[]}`},
		{name: "snake case", settings: `{"ips_blocked":[]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildRouteConfig([]api.Route{
				{Id: 1, Action: api.RouteActionDefaultOut, ActionValue: `{"tag":"direct","protocol":"freedom","settings":` + tt.settings + `}`},
			}, api.Rules{})
			if err == nil || !strings.Contains(err.Error(), "ipsBlocked") {
				t.Fatalf("expected ipsBlocked policy error, got %v", err)
			}
		})
	}
}

func TestBuildRouteConfigRejectsInvalidOutbound(t *testing.T) {
	_, err := buildRouteConfig([]api.Route{
		{Id: 1, Action: api.RouteActionRoute, Match: []string{"domain:example.com"}, ActionValue: `{`},
	}, api.Rules{})
	if err == nil || !strings.Contains(err.Error(), "parse route 1 outbound") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestBuildRouteConfigRejectsTagConflict(t *testing.T) {
	_, err := buildRouteConfig([]api.Route{
		{Id: 1, Action: api.RouteActionRoute, Match: []string{"domain:example.com"}, ActionValue: `{"tag":"direct","protocol":"freedom"}`},
	}, api.Rules{})
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestBuildRouteConfigLegacyRules(t *testing.T) {
	result, err := buildRouteConfig(nil, api.Rules{
		Regexp:   []string{"ads.example.com"},
		Protocol: []string{"bittorrent"},
	})
	if err != nil {
		t.Fatalf("buildRouteConfig returned error: %v", err)
	}
	if !result.needsBlock {
		t.Fatal("expected block outbound")
	}
	if got := len(result.router.GetRule()); got != 2 {
		t.Fatalf("rule count = %d, want 2", got)
	}
}
