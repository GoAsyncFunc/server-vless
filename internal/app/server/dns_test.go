package server

import (
	"net"
	"strings"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestParseDNSServer(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		wantHost    string
		wantPort    uint16
		wantNetwork xnet.Network
	}{
		{name: "bare ipv4", input: "1.1.1.1", wantHost: "1.1.1.1", wantPort: 53, wantNetwork: xnet.Network_UDP},
		{name: "ipv4 with port", input: "1.1.1.1:5353", wantHost: "1.1.1.1", wantPort: 5353, wantNetwork: xnet.Network_UDP},
		{name: "udp scheme bare", input: "udp://8.8.8.8", wantHost: "8.8.8.8", wantPort: 53, wantNetwork: xnet.Network_UDP},
		{name: "udp scheme with port", input: "udp://8.8.8.8:53", wantHost: "8.8.8.8", wantPort: 53, wantNetwork: xnet.Network_UDP},
		{name: "tcp scheme bare", input: "tcp://9.9.9.9", wantHost: "9.9.9.9", wantPort: 53, wantNetwork: xnet.Network_TCP},
		{name: "tcp scheme with port", input: "tcp://9.9.9.9:5353", wantHost: "9.9.9.9", wantPort: 5353, wantNetwork: xnet.Network_TCP},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns, err := parseDNSServer(tc.input)
			if err != nil {
				t.Fatalf("parseDNSServer(%q) returned error: %v", tc.input, err)
			}
			if ns.Address == nil || ns.Address.Address == nil {
				t.Fatalf("parseDNSServer(%q) produced nil address", tc.input)
			}
			gotIP := net.IP(ns.Address.Address.GetIp()).String()
			if gotIP != tc.wantHost {
				t.Fatalf("host = %q, want %q", gotIP, tc.wantHost)
			}
			if uint16(ns.Address.Port) != tc.wantPort {
				t.Fatalf("port = %d, want %d", ns.Address.Port, tc.wantPort)
			}
			if ns.Address.Network != tc.wantNetwork {
				t.Fatalf("network = %v, want %v", ns.Address.Network, tc.wantNetwork)
			}
		})
	}
}

func TestParseDNSServerRejectsInvalidPort(t *testing.T) {
	_, err := parseDNSServer("1.1.1.1:notaport")
	if err == nil || !strings.Contains(err.Error(), "invalid DNS port") {
		t.Fatalf("expected invalid port error, got %v", err)
	}
}

func TestParseDNSServerRejectsPortOverflow(t *testing.T) {
	_, err := parseDNSServer("1.1.1.1:99999")
	if err == nil || !strings.Contains(err.Error(), "invalid DNS port") {
		t.Fatalf("expected port overflow error, got %v", err)
	}
}

func TestParseDNSServerRejectsInvalidHost(t *testing.T) {
	_, err := parseDNSServer("not-an-ip")
	if err == nil || !strings.Contains(err.Error(), "invalid DNS server") {
		t.Fatalf("expected invalid host error, got %v", err)
	}
}

func TestDNSFromListSkipsBlankAndAcceptsMultiple(t *testing.T) {
	cfg, err := dnsFromList([]string{"  ", "1.1.1.1", "", "tcp://8.8.8.8:5353"})
	if err != nil {
		t.Fatalf("dnsFromList returned error: %v", err)
	}
	if got := len(cfg.NameServer); got != 2 {
		t.Fatalf("name server count = %d, want 2", got)
	}
	if cfg.NameServer[1].Address.Network != xnet.Network_TCP {
		t.Fatalf("second server network = %v, want TCP", cfg.NameServer[1].Address.Network)
	}
}

func TestDNSFromListRejectsAllBlank(t *testing.T) {
	_, err := dnsFromList([]string{"", "  ", "\t"})
	if err == nil || !strings.Contains(err.Error(), "no valid DNS servers") {
		t.Fatalf("expected no valid DNS error, got %v", err)
	}
}

func TestDNSFromListPropagatesParseError(t *testing.T) {
	_, err := dnsFromList([]string{"1.1.1.1", "not-an-ip"})
	if err == nil || !strings.Contains(err.Error(), "invalid DNS server") {
		t.Fatalf("expected propagated parse error, got %v", err)
	}
}

func TestBuildDNSConfigCLIWins(t *testing.T) {
	raw := api.RawDNS{
		DNSJson: []byte(`{"servers":["8.8.4.4"]}`),
		DNSMap:  map[string]map[string]any{"x": {"address": "9.9.9.9"}},
	}
	cfg, err := buildDNSConfig("1.1.1.1, tcp://1.0.0.1:5353 ", raw)
	if err != nil {
		t.Fatalf("buildDNSConfig returned error: %v", err)
	}
	if got := len(cfg.NameServer); got != 2 {
		t.Fatalf("name server count = %d, want 2", got)
	}
	if got := net.IP(cfg.NameServer[0].Address.Address.GetIp()).String(); got != "1.1.1.1" {
		t.Fatalf("first server = %q, want 1.1.1.1", got)
	}
}

func TestBuildDNSConfigUsesDNSJsonWhenCLIEmpty(t *testing.T) {
	raw := api.RawDNS{
		DNSJson: []byte(`{"servers":["8.8.4.4"]}`),
	}
	cfg, err := buildDNSConfig("", raw)
	if err != nil {
		t.Fatalf("buildDNSConfig returned error: %v", err)
	}
	if len(cfg.NameServer) == 0 {
		t.Fatalf("expected at least one server from DNSJson")
	}
}

func TestBuildDNSConfigInvalidDNSJsonReturnsError(t *testing.T) {
	raw := api.RawDNS{DNSJson: []byte("{not json")}
	_, err := buildDNSConfig("", raw)
	if err == nil || !strings.Contains(err.Error(), "parse DNSJson") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestBuildDNSConfigUsesDNSMapWhenJsonEmpty(t *testing.T) {
	raw := api.RawDNS{
		DNSMap: map[string]map[string]any{
			"primary": {"address": "8.8.8.8:5353"},
		},
	}
	cfg, err := buildDNSConfig("", raw)
	if err != nil {
		t.Fatalf("buildDNSConfig returned error: %v", err)
	}
	if len(cfg.NameServer) != 1 {
		t.Fatalf("name server count = %d, want 1", len(cfg.NameServer))
	}
	if got := net.IP(cfg.NameServer[0].Address.Address.GetIp()).String(); got != "8.8.8.8" {
		t.Fatalf("server host = %q, want 8.8.8.8", got)
	}
	if got := cfg.NameServer[0].Address.Port; got != 5353 {
		t.Fatalf("server port = %d, want 5353", got)
	}
}

func TestBuildDNSConfigDefaultWhenAllSourcesEmpty(t *testing.T) {
	cfg, err := buildDNSConfig("", api.RawDNS{})
	if err != nil {
		t.Fatalf("buildDNSConfig returned error: %v", err)
	}
	if len(cfg.NameServer) != 1 {
		t.Fatalf("name server count = %d, want 1 default", len(cfg.NameServer))
	}
	if got := net.IP(cfg.NameServer[0].Address.Address.GetIp()).String(); got != DefaultDNSServer {
		t.Fatalf("default server = %q, want %s", got, DefaultDNSServer)
	}
}
