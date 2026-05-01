package server

import (
	"bytes"
	"strings"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func TestPrintStartupBannerTLS(t *testing.T) {
	var buf bytes.Buffer
	node := &api.NodeInfo{
		Id:       17,
		Security: api.Tls,
		Vless: &api.VlessNode{
			CommonNode: api.CommonNode{ServerPort: 443},
			Network:    "ws",
		},
	}
	printStartupBannerTo(&buf, "v1.2.3", node, 5)

	got := buf.String()
	for _, want := range []string{"vless-node v1.2.3", "node=17", ":443", "ws/tls", "users=5"} {
		if !strings.Contains(got, want) {
			t.Fatalf("banner missing %q in output: %q", want, got)
		}
	}
}

func TestPrintStartupBannerReality(t *testing.T) {
	var buf bytes.Buffer
	node := &api.NodeInfo{
		Id:       42,
		Security: api.Reality,
		Vless: &api.VlessNode{
			CommonNode: api.CommonNode{ServerPort: 8443},
			Network:    "tcp",
		},
	}
	printStartupBannerTo(&buf, "v0.0.0", node, 0)

	got := buf.String()
	if !strings.Contains(got, "tcp/reality") {
		t.Fatalf("expected tcp/reality, got %q", got)
	}
	if !strings.Contains(got, ":8443") {
		t.Fatalf("expected :8443, got %q", got)
	}
}

func TestPrintStartupBannerNoSecurity(t *testing.T) {
	var buf bytes.Buffer
	node := &api.NodeInfo{
		Id:       1,
		Security: api.None,
		Vless: &api.VlessNode{
			CommonNode: api.CommonNode{ServerPort: 80},
			Network:    "tcp",
		},
	}
	printStartupBannerTo(&buf, "dev", node, 1)

	got := buf.String()
	if !strings.Contains(got, "tcp/none") {
		t.Fatalf("expected tcp/none, got %q", got)
	}
}

func TestPrintStartupBannerDefaultsWhenVlessNil(t *testing.T) {
	var buf bytes.Buffer
	node := &api.NodeInfo{
		Id:       99,
		Security: api.None,
		Vless:    nil,
	}
	printStartupBannerTo(&buf, "dev", node, 0)

	got := buf.String()
	if !strings.Contains(got, ":0 tcp/none") {
		t.Fatalf("expected default network/port for nil Vless, got %q", got)
	}
}

func TestPrintStartupBannerDefaultsNetworkWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	node := &api.NodeInfo{
		Id:       3,
		Security: api.Tls,
		Vless: &api.VlessNode{
			CommonNode: api.CommonNode{ServerPort: 443},
			Network:    "",
		},
	}
	printStartupBannerTo(&buf, "v1", node, 0)

	got := buf.String()
	if !strings.Contains(got, "tcp/tls") {
		t.Fatalf("expected fallback tcp/tls when Network empty, got %q", got)
	}
}

func TestPrintStartupBannerEndsWithNewline(t *testing.T) {
	var buf bytes.Buffer
	node := &api.NodeInfo{Id: 1, Vless: &api.VlessNode{}}
	printStartupBannerTo(&buf, "v", node, 0)
	if got := buf.String(); !strings.HasSuffix(got, "\n") {
		t.Fatalf("banner must end with newline, got %q", got)
	}
}
