package service

import (
	"strings"
	"testing"
)

func TestBuildLegacyKCPMasks(t *testing.T) {
	tests := []struct {
		name         string
		settings     string
		wantNil      bool
		wantSettings []string // expected settings JSON per udp mask, in order
	}{
		{name: "no header or seed", settings: `{"mtu":1350,"tti":50}`, wantNil: true},
		{name: "header none", settings: `{"header":{"type":"none"}}`, wantNil: true},
		{name: "empty bytes", settings: ``, wantNil: true},
		{name: "srtp", settings: `{"header":{"type":"srtp"}}`, wantSettings: []string{`{"header":"srtp"}`}},
		{name: "utp", settings: `{"header":{"type":"utp"}}`, wantSettings: []string{`{"header":"utp"}`}},
		{name: "wechat-video maps to wechat", settings: `{"header":{"type":"wechat-video"}}`, wantSettings: []string{`{"header":"wechat"}`}},
		{name: "dtls", settings: `{"header":{"type":"dtls"}}`, wantSettings: []string{`{"header":"dtls"}`}},
		{name: "wireguard", settings: `{"header":{"type":"wireguard"}}`, wantSettings: []string{`{"header":"wireguard"}`}},
		{name: "seed only", settings: `{"seed":"pw"}`, wantSettings: []string{`{"value":"pw"}`}},
		{name: "header and seed order", settings: `{"header":{"type":"srtp"},"seed":"pw"}`, wantSettings: []string{`{"value":"pw"}`, `{"header":"srtp"}`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm, err := buildLegacyKCPMasks([]byte(tt.settings))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil {
				if fm != nil {
					t.Fatalf("expected nil FinalMask, got %+v", fm)
				}
				return
			}
			if fm == nil {
				t.Fatal("expected non-nil FinalMask")
			}
			if len(fm.Udp) != len(tt.wantSettings) {
				t.Fatalf("expected %d udp masks, got %d", len(tt.wantSettings), len(fm.Udp))
			}
			for i, want := range tt.wantSettings {
				m := fm.Udp[i]
				if m.Type != "mkcp-legacy" {
					t.Fatalf("mask %d: expected type mkcp-legacy, got %q", i, m.Type)
				}
				if m.Settings == nil {
					t.Fatalf("mask %d: expected non-nil settings", i)
				}
				if got := string(*m.Settings); got != want {
					t.Fatalf("mask %d: expected settings %s, got %s", i, want, got)
				}
			}
		})
	}
}

func TestBuildLegacyKCPMasksUnknownHeader(t *testing.T) {
	_, err := buildLegacyKCPMasks([]byte(`{"header":{"type":"bogus"}}`))
	if err == nil || !strings.Contains(err.Error(), "unsupported mkcp header type") {
		t.Fatalf("expected unsupported header error, got %v", err)
	}
}

func TestBuildLegacyKCPMasksBadJSON(t *testing.T) {
	_, err := buildLegacyKCPMasks([]byte(`{not-json`))
	if err == nil || !strings.Contains(err.Error(), "parse kcp legacy mask") {
		t.Fatalf("expected parse error, got %v", err)
	}
}
