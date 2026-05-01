package service

import (
	"encoding/json"
	"strings"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func TestBuildStreamConfigWSTransport(t *testing.T) {
	v := &api.VlessNode{
		Network:         "ws",
		NetworkSettings: json.RawMessage(`{"path":"/ws"}`),
	}
	stream, err := buildStreamConfig(v, &api.NodeInfo{}, &Config{})
	if err != nil {
		t.Fatalf("buildStreamConfig returned error: %v", err)
	}
	if stream.WSSettings == nil || stream.WSSettings.Path != "/ws" {
		t.Fatalf("expected WS settings.Path=/ws, got %+v", stream.WSSettings)
	}
}

func TestBuildStreamConfigGRPCTransport(t *testing.T) {
	v := &api.VlessNode{
		Network:         "grpc",
		NetworkSettings: json.RawMessage(`{"serviceName":"svc"}`),
	}
	stream, err := buildStreamConfig(v, &api.NodeInfo{}, &Config{})
	if err != nil {
		t.Fatalf("buildStreamConfig returned error: %v", err)
	}
	if stream.GRPCSettings == nil || stream.GRPCSettings.ServiceName != "svc" {
		t.Fatalf("expected GRPC settings.ServiceName=svc, got %+v", stream.GRPCSettings)
	}
}

func TestBuildStreamConfigXHTTPTransport(t *testing.T) {
	v := &api.VlessNode{
		Network:         "xhttp",
		NetworkSettings: json.RawMessage(`{"path":"/x"}`),
	}
	stream, err := buildStreamConfig(v, &api.NodeInfo{}, &Config{})
	if err != nil {
		t.Fatalf("buildStreamConfig returned error: %v", err)
	}
	if stream.XHTTPSettings == nil {
		t.Fatal("expected XHTTPSettings to be set")
	}
}

func TestBuildStreamConfigHTTPUpgradeTransport(t *testing.T) {
	v := &api.VlessNode{
		Network:         "httpupgrade",
		NetworkSettings: json.RawMessage(`{"path":"/up"}`),
	}
	stream, err := buildStreamConfig(v, &api.NodeInfo{}, &Config{})
	if err != nil {
		t.Fatalf("buildStreamConfig returned error: %v", err)
	}
	if stream.HTTPUPGRADESettings == nil {
		t.Fatal("expected HTTPUPGRADESettings to be set")
	}
}

func TestBuildStreamConfigKCPTransport(t *testing.T) {
	v := &api.VlessNode{
		Network:         "kcp",
		NetworkSettings: json.RawMessage(`{"mtu":1350}`),
	}
	stream, err := buildStreamConfig(v, &api.NodeInfo{}, &Config{})
	if err != nil {
		t.Fatalf("buildStreamConfig returned error: %v", err)
	}
	if stream.KCPSettings == nil {
		t.Fatal("expected KCPSettings to be set")
	}
}

func TestBuildStreamConfigPropagatesTransportError(t *testing.T) {
	v := &api.VlessNode{
		Network:         "ws",
		NetworkSettings: json.RawMessage(`{not-json`),
	}
	_, err := buildStreamConfig(v, &api.NodeInfo{}, &Config{})
	if err == nil || !strings.Contains(err.Error(), "ws config") {
		t.Fatalf("expected ws parse error, got %v", err)
	}
}

func TestBuildStreamConfigSecurityNone(t *testing.T) {
	v := &api.VlessNode{Network: "tcp"}
	stream, err := buildStreamConfig(v, &api.NodeInfo{Security: api.None}, &Config{})
	if err != nil {
		t.Fatalf("buildStreamConfig returned error: %v", err)
	}
	if stream.Security != "none" {
		t.Fatalf("security = %q, want none", stream.Security)
	}
}

func TestBuildStreamConfigReality(t *testing.T) {
	v := &api.VlessNode{
		Network: "tcp",
		TlsSettings: api.TlsSettings{
			ServerName: "example.com",
			Dest:       "example.com",
			ServerPort: "443",
			PrivateKey: "test-private-key",
			ShortId:    "abcd",
		},
	}
	stream, err := buildStreamConfig(v, &api.NodeInfo{Security: api.Reality}, &Config{})
	if err != nil {
		t.Fatalf("buildStreamConfig returned error: %v", err)
	}
	if stream.Security != "reality" {
		t.Fatalf("security = %q, want reality", stream.Security)
	}
	if stream.REALITYSettings == nil {
		t.Fatal("expected REALITYSettings to be populated")
	}
	if stream.REALITYSettings.PrivateKey != "test-private-key" {
		t.Fatalf("private key = %q, want test-private-key", stream.REALITYSettings.PrivateKey)
	}
	if len(stream.REALITYSettings.ShortIds) != 1 || stream.REALITYSettings.ShortIds[0] != "abcd" {
		t.Fatalf("short ids = %v, want [abcd]", stream.REALITYSettings.ShortIds)
	}
	if len(stream.REALITYSettings.ServerNames) != 1 || stream.REALITYSettings.ServerNames[0] != "example.com" {
		t.Fatalf("server names = %v, want [example.com]", stream.REALITYSettings.ServerNames)
	}
}

func TestBuildStreamConfigRealityDefaultsDestPortAndDestFromServerName(t *testing.T) {
	v := &api.VlessNode{
		Network: "tcp",
		TlsSettings: api.TlsSettings{
			ServerName: "fallback.example.com",
			// Dest empty -> falls back to ServerName.
			// ServerPort empty -> falls back to "443".
		},
	}
	stream, err := buildStreamConfig(v, &api.NodeInfo{Security: api.Reality}, &Config{})
	if err != nil {
		t.Fatalf("buildStreamConfig returned error: %v", err)
	}
	if stream.REALITYSettings == nil {
		t.Fatal("expected REALITYSettings to be populated")
	}
	dest := string(stream.REALITYSettings.Dest)
	if !strings.Contains(dest, "fallback.example.com:443") {
		t.Fatalf("reality dest = %s, expected to contain fallback.example.com:443", dest)
	}
}

func TestBuildStreamConfigRealityXverFallback(t *testing.T) {
	v := &api.VlessNode{
		Network: "tcp",
		TlsSettings: api.TlsSettings{
			ServerName: "example.com",
			Xver:       0,
		},
		RealityConfig: api.RealityConfig{Xver: 7},
	}
	stream, err := buildStreamConfig(v, &api.NodeInfo{Security: api.Reality}, &Config{})
	if err != nil {
		t.Fatalf("buildStreamConfig returned error: %v", err)
	}
	if stream.REALITYSettings == nil || stream.REALITYSettings.Xver != 7 {
		t.Fatalf("xver = %v, want 7 from RealityConfig fallback", stream.REALITYSettings)
	}
}
