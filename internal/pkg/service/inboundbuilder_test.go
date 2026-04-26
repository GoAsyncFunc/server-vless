package service

import (
	"strings"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
)

func TestInboundBuilderRequiresVlessConfig(t *testing.T) {
	_, err := InboundBuilder(&Config{}, &api.NodeInfo{})
	if err == nil || !strings.Contains(err.Error(), "missing VLESS") {
		t.Fatalf("expected missing VLESS error, got %v", err)
	}
}

func TestInboundBuilderRejectsUnsupportedEncryption(t *testing.T) {
	_, err := InboundBuilder(&Config{}, &api.NodeInfo{
		Vless: &api.VlessNode{
			CommonNode: api.CommonNode{ServerPort: 443},
			Network:    "tcp",
			Encryption: "unsupported",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected unsupported encryption error, got %v", err)
	}
}

func TestInboundBuilderDefaultsMLKEMSettingsFromV2Board(t *testing.T) {
	inbound, err := InboundBuilder(&Config{}, &api.NodeInfo{
		Vless: &api.VlessNode{
			CommonNode: api.CommonNode{ServerPort: 443},
			Network:    "tcp",
			Encryption: "mlkem768x25519plus",
			EncryptionSettings: api.EncSettings{
				PrivateKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
			},
		},
	})
	if err != nil {
		t.Fatalf("InboundBuilder returned error: %v", err)
	}

	message, err := inbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatalf("GetInstance returned error: %v", err)
	}
	config, ok := message.(*vlessinbound.Config)
	if !ok {
		t.Fatalf("proxy settings type = %T, want *vlessinbound.Config", message)
	}
	if got, want := config.Decryption, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"; got != want {
		t.Fatalf("decryption = %q, want %q", got, want)
	}
	if config.SecondsFrom != 0 {
		t.Fatalf("seconds_from = %d, want 0", config.SecondsFrom)
	}
}

func TestBuildStreamConfigDefaultsEmptyGRPCSettings(t *testing.T) {
	stream, err := buildStreamConfig(&api.VlessNode{Network: "grpc"}, &api.NodeInfo{}, &Config{})
	if err != nil {
		t.Fatalf("buildStreamConfig returned error: %v", err)
	}
	if stream.GRPCSettings == nil {
		t.Fatal("expected default grpc settings")
	}
}

func TestBuildStreamConfigTLSRequiresCertConfig(t *testing.T) {
	_, err := buildStreamConfig(&api.VlessNode{Network: "tcp"}, &api.NodeInfo{Security: api.Tls}, &Config{})
	if err == nil || !strings.Contains(err.Error(), "cert config") {
		t.Fatalf("expected cert config error, got %v", err)
	}
}

func TestBuildStreamConfigTLSUsesCertConfig(t *testing.T) {
	stream, err := buildStreamConfig(
		&api.VlessNode{Network: "tcp"},
		&api.NodeInfo{Security: api.Tls},
		&Config{Cert: &CertConfig{CertFile: "server.crt", KeyFile: "server.key"}},
	)
	if err != nil {
		t.Fatalf("buildStreamConfig returned error: %v", err)
	}
	if stream.Security != "tls" {
		t.Fatalf("security = %q, want tls", stream.Security)
	}
	if len(stream.TLSSettings.Certs) != 1 {
		t.Fatalf("cert count = %d, want 1", len(stream.TLSSettings.Certs))
	}
	cert := stream.TLSSettings.Certs[0]
	if cert.CertFile != "server.crt" || cert.KeyFile != "server.key" {
		t.Fatalf("cert = %+v", cert)
	}
}
