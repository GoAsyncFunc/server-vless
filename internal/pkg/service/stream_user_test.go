package service

import (
	"encoding/json"
	"strings"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/infra/conf"
)

func TestBuildTCPConfigSucceeds(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`{"acceptProxyProtocol":true}`)}
	if err := buildTCPConfig(stream, v); err != nil {
		t.Fatalf("buildTCPConfig returned error: %v", err)
	}
	if stream.TCPSettings == nil {
		t.Fatal("expected TCPSettings to be set")
	}
}

func TestBuildTCPConfigRejectsBadJSON(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`{not-json`)}
	err := buildTCPConfig(stream, v)
	if err == nil || !strings.Contains(err.Error(), "tcp config") {
		t.Fatalf("expected tcp parse error, got %v", err)
	}
}

func TestBuildWSConfigSucceeds(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`{"path":"/ws"}`)}
	if err := buildWSConfig(stream, v); err != nil {
		t.Fatalf("buildWSConfig returned error: %v", err)
	}
	if stream.WSSettings == nil || stream.WSSettings.Path != "/ws" {
		t.Fatalf("expected WSSettings.Path=/ws, got %+v", stream.WSSettings)
	}
}

func TestBuildWSConfigRejectsBadJSON(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`{`)}
	err := buildWSConfig(stream, v)
	if err == nil || !strings.Contains(err.Error(), "ws config") {
		t.Fatalf("expected ws parse error, got %v", err)
	}
}

func TestBuildGRPCConfigSucceeds(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`{"serviceName":"grpc-svc"}`)}
	if err := buildGRPCConfig(stream, v); err != nil {
		t.Fatalf("buildGRPCConfig returned error: %v", err)
	}
	if stream.GRPCSettings == nil || stream.GRPCSettings.ServiceName != "grpc-svc" {
		t.Fatalf("expected GRPCSettings.ServiceName=grpc-svc, got %+v", stream.GRPCSettings)
	}
}

func TestBuildGRPCConfigRejectsBadJSON(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`bad`)}
	err := buildGRPCConfig(stream, v)
	if err == nil || !strings.Contains(err.Error(), "grpc config") {
		t.Fatalf("expected grpc parse error, got %v", err)
	}
}

func TestBuildXHTTPConfigSucceeds(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`{"path":"/xhttp"}`)}
	if err := buildXHTTPConfig(stream, v); err != nil {
		t.Fatalf("buildXHTTPConfig returned error: %v", err)
	}
	if stream.XHTTPSettings == nil {
		t.Fatal("expected XHTTPSettings to be set")
	}
}

func TestBuildXHTTPConfigRejectsBadJSON(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`bad`)}
	err := buildXHTTPConfig(stream, v)
	if err == nil || !strings.Contains(err.Error(), "xhttp config") {
		t.Fatalf("expected xhttp parse error, got %v", err)
	}
}

func TestBuildHTTPUpgradeConfigSucceeds(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`{"path":"/up"}`)}
	if err := buildHTTPUpgradeConfig(stream, v); err != nil {
		t.Fatalf("buildHTTPUpgradeConfig returned error: %v", err)
	}
	if stream.HTTPUPGRADESettings == nil {
		t.Fatal("expected HTTPUPGRADESettings to be set")
	}
}

func TestBuildHTTPUpgradeConfigRejectsBadJSON(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`bad`)}
	err := buildHTTPUpgradeConfig(stream, v)
	if err == nil || !strings.Contains(err.Error(), "httpupgrade config") {
		t.Fatalf("expected httpupgrade parse error, got %v", err)
	}
}

func TestBuildKCPConfigSucceeds(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`{"mtu":1350}`)}
	if err := buildKCPConfig(stream, v); err != nil {
		t.Fatalf("buildKCPConfig returned error: %v", err)
	}
	if stream.KCPSettings == nil {
		t.Fatal("expected KCPSettings to be set")
	}
}

func TestBuildKCPConfigRejectsBadJSON(t *testing.T) {
	stream := &conf.StreamConfig{}
	v := &api.VlessNode{NetworkSettings: json.RawMessage(`bad`)}
	err := buildKCPConfig(stream, v)
	if err == nil || !strings.Contains(err.Error(), "kcp config") {
		t.Fatalf("expected kcp parse error, got %v", err)
	}
}

func TestBuildUserEmailFormat(t *testing.T) {
	got := buildUserEmail("inbound-tag", 42, "uuid-x")
	want := "inbound-tag|42|uuid-x"
	if got != want {
		t.Fatalf("buildUserEmail = %q, want %q", got, want)
	}
}

func TestBuildUserPopulatesAllFields(t *testing.T) {
	users := buildUser("tag-a", []api.UserInfo{
		{Id: 1, Uuid: "aaaa-bbbb-1"},
		{Id: 2, Uuid: "uuid-2"},
	}, "xtls-rprx-vision")

	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0].Email != "tag-a|1|aaaa-bbbb-1" {
		t.Fatalf("user[0].Email = %q", users[0].Email)
	}
	if users[1].Email != "tag-a|2|uuid-2" {
		t.Fatalf("user[1].Email = %q", users[1].Email)
	}
	if users[0].Account == nil {
		t.Fatal("expected populated Account")
	}
	if users[0].Level != 0 {
		t.Fatalf("expected Level 0, got %d", users[0].Level)
	}
}

func TestBuildUserEmptyInputReturnsEmptySlice(t *testing.T) {
	users := buildUser("tag", nil, "")
	if len(users) != 0 {
		t.Fatalf("expected empty slice, got %d", len(users))
	}
}
