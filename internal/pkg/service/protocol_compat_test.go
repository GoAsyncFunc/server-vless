package service

import (
	"encoding/json"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func TestTransportAliasesPreserveSettings(t *testing.T) {
	for _, tc := range []struct{ alias, canonical, settings string }{
		{"raw", "tcp", `{"acceptProxyProtocol":true}`},
		{"websocket", "ws", `{"path":"/not-default"}`},
		{"splithttp", "xhttp", `{"path":"/not-default","mode":"auto"}`},
		{"mkcp", "kcp", `{"mtu":1300,"header":{"type":"srtp"},"seed":"test"}`},
		{"GRPC", "grpc", `{"serviceName":"not-default"}`},
	} {
		t.Run(tc.alias, func(t *testing.T) {
			alias := &api.VlessNode{Network: tc.alias, NetworkSettings: json.RawMessage(tc.settings)}
			canonical := *alias
			canonical.Network = tc.canonical
			a, err := buildStreamConfig(alias, &api.NodeInfo{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			c, err := buildStreamConfig(&canonical, &api.NodeInfo{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			aj, _ := json.Marshal(a)
			cj, _ := json.Marshal(c)
			if string(aj) != string(cj) {
				t.Fatalf("alias silently lost settings: %s != %s", aj, cj)
			}
			if _, err = a.Build(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRealityFieldsPreserved(t *testing.T) {
	for _, host := range []string{"2001:db8::1", "[2001:db8::1]", "target.example"} {
		t.Run(host, func(t *testing.T) {
			v := &api.VlessNode{Network: "tcp", TlsSettings: api.TlsSettings{Dest: host, ServerPort: "8443", ServerName: "test.example", Mldsa65Seed: "test-seed"}}
			stream, err := buildStreamConfig(v, &api.NodeInfo{Security: api.Reality}, nil)
			if err != nil {
				t.Fatal(err)
			}
			r := stream.REALITYSettings
			if len(r.ShortIds) != 1 || r.ShortIds[0] != "" {
				t.Fatal("empty short ID not preserved")
			}
			if r.Mldsa65Seed != "test-seed" {
				t.Fatal("ML-DSA seed discarded")
			}
			var dest string
			if err = json.Unmarshal(r.Dest, &dest); err != nil {
				t.Fatal(err)
			}
			want := "[2001:db8::1]:8443"
			if host == "target.example" {
				want = "target.example:8443"
			}
			if dest != want {
				t.Fatalf("destination %q, want %q", dest, want)
			}
		})
	}
}
