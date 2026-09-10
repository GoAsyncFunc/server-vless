package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	appdispatcher "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func TestReloadRollback304TrafficAndIdlePush(t *testing.T) {
	var mu sync.Mutex
	oldPort := freePort(t)
	occupied, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	newPort := occupied.Addr().(*net.TCPAddr).Port
	desiredPort := oldPort
	config304 := 0
	user304 := 0
	pushes := []map[int][]int64{}
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			etag := fmt.Sprintf("\"%d\"", desiredPort)
			if r.Header.Get("If-None-Match") == etag {
				config304++
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", etag)
			fmt.Fprintf(w, `{"server_port":%d,"network":"tcp","tls":0,"encryption":"none"}`, desiredPort)
		case "/api/v1/server/UniProxy/user":
			if r.Header.Get("If-None-Match") == `"users"` {
				user304++
				w.WriteHeader(304)
				return
			}
			w.Header().Set("ETag", `"users"`)
			fmt.Fprint(w, `{"users":[{"id":1,"uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}]}`)
		case "/api/v1/server/UniProxy/push":
			var data map[int][]int64
			if e := json.NewDecoder(r.Body).Decode(&data); e != nil {
				t.Error(e)
			}
			pushes = append(pushes, data)
			fmt.Fprint(w, `{"data":true}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer panel.Close()
	client, err := NewPanelClient(&api.Config{APIHost: panel.URL, NodeID: 1, NodeType: "vless", Key: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	node, err := client.GetNodeInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	users, err := client.GetUserList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	ic, err := InboundBuilder(cfg, node)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(&core.Config{App: []*serial.TypedMessage{serial.ToTypedMessage(&appdispatcher.Config{}), serial.ToTypedMessage(&proxyman.InboundConfig{}), serial.ToTypedMessage(&proxyman.OutboundConfig{}), serial.ToTypedMessage(&appstats.Config{})}, Inbound: []*core.InboundHandlerConfig{ic}})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	b := New(ctx, ic.Tag, instance, cfg, node, client)
	defer b.cancel()
	b.userList = users
	if err = b.addNewUser(users); err != nil {
		t.Fatal(err)
	}
	count := func(tag string) int64 {
		h, e := instance.GetFeature(inbound.ManagerType()).(inbound.Manager).GetHandler(ctx, tag)
		if e != nil {
			t.Fatal(e)
		}
		return h.(proxy.GetInbound).GetInbound().(proxy.UserManager).GetUsersCount(ctx)
	}
	sm := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	email := buildUserEmail(ic.Tag, 1, users[0].Uuid)
	up, _ := sm.GetOrRegisterCounter("user>>>" + email + ">>>traffic>>>uplink")
	down, _ := sm.GetOrRegisterCounter("user>>>" + email + ">>>traffic>>>downlink")
	up.Add(123)
	down.Add(456)
	mu.Lock()
	desiredPort = newPort
	mu.Unlock()
	for range 2 {
		if err = b.checkNodeConfigMonitor(); err != nil {
			t.Fatal(err)
		}
		if count(ic.Tag) != 1 {
			t.Fatal("rollback lost users")
		}
		if err = b.fetchUsersMonitor(); err != nil {
			t.Fatal(err)
		}
		if count(ic.Tag) != 1 {
			t.Fatal("304 user refresh lost users")
		}
	}
	occupied.Close()
	if err = b.checkNodeConfigMonitor(); err != nil {
		t.Fatal(err)
	}
	if b.inboundTag == ic.Tag || count(b.inboundTag) != 1 {
		t.Fatal("304 did not retry desired config successfully")
	}
	// Old connection writers can still hold and increment the retired counters.
	up.Add(7)
	down.Add(9)
	for range 3 {
		if err = b.reportTrafficsMonitor(); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if config304 < 2 || user304 < 2 {
		t.Fatalf("missing real 304 coverage: %d %d", config304, user304)
	}
	if len(pushes) != 3 {
		t.Fatalf("push count %d, want traffic + 2 idle heartbeats", len(pushes))
	}
	if got := pushes[0][1]; len(got) != 2 || got[0] != 130 || got[1] != 465 {
		t.Fatalf("lost/duplicated retired traffic: %v", pushes)
	}
	if len(pushes[1]) != 0 || len(pushes[2]) != 0 {
		t.Fatalf("idle heartbeat must be empty object: %v", pushes)
	}
}
