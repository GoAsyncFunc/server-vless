package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GoAsyncFunc/server-vless/internal/pkg/limiter"
	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func TestPanelDeviceCountsEnforceAdmission(t *testing.T) {
	calls := 0
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/server/UniProxy/alivelist" {
			t.Errorf("unexpected %s", r.URL.Path)
		}
		calls++
		fmt.Fprint(w, `{"alive":{"1":2}}`)
	}))
	defer panel.Close()
	c, e := NewPanelClient(&api.Config{APIHost: panel.URL, NodeID: 1, NodeType: "vless", Key: "test"})
	if e != nil {
		t.Fatal(e)
	}
	b := &Builder{apiClient: c, ctx: context.Background(), inboundTag: "vless_test", userList: []api.UserInfo{{Id: 1, Uuid: "test", DeviceLimit: 2}}}
	email := buildUserEmail(b.inboundTag, 1, "test")
	defer limiter.RemoveDevices(email)
	b.syncDeviceLimits()
	if calls != 1 {
		t.Fatal("did not query panel alive counts")
	}
	if _, ok := limiter.AcquireDevice(email, "192.0.2.10"); ok {
		t.Fatal("global limit was not enforced")
	}
	b.lastReportedIPs = map[int][]string{1: {"192.0.2.1"}}
	b.lastReportedAt = map[int]time.Time{1: time.Now()}
	b.syncDeviceLimits()
	release, ok := limiter.AcquireDevice(email, "192.0.2.10")
	if !ok {
		t.Fatal("fresh local report should receive credit")
	}
	release()
	b.lastReportedAt[1] = time.Now().Add(-localDeviceCreditTTL - time.Second)
	b.syncDeviceLimits()
	if _, ok := limiter.AcquireDevice(email, "192.0.2.10"); ok {
		t.Fatal("expired local report hid remote occupancy")
	}
	if len(b.lastReportedIPs) != 0 || len(b.lastReportedAt) != 0 {
		t.Fatal("expired metadata not removed")
	}
}
