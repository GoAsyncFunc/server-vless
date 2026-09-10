package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func TestEmptyHeartbeatDoesNotFollowRedirectOrLeakToken(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer target.Close()
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer panel.Close()
	c, err := NewPanelClient(&api.Config{APIHost: panel.URL, NodeID: 1, NodeType: "vless", Key: "secret-heartbeat-token"})
	if err != nil {
		t.Fatal(err)
	}
	err = c.ReportUserTraffic(context.Background(), nil)
	if err == nil || hit {
		t.Fatal("heartbeat must reject redirect")
	}
	if strings.Contains(err.Error(), "secret-heartbeat-token") {
		t.Fatal("token leaked")
	}
}
