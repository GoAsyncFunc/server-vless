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
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
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

// roundTripperFunc adapts a function to http.RoundTripper so a test can install
// something other than *http.Transport as http.DefaultTransport.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestNewPanelClientRejectsNonTransportDefaultTransport pins the contract that
// NewPanelClient reports an unusable http.DefaultTransport instead of
// panicking on it. The variable is package-level, so any importer can replace
// it out from under the client.
//
// Two layers check it: the assertion in NewPanelClient, and uniproxy's
// constructor, which panicked on this until v0.1.2. The constructor runs first
// and now returns an error, so this test guards the user-visible behaviour
// rather than one particular check.
func TestNewPanelClientRejectsNonTransportDefaultTransport(t *testing.T) {
	config := func() *api.Config {
		return &api.Config{APIHost: "http://127.0.0.1:1", NodeID: 1, NodeType: "vless", Key: "k"}
	}

	// Control: the APISendIP path is otherwise healthy, so a later failure is
	// attributable to the replaced transport rather than to the config.
	if _, err := NewPanelClient(config()); err != nil {
		t.Fatalf("control: NewPanelClient failed with the default transport: %v", err)
	}

	prev := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, nil
	})
	t.Cleanup(func() { http.DefaultTransport = prev })

	_, err := NewPanelClient(config())
	if err == nil {
		t.Fatal("NewPanelClient accepted a non-*http.Transport DefaultTransport instead of reporting it")
	}
	if !strings.Contains(err.Error(), "http.DefaultTransport") {
		t.Errorf("error %q does not name http.DefaultTransport", err)
	}
}
