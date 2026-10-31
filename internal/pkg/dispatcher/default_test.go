package dispatcher

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
)

func TestUserFromContext(t *testing.T) {
	user := &protocol.MemoryUser{Email: "user@example.com"}
	inbound := &session.Inbound{User: user}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	gotInbound, gotUser := userFromContext(ctx)
	if gotInbound != inbound {
		t.Fatalf("inbound = %p, want %p", gotInbound, inbound)
	}
	if gotUser != user {
		t.Fatalf("user = %p, want %p", gotUser, user)
	}
}

func TestUserFromContextMissingInbound(t *testing.T) {
	gotInbound, gotUser := userFromContext(context.Background())
	if gotInbound != nil || gotUser != nil {
		t.Fatalf("expected nil inbound and user, got inbound=%v user=%v", gotInbound, gotUser)
	}
}

func TestSniffDestinationRouteOnlyUsesSniffedDomainForRouting(t *testing.T) {
	d := &DefaultDispatcher{}
	ob := &session.Outbound{Target: net.TCPDestination(net.ParseAddress("203.0.113.1"), 443)}
	content := &session.Content{SniffingRequest: session.SniffingRequest{
		Enabled:                        true,
		RouteOnly:                      true,
		OverrideDestinationForProtocol: []string{"tls"},
	}}
	reader := &testTimeoutReader{mb: buf.MultiBuffer{buf.FromBytes(tlsClientHelloSNI("example.com"))}}

	wrapped, destination := d.sniffDestination(context.Background(), reader, ob.Target, ob, content)

	if wrapped == reader {
		t.Fatal("reader was not wrapped for sniffing")
	}
	if got, want := content.Protocol, "tls"; got != want {
		t.Fatalf("protocol = %q, want %q", got, want)
	}
	if got, want := ob.RouteTarget.Address.String(), "example.com"; got != want {
		t.Fatalf("route target = %q, want %q", got, want)
	}
	if got, want := ob.Target.Address.String(), "203.0.113.1"; got != want {
		t.Fatalf("target = %q, want %q", got, want)
	}
	if got, want := destination.Address.String(), "example.com"; got != want {
		t.Fatalf("destination = %q, want %q", got, want)
	}
}

func TestRoutedDispatchUsesForcedOutboundTag(t *testing.T) {
	defaultHandler := &testOutboundHandler{tag: "default"}
	forcedHandler := &testOutboundHandler{tag: "forced"}
	d := &DefaultDispatcher{ohm: testOutboundManager{
		defaultHandler: defaultHandler,
		handlers: map[string]outbound.Handler{
			"forced": forcedHandler,
		},
	}}
	ctx := session.SetForcedOutboundTagToContext(context.Background(), "forced")
	outbounds := []*session.Outbound{{}}
	ctx = session.ContextWithOutbounds(ctx, outbounds)
	link := &transport.Link{}

	d.routedDispatch(ctx, link, net.TCPDestination(net.DomainAddress("example.com"), 443))

	if defaultHandler.dispatched {
		t.Fatal("default outbound was dispatched")
	}
	if !forcedHandler.dispatched {
		t.Fatal("forced outbound was not dispatched")
	}
	if got, want := outbounds[0].Tag, "forced"; got != want {
		t.Fatalf("outbound tag = %q, want %q", got, want)
	}
}

type testOutboundManager struct {
	defaultHandler outbound.Handler
	handlers       map[string]outbound.Handler
}

func (m testOutboundManager) Type() interface{} { return outbound.ManagerType() }
func (m testOutboundManager) Start() error      { return nil }
func (m testOutboundManager) Close() error      { return nil }
func (m testOutboundManager) GetHandler(tag string) outbound.Handler {
	return m.handlers[tag]
}
func (m testOutboundManager) GetDefaultHandler() outbound.Handler { return m.defaultHandler }
func (m testOutboundManager) AddHandler(context.Context, outbound.Handler) error {
	return common.ErrNoClue
}

func (m testOutboundManager) RemoveHandler(context.Context, string) error {
	return common.ErrNoClue
}
func (m testOutboundManager) ListHandlers(context.Context) []outbound.Handler { return nil }

type testOutboundHandler struct {
	tag        string
	dispatched bool
}

func (h *testOutboundHandler) Type() interface{} { return (*outbound.Handler)(nil) }
func (h *testOutboundHandler) Start() error      { return nil }
func (h *testOutboundHandler) Close() error      { return nil }
func (h *testOutboundHandler) Tag() string       { return h.tag }
func (h *testOutboundHandler) Dispatch(context.Context, *transport.Link) {
	h.dispatched = true
}
func (h *testOutboundHandler) SenderSettings() *serial.TypedMessage { return nil }
func (h *testOutboundHandler) ProxySettings() *serial.TypedMessage  { return nil }

type testTimeoutReader struct {
	mb   buf.MultiBuffer
	read bool
}

func (r *testTimeoutReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.ReadMultiBufferTimeout(0)
}

func (r *testTimeoutReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	if r.read {
		return nil, common.ErrNoClue
	}
	r.read = true
	return r.mb, nil
}

func tlsClientHelloSNI(name string) []byte {
	serverName := []byte(name)
	serverNameList := append([]byte{0x00, byte(len(serverName) >> 8), byte(len(serverName))}, serverName...)
	serverNameExt := append([]byte{0x00, 0x00, byte((len(serverNameList) + 2) >> 8), byte(len(serverNameList) + 2), byte(len(serverNameList) >> 8), byte(len(serverNameList))}, serverNameList...)
	handshakeBody := append([]byte{
		0x03, 0x03,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x00,
		0x00, 0x02, 0x13, 0x01,
		0x01, 0x00,
		byte(len(serverNameExt) >> 8), byte(len(serverNameExt)),
	}, serverNameExt...)
	handshakeLen := len(handshakeBody)
	handshake := append([]byte{0x01, byte(handshakeLen >> 16), byte(handshakeLen >> 8), byte(handshakeLen)}, handshakeBody...)
	recordLen := len(handshake)
	return append([]byte{0x16, 0x03, 0x01, byte(recordLen >> 8), byte(recordLen)}, handshake...)
}

// The HTTP sniffer names its protocol "http1" or "http2"; the inbound config
// says "http". Upstream matches the two by prefix. An exact comparison here
// meant plain-HTTP sessions kept their IP destination, so the panel's domain
// rules never saw them.
func TestSniffDestinationOverridesHTTP1ForHTTPConfig(t *testing.T) {
	d := &DefaultDispatcher{}
	ob := &session.Outbound{Target: net.TCPDestination(net.ParseAddress("203.0.113.1"), 80)}
	content := &session.Content{SniffingRequest: session.SniffingRequest{
		Enabled:                        true,
		OverrideDestinationForProtocol: []string{"http", "tls", "quic"},
	}}
	request := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n"
	reader := &testTimeoutReader{mb: buf.MultiBuffer{buf.FromBytes([]byte(request))}}

	_, destination := d.sniffDestination(context.Background(), reader, ob.Target, ob, content)

	if got, want := content.Protocol, "http1"; got != want {
		t.Fatalf("protocol = %q, want %q", got, want)
	}
	if got, want := destination.Address.String(), "example.com"; got != want {
		t.Fatalf("destination = %q, want the sniffed Host %q", got, want)
	}
	if got, want := ob.Target.Address.String(), "example.com"; got != want {
		t.Fatalf("target = %q, want %q", got, want)
	}
}

type fakeSniffResult struct{ protocol, domain string }

func (r fakeSniffResult) Protocol() string { return r.protocol }
func (r fakeSniffResult) Domain() string   { return r.domain }

func TestShouldOverrideMatchesProtocolByPrefixBothWays(t *testing.T) {
	d := &DefaultDispatcher{}
	dest := net.TCPDestination(net.ParseAddress("203.0.113.1"), 80)
	cases := []struct {
		sniffed    string
		configured []string
		want       bool
	}{
		{"http1", []string{"http"}, true},
		{"http2", []string{"http"}, true},
		{"http", []string{"http1"}, true},
		{"tls", []string{"tls"}, true},
		{"quic", []string{"http", "tls", "quic"}, true},
		{"http1", []string{"tls"}, false},
		{"bittorrent", []string{"http", "tls", "quic"}, false},
	}
	for _, c := range cases {
		req := session.SniffingRequest{Enabled: true, OverrideDestinationForProtocol: c.configured}
		if got := d.shouldOverride(fakeSniffResult{c.sniffed, "example.com"}, req, dest); got != c.want {
			t.Errorf("shouldOverride(%q, %v) = %v, want %v", c.sniffed, c.configured, got, c.want)
		}
	}
}
