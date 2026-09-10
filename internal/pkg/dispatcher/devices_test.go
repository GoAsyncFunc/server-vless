package dispatcher

import (
	"context"
	"testing"

	"github.com/GoAsyncFunc/server-vless/internal/pkg/limiter"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

func TestDispatcherRejectsDeviceBeforeRouting(t *testing.T) {
	const email = "dispatcher-device-limit"
	defer limiter.RemoveDevices(email)
	limiter.SetDeviceLimit(email, 1)
	occupied, ok := limiter.AcquireDevice(email, "192.0.2.1")
	if !ok {
		t.Fatal("reserve first device")
	}
	defer occupied()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{User: &protocol.MemoryUser{Email: email}, Source: net.TCPDestination(net.ParseAddress("192.0.2.2"), 1234)})
	d := &DefaultDispatcher{}
	if link, err := d.Dispatch(ctx, net.TCPDestination(net.DomainAddress("example.com"), 80)); err == nil || link != nil {
		t.Fatal("device check must precede link creation/routing")
	}
	if err := d.DispatchLink(ctx, net.TCPDestination(net.DomainAddress("example.com"), 80), &transport.Link{}); err == nil {
		t.Fatal("DispatchLink bypassed device check")
	}
}
