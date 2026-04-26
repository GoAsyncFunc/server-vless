package dispatcher

import (
	"context"
	"runtime/debug"

	"github.com/juju/ratelimit"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	"github.com/GoAsyncFunc/server-vless/internal/pkg/limiter"
)

// DefaultDispatcher is a default implementation of Dispatcher.
type DefaultDispatcher struct {
	ohm    outbound.Manager
	router routing.Router
	policy policy.Manager
	stats  stats.Manager
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager) error {
			return d.Init(config.(*Config), om, router, pm, sm)
		}); err != nil {
			return nil, err
		}
		return d, nil
	}))
}

// Init initializes DefaultDispatcher.
func (d *DefaultDispatcher) Init(config *Config, om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager) error {
	d.ohm = om
	d.router = router
	d.policy = pm
	d.stats = sm
	return nil
}

// Type implements common.HasType.
func (*DefaultDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (*DefaultDispatcher) Close() error { return nil }

func (d *DefaultDispatcher) getLink(ctx context.Context) (*transport.Link, *transport.Link) {
	opt := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	d.wrapDispatchLinks(ctx, inboundLink, outboundLink)

	return inboundLink, outboundLink
}

func userFromContext(ctx context.Context) (*session.Inbound, *protocol.MemoryUser) {
	sessionInbound := session.InboundFromContext(ctx)
	if sessionInbound == nil {
		return nil, nil
	}
	return sessionInbound, sessionInbound.User
}

func (d *DefaultDispatcher) wrapDispatchLinks(ctx context.Context, inboundLink, outboundLink *transport.Link) {
	sessionInbound, user := userFromContext(ctx)
	if user == nil || user.Email == "" {
		return
	}

	p := d.policy.ForLevel(user.Level)
	bucket := limiter.Bucket(user.Email)
	if c := d.userCounter(user.Email, p.Stats.UserUplink, "uplink"); c != nil {
		inboundLink.Writer = &SizeStatWriter{Counter: c, Writer: inboundLink.Writer}
	}
	if c := d.userCounter(user.Email, p.Stats.UserDownlink, "downlink"); c != nil {
		outboundLink.Writer = &SizeStatWriter{Counter: c, Writer: outboundLink.Writer}
	}
	if bucket != nil {
		inboundLink.Writer = &RateLimitedWriter{Bucket: bucket, Writer: inboundLink.Writer}
		outboundLink.Writer = &RateLimitedWriter{Bucket: bucket, Writer: outboundLink.Writer}
	}
	d.trackUserOnline(ctx, sessionInbound, user.Email, p.Stats.UserOnline)
}

func (d *DefaultDispatcher) wrapDispatchLink(ctx context.Context, outbound *transport.Link) {
	sessionInbound, user := userFromContext(ctx)
	if user == nil || user.Email == "" {
		return
	}

	p := d.policy.ForLevel(user.Level)
	bucket := limiter.Bucket(user.Email)
	if c := d.userCounter(user.Email, p.Stats.UserUplink, "uplink"); c != nil {
		outbound.Reader = &SizeStatReader{Counter: c, Reader: outbound.Reader}
	}
	if c := d.userCounter(user.Email, p.Stats.UserDownlink, "downlink"); c != nil {
		outbound.Writer = &SizeStatWriter{Counter: c, Writer: outbound.Writer}
	}
	if bucket != nil {
		outbound.Reader = &RateLimitedReader{Bucket: bucket, Reader: outbound.Reader}
		outbound.Writer = &RateLimitedWriter{Bucket: bucket, Writer: outbound.Writer}
	}
	d.trackUserOnline(ctx, sessionInbound, user.Email, p.Stats.UserOnline)
}

func (d *DefaultDispatcher) userCounter(email string, enabled bool, direction string) stats.Counter {
	if !enabled {
		return nil
	}
	name := "user>>>" + email + ">>>traffic>>>" + direction
	c, _ := stats.GetOrRegisterCounter(d.stats, name)
	return c
}

func (d *DefaultDispatcher) trackUserOnline(ctx context.Context, sessionInbound *session.Inbound, email string, enabled bool) {
	if enabled && sessionInbound.Source.Address != nil {
		trackOnlineIP(ctx, d.stats, email, sessionInbound.Source.Address.String())
	}
}

func trackOnlineIP(ctx context.Context, sm stats.Manager, email, ip string) {
	name := "user>>>" + email + ">>>online"
	if om, _ := stats.GetOrRegisterOnlineMap(sm, name); om != nil {
		om.AddIP(ip)
		context.AfterFunc(ctx, func() { om.RemoveIP(ip) })
	}
}

// Dispatch implements routing.Dispatcher.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if !destination.IsValid() {
		panic("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}

	inbound, outbound := d.getLink(ctx)

	// Sniffing logic omitted in custom dispatcher for simplicity.
	// Rely on Inbound sniffing or routed directly.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errors.LogError(ctx, "CustomDispatcher: panic in routedDispatch: ",
					r, "\n", string(debug.Stack()))
				common.Close(outbound.Writer)
				common.Interrupt(outbound.Reader)
			}
		}()
		d.routedDispatch(ctx, outbound, destination)
	}()

	return inbound, nil
}

// DispatchLink implements routing.Dispatcher.
func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	if !destination.IsValid() {
		return errors.New("Dispatcher: Invalid destination.")
	}

	// Ensure Outbounds context exists and set valid Target for Freedom
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination

	d.wrapDispatchLink(ctx, outbound)

	// Direct route dispatch for Link (Synchronous)
	// Must NOT use goroutine here, otherwise the caller (Inbound) might cancel the context immediately.
	defer func() {
		if r := recover(); r != nil {
			errors.LogError(ctx, "CustomDispatcher: panic in DispatchLink routedDispatch: ",
				r, "\n", string(debug.Stack()))
			common.Close(outbound.Writer)
			common.Interrupt(outbound.Reader)
		}
	}()
	d.routedDispatch(ctx, outbound, destination)
	return nil
}

func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {
	var handler outbound.Handler

	routingLink := routing_session.AsRoutingContext(ctx)
	inTag := routingLink.GetInboundTag()
	isPickRoute := 0

	if d.router != nil {
		if route, err := d.router.PickRoute(routingLink); err == nil {
			outTag := route.GetOutboundTag()
			if h := d.ohm.GetHandler(outTag); h != nil {
				isPickRoute = 2
				errors.LogInfo(ctx, "CustomDispatcher: route rule [", route.GetRuleTag(), "] -> [", outTag, "] for [", destination, "]")
				handler = h
			} else {
				errors.LogWarning(ctx, "CustomDispatcher: non existing outTag: ", outTag)
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				return
			}
		} else {
			errors.LogInfo(ctx, "CustomDispatcher: default route for ", destination)
		}
	}

	if handler == nil {
		handler = d.ohm.GetDefaultHandler()
	}

	if handler == nil {
		errors.LogInfo(ctx, "CustomDispatcher: default outbound handler not exist")
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return
	}

	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		if tag := handler.Tag(); tag != "" {
			if inTag == "" {
				accessMessage.Detour = tag
			} else if isPickRoute == 2 {
				accessMessage.Detour = inTag + " -> " + tag
			} else {
				accessMessage.Detour = inTag + " >> " + tag
			}
		}
		log.Record(accessMessage)
	}

	handler.Dispatch(ctx, link)
}

// Stats Writer
type SizeStatWriter struct {
	Counter stats.Counter
	Writer  buf.Writer
}

func (w *SizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		return nil
	}

	w.Counter.Add(int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}

// Stats Reader
type SizeStatReader struct {
	Counter stats.Counter
	Reader  buf.Reader
}

func (r *SizeStatReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if !mb.IsEmpty() {
		r.Counter.Add(int64(mb.Len()))
	}
	return mb, err
}

func (r *SizeStatReader) Interrupt() {
	common.Interrupt(r.Reader)
}

// RateLimitedWriter wraps a buf.Writer with a token-bucket cap. Each byte
// written consumes one token. When the bucket is empty the call blocks
// (via bucket.Wait) until enough tokens refill, throttling the connection.
type RateLimitedWriter struct {
	Bucket *ratelimit.Bucket
	Writer buf.Writer
}

func (w *RateLimitedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if n := int64(mb.Len()); n > 0 {
		w.Bucket.Wait(n)
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *RateLimitedWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *RateLimitedWriter) Interrupt() {
	common.Interrupt(w.Writer)
}

// RateLimitedReader wraps a buf.Reader so the reading side also throttles.
// Used on DispatchLink's outbound.Reader (which delivers uplink bytes to
// the outbound handler).
type RateLimitedReader struct {
	Bucket *ratelimit.Bucket
	Reader buf.Reader
}

func (r *RateLimitedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if n := int64(mb.Len()); n > 0 {
		r.Bucket.Wait(n)
	}
	return mb, err
}

func (r *RateLimitedReader) Interrupt() {
	common.Interrupt(r.Reader)
}
