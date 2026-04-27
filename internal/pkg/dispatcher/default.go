package dispatcher

import (
	"context"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/juju/ratelimit"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/bittorrent"
	"github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/protocol/quic"
	protocoltls "github.com/xtls/xray-core/common/protocol/tls"
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

var errSniffingTimeout = errors.New("timeout on sniffing")

type cachedReader struct {
	sync.Mutex
	reader buf.TimeoutReader
	cache  buf.MultiBuffer
}

func (r *cachedReader) Cache(b *buf.Buffer, deadline time.Duration) error {
	mb, err := r.reader.ReadMultiBufferTimeout(deadline)
	if err != nil {
		return err
	}
	r.Lock()
	if !mb.IsEmpty() {
		r.cache, _ = buf.MergeMulti(r.cache, mb)
	}
	b.Clear()
	rawBytes := b.Extend(min(r.cache.Len(), b.Cap()))
	n := r.cache.Copy(rawBytes)
	b.Resize(0, int32(n))
	r.Unlock()
	return nil
}

func (r *cachedReader) readInternal() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()
	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb
	}
	return nil
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if mb := r.readInternal(); mb != nil {
		return mb, nil
	}
	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	if mb := r.readInternal(); mb != nil {
		return mb, nil
	}
	return r.reader.ReadMultiBufferTimeout(timeout)
}

func (r *cachedReader) Interrupt() {
	r.Lock()
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	r.Unlock()
	common.Interrupt(r.reader)
}

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

type SniffResult interface {
	Protocol() string
	Domain() string
}

type protocolSniffer func(context.Context, []byte) (SniffResult, error)

type protocolSnifferWithNetwork struct {
	protocolSniffer protocolSniffer
	network         net.Network
}

type Sniffer struct {
	sniffers []protocolSnifferWithNetwork
}

func NewSniffer() *Sniffer {
	return &Sniffer{sniffers: []protocolSnifferWithNetwork{
		{func(c context.Context, b []byte) (SniffResult, error) { return http.SniffHTTP(b, c) }, net.Network_TCP},
		{func(_ context.Context, b []byte) (SniffResult, error) { return protocoltls.SniffTLS(b) }, net.Network_TCP},
		{func(_ context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffBittorrent(b) }, net.Network_TCP},
		{func(_ context.Context, b []byte) (SniffResult, error) { return quic.SniffQUIC(b) }, net.Network_UDP},
		{func(_ context.Context, b []byte) (SniffResult, error) { return bittorrent.SniffUTP(b) }, net.Network_UDP},
	}}
}

var errUnknownContent = errors.New("unknown content")

func (s *Sniffer) Sniff(c context.Context, payload []byte, network net.Network) (SniffResult, error) {
	var pendingSniffers []protocolSnifferWithNetwork
	for _, si := range s.sniffers {
		if si.network != network {
			continue
		}
		result, err := si.protocolSniffer(c, payload)
		if err == common.ErrNoClue {
			pendingSniffers = append(pendingSniffers, si)
			continue
		}
		if err == protocol.ErrProtoNeedMoreData {
			s.sniffers = []protocolSnifferWithNetwork{si}
			return nil, err
		}
		if err == nil && result != nil {
			return result, nil
		}
	}
	if len(pendingSniffers) > 0 {
		s.sniffers = pendingSniffers
		return nil, common.ErrNoClue
	}
	return nil, errUnknownContent
}

func ensureTimeoutReader(reader buf.Reader) buf.TimeoutReader {
	if timeoutReader, ok := reader.(buf.TimeoutReader); ok {
		return timeoutReader
	}
	return &buf.TimeoutWrapperReader{Reader: reader}
}

func (d *DefaultDispatcher) shouldOverride(result SniffResult, request session.SniffingRequest, destination net.Destination) bool {
	domain := result.Domain()
	if domain == "" {
		return false
	}
	if request.ExcludeForDomain != nil && request.ExcludeForDomain.MatchAny(strings.ToLower(domain)) {
		return false
	}
	if request.ExcludeForIP != nil && destination.Address.Family().IsIP() && request.ExcludeForIP.Match(destination.Address.IP()) {
		return false
	}
	protocolString := result.Protocol()
	for _, p := range request.OverrideDestinationForProtocol {
		if protocolString == p {
			return true
		}
	}
	return false
}

func sniffer(ctx context.Context, cReader *cachedReader, metadataOnly bool, network net.Network) (SniffResult, error) {
	if metadataOnly {
		return nil, common.ErrNoClue
	}

	payload := buf.NewWithSize(32767)
	defer payload.Release()

	sniffer := NewSniffer()

	cacheDeadline := 200 * time.Millisecond
	totalAttempt := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			start := time.Now()
			err := cReader.Cache(payload, cacheDeadline)
			if err != nil {
				return nil, err
			}
			cacheDeadline -= time.Since(start)

			if !payload.IsEmpty() {
				result, err := sniffer.Sniff(ctx, payload.Bytes(), network)
				switch err {
				case common.ErrNoClue:
					totalAttempt++
				case protocol.ErrProtoNeedMoreData:
				default:
					return result, err
				}
			} else {
				totalAttempt++
			}
			if totalAttempt >= 2 || cacheDeadline <= 0 {
				return nil, errSniffingTimeout
			}
		}
	}
}

func (d *DefaultDispatcher) sniffDestination(ctx context.Context, reader buf.Reader, destination net.Destination, ob *session.Outbound, content *session.Content) (buf.Reader, net.Destination) {
	// This dispatcher only does payload sniffing; metadata-only/FakeDNS is intentionally not handled here.
	sniffingRequest := content.SniffingRequest
	if !sniffingRequest.Enabled || sniffingRequest.MetadataOnly {
		return reader, destination
	}
	cReader := &cachedReader{reader: ensureTimeoutReader(reader)}
	result, err := sniffer(ctx, cReader, false, destination.Network)
	if err == nil {
		content.Protocol = result.Protocol()
	}
	if err == nil && d.shouldOverride(result, sniffingRequest, destination) {
		destination.Address = net.ParseAddress(result.Domain())
		if sniffingRequest.RouteOnly {
			ob.RouteTarget = destination
		} else {
			ob.Target = destination
		}
	}
	return cReader, destination
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

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errors.LogError(ctx, "CustomDispatcher: panic in routedDispatch: ",
					r, "\n", string(debug.Stack()))
				common.Close(outbound.Writer)
				common.Interrupt(outbound.Reader)
			}
		}()
		outbound.Reader, destination = d.sniffDestination(ctx, outbound.Reader, destination, ob, content)
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
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}

	d.wrapDispatchLink(ctx, outbound)
	outbound.Reader, destination = d.sniffDestination(ctx, outbound.Reader, destination, ob, content)

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
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]

	var handler outbound.Handler

	routingLink := routing_session.AsRoutingContext(ctx)
	inTag := routingLink.GetInboundTag()
	isPickRoute := 0

	if forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		if h := d.ohm.GetHandler(forcedOutboundTag); h != nil {
			isPickRoute = 1
			errors.LogInfo(ctx, "CustomDispatcher: taking platform initialized detour [", forcedOutboundTag, "] for [", destination, "]")
			handler = h
		} else {
			errors.LogError(ctx, "CustomDispatcher: non existing tag for platform initialized detour: ", forcedOutboundTag)
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
	} else if d.router != nil {
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

	ob.Tag = handler.Tag()
	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		if tag := handler.Tag(); tag != "" {
			if inTag == "" {
				accessMessage.Detour = tag
			} else if isPickRoute == 1 {
				accessMessage.Detour = inTag + " ==> " + tag
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
