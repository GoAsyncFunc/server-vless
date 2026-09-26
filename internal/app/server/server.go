package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/GoAsyncFunc/server-vless/internal/pkg/dispatcher"
	"github.com/GoAsyncFunc/server-vless/internal/pkg/service"
	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

type Config struct {
	LogLevel   string
	DNSServers string // comma-separated
	AssetDir   string
	Version    string // set from main, used in startup banner
}

const (
	LogLevelDebug    = "debug"
	LogLevelInfo     = "info"
	LogLevelError    = "error"
	DefaultDNSServer = "8.8.8.8"
)

type Server struct {
	instance      *core.Instance
	serviceConfig *service.Config
	apiClient     *service.PanelClient
	config        *Config
	service       *service.Builder
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
}

func New(config *Config, apiConfig *api.Config, serviceConfig *service.Config) (*Server, error) {
	client, err := service.NewPanelClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("create panel API client: %w", err)
	}
	return &Server{
		config:        config,
		apiClient:     client,
		serviceConfig: serviceConfig,
	}, nil
}

// nodeInfoFetcher is the minimal panel-API surface used during startup. It is
// satisfied by *api.Client; tests substitute lightweight stubs.
type nodeInfoFetcher interface {
	GetNodeInfo(ctx context.Context) (*api.NodeInfo, error)
}

// initialNodeInfoBackoffs is the retry schedule fetchInitialNodeInfo walks
// before giving up. Declared as a package variable so tests can shorten it.
var initialNodeInfoBackoffs = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second}

// fetchInitialNodeInfo retries transient failures during startup (panel
// temporarily unreachable, 5xx etc.). Max ~30s total: 1s, 2s, 4s, 8s, 15s.
func fetchInitialNodeInfo(ctx context.Context, client nodeInfoFetcher) (*api.NodeInfo, error) {
	var lastErr error
	for i, wait := range append([]time.Duration{0}, initialNodeInfoBackoffs...) {
		if wait > 0 {
			log.Warnf("retry GetNodeInfo in %v (attempt %d): %v", wait, i, lastErr)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}
		info, err := client.GetNodeInfo(ctx)
		if err == nil {
			return info, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Infoln("server start")

	if err := applyAssetDir(s.config.AssetDir); err != nil {
		return err
	}
	if err := checkGeoIPAsset(); err != nil {
		return err
	}

	s.ctx, s.cancel = context.WithCancel(context.Background())
	ctx := s.ctx

	// On any error after resources are allocated, clean them up so we don't
	// leak an idle xray core or leftover goroutines. Cleared once Start fully
	// succeeds at the end of the function.
	success := false
	defer func() {
		if success {
			return
		}
		if s.service != nil {
			if err := s.service.Close(); err != nil {
				log.Errorf("service cleanup after failed start: %s", err)
				if errors.Is(err, service.ErrShutdownIncomplete) {
					return
				}
			}
			s.service = nil
		}
		if s.instance != nil {
			done := make(chan error, 1)
			go func() { done <- s.instance.Close() }()
			select {
			case err := <-done:
				if err != nil {
					log.Errorf("xray core cleanup after failed start: %s", err)
				}
			case <-time.After(closeTimeout):
				log.Errorf("xray core close timed out during failed-start cleanup")
			}
			s.instance = nil
		}
		if s.cancel != nil {
			s.cancel()
		}
	}()

	if s.serviceConfig.AllowPrivateOutbound {
		log.Warnln("allow-private-outbound is enabled; proxy users can reach private and loopback IP destinations from this server")
	}

	nodeConfig, err := fetchInitialNodeInfo(ctx, s.apiClient)
	if err != nil {
		return fmt.Errorf("get node info error: %w", err)
	}
	if nodeConfig == nil {
		return fmt.Errorf("node info is empty")
	}

	s.serviceConfig.NodeID = nodeConfig.Id

	inboundHandlerConfig, err := service.InboundBuilder(s.serviceConfig, nodeConfig)
	if err != nil {
		return fmt.Errorf("build inbound config error: %w", err)
	}

	outboundHandlerConfig, err := service.OutboundBuilder(s.serviceConfig, nodeConfig)
	if err != nil {
		return fmt.Errorf("build outbound config error: %w", annotateGeoAssetError(err))
	}

	pbConfig, err := s.loadCore(inboundHandlerConfig, outboundHandlerConfig, nodeConfig)
	if err != nil {
		return fmt.Errorf("load core config error: %w", annotateGeoAssetError(err))
	}

	instance, err := core.New(pbConfig)
	if err != nil {
		return fmt.Errorf("create core instance error: %w", err)
	}
	s.instance = instance

	if err := s.instance.Start(); err != nil {
		return fmt.Errorf("start core instance error: %w", err)
	}

	s.service = service.New(
		s.ctx,
		inboundHandlerConfig.Tag,
		s.instance,
		s.serviceConfig,
		nodeConfig,
		s.apiClient,
	)

	if err := s.service.Start(); err != nil {
		return fmt.Errorf("start service error: %w", err)
	}

	success = true
	printStartupBanner(s.config.Version, nodeConfig, len(s.service.Users()))
	return nil
}

func applyAssetDir(assetDir string) error {
	assetDir = strings.TrimSpace(assetDir)
	if assetDir == "" {
		return nil
	}
	if err := os.Setenv(platform.AssetLocation, assetDir); err != nil {
		return fmt.Errorf("set asset dir: %w", err)
	}
	return nil
}

const (
	geoIPAsset   = "geoip.dat"
	geoSiteAsset = "geosite.dat"
)

// checkGeoIPAsset fails fast when geoip.dat is unreadable.
//
// The direct egress always carries a "geoip:private" final rule, and Xray
// resolves that attribute by opening geoip.dat while building the outbound, so
// every start needs the file even when no route names a geoip code. Without
// this check the failure surfaces as a bare "failed to open geoip.dat" from
// deep inside config building, with no hint of where the file was expected.
//
// geosite.dat is not checked here: it is only read when a route or the panel
// DNS names a "geosite:" attribute, so requiring it unconditionally would break
// installs that never use one. A missing geosite.dat is reported by
// annotateGeoAssetError at the point Xray actually asks for it.
func checkGeoIPAsset() error {
	return checkGeoIPAssetAt(platform.GetAssetLocation(geoIPAsset))
}

// checkGeoIPAssetAt holds the checks for a path already resolved through
// platform.GetAssetLocation, so tests can exercise them without depending on
// whichever system asset directories happen to exist on the host.
func checkGeoIPAssetAt(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s is required but not readable at %s; place it next to the binary or point --asset-dir at the directory that holds it (release archives ship %s beside the binary): %w", geoIPAsset, path, geoIPAsset, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s at %s is not a regular file", geoIPAsset, path)
	}
	// os.Stat succeeds on a file the process cannot read, so probe a real open
	// the way Xray will.
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s at %s cannot be opened: %w", geoIPAsset, path, err)
	}
	return f.Close()
}

// annotateGeoAssetError appends a fix hint when err is Xray reporting a geo
// data file it could not open or a code it could not find in one. Both come out
// of config building with no mention of the asset directory, which leaves the
// operator guessing. Errors that do not concern a geo asset are returned as-is.
func annotateGeoAssetError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, name := range []string{geoIPAsset, geoSiteAsset} {
		var hint string
		switch {
		case strings.Contains(msg, "failed to open "+name):
			hint = fmt.Sprintf("install %s in the Xray asset directory, or point --asset-dir at the directory that holds it (release archives ship %s beside the binary)", name, name)
		case strings.Contains(msg, "failed to check code") && strings.Contains(msg, "from "+name):
			hint = fmt.Sprintf("the requested code is not present in %s; update the file or choose a code it provides", name)
		}
		if hint != "" {
			return fmt.Errorf("%w\n  hint: %s", err, hint)
		}
	}
	return err
}

func (s *Server) loadCore(inboundConfig *core.InboundHandlerConfig, outboundConfig *core.OutboundHandlerConfig, nodeInfo *api.NodeInfo) (*core.Config, error) {
	logConfig := &conf.LogConfig{}
	logConfig.LogLevel = s.config.LogLevel
	logConfig.DNSLog = false
	if s.config.LogLevel != LogLevelDebug {
		logConfig.AccessLog = "none"
		logConfig.ErrorLog = "none"
	}
	pbLogConfig := logConfig.Build()

	allowPrivateOutbound := s.serviceConfig != nil && s.serviceConfig.AllowPrivateOutbound
	routeConfig, err := buildRouteConfigWithPolicy(nodeInfo.Routes, nodeInfo.Rules, allowPrivateOutbound)
	if err != nil {
		return nil, err
	}

	inboundConfigs := []*core.InboundHandlerConfig{inboundConfig}
	outBoundConfigs := []*core.OutboundHandlerConfig{outboundConfig}
	if routeConfig.defaultOutbound != nil {
		outBoundConfigs[0] = routeConfig.defaultOutbound
	}
	if routeConfig.needsBlock {
		blockOutbound, err := (&conf.OutboundDetourConfig{
			Protocol: "blackhole",
			Tag:      "block",
		}).Build()
		if err != nil {
			return nil, fmt.Errorf("build block outbound: %w", err)
		}
		outBoundConfigs = append(outBoundConfigs, blockOutbound)
	}
	outBoundConfigs = append(outBoundConfigs, routeConfig.outbounds...)

	policyConfig := &conf.PolicyConfig{}
	pbPolicy := &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		StatsUserOnline:   true,
	}
	policyConfig.Levels = map[uint32]*conf.Policy{0: pbPolicy}
	pbPolicyConfig, err := policyConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("build policy config: %w", err)
	}

	pbDnsConfig, err := buildDNSConfig(s.config.DNSServers, nodeInfo.RawDNS)
	if err != nil {
		return nil, fmt.Errorf("build dns config: %w", err)
	}

	appMsgs := []*serial.TypedMessage{
		serial.ToTypedMessage(pbLogConfig),
		serial.ToTypedMessage(pbPolicyConfig),
		serial.ToTypedMessage(&stats.Config{}),
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(pbDnsConfig),
	}

	if routeConfig.router != nil {
		appMsgs = append(appMsgs, serial.ToTypedMessage(routeConfig.router))
	}

	pbCoreConfig := &core.Config{
		App:      appMsgs,
		Outbound: outBoundConfigs,
		Inbound:  inboundConfigs,
	}

	return pbCoreConfig, nil
}

// buildDNSConfig chooses DNS source in priority:
// 1) CLI --dns (comma-separated)
// 2) nodeInfo.RawDNS.DNSJson (v2board full DNS json)
// 3) nodeInfo.RawDNS.DNSMap  (v2board per-domain DNS)
// 4) default 8.8.8.8
func buildDNSConfig(cliDNS string, raw api.RawDNS) (*dns.Config, error) {
	if cliDNS = strings.TrimSpace(cliDNS); cliDNS != "" {
		return dnsFromList(strings.Split(cliDNS, ","))
	}
	if len(raw.DNSJson) != 0 {
		dc := &conf.DNSConfig{}
		if err := json.Unmarshal(raw.DNSJson, dc); err != nil {
			return nil, fmt.Errorf("parse DNSJson: %w", err)
		}
		return dc.Build()
	}
	if len(raw.DNSMap) != 0 {
		dc := &conf.DNSConfig{}
		servers := make([]any, 0, len(raw.DNSMap))
		for _, value := range raw.DNSMap {
			entry := value
			addr, _ := value["address"].(string)
			if strings.Contains(addr, ":") && !strings.Contains(addr, "/") {
				host, port, err := net.SplitHostPort(addr)
				if err == nil {
					if p, perr := strconv.ParseUint(port, 10, 16); perr == nil {
						// Copy before rewriting. raw.DNSMap is the panel
						// snapshot shared with the stored node info, so
						// mutating it in place would make the hot-reload
						// comparison see a permanent difference and force a
						// restart on every inbound change.
						entry = make(map[string]any, len(value)+1)
						for k, v := range value {
							entry[k] = v
						}
						entry["address"] = host
						entry["port"] = uint16(p)
					}
				}
			}
			servers = append(servers, entry)
		}
		// DNSConfig.Servers is []*NameServerConfig; we need to go through JSON round-trip.
		b, err := json.Marshal(map[string]any{"servers": servers})
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, dc); err != nil {
			return nil, err
		}
		return dc.Build()
	}
	return dnsFromList([]string{DefaultDNSServer})
}

func dnsFromList(servers []string) (*dns.Config, error) {
	cfg := &dns.Config{}
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ns, err := parseDNSServer(s)
		if err != nil {
			return nil, err
		}
		cfg.NameServer = append(cfg.NameServer, ns)
	}
	if len(cfg.NameServer) == 0 {
		return nil, fmt.Errorf("no valid DNS servers")
	}
	return cfg, nil
}

// parseDNSServer accepts:
//
//	1.1.1.1
//	1.1.1.1:53
//	udp://1.1.1.1
//	udp://1.1.1.1:53
//	tcp://1.1.1.1
//	tcp://1.1.1.1:53
//
// Default scheme is UDP and default port is 53.
func parseDNSServer(s string) (*dns.NameServer, error) {
	network := xnet.Network_UDP
	if strings.HasPrefix(s, "tcp://") {
		network = xnet.Network_TCP
		s = strings.TrimPrefix(s, "tcp://")
	} else if strings.HasPrefix(s, "udp://") {
		s = strings.TrimPrefix(s, "udp://")
	}

	host := s
	var port uint16 = 53
	if h, p, err := net.SplitHostPort(s); err == nil {
		host = h
		parsed, perr := strconv.ParseUint(p, 10, 16)
		if perr != nil {
			return nil, fmt.Errorf("invalid DNS port in %q: %w", s, perr)
		}
		port = uint16(parsed)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid DNS server: %q", s)
	}

	return &dns.NameServer{
		Address: &xnet.Endpoint{
			Address: &xnet.IPOrDomain{
				Address: &xnet.IPOrDomain_Ip{Ip: ip},
			},
			Port:    uint32(port),
			Network: network,
		},
	}, nil
}

type routeBuildResult struct {
	router          *router.Config
	outbounds       []*core.OutboundHandlerConfig
	needsBlock      bool
	defaultOutbound *core.OutboundHandlerConfig
}

func buildRouteConfig(routes []api.Route, legacy api.Rules) (*routeBuildResult, error) {
	return buildRouteConfigWithPolicy(routes, legacy, false)
}

func buildRouteConfigWithPolicy(routes []api.Route, legacy api.Rules, allowPrivateOutbound bool) (*routeBuildResult, error) {
	result := &routeBuildResult{}
	rc := &conf.RouterConfig{}
	seenTags := map[string]struct{}{"direct": {}, "block": {}}

	addRule := func(field string, values []string, outboundTag string) error {
		if len(values) == 0 {
			return nil
		}
		rule := map[string]any{
			"type":        "field",
			field:         values,
			"outboundTag": outboundTag,
		}
		if field == "port" {
			rule[field] = strings.Join(values, ",")
		}
		raw, err := json.Marshal(rule)
		if err != nil {
			return err
		}
		rc.RuleList = append(rc.RuleList, raw)
		return nil
	}

	if len(routes) == 0 {
		for _, re := range legacy.Regexp {
			re = strings.TrimSpace(re)
			if re == "" {
				continue
			}
			if err := addRule("domain", []string{"regexp:" + re}, "block"); err != nil {
				return nil, err
			}
			result.needsBlock = true
		}
		if protocols := api.TrimRouteValues(legacy.Protocol); len(protocols) > 0 {
			if err := addRule("protocol", protocols, "block"); err != nil {
				return nil, err
			}
			result.needsBlock = true
		}
	}

	for _, route := range routes {
		matches := route.Matches()
		switch route.Action {
		case api.RouteActionBlock:
			domains, protocols := api.SplitBlockRouteMatches(matches)
			if err := addRule("domain", domains, "block"); err != nil {
				return nil, err
			}
			if err := addRule("protocol", protocols, "block"); err != nil {
				return nil, err
			}
			if len(matches) > 0 {
				result.needsBlock = true
			}
		case api.RouteActionBlockIP:
			if err := addRule("ip", matches, "block"); err != nil {
				return nil, err
			}
			if len(matches) > 0 {
				result.needsBlock = true
			}
		case api.RouteActionBlockPort:
			if err := addRule("port", matches, "block"); err != nil {
				return nil, err
			}
			if len(matches) > 0 {
				result.needsBlock = true
			}
		case api.RouteActionProtocol:
			if err := addRule("protocol", matches, "block"); err != nil {
				return nil, err
			}
			if len(matches) > 0 {
				result.needsBlock = true
			}
		case api.RouteActionDNS:
			continue
		case api.RouteActionRoute, api.RouteActionRouteIP:
			if len(matches) == 0 {
				continue
			}
			outbound, tag, err := buildRouteOutbound(route, seenTags, allowPrivateOutbound)
			if err != nil {
				return nil, err
			}
			seenTags[tag] = struct{}{}
			result.outbounds = append(result.outbounds, outbound)
			field := "domain"
			if route.Action == api.RouteActionRouteIP {
				field = "ip"
			}
			if err := addRule(field, matches, tag); err != nil {
				return nil, err
			}
		case api.RouteActionDefaultOut:
			defaultSeenTags := copyStringSet(seenTags)
			delete(defaultSeenTags, "direct")
			if result.defaultOutbound != nil {
				delete(defaultSeenTags, result.defaultOutbound.Tag)
			}
			outbound, tag, err := buildRouteOutbound(route, defaultSeenTags, allowPrivateOutbound)
			if err != nil {
				return nil, err
			}
			if result.defaultOutbound != nil {
				delete(seenTags, result.defaultOutbound.Tag)
			}
			seenTags[tag] = struct{}{}
			result.defaultOutbound = outbound
		default:
			log.Warnf("skip unsupported route action %q", route.Action)
		}
	}

	if len(rc.RuleList) > 0 {
		routerConfig, err := rc.Build()
		if err != nil {
			return nil, err
		}
		result.router = routerConfig
	}
	return result, nil
}

func copyStringSet(values map[string]struct{}) map[string]struct{} {
	copied := make(map[string]struct{}, len(values))
	for value := range values {
		copied[value] = struct{}{}
	}
	return copied
}

func validateRouteOutboundPolicy(route api.Route, outbound conf.OutboundDetourConfig, allowPrivateOutbound bool) error {
	protocol := strings.ToLower(strings.TrimSpace(outbound.Protocol))
	if allowPrivateOutbound || (protocol != "freedom" && protocol != "direct") || outbound.Settings == nil {
		return nil
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(*outbound.Settings, &settings); err != nil {
		return fmt.Errorf("parse route %d outbound settings: %w", route.Id, err)
	}
	for key := range settings {
		normalizedKey := strings.ToLower(strings.ReplaceAll(key, "_", ""))
		if normalizedKey == "ipsblocked" || normalizedKey == "finalrules" {
			return fmt.Errorf("route %d freedom outbound ipsBlocked/finalRules cannot be set when private outbound is disabled", route.Id)
		}
	}
	return nil
}

// uncoveredOutboundReason reports why --allow-private-outbound does not restrict
// this outbound, or "" when it does. The flag only reaches freedom/direct
// outbounds and only looks at their settings, so two shapes slip past it, and
// an operator treating the flag as a fence around panel egress should hear
// about them at startup.
func uncoveredOutboundReason(outbound conf.OutboundDetourConfig) string {
	protocol := strings.ToLower(strings.TrimSpace(outbound.Protocol))
	if protocol != "freedom" && protocol != "direct" {
		return fmt.Sprintf("protocol %q is not freedom or direct, so the node dials wherever the panel points it", outbound.Protocol)
	}
	if outbound.StreamSetting != nil && outbound.StreamSetting.SocketSettings != nil &&
		strings.TrimSpace(outbound.StreamSetting.SocketSettings.DialerProxy) != "" {
		return "sockopt.dialerProxy is set, which makes Xray skip finalRules and its default private-IP rule"
	}
	return ""
}

func buildRouteOutbound(route api.Route, seenTags map[string]struct{}, allowPrivateOutbound bool) (*core.OutboundHandlerConfig, string, error) {
	if strings.TrimSpace(route.ActionValue) == "" {
		return nil, "", fmt.Errorf("route %d %s action_value is required", route.Id, route.Action)
	}
	var outbound conf.OutboundDetourConfig
	if err := json.Unmarshal([]byte(route.ActionValue), &outbound); err != nil {
		return nil, "", fmt.Errorf("parse route %d outbound: %w", route.Id, err)
	}
	if err := validateRouteOutboundPolicy(route, outbound, allowPrivateOutbound); err != nil {
		return nil, "", err
	}
	// Only worth saying while the flag is off: with it on the node has already
	// opted into private access, so scope is no longer the interesting part.
	if !allowPrivateOutbound {
		if reason := uncoveredOutboundReason(outbound); reason != "" {
			log.Warnf("route %d outbound is outside --allow-private-outbound's scope: %s", route.Id, reason)
		}
	}
	if outbound.Tag == "" {
		outbound.Tag = fmt.Sprintf("route_%d", route.Id)
	}
	if _, ok := seenTags[outbound.Tag]; ok {
		return nil, "", fmt.Errorf("route %d outbound tag %q conflicts with existing outbound", route.Id, outbound.Tag)
	}
	if allowPrivateOutbound {
		if err := service.ApplyPrivateOutboundOptIn(&outbound); err != nil {
			return nil, "", err
		}
	}
	built, err := outbound.Build()
	if err != nil {
		return nil, "", fmt.Errorf("build route %d outbound: %w", route.Id, err)
	}
	return built, outbound.Tag, nil
}

// closeTimeout caps the total wait when shutting down xray core.
const closeTimeout = 10 * time.Second

// printStartupBanner writes a one-line startup summary to stderr via fmt so it
// shows up in docker logs / journald regardless of --log_mode.
func printStartupBanner(version string, node *api.NodeInfo, userCount int) {
	printStartupBannerTo(os.Stderr, version, node, userCount)
}

// printStartupBannerTo is the testable form that takes an explicit writer.
func printStartupBannerTo(w io.Writer, version string, node *api.NodeInfo, userCount int) {
	security := "none"
	switch node.Security {
	case api.Tls:
		security = "tls"
	case api.Reality:
		security = "reality"
	}
	network := "tcp"
	port := 0
	if node.Vless != nil {
		if node.Vless.Network != "" {
			network = node.Vless.Network
		}
		port = node.Vless.ServerPort
	}
	fmt.Fprintf(w, "vless-node %s (xray %s) started: node=%d :%d %s/%s users=%d\n",
		version, core.Version(), node.Id, port, network, security, userCount)
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	if s.service != nil {
		if err := s.service.Close(); err != nil {
			log.Errorf("service close failed: %s", err)
			if errors.Is(err, service.ErrShutdownIncomplete) {
				log.Error("core left intact because a background task has not exited")
				return
			}
		}
	}

	if s.instance != nil {
		done := make(chan error, 1)
		go func() { done <- s.instance.Close() }()
		select {
		case err := <-done:
			if err != nil {
				log.Errorf("xray core close failed: %s", err)
			}
		case <-time.After(closeTimeout):
			log.Errorf("xray core close timed out after %v; giving up", closeTimeout)
		}
	}

	log.Infoln("server close")
}
