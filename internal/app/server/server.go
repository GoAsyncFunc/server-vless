package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
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
	apiClient     *api.Client
	config        *Config
	extConfBytes  []byte
	service       *service.Builder
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
}

func New(config *Config, apiConfig *api.Config, serviceConfig *service.Config, extConfBytes []byte) (*Server, error) {
	client := api.New(apiConfig)
	return &Server{
		config:        config,
		apiClient:     client,
		serviceConfig: serviceConfig,
		extConfBytes:  extConfBytes,
	}, nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if lvl, err := log.ParseLevel(s.config.LogLevel); err == nil {
		log.SetLevel(lvl)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	log.Infoln("server start")

	s.ctx, s.cancel = context.WithCancel(context.Background())
	ctx := s.ctx

	nodeConfig, err := s.apiClient.GetNodeInfo(ctx)
	if err != nil {
		return fmt.Errorf("get node info error: %s", err)
	}
	if nodeConfig == nil {
		return fmt.Errorf("node info is empty")
	}

	s.serviceConfig.NodeID = nodeConfig.Id

	inboundHandlerConfig, err := service.InboundBuilder(s.serviceConfig, nodeConfig)
	if err != nil {
		return fmt.Errorf("build inbound config error: %s", err)
	}

	outboundHandlerConfig, err := service.OutboundBuilder(s.serviceConfig, nodeConfig, s.extConfBytes)
	if err != nil {
		return fmt.Errorf("build outbound config error: %s", err)
	}

	pbConfig, err := s.loadCore(inboundHandlerConfig, outboundHandlerConfig, nodeConfig)
	if err != nil {
		return fmt.Errorf("load core config error: %s", err)
	}

	instance, err := core.New(pbConfig)
	if err != nil {
		return fmt.Errorf("create core instance error: %s", err)
	}
	s.instance = instance

	if err := s.instance.Start(); err != nil {
		return fmt.Errorf("start core instance error: %s", err)
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
		return fmt.Errorf("start service error: %s", err)
	}

	log.Infof("Server started")
	return nil
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

	blockOutbound, err := (&conf.OutboundDetourConfig{
		Protocol: "blackhole",
		Tag:      "block",
	}).Build()
	if err != nil {
		return nil, fmt.Errorf("build block outbound: %w", err)
	}
	inboundConfigs := []*core.InboundHandlerConfig{inboundConfig}
	outBoundConfigs := []*core.OutboundHandlerConfig{outboundConfig, blockOutbound}

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

	pbRouteConfig, err := buildRouterConfig(nodeInfo.Rules)
	if err != nil {
		return nil, fmt.Errorf("build router config: %w", err)
	}

	pbCoreConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(pbLogConfig),
			serial.ToTypedMessage(pbPolicyConfig),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(pbRouteConfig),
			serial.ToTypedMessage(pbDnsConfig),
		},
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
		dc := &conf.DNSConfig{Tag: "dns_inbound"}
		servers := []any{"1.1.1.1", "localhost"}
		for _, value := range raw.DNSMap {
			addr, _ := value["address"].(string)
			if strings.Contains(addr, ":") && !strings.Contains(addr, "/") {
				host, port, err := net.SplitHostPort(addr)
				if err == nil {
					if p, perr := strconv.ParseUint(port, 10, 16); perr == nil {
						value["address"] = host
						value["port"] = uint16(p)
					}
				}
			}
			servers = append(servers, value)
		}
		// DNSConfig.Servers is []*NameServerConfig; we need to go through JSON round-trip.
		b, err := json.Marshal(map[string]any{"servers": servers, "tag": "dns_inbound"})
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
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid DNS server: %q", s)
		}
		cfg.NameServer = append(cfg.NameServer, &dns.NameServer{
			Address: &xnet.Endpoint{
				Address: &xnet.IPOrDomain{
					Address: &xnet.IPOrDomain_Ip{Ip: ip},
				},
				Network: xnet.Network_UDP,
			},
		})
	}
	if len(cfg.NameServer) == 0 {
		return nil, fmt.Errorf("no valid DNS servers")
	}
	return cfg, nil
}

// buildRouterConfig turns v2board Rules into xray routing rules pointing to
// the "block" blackhole outbound.
func buildRouterConfig(rules api.Rules) (*router.Config, error) {
	rc := &conf.RouterConfig{}
	for _, re := range rules.Regexp {
		re = strings.TrimSpace(re)
		if re == "" {
			continue
		}
		raw, err := json.Marshal(map[string]any{
			"type":        "field",
			"domain":      []string{"regexp:" + re},
			"outboundTag": "block",
		})
		if err != nil {
			return nil, err
		}
		rc.RuleList = append(rc.RuleList, raw)
	}
	if len(rules.Protocol) > 0 {
		raw, err := json.Marshal(map[string]any{
			"type":        "field",
			"protocol":    rules.Protocol,
			"outboundTag": "block",
		})
		if err != nil {
			return nil, err
		}
		rc.RuleList = append(rc.RuleList, raw)
	}
	return rc.Build()
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
		}
	}

	if s.instance != nil {
		if err := s.instance.Close(); err != nil {
			log.Errorf("xray core close failed: %s", err)
		}
	}

	log.Infoln("server close")
}
