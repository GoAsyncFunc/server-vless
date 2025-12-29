package server

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/GoAsyncFunc/server-vless/internal/pkg/dispatcher"
	"github.com/GoAsyncFunc/server-vless/internal/pkg/service"
	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

type Config struct {
	LogLevel string
}

const (
	LogLevelDebug    = "debug"
	LogLevelInfo     = "info"
	LogLevelError    = "error"
	DefaultDataDir   = "/var/lib/vless-node"
	DefaultDNSServer = "8.8.8.8"
)

type Server struct {
	instance      *core.Instance
	logLevel      string
	serviceConfig *service.Config
	apiClient     *api.Client
	config        *Config
	extConfBytes  []byte
	service       *service.Builder
	mu            sync.Mutex
	dataDir       string
	ctx           context.Context
	cancel        context.CancelFunc
}

func New(config *Config, apiConfig *api.Config, serviceConfig *service.Config, extConfBytes []byte, dataDir string) (*Server, error) {
	// API Client initialization
	client := api.New(apiConfig)
	if dataDir == "" {
		// dataDir = DefaultDataDir // DefaultDataDir not defined? Use literal or invalid
		dataDir = "/var/lib/vless-node"
	}
	return &Server{
		config:        config,
		logLevel:      config.LogLevel,
		apiClient:     client,
		serviceConfig: serviceConfig,
		extConfBytes:  extConfBytes,
		dataDir:       dataDir,
	}, nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Configure logrus level
	if lvl, err := log.ParseLevel(s.config.LogLevel); err == nil {
		log.SetLevel(lvl)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	log.Infoln("server start")

	// Create context with cancel for lifecycle management
	s.ctx, s.cancel = context.WithCancel(context.Background())
	ctx := s.ctx

	// Fetch node config
	// uniproxy Client stores NodeID/Type internally, so we just call GetNodeInfo(ctx)
	nodeConfig, err := s.apiClient.GetNodeInfo(ctx)
	if err != nil {
		return fmt.Errorf("get node info error: %s", err)
	}
	// If uniproxy returns nil (Not Modified) on first call?
	// Usually first call should return data if client is fresh.
	// But check nil safety.
	if nodeConfig == nil {
		return fmt.Errorf("node info is empty (or 304 Not Modified on first start)")
	}

	// Update serviceConfig NodeID if needed (though client has it)
	s.serviceConfig.NodeID = nodeConfig.Id

	// Registration: uniproxy implementation seems to not imply explicit Register call.
	// We proceed to build services.

	inboundHandlerConfig, err := service.InboundBuilder(s.serviceConfig, nodeConfig)
	if err != nil {
		return fmt.Errorf("build inbound config error: %s", err)
	}

	outboundHandlerConfig, err := service.OutboundBuilder(s.serviceConfig, nodeConfig, s.extConfBytes)
	if err != nil {
		return fmt.Errorf("build outbound config error: %s", err)
	}

	pbConfig, err := s.loadCore(inboundHandlerConfig, outboundHandlerConfig)
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

func (s *Server) loadCore(inboundConfig *core.InboundHandlerConfig, outboundConfig *core.OutboundHandlerConfig) (*core.Config, error) {
	logConfig := &conf.LogConfig{}
	logConfig.LogLevel = s.config.LogLevel
	logConfig.DNSLog = false // match server-vless1 default
	if s.config.LogLevel != LogLevelDebug {
		logConfig.AccessLog = "none"
		logConfig.ErrorLog = "none"
	}
	pbLogConfig := logConfig.Build()

	inboundConfigs := []*core.InboundHandlerConfig{inboundConfig}
	outBoundConfigs := []*core.OutboundHandlerConfig{outboundConfig}

	// PolicyConfig
	policyConfig := &conf.PolicyConfig{}
	pbPolicy := &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
	}
	policyConfig.Levels = map[uint32]*conf.Policy{0: pbPolicy}
	pbPolicyConfig, _ := policyConfig.Build()

	// Public DNS - Use Google DNS (8.8.8.8) directly via protobuf
	// This enables domainStrategy: UseIPv4 in inbound/outbound to fix IPv6 hangs.
	pbDnsConfig := &dns.Config{
		NameServer: []*dns.NameServer{
			{
				Address: &net.Endpoint{
					Address: &net.IPOrDomain{
						Address: &net.IPOrDomain_Ip{
							Ip: net.ParseIP(DefaultDNSServer),
						},
					},
					Network: net.Network_UDP,
				},
			},
		},
	}

	// Routing config
	routerConfig := &conf.RouterConfig{}
	pbRouteConfig, _ := routerConfig.Build()

	pbCoreConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(pbLogConfig),
			serial.ToTypedMessage(pbPolicyConfig),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&dispatcher.Config{}), // Custom dispatcher
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

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Cancel context to stop all sub-services
	if s.cancel != nil {
		s.cancel()
	}

	if s.service != nil {
		err := s.service.Close()
		if err != nil {
			log.Errorf("server close failed: %s", err)
		}
	}
	log.Infoln("server close")
}
