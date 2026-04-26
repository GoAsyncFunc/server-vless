package service

import (
	"encoding/json"
	"fmt"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// InboundBuilder builds Inbound config.
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo) (*core.InboundHandlerConfig, error) {
	// VLESS config from uniproxy NodeInfo
	if nodeInfo.Vless == nil {
		return nil, fmt.Errorf("node info missing VLESS config")
	}
	vlessInfo := nodeInfo.Vless

	inboundDetourConfig := &conf.InboundDetourConfig{}

	// Port
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: uint32(vlessInfo.ServerPort), To: uint32(vlessInfo.ServerPort)}},
	}
	inboundDetourConfig.PortList = portList

	// Tag (using vless_PORT format)
	inboundDetourConfig.Tag = fmt.Sprintf("vless_%d", vlessInfo.ServerPort)

	// Sniffing
	sniffingConfig := &conf.SniffingConfig{
		Enabled: true,
		DestOverride: conf.StringList{
			"http", "tls", "quic",
		},
	}
	inboundDetourConfig.SniffingConfig = sniffingConfig

	// Protocol
	inboundDetourConfig.Protocol = api.Vless

	// Stream Settings
	streamSetting, err := buildStreamConfig(vlessInfo, nodeInfo, config)
	if err != nil {
		return nil, err
	}
	inboundDetourConfig.StreamSetting = streamSetting

	// VLESS Encryption/Decryption
	decryption := "none"
	switch vlessInfo.Encryption {
	case "", "none":
		// decryption stays "none"
	case "mlkem768x25519plus":
		enc := vlessInfo.EncryptionSettings
		mode := enc.Mode
		if mode == "" {
			mode = "native"
		}
		ticket := enc.Ticket
		if ticket == "" {
			ticket = "0s"
		}
		decryption = fmt.Sprintf("mlkem768x25519plus.%s.%s", mode, ticket)
		if enc.ServerPadding != "" {
			decryption += "." + enc.ServerPadding
		}
		decryption += "." + enc.PrivateKey
	default:
		return nil, fmt.Errorf("vless decryption method %s is not supported", vlessInfo.Encryption)
	}

	clients := []json.RawMessage{}
	type VLESSSettings struct {
		Clients    []json.RawMessage `json:"clients"`
		Decryption string            `json:"decryption"`
	}
	settingsBytes, err := json.Marshal(VLESSSettings{
		Clients:    clients,
		Decryption: decryption,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal vless settings: %w", err)
	}
	settingsJSON := json.RawMessage(settingsBytes)
	inboundDetourConfig.Settings = &settingsJSON

	return inboundDetourConfig.Build()
}

func buildStreamConfig(vlessInfo *api.VlessNode, nodeInfo *api.NodeInfo, config *Config) (*conf.StreamConfig, error) {
	streamSetting := new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(vlessInfo.Network)
	streamSetting.Network = &transportProtocol

	if len(vlessInfo.NetworkSettings) > 0 {
		var err error
		switch transportProtocol {
		case "tcp":
			err = buildTCPConfig(streamSetting, vlessInfo)
		case "ws":
			err = buildWSConfig(streamSetting, vlessInfo)
		case "grpc":
			err = buildGRPCConfig(streamSetting, vlessInfo)
		case "xhttp":
			err = buildXHTTPConfig(streamSetting, vlessInfo)
		case "httpupgrade":
			err = buildHTTPUpgradeConfig(streamSetting, vlessInfo)
		case "kcp", "mkcp":
			err = buildKCPConfig(streamSetting, vlessInfo)
		}
		if err != nil {
			return nil, err
		}
	} else if transportProtocol == "grpc" {
		streamSetting.GRPCSettings = &conf.GRPCConfig{}
	}

	// Security (TLS / Reality)
	tlsSettings := new(conf.TLSConfig)
	switch nodeInfo.Security {
	case 1: // TLS
		if config == nil || config.Cert == nil {
			return nil, fmt.Errorf("tls cert config is required")
		}
		streamSetting.Security = "tls"
		tlsSettings.Certs = []*conf.TLSCertConfig{
			{
				CertFile: config.Cert.CertFile,
				KeyFile:  config.Cert.KeyFile,
			},
		}
		streamSetting.TLSSettings = tlsSettings
	case 2: // REALITY
		streamSetting.Security = "reality"
		realitySettings := new(conf.REALITYConfig)

		realitySettings.PrivateKey = vlessInfo.TlsSettings.PrivateKey
		if len(vlessInfo.TlsSettings.ShortId) > 0 {
			realitySettings.ShortIds = []string{vlessInfo.TlsSettings.ShortId}
		}
		realitySettings.ServerNames = []string{vlessInfo.TlsSettings.ServerName}

		dest := vlessInfo.TlsSettings.Dest
		if dest == "" {
			dest = vlessInfo.TlsSettings.ServerName
		}
		destPort := vlessInfo.TlsSettings.ServerPort
		if destPort == "" {
			destPort = "443"
		}

		fullDest := dest + ":" + destPort
		fullDestBytes, err := json.Marshal(fullDest)
		if err != nil {
			return nil, fmt.Errorf("marshal REALITY dest: %w", err)
		}
		realitySettings.Dest = json.RawMessage(fullDestBytes)

		xver := vlessInfo.TlsSettings.Xver
		if xver == 0 {
			xver = vlessInfo.RealityConfig.Xver
		}
		realitySettings.Xver = xver

		streamSetting.REALITYSettings = realitySettings
	default:
		streamSetting.Security = "none"
	}

	return streamSetting, nil
}

func buildTCPConfig(streamSetting *conf.StreamConfig, vlessInfo *api.VlessNode) error {
	tcpConfig := new(conf.TCPConfig)
	if err := json.Unmarshal(vlessInfo.NetworkSettings, tcpConfig); err != nil {
		return fmt.Errorf("unmarshal tcp config error: %w", err)
	}
	streamSetting.TCPSettings = tcpConfig
	return nil
}

func buildWSConfig(streamSetting *conf.StreamConfig, vlessInfo *api.VlessNode) error {
	wsConfig := new(conf.WebSocketConfig)
	if err := json.Unmarshal(vlessInfo.NetworkSettings, wsConfig); err != nil {
		return fmt.Errorf("unmarshal ws config error: %w", err)
	}
	streamSetting.WSSettings = wsConfig
	return nil
}

func buildGRPCConfig(streamSetting *conf.StreamConfig, vlessInfo *api.VlessNode) error {
	grpcConfig := new(conf.GRPCConfig)
	if err := json.Unmarshal(vlessInfo.NetworkSettings, grpcConfig); err != nil {
		return fmt.Errorf("unmarshal grpc config error: %w", err)
	}
	streamSetting.GRPCSettings = grpcConfig
	return nil
}

func buildXHTTPConfig(streamSetting *conf.StreamConfig, vlessInfo *api.VlessNode) error {
	xhttpConfig := new(conf.SplitHTTPConfig)
	if err := json.Unmarshal(vlessInfo.NetworkSettings, xhttpConfig); err != nil {
		return fmt.Errorf("unmarshal xhttp config error: %w", err)
	}
	streamSetting.XHTTPSettings = xhttpConfig
	return nil
}

func buildHTTPUpgradeConfig(streamSetting *conf.StreamConfig, vlessInfo *api.VlessNode) error {
	huConfig := new(conf.HttpUpgradeConfig)
	if err := json.Unmarshal(vlessInfo.NetworkSettings, huConfig); err != nil {
		return fmt.Errorf("unmarshal httpupgrade config error: %w", err)
	}
	streamSetting.HTTPUPGRADESettings = huConfig
	return nil
}

func buildKCPConfig(streamSetting *conf.StreamConfig, vlessInfo *api.VlessNode) error {
	kcpConfig := new(conf.KCPConfig)
	if err := json.Unmarshal(vlessInfo.NetworkSettings, kcpConfig); err != nil {
		return fmt.Errorf("unmarshal kcp config error: %w", err)
	}
	streamSetting.KCPSettings = kcpConfig
	return nil
}
