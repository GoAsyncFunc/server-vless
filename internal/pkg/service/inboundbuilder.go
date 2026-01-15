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

	var (
		streamSetting *conf.StreamConfig
	)

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
		Enabled: true, // Enabled for Vision support
		// Default dest override options?
		// "http", "tls", "quic" -> Only "http", "tls" supported by current deps
		DestOverride: &conf.StringList{
			"http", "tls",
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
	if vlessInfo.Encryption != "" {
		switch vlessInfo.Encryption {
		case "mlkem768x25519plus": // Support for latest Xray encryption
			encSettings := vlessInfo.EncryptionSettings
			// Format: "mlkem768x25519plus.<mode>.<ticket>.<padding>.<private_key>"
			// If padding is empty, it is omitted? No, V2bX joins all parts?
			// V2bX code:
			// parts := []string{"mlkem768x25519plus", encSettings.Mode, encSettings.Ticket}
			// if encSettings.ServerPadding != "" { parts = append(parts, encSettings.ServerPadding) }
			// parts = append(parts, encSettings.PrivateKey)
			// decryption = strings.Join(parts, ".")

			// Note: strings package needed
			decryption = fmt.Sprintf("mlkem768x25519plus.%s.%s", encSettings.Mode, encSettings.Ticket)
			if encSettings.ServerPadding != "" {
				decryption += "." + encSettings.ServerPadding
			}
			decryption += "." + encSettings.PrivateKey
		default:
			// Unsupported encryption: log error but fallback to "none"?
			// Or return "none" if it's just "none"?
			if vlessInfo.Encryption == "none" {
				decryption = "none"
			} else {
				// Warn but don't crash, fallback to none
				// Or strict error? V2bX errors.
				// Let's stick to error ONLY if it's clearly a configured algo we don't support.
				// If "none", it's fine.
				return nil, fmt.Errorf("vless decryption method %s is not supported", vlessInfo.Encryption)
			}
		}
	}

	// Prepare Clients placeholders (users added dynamically, but we need empty array)
	clients := []json.RawMessage{}

	// Fallbacks
	type Fallback struct {
		Alpn string          `json:"alpn,omitempty"`
		Path string          `json:"path,omitempty"`
		Dest json.RawMessage `json:"dest"`
		Xver int             `json:"xver,omitempty"`
	}
	type VLESSSettings struct {
		Clients    []json.RawMessage `json:"clients"`
		Decryption string            `json:"decryption"`
		Fallbacks  []*Fallback       `json:"fallbacks,omitempty"`
	}

	settings := VLESSSettings{
		Clients:    clients,
		Decryption: decryption,
	}

	settingsBytes, _ := json.Marshal(settings)
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
		}
		if err != nil {
			return nil, err
		}
	} else if transportProtocol == "grpc" {
		streamSetting.GRPCSettings = &conf.GRPCConfig{}
	}

	// Security (TLS / Reality)
	// Security (TLS / Reality)
	tlsSettings := new(conf.TLSConfig)
	switch nodeInfo.Security {
	case 1: // TLS
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

		// Logic adapted from V2bX to ensure fallback to SNI if Dest is empty
		dest := vlessInfo.TlsSettings.Dest
		if dest == "" {
			dest = vlessInfo.TlsSettings.ServerName
		}

		fullDest := dest + ":" + vlessInfo.TlsSettings.ServerPort
		fullDestBytes, _ := json.Marshal(fullDest)
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
	if err := json.Unmarshal(vlessInfo.NetworkSettings, tcpConfig); err == nil {
		streamSetting.TCPSettings = tcpConfig
	}
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
