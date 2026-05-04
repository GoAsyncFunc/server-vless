package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/GoAsyncFunc/server-vless/internal/app/server"
	"github.com/GoAsyncFunc/server-vless/internal/pkg/service"
	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

// Package-level config holders. cli.Flag.Destination requires stable addresses;
// promoting these from main()'s locals lets appFlags / setupLogger / runVlessNode
// be top-level functions without closure capture.
var (
	config        server.Config
	apiConfig     api.Config
	serviceConfig service.Config
	certConfig    service.CertConfig
)

// appFlags returns the full cli.Flag list for the vless-node binary. Each flag
// binds Destination to a field in the package-level config holders above.
func appFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "api",
			Usage:       "Server address",
			EnvVars:     []string{"API"},
			Destination: &apiConfig.APIHost,
		},
		&cli.StringFlag{
			Name:        "token",
			Usage:       "Token of server API",
			EnvVars:     []string{"TOKEN"},
			Destination: &apiConfig.Key,
		},
		&cli.StringFlag{
			Name:        "cert_file",
			Usage:       "Cert file",
			EnvVars:     []string{"CERT_FILE"},
			Value:       "/root/.cert/server.crt",
			Required:    false,
			DefaultText: "/root/.cert/server.crt",
			Destination: &certConfig.CertFile,
		},
		&cli.StringFlag{
			Name:        "key_file",
			Usage:       "Key file",
			EnvVars:     []string{"KEY_FILE"},
			Value:       "/root/.cert/server.key",
			Required:    false,
			DefaultText: "/root/.cert/server.key",
			Destination: &certConfig.KeyFile,
		},
		&cli.IntFlag{
			Name:        "node",
			Usage:       "Node ID",
			EnvVars:     []string{"NODE"},
			Destination: &apiConfig.NodeID,
		},
		&cli.DurationFlag{
			Name:        "fetch_users_interval, fui",
			Usage:       "API request cycle(fetch users), unit: second",
			EnvVars:     []string{"FETCH_USER_INTERVAL"},
			Value:       time.Second * 60,
			DefaultText: "60",
			Required:    false,
			Destination: &serviceConfig.FetchUsersInterval,
		},
		&cli.DurationFlag{
			Name:        "report_traffics_interval, rti",
			Usage:       "API request cycle(report traffics), unit: second",
			EnvVars:     []string{"REPORT_TRAFFICS_INTERVAL"},
			Value:       time.Second * 80,
			DefaultText: "80",
			Required:    false,
			Destination: &serviceConfig.ReportTrafficsInterval,
		},
		// HeartbeatInterval check.
		&cli.DurationFlag{
			Name:        "heartbeat_interval, hbi",
			Usage:       "API request cycle(heartbeat), unit: second",
			EnvVars:     []string{"HEARTBEAT_INTERVAL"},
			Value:       time.Second * 60,
			DefaultText: "60",
			Required:    false,
			Destination: &serviceConfig.HeartbeatInterval,
		},
		&cli.DurationFlag{
			Name:        "check_node_interval, cni",
			Usage:       "Node config change detection cycle. Defaults to fetch_users_interval when unset.",
			EnvVars:     []string{"CHECK_NODE_INTERVAL"},
			Required:    false,
			Destination: &serviceConfig.CheckNodeInterval,
		},
		&cli.StringFlag{
			Name:        "log_mode",
			Value:       server.LogLevelError,
			Usage:       "Log mode",
			EnvVars:     []string{"LOG_LEVEL"},
			Destination: &config.LogLevel,
			Required:    false,
		},
		&cli.StringFlag{
			Name:        "dns",
			Usage:       "Comma-separated DNS servers (overrides v2board routes DNS and default)",
			EnvVars:     []string{"DNS"},
			Destination: &config.DNSServers,
			Required:    false,
		},
		&cli.StringFlag{
			Name:        "asset-dir",
			Usage:       "Directory containing geoip.dat and geosite.dat",
			EnvVars:     []string{"ASSET_DIR", "SERVER_VLESS_ASSET_DIR"},
			Destination: &config.AssetDir,
			Required:    false,
		},
		&cli.BoolFlag{
			Name:        "disable_sniffing",
			Usage:       "Disable inbound sniffing for lower connection setup overhead when routing does not need it",
			EnvVars:     []string{"DISABLE_SNIFFING"},
			Destination: &serviceConfig.DisableSniffing,
			Required:    false,
		},
		&cli.BoolFlag{
			Name:        "allow-private-outbound",
			Usage:       "Security-sensitive: allow users to reach the server's private and loopback IP destinations through the default freedom outbound",
			EnvVars:     []string{"ALLOW_PRIVATE_OUTBOUND"},
			Destination: &serviceConfig.AllowPrivateOutbound,
			Required:    false,
		},
		&cli.StringFlag{
			Name:        "domain_strategy, ds",
			Usage:       "Freedom outbound domain strategy (AsIs|UseIP|UseIPv4v6|UseIPv6|UseIPv4v6v6)",
			EnvVars:     []string{"DOMAIN_STRATEGY"},
			Value:       "UseIPv4v6",
			DefaultText: "UseIPv4v6",
			Destination: &serviceConfig.DomainStrategy,
			Required:    false,
		},
	}
}

// setupLogger is the cli.App.Before hook. Configures logrus level from the
// resolved log_mode flag.
func setupLogger(_ *cli.Context) error {
	log.SetFormatter(&log.TextFormatter{})
	switch config.LogLevel {
	case server.LogLevelDebug:
		log.SetFormatter(&log.TextFormatter{
			FullTimestamp: true,
		})
		log.SetLevel(log.DebugLevel)
		log.SetReportCaller(true)
	case server.LogLevelInfo:
		log.SetLevel(log.InfoLevel)
	case server.LogLevelError:
		log.SetLevel(log.ErrorLevel)
	default:
		return fmt.Errorf("log mode %s not supported", config.LogLevel)
	}
	return nil
}

// validateRequiredConfig verifies the fields that must be supplied for the
// node binary to start. We do this manually instead of marking the cli flags
// `Required: true` so the `version` subcommand path is not blocked by missing
// daemon credentials (urfave/cli v2 enforces App.Required before subcommand
// Actions run).
func validateRequiredConfig() error {
	var missing []string
	if apiConfig.APIHost == "" {
		missing = append(missing, "api")
	}
	if apiConfig.Key == "" {
		missing = append(missing, "token")
	}
	if apiConfig.NodeID == 0 {
		missing = append(missing, "node")
	}
	if len(missing) > 0 {
		return fmt.Errorf("required flag(s) not set: %s", strings.Join(missing, ", "))
	}
	return nil
}

// runVlessNode is the cli.App.Action handler. Wires the parsed flag values into
// the server.Server, starts the daemon loops, and blocks until SIGINT/SIGTERM.
func runVlessNode(_ *cli.Context) error {
	if err := validateRequiredConfig(); err != nil {
		return err
	}

	serviceConfig.Cert = &certConfig

	// Ensure NodeType is set properly
	apiConfig.NodeType = api.Vless
	config.Version = Version

	serv, err := server.New(&config, &apiConfig, &serviceConfig)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}
	if err := serv.Start(); err != nil {
		serv.Close()
		return fmt.Errorf("failed to start server: %w", err)
	}

	defer func() {
		if e := recover(); e != nil {
			log.Errorf("panic: %v", e)
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			log.Errorf("stack trace:\n%s", buf[:n])
			serv.Close()
			os.Exit(1)
		} else {
			serv.Close()
		}
	}()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	<-osSignals
	return nil
}
