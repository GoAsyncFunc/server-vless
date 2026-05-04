package main

import (
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/GoAsyncFunc/server-vless/internal/app/server"
)

// snapshotLogger captures the global logrus and config state that setupLogger
// mutates, and restores it via t.Cleanup. Required because setupLogger reads
// the package-level config.LogLevel and writes to log.StandardLogger().
func snapshotLogger(t *testing.T) {
	t.Helper()
	prevLevel := log.GetLevel()
	prevFormatter := log.StandardLogger().Formatter
	prevReportCaller := log.StandardLogger().ReportCaller
	prevConfigLevel := config.LogLevel
	t.Cleanup(func() {
		log.SetLevel(prevLevel)
		log.SetFormatter(prevFormatter)
		log.SetReportCaller(prevReportCaller)
		config.LogLevel = prevConfigLevel
	})
}

func TestAppFlagsNamesAreUnique(t *testing.T) {
	flags := appFlags()
	if len(flags) == 0 {
		t.Fatal("appFlags() returned empty slice")
	}

	seen := make(map[string]struct{}, len(flags))
	for _, f := range flags {
		for _, name := range f.Names() {
			if _, dup := seen[name]; dup {
				t.Errorf("duplicate flag name %q", name)
			}
			seen[name] = struct{}{}
		}
	}
}

func TestAppFlagsEnvVarsAreUnique(t *testing.T) {
	type envVarLister interface {
		// urfave/cli v2 flag types expose GetEnvVars (added in v2.4.0).
		GetEnvVars() []string
	}

	flags := appFlags()
	seen := make(map[string]string, len(flags)) // env -> first flag name owning it
	for _, f := range flags {
		lister, ok := f.(envVarLister)
		if !ok {
			continue
		}
		owner := f.Names()[0]
		for _, env := range lister.GetEnvVars() {
			if prev, dup := seen[env]; dup {
				t.Errorf("env var %q claimed by both %q and %q", env, prev, owner)
			}
			seen[env] = owner
		}
	}
}

func TestAppFlagsRequiredSet(t *testing.T) {
	type requiredLister interface {
		// urfave/cli v2's RequiredFlag interface.
		IsRequired() bool
	}

	wantRequired := map[string]bool{
		"api":   true,
		"token": true,
		"node":  true,
	}

	flags := appFlags()
	got := make(map[string]bool, len(wantRequired))
	for _, f := range flags {
		name := f.Names()[0]
		if _, watch := wantRequired[name]; !watch {
			continue
		}
		req, ok := f.(requiredLister)
		if !ok {
			t.Errorf("flag %q does not expose IsRequired()", name)
			continue
		}
		got[name] = req.IsRequired()
	}

	for name, want := range wantRequired {
		if got[name] != want {
			t.Errorf("flag %q: Required=%v, want %v", name, got[name], want)
		}
	}
}

// TestDNSFlagBindsDirectlyToConfig is a regression guard for L3: the --dns
// flag's Destination must point at &config.DNSServers, not at a separate
// package-level holder requiring a manual copy in runVlessNode.
func TestDNSFlagBindsDirectlyToConfig(t *testing.T) {
	flags := appFlags()
	for _, f := range flags {
		sf, ok := f.(*cli.StringFlag)
		if !ok || sf.Name != "dns" {
			continue
		}
		if sf.Destination != &config.DNSServers {
			t.Fatalf("--dns Destination = %p, want &config.DNSServers (%p)", sf.Destination, &config.DNSServers)
		}
		return
	}
	t.Fatal("--dns flag not found in appFlags()")
}

func TestSetupLoggerLevels(t *testing.T) {
	snapshotLogger(t)

	cases := []struct {
		input     string
		wantLevel log.Level
	}{
		{server.LogLevelDebug, log.DebugLevel},
		{server.LogLevelInfo, log.InfoLevel},
		{server.LogLevelError, log.ErrorLevel},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			config.LogLevel = tc.input
			if err := setupLogger(nil); err != nil {
				t.Fatalf("setupLogger(%q) returned error: %v", tc.input, err)
			}
			if got := log.GetLevel(); got != tc.wantLevel {
				t.Errorf("log level after setupLogger(%q) = %v, want %v", tc.input, got, tc.wantLevel)
			}
		})
	}
}

func TestSetupLoggerDebugEnablesReportCaller(t *testing.T) {
	snapshotLogger(t)

	// Pre-condition: ensure ReportCaller is off so we can detect the flip.
	log.SetReportCaller(false)
	config.LogLevel = server.LogLevelDebug

	if err := setupLogger(nil); err != nil {
		t.Fatalf("setupLogger returned error: %v", err)
	}
	if !log.StandardLogger().ReportCaller {
		t.Error("debug level did not enable ReportCaller")
	}
}

func TestSetupLoggerRejectsUnknownLevel(t *testing.T) {
	snapshotLogger(t)
	config.LogLevel = "trace-not-supported"

	err := setupLogger(nil)
	if err == nil {
		t.Fatal("setupLogger accepted unknown log mode")
	}
	if !strings.Contains(err.Error(), "trace-not-supported") {
		t.Errorf("error message %q does not mention rejected value", err.Error())
	}
}
