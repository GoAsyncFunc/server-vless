package main

import (
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
	"github.com/xtls/xray-core/infra/conf"

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

// TestAppLevelRequiredFlagsAvoided is a regression guard for the version
// subcommand fix: no flag in appFlags() may set Required=true. urfave/cli v2
// enforces App.Required before any subcommand Action runs, so marking
// api/token/node as Required would block `vless-node version` from ever
// reaching printVersion. validateRequiredConfig() handles the check inside
// runVlessNode instead.
func TestAppLevelRequiredFlagsAvoided(t *testing.T) {
	type requiredLister interface {
		IsRequired() bool
	}

	flags := appFlags()
	for _, f := range flags {
		req, ok := f.(requiredLister)
		if !ok {
			continue
		}
		if req.IsRequired() {
			t.Errorf("flag %q is App-Required; would block `version` subcommand. Move the check into validateRequiredConfig.", f.Names()[0])
		}
	}
}

// snapshotAPIConfig saves and restores the apiConfig package var so
// validateRequiredConfig tests stay isolated.
func snapshotAPIConfig(t *testing.T) {
	t.Helper()
	prev := apiConfig
	t.Cleanup(func() { apiConfig = prev })
}

func TestValidateRequiredConfig(t *testing.T) {
	cases := []struct {
		name        string
		host        string
		key         string
		nodeID      int
		wantErr     bool
		wantMissing []string // substrings expected in error message
	}{
		{name: "all set", host: "https://api.example", key: "tok", nodeID: 1, wantErr: false},
		{name: "all missing", wantErr: true, wantMissing: []string{"api", "token", "node"}},
		{name: "missing api", key: "tok", nodeID: 1, wantErr: true, wantMissing: []string{"api"}},
		{name: "missing token", host: "h", nodeID: 1, wantErr: true, wantMissing: []string{"token"}},
		{name: "missing node", host: "h", key: "tok", wantErr: true, wantMissing: []string{"node"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshotAPIConfig(t)
			apiConfig.APIHost = tc.host
			apiConfig.Key = tc.key
			apiConfig.NodeID = tc.nodeID

			err := validateRequiredConfig()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				for _, want := range tc.wantMissing {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q missing expected substring %q", err.Error(), want)
					}
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
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

// fakeCloser counts Close() invocations for recoverPanic tests.
type fakeCloser struct{ closed int }

func (f *fakeCloser) Close() { f.closed++ }

func TestRecoverPanicCapturesPanic(t *testing.T) {
	snapshotLogger(t)

	var got error
	closer := &fakeCloser{}

	func() {
		defer recoverPanic(closer, &got)
		panic("boom-from-test")
	}()

	if got == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(got.Error(), "boom-from-test") {
		t.Errorf("error %q missing original panic value", got.Error())
	}
	if closer.closed != 1 {
		t.Errorf("closer.Close called %d times, want 1", closer.closed)
	}
}

func TestRecoverPanicNoPanicStillCloses(t *testing.T) {
	snapshotLogger(t)

	var got error
	closer := &fakeCloser{}

	func() {
		defer recoverPanic(closer, &got)
		// no panic
	}()

	if got != nil {
		t.Errorf("unexpected error: %v", got)
	}
	if closer.closed != 1 {
		t.Errorf("closer.Close called %d times, want 1", closer.closed)
	}
}

func TestRecoverPanicToleratesNilCloserAndErrPtr(t *testing.T) {
	snapshotLogger(t)

	// Should not segfault when called with nil dependencies after a panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("recoverPanic itself panicked: %v", r)
		}
	}()

	func() {
		defer recoverPanic(nil, nil)
		panic("nil-deps")
	}()
}

// acceptedDomainStrategies mirrors the values Xray's freedom outbound accepts
// (infra/conf/freedom.go, matched case-insensitively). The flag usage is the
// only place users learn them, and an unsupported value aborts startup, so the
// two are asserted against each other here.
var acceptedDomainStrategies = []string{
	"AsIs",
	"UseIP",
	"UseIPv4",
	"UseIPv6",
	"UseIPv4v6",
	"UseIPv6v4",
	"ForceIP",
	"ForceIPv4",
	"ForceIPv6",
	"ForceIPv4v6",
	"ForceIPv6v4",
}

// domainStrategyFlagUsage returns the usage text of the --domain_strategy flag.
func domainStrategyFlagUsage(t *testing.T) string {
	t.Helper()
	for _, f := range appFlags() {
		stringFlag, ok := f.(*cli.StringFlag)
		if !ok {
			continue
		}
		for _, name := range stringFlag.Names() {
			if name == "domain_strategy" {
				return stringFlag.Usage
			}
		}
	}
	t.Fatal("appFlags() has no domain_strategy flag")
	return ""
}

// TestDomainStrategyUsageMatchesXray is the regression guard for a usage string
// that advertised "UseIPv4v6v6", which Xray rejects: copying it out of --help
// made the node fail at startup with "unsupported domain strategy".
func TestDomainStrategyUsageMatchesXray(t *testing.T) {
	usage := domainStrategyFlagUsage(t)

	const marker = "One of "
	start := strings.Index(usage, marker)
	if start < 0 {
		t.Fatalf("usage %q does not list the accepted values after %q", usage, marker)
	}
	rest := usage[start+len(marker):]
	end := strings.Index(rest, ".")
	if end < 0 {
		t.Fatalf("usage %q does not terminate the value list with a period", usage)
	}
	listed := strings.Split(rest[:end], ", ")

	if len(listed) != len(acceptedDomainStrategies) {
		t.Errorf("usage lists %d values, want %d: %v", len(listed), len(acceptedDomainStrategies), listed)
	}
	want := make(map[string]struct{}, len(acceptedDomainStrategies))
	for _, s := range acceptedDomainStrategies {
		want[s] = struct{}{}
	}
	for _, s := range listed {
		if _, ok := want[s]; !ok {
			t.Errorf("usage advertises %q, which is not an accepted strategy", s)
		}
		delete(want, s)
	}
	for s := range want {
		t.Errorf("usage omits the accepted strategy %q", s)
	}

	// The list is only trustworthy if Xray still accepts every entry.
	for _, s := range acceptedDomainStrategies {
		if _, err := (&conf.FreedomConfig{TargetStrategy: s}).Build(); err != nil {
			t.Errorf("xray rejects %q: %v", s, err)
		}
	}
	if _, err := (&conf.FreedomConfig{TargetStrategy: "UseIPv4v6v6"}).Build(); err == nil {
		t.Error("xray accepted UseIPv4v6v6; the guard assumes it is invalid")
	}
}
