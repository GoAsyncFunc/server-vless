package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn while os.Stdout is redirected to a pipe, returning
// whatever fn wrote. Used because printVersion writes via fmt.Printf and we
// have no injectable writer.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	prev := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = prev })

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		done <- sb.String()
	}()

	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("pipe writer close: %v", err)
	}
	return <-done
}

func TestPrintVersionFormat(t *testing.T) {
	prev := Version
	Version = "test-1.2.3"
	t.Cleanup(func() { Version = prev })

	out := captureStdout(t, func() {
		if err := printVersion(nil); err != nil {
			t.Fatalf("printVersion returned error: %v", err)
		}
	})

	wantPrefix := Name + " version test-1.2.3 "
	if !strings.HasPrefix(out, wantPrefix) {
		t.Errorf("output %q does not start with %q", out, wantPrefix)
	}
	if !strings.Contains(out, "xray.version=") {
		t.Errorf("output %q missing xray.version field", out)
	}
}

// TestVersionLineUnifiesFormat is the L2 regression guard: both --version
// (cli.VersionPrinter) and the `version` subcommand must emit the same
// canonical string. We assert the helper format directly so any future
// drift between the two callers is caught.
func TestVersionLineUnifiesFormat(t *testing.T) {
	got := versionLine("vless-node", "1.0.0")
	if !strings.HasPrefix(got, "vless-node version 1.0.0 xray.version=") {
		t.Errorf("versionLine = %q, want prefix %q", got, "vless-node version 1.0.0 xray.version=")
	}
}

func TestVersionCommandWiring(t *testing.T) {
	if versionCommand.Name != "version" {
		t.Errorf("versionCommand.Name = %q, want %q", versionCommand.Name, "version")
	}
	if len(versionCommand.Aliases) == 0 || versionCommand.Aliases[0] != "v" {
		t.Errorf("versionCommand.Aliases = %v, want [v]", versionCommand.Aliases)
	}
	if versionCommand.Action == nil {
		t.Error("versionCommand.Action is nil")
	}
}
