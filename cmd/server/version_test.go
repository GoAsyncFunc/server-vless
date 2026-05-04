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

	if !strings.HasPrefix(out, "version=test-1.2.3 ") {
		t.Errorf("output %q does not start with injected version", out)
	}
	if !strings.Contains(out, "xray.version=") {
		t.Errorf("output %q missing xray.version field", out)
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
