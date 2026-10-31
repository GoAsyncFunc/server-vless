package main

import (
	"flag"
	"io"
	"strings"
	"testing"

	cli "github.com/urfave/cli/v2"
)

// The flags used to carry their aliases inside Name, v1 style: "fetch_users_interval, fui".
// urfave/cli v2 cuts a Name at its first comma or space, so the long name
// survived and every short alias was silently dropped. Register each flag the
// way the real app does and look every advertised name up in the resulting
// flag set, so a name that is written down but not registered fails here.
func TestEveryFlagNameAndAliasIsRegistered(t *testing.T) {
	set := flag.NewFlagSet("vless-node", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	for _, f := range appFlags() {
		if err := f.Apply(set); err != nil {
			t.Fatalf("apply %v: %v", f.Names(), err)
		}
	}
	checked := 0
	for _, f := range appFlags() {
		for _, name := range f.Names() {
			checked++
			if strings.ContainsAny(name, ", ") {
				t.Errorf("flag name %q still carries a v1-style alias list", name)
			}
			if set.Lookup(name) == nil {
				t.Errorf("flag name %q is advertised but not registered", name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no flag names found; the guard checked nothing")
	}
}

// The short aliases are the ones that were lost; pin them by name so a
// refactor cannot drop them again without noticing.
func TestShortAliasesExist(t *testing.T) {
	want := map[string]string{
		"fui": "fetch-users-interval",
		"rti": "report-traffics-interval",
		"hbi": "heartbeat-interval",
		"cni": "check-node-interval",
		"ds":  "domain-strategy",
	}
	for _, f := range appFlags() {
		names := f.Names()
		for _, name := range names {
			if primary, ok := want[name]; ok {
				if names[0] != primary {
					t.Errorf("alias %q belongs to %q, want %q", name, names[0], primary)
				}
				delete(want, name)
			}
		}
	}
	for alias, primary := range want {
		t.Errorf("alias %q for %q is missing", alias, primary)
	}
}

var _ cli.Flag = (*cli.DurationFlag)(nil)
