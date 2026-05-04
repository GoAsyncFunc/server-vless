package main

import (
	"fmt"

	cli "github.com/urfave/cli/v2"
	"github.com/xtls/xray-core/core"
)

// versionCommand implements the `vless-node version` subcommand.
// Kept in its own file so additional subcommands (e.g. validate, health)
// can follow the same per-file pattern.
var versionCommand = &cli.Command{
	Name:    "version",
	Aliases: []string{"v"},
	Usage:   "Show version information",
	Action:  printVersion,
}

// versionLine returns the canonical "<app> version <ver> xray.version=<core>"
// string. Both cli.VersionPrinter (the --version flag handler in main.go) and
// printVersion (the `version` subcommand) format their output through this
// helper so the two paths stay byte-identical.
func versionLine(appName, appVersion string) string {
	return fmt.Sprintf("%s version %s xray.version=%s", appName, appVersion, core.Version())
}

func printVersion(_ *cli.Context) error {
	fmt.Println(versionLine(Name, Version))
	return nil
}
