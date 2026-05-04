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

func printVersion(c *cli.Context) error {
	fmt.Printf("version=%s xray.version=%s\n", Version, core.Version())
	return nil
}
