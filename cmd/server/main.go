package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	_ "github.com/GoAsyncFunc/server-vless/internal/pkg/dep"
)

const (
	Name      = "vless-node"
	CopyRight = "GoAsyncFunc@2025"
)

// Version is injected at build time via -ldflags "-X main.Version=...".
// Kept in package main so the linker flag resolves; referenced by
// version.go (printVersion) and node.go (runVlessNode populates config.Version).
var Version = "dev"

func main() {
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Println(versionLine(c.App.Name, c.App.Version))
	}

	app := &cli.App{
		Name:      Name,
		Version:   Version,
		Copyright: CopyRight,
		Usage:     "Provide VLESS service for V2Board",
		Flags:     appFlags(),
		Before:    setupLogger,
		Action:    runVlessNode,
		Commands:  []*cli.Command{versionCommand},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
