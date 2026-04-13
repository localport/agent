package main

import (
	"fmt"
	"os"

	"github.com/localport/agent/internal/cli"
)

// Populated via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	app := cli.New(version, commit, date)
	if err := app.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
