package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/localport/agent/internal/cli"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
)

// Populated via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Runs before any token is read: the process holds bearer credentials for
	// its lifetime, and a core dump or same-user debugger would expose them.
	security.HardenProcess()

	app := cli.New(version, commit, date)
	if err := app.Run(os.Args[1:]); err != nil {
		os.Exit(report(os.Stderr, app, err))
	}
}

// report prints err as the user sees it (cli.App.ErrorText), its codes
// included, and returns the exit status: a positive ExitError Code, else 1.
// -h has printed the usage already and exits 0.
func report(w io.Writer, app *cli.App, err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	fmt.Fprintln(w, "error:", app.ErrorText(err))
	var exitErr *service.ExitError
	if errors.As(err, &exitErr) && exitErr.Code > 0 {
		return exitErr.Code
	}
	return 1
}
