package main

import (
	"errors"
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
	// Called before any token is read. The process holds bearer credentials
	// for its lifetime, and a core dump or same-user debugger exposes them.
	security.HardenProcess()

	app := cli.New(version, commit, date)
	if err := app.Run(os.Args[1:]); err != nil {
		os.Exit(report(os.Stderr, err))
	}
}

// report prints err, its code included, and returns the exit status: a
// positive ExitError Code, else 1.
func report(w io.Writer, err error) int {
	fmt.Fprintln(w, "error:", err)
	var exitErr *service.ExitError
	if errors.As(err, &exitErr) && exitErr.Code > 0 {
		return exitErr.Code
	}
	return 1
}
