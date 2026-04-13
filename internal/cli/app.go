package cli

import (
	"fmt"
	"io"
	"os"
)

// App is the top-level CLI router. It dispatches `localport <command> …`
// invocations and also tolerates the legacy flat form for tunnel mode.
type App struct {
	version string
	commit  string
	date    string
	stderr  io.Writer
}

func New(version, commit, date string) *App {
	return &App{version: version, commit: commit, date: date, stderr: os.Stderr}
}

func (a *App) Run(args []string) error {
	if len(args) == 0 {
		return runTunnel(a.version, args)
	}
	switch args[0] {
	case "tunnel":
		return runTunnel(a.version, args[1:])
	case "connect":
		return runConnect(args[1:])
	case "version", "--version", "-version":
		fmt.Printf("localport %s (%s) built %s\n", a.version, a.commit, a.date)
		return nil
	case "help", "--help", "-h":
		printMainUsage(a.stderr)
		return nil
	default:
		// Legacy: anything that doesn't match a subcommand is treated as
		// a flat tunnel invocation so old scripts keep working.
		return runTunnel(a.version, args)
	}
}

func printMainUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: localport <command> [flags]

Commands:
  tunnel    Open tunnels to the Localport edge (default)
  connect   Forward a local port through an mTLS tunnel
  version   Print version and exit

Examples:
  localport tunnel --config localport.yaml
  localport tunnel --token <token> --local 127.0.0.1:3000 --region eu
  localport connect db.tunnel.localport.dev:5432 \
    -c client.crt -k client.key -ca mesh-ca.crt -p 5432
`)
}
