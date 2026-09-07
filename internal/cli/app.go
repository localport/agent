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
	case "access":
		return runAccess(args[1:])
	case "connect":
		// Matched here so the old verb explains itself. Without this case it
		// falls through to the default branch below, which reads an unknown first
		// argument as a flat tunnel invocation and dies with "--local is required
		// for token-based tunnel mode". That message never mentions the rename.
		return fmt.Errorf(`"connect" is now "access": localport access <URL> -p <port>`)
	case "setup":
		return runSetup(args[1:])
	case "identity":
		return runIdentity(args[1:])
	case "login":
		return runLogin(args[1:])
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
  access    Reach a fleet device through your client certificate
  setup     Redeem a setup token so this MACHINE can reach locked tunnels
  login     Sign in as YOURSELF and get a short-lived certificate
  identity  List, renew and remove the credentials on this machine
  version   Print version and exit

Examples:
  # Expose a service running on localhost (protocol and port):
  localport http 3000 --token <token> --region eu
  localport tcp 11434 --token <token> --region eu

  # Expose a service on another host (LAN address or hostname):
  localport --token <token> --local 192.168.1.13:3000 --region eu
  localport --token <token> --local tcp://192.168.1.13:11434 --region eu

  # Run several tunnels at once from a config file:
  localport tunnel --config localport.yaml

  # Reach a fleet device with your client certificate:
  localport access https://gateway-warehouse.eu.localport.dev --pem client.pem -p 3001
  localport access tcp://db-warehouse.eu.localport.dev:5432 --pem db.pem -p 5432

  # Or set the machine up once and let the agent obtain and renew for you:
  localport setup <TOKEN>
  localport access https://gateway-warehouse.eu.localport.dev -p 3001

  # See what this machine holds:
  localport identity list
`)
}
