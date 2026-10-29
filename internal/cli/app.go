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
	case "connect":
		return runConnect(a.version, args[1:])
	case "run":
		return runRun(a.version, args[1:])
	case "service":
		return runService(args[1:])
	case "access":
		return runAccess(args[1:])
	case "tunnel":
		// Without this case the flat tunnel form would reject "tunnel" with a
		// missing --local error.
		return fmt.Errorf(`"tunnel" is now "connect": localport connect --config <file>`)
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
		// Anything else is the flat tunnel form.
		return runTunnel(a.version, args)
	}
}

func printMainUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: localport <command> [flags]

Commands:
  connect   Enrol this machine as a fleet device, or run a config file
  run       Run every device enrolled on this machine
  service   Install or remove the device service (service install|uninstall)
  access    Reach a fleet device's ports through your client certificate
  setup     Redeem a setup token so this MACHINE can reach fleet devices
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

  # Run several tunnels and devices from one config file:
  localport connect --config localport.yaml

  # Enrol this machine as a fleet device with the command the dashboard shows:
  sudo localport connect <join-token> --enable terminal,files --logins pi

  # A device serving another machine on this network (ports are set in the dashboard):
  sudo localport connect <join-token> --host 192.168.1.100 --allow-ports 502,80

  # Reach a device's ports with your client certificate:
  localport access plc-01-factory.ap.localport.dev -L 5020:502 -L 8080:80

  # Or set the machine up once and let the agent obtain and renew for you:
  localport setup <TOKEN>
  localport access plc-01-factory.ap.localport.dev -L 502

  # See what this machine holds:
  localport identity list
`)
}
