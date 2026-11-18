package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

// App is the top-level CLI router. It dispatches `localport <command> …`
// invocations and also accepts the flat tunnel form (`localport http 8080`).
type App struct {
	version string
	commit  string
	date    string
	stderr  io.Writer
}

func New(version, commit, date string) *App {
	return &App{version: version, commit: commit, date: date, stderr: os.Stderr}
}

// verbose is the global --verbose flag: user-facing errors print their full
// cause chain instead of errcode.Render's text.
var verbose bool

// userText is err as a one-shot command shows it: errcode.Render's text, or
// the full chain under --verbose.
func userText(err error) string {
	if verbose {
		return err.Error()
	}
	text, _ := errcode.Render(err)
	return text
}

// ErrorText is the final error of a command as main prints it: userText,
// and a pointer to --verbose when a cause was left out.
func (a *App) ErrorText(err error) string {
	if verbose {
		return err.Error()
	}
	text, hidden := errcode.Render(err)
	if hidden {
		text += "\n  run the command again with --verbose for the cause"
	}
	return text
}

// Run parses the global flags (--verbose), which come before the command,
// then runs the command.
func (a *App) Run(args []string) error {
	for len(args) > 0 && (args[0] == "--verbose" || args[0] == "-verbose") {
		verbose, args = true, args[1:]
	}
	if len(args) == 0 {
		return runTunnel(a.version, args)
	}
	if args[0] == agentChildCommand {
		return runAgentChild(a, args[1:])
	}
	if rootRunsAsAgent(args[0]) {
		switch args[0] {
		case "run":
			return runRunAsAgent(args, os.Stdin, os.Stdout)
		case "status":
			return runRootStatus(args)
		}
		return runAsAgentAccount(args, os.Stdin, os.Stdout)
	}
	switch args[0] {
	case "up":
		return runUp(a.version, args[1:])
	case "down":
		return runDown(args[1:])
	case "run":
		return runRun(a.version, args[1:])
	case "set":
		return runSet(args[1:])
	case "service":
		return runService(args[1:])
	case "system":
		// The Windows installer's internal steps; not in `localport help`.
		return runSystem(a.version, args[1:])
	case "status":
		return runStatus(args[1:])
	case "access":
		return runAccess(args[1:])
	case "ssh":
		return runSSH(args[1:])
	case "ssh-config":
		return runSSHConfig(args[1:])
	case "ssh-cert":
		return runSSHCert(args[1:])
	case "ssh-proxy":
		return runSSHProxy(args[1:])
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
		// Flags or a protocol start the flat tunnel form; any other word is
		// not a command.
		if !strings.HasPrefix(args[0], "-") && !isTunnelProto(args[0]) {
			remedy := "run localport help for the list"
			if args[0] == "connect" {
				remedy = "a device enrols with: localport up <join-token>"
			}
			return errcode.WithRemedy(errcode.New(errcode.UnknownCommand).With(nil, fmt.Sprintf("%q", security.SanitizeDisplay(args[0]))), remedy)
		}
		return runTunnel(a.version, args)
	}
}

func printMainUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: localport <command> [flags]

Commands:
  up        Enrol this machine as a fleet device, resume a paused one, or run a config file
  down      Pause an enrolled device until up
  run       Run every device enrolled on this machine
  set       Change what an enrolled device allows
  service   Install or remove the device service (service install|uninstall)
  status    Show the device service, and to root or the agent group the devices
  access    Reach a fleet device's ports through your client certificate
  ssh       Open an SSH session on a fleet device with the system ssh
  ssh-config  Print ssh_config lines so ssh, scp, sftp and rsync reach devices
  setup     Redeem a setup token so this MACHINE can reach fleet devices
  login     Sign in as YOURSELF and get a short-lived certificate
  identity  List, renew and remove the credentials on this machine
  version   Print version and exit

Global flags (before the command):
  --verbose  print an error's full cause, network and server detail included

Examples:
  # Expose a service running on localhost (protocol and port):
  localport http 3000 --token <token> --region eu
  localport tcp 11434 --token <token> --region eu

  # Expose a service on another host (LAN address or hostname):
  localport --token <token> --local 192.168.1.13:3000 --region eu
  localport --token <token> --local tcp://192.168.1.13:11434 --region eu

  # Run several tunnels from one config file:
  localport up --config localport.yaml

  # Enrol this machine as a fleet device with the command the dashboard shows%[2]s:
  %[1]s up <join-token> --enable terminal,files --logins pi

  # A device serving another machine on this network (ports are set in the dashboard)%[2]s:
  %[1]s up <join-token> --host 192.168.1.100 --allow-ports 502,80

  # Take a device offline until you bring it back%[2]s:
  %[1]s down
  %[1]s up

  # Reach a device's ports with your client certificate:
  localport access plc-01-factory.ap.localport.dev -L 5020:502 -L 8080:80

  # SSH to a device, or add it to ~/.ssh/config for scp, sftp and rsync:
  localport ssh pi@gw-01-factory.eu.localport.dev
  localport ssh-config gw-01-factory.eu.localport.dev >> ~/.ssh/config

  # Or set the machine up once and let the agent obtain and renew for you:
  localport setup <TOKEN>
  localport access plc-01-factory.ap.localport.dev -L 502

  # See what this machine holds:
  localport identity list
`, elevatedLocalport(), elevatedNote())
}
