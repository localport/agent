package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/tunnel"
	"github.com/localport/agent/internal/ui"
)

// tunnelUI is the renderer interface of the tunnel command, EventHandler plus
// banner and shutdown hooks. display and ui both implement it.
type tunnelUI interface {
	tunnel.EventHandler
	Banner(version string, cfg *config.Config)
	Shutdown()
}

func runTunnel(version string, args []string) error {
	posProto, posLocal, rest := extractPositional(args)

	fs := flag.NewFlagSet("tunnel", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		configPath  = fs.String("config", "", "path to YAML config")
		token       = fs.String("token", "", "tunnel token (single-endpoint mode)")
		region      = fs.String("region", "", "edge region: eu, us, ap")
		local       = fs.String("local", "", "local service: tcp://host:port, http://host:port, or host:port")
		proto       = fs.String("proto", "http", "tunnel protocol: http, tcp, tls (overridden when --local has a scheme)")
		name        = fs.String("name", "", "endpoint name (default: \"default\")")
		noUI        = fs.Bool("noui", false, "disable the live TUI and emit plain logs (auto-enabled when stderr is not a TTY)")
		noMux       = fs.Bool("no-mux", false, "send each inbound connection over its own connection instead of multiplexing them")
		noInspect   = fs.Bool("no-inspect", false, "do not inspect HTTP requests, even under the TUI")
		logRequests = fs.Bool("log-requests", false, "log one line per HTTP request in headless mode (http tunnels)")
		showVer     = fs.Bool("version", false, "print version and exit")
	)
	fs.StringVar(token, "t", "", "alias for --token")
	fs.StringVar(local, "l", "", "alias for --local")
	fs.Usage = func() { usageTunnel(fs) }

	if err := fs.Parse(rest); err != nil {
		return errcode.UsageError(err)
	}

	if err := refuseBesideConfig(fs, *configPath, "token", "t", "region", "local", "l", "proto", "name"); err != nil {
		return err
	}
	if posProto != "" {
		if *configPath != "" {
			return errcode.Invalidf("a positional protocol and port cannot be combined with --config: set it in the config file")
		}
		if *local != "" {
			return errcode.Invalidf("--local cannot be combined with positional protocol/address")
		}
		*proto = posProto
		*local = posLocal
	}
	if *showVer {
		fmt.Printf("localport %s\n", version)
		return nil
	}

	cfg, err := buildTunnelConfig(*configPath, *token, *region, *local, *proto, *name)
	if err != nil {
		fs.Usage()
		return err
	}
	if *noMux {
		cfg.NoMux = true
	}
	// Build version from ldflags, sent on registration.
	cfg.AgentVersion = version
	mode := ui.DetectMode(*noUI, os.Stderr)
	cfg.NoInspect = inspectDisabled(mode, *noInspect, *logRequests)

	a := agent.New(cfg)
	renderer := pickRenderer(mode, a)
	renderer.Banner(version, cfg)
	warnTokenFlag(renderer, *configPath == "" && strings.TrimSpace(*token) != "")

	ctx, stop := signalContext(func() {
		renderer.Shutdown()
		a.Stop()
	})
	defer stop()

	err = a.Run(ctx, renderer)
	renderer.Shutdown()
	// An edge refusal prints as its message and code (errcode.Render).
	return err
}

// inspectDisabled reports whether the HTTP request view is off. --no-inspect
// turns it off. Otherwise it is on in the TUI, and in plain mode only with
// --log-requests. Used by up --config and the flat tunnel form.
func inspectDisabled(mode ui.Mode, noInspect, logRequests bool) bool {
	switch {
	case noInspect:
		return true
	case logRequests:
		return false
	default:
		return mode == ui.ModePlain
	}
}

// tokenFlagWarning names the exposure of -t/--token and the alternatives.
const tokenFlagWarning = "--token is readable by other local accounts in the process list. " +
	"Set LOCALPORT_TOKEN_FILE or LOCALPORT_TOKEN instead."

// warnTokenFlag logs tokenFlagWarning in plain mode when the token came from
// -t/--token. The TUI shows no startup warnings.
func warnTokenFlag(renderer tunnelUI, fromFlag bool) {
	if p, ok := renderer.(*ui.Plain); ok && fromFlag {
		p.Warn(tokenFlagWarning)
	}
}

// warnNoPortCeiling logs one warning per device without --allow-ports, the
// only port limit enforced locally; plain mode only, the TUI shows it itself.
func warnNoPortCeiling(renderer tunnelUI, devices []config.DeviceSpec) {
	p, ok := renderer.(*ui.Plain)
	if !ok {
		return
	}
	for _, device := range devices {
		if len(device.AllowPorts) > 0 {
			continue
		}
		p.Warn(fmt.Sprintf("device %q: no --allow-ports set, so any port the dashboard allows is served on %s; set --allow-ports or allow_ports to limit it",
			device.Name, device.Host))
	}
}

// refuseBesideConfig reports the named flags given alongside --config. The file
// describes everything that runs, so an endpoint flag would be ignored; it is
// refused instead of dropped silently. Visit sees only flags actually passed,
// so a default such as --proto=http is never mistaken for one.
func refuseBesideConfig(fs *flag.FlagSet, configPath string, names ...string) error {
	if configPath == "" {
		return nil
	}
	return refuseGiven(fs, "cannot be combined with --config: set it in the config file", names...)
}

// refuseGiven reports the named flags that were passed, followed by reason.
func refuseGiven(fs *flag.FlagSet, reason string, names ...string) error {
	conflicting := make(map[string]bool, len(names))
	for _, n := range names {
		conflicting[n] = true
	}
	var given []string
	fs.Visit(func(f *flag.Flag) {
		if !conflicting[f.Name] {
			return
		}
		if len(f.Name) == 1 {
			given = append(given, "-"+f.Name)
		} else {
			given = append(given, "--"+f.Name)
		}
	})
	if len(given) == 0 {
		return nil
	}
	return errcode.Invalidf("%s %s", strings.Join(given, ", "), reason)
}

func pickRenderer(mode ui.Mode, a *agent.Agent) tunnelUI {
	if mode == ui.ModePlain {
		return ui.NewPlain()
	}
	t := ui.NewTUI()
	t.SetTunnelProvider(a.Tunnels)
	return t
}

func buildTunnelConfig(path, flagToken, region, local, proto, name string) (*config.Config, error) {
	if path != "" {
		return config.Load(path)
	}
	token, err := security.ResolveToken(flagToken, "LOCALPORT_TOKEN")
	if err != nil {
		return nil, err
	}
	if local == "" {
		return nil, errcode.Invalidf("--local is required for token-based tunnel mode")
	}
	return config.TunnelFromFlags(token, region, local, proto, name)
}

func usageTunnel(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage: localport <proto> <port|host:port> [flags]
       localport --token <token> --local <address> [flags]

  Config file (it sets every endpoint, so endpoint flags beside it are refused):
    localport up --config localport.yaml

  Single endpoint, scheme in --local sets the protocol:
    localport --token <token> --local tcp://localhost:18789
    localport -t <token> -l http://localhost:3000

  Positional shorthand (proto + port or host:port):
    localport tcp 18789 -t <token>
    localport http localhost:3000 -t <token>
    localport tls 8443 -t <token>

Environment:
  LOCALPORT_TOKEN        tunnel token (alternative to --token)
  LOCALPORT_TOKEN_FILE   file to read the token from, for systemd LoadCredential=
                         and docker secrets
  NO_COLOR          disable colored output

Flags:
`)
	fs.PrintDefaults()
}

// isTunnelProto reports whether word is a positional tunnel protocol.
func isTunnelProto(word string) bool {
	switch strings.ToLower(word) {
	case "http", "https", "tcp", "tls":
		return true
	}
	return false
}

// extractPositional consumes a leading "<proto> <port|host:port>" pair
// when present so callers can write `localport tcp 18789 -t tok`. The
// recognised protocols are http, https, tcp, tls; anything else leaves
// args untouched so the regular flag parser sees them.
func extractPositional(args []string) (proto, local string, rest []string) {
	if len(args) < 2 || strings.HasPrefix(args[0], "-") {
		return "", "", args
	}
	if !isTunnelProto(args[0]) {
		return "", "", args
	}
	if strings.HasPrefix(args[1], "-") {
		return "", "", args
	}
	return args[0], args[1], args[2:]
}
