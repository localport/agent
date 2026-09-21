package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
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
		noUI        = fs.Bool("noui", false, "disable the live TUI and emit plain logs (auto-enabled when stdout is not a TTY)")
		noMux       = fs.Bool("no-mux", false, "send each inbound connection over its own connection instead of multiplexing them")
		noInspect   = fs.Bool("no-inspect", false, "do not inspect HTTP requests, even under the TUI")
		logRequests = fs.Bool("log-requests", false, "log one line per HTTP request in headless mode (http tunnels)")
		showVer     = fs.Bool("version", false, "print version and exit")
	)
	fs.StringVar(token, "t", "", "alias for --token")
	fs.StringVar(local, "l", "", "alias for --local")
	fs.Usage = func() { usageTunnel(fs) }

	if err := fs.Parse(rest); err != nil {
		return err
	}

	if posProto != "" {
		if *local != "" {
			return errors.New("--local cannot be combined with positional protocol/address")
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

	ctx, stop := signalContext(func() {
		renderer.Shutdown()
		a.Stop()
	})
	defer stop()

	err = a.Run(ctx, renderer)
	renderer.Shutdown()
	// Print one line for a fatal error. The sanitized message is followed by
	// the opaque debug code for support.
	var regErr *tunnel.RegistrationError
	if errors.As(err, &regErr) && regErr.Code != "" {
		return fmt.Errorf("%s [%s]", regErr.Error(), regErr.Code)
	}
	return err
}

// inspectDisabled reports whether the HTTP request view is off. --no-inspect
// turns it off. Otherwise it is on in the TUI, and in plain mode only with
// --log-requests. Used by connect and the flat tunnel form.
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
		return nil, errors.New("--local is required for token-based tunnel mode")
	}
	return config.TunnelFromFlags(token, region, local, proto, name)
}

func usageTunnel(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage: localport <proto> <port|host:port> [flags]
       localport --token <token> --local <address> [flags]

  Config file:
    localport connect --config localport.yaml

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

// extractPositional consumes a leading "<proto> <port|host:port>" pair
// when present so callers can write `localport tcp 18789 -t tok`. The
// recognised protocols are http, https, tcp, tls; anything else leaves
// args untouched so the regular flag parser sees them.
func extractPositional(args []string) (proto, local string, rest []string) {
	if len(args) < 2 || strings.HasPrefix(args[0], "-") {
		return "", "", args
	}
	switch strings.ToLower(args[0]) {
	case "http", "https", "tcp", "tls":
	default:
		return "", "", args
	}
	if strings.HasPrefix(args[1], "-") {
		return "", "", args
	}
	return args[0], args[1], args[2:]
}
