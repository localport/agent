package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/tunnel"
	"github.com/localport/agent/internal/ui"
)

// tunnelUI is what the tunnel command needs from its renderer: the
// EventHandler contract plus banner / shutdown lifecycle hooks. This
// keeps display and ui interchangeable behind one switch.
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
		configPath = fs.String("config", "", "path to YAML config")
		token      = fs.String("token", "", "tunnel token (single-endpoint mode)")
		region     = fs.String("region", "", "edge region: eu, us, ap")
		local      = fs.String("local", "", "local service: tcp://host:port, http://host:port, or host:port")
		proto      = fs.String("proto", "http", "tunnel protocol: http, tcp, tls (overridden when --local has a scheme)")
		name       = fs.String("name", "", "endpoint name (default: \"default\")")
		modeUI     = fs.String("ui", "auto", "ui mode: auto, tui, plain")
		showVer    = fs.Bool("version", false, "print version and exit")
	)
	fs.StringVar(token, "t", "", "alias for --token")
	fs.StringVar(local, "l", "", "alias for --local")
	fs.Usage = func() { usageTunnel(fs) }

	if err := fs.Parse(rest); err != nil {
		return err
	}

	if posProto != "" {
		if *local != "" {
			return fmt.Errorf("--local cannot be combined with positional protocol/address")
		}
		*proto = posProto
		*local = posLocal
	}
	if *showVer {
		fmt.Printf("localport %s\n", version)
		return nil
	}

	cfg, warning, err := buildTunnelConfig(*configPath, *token, *region, *local, *proto, *name)
	if err != nil {
		fs.Usage()
		return err
	}
	if warning != "" {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := agent.New(cfg, nil) // handler attached below so renderer can poll a.Tunnels()
	renderer := pickRenderer(*modeUI, a)
	a.SetHandler(renderer)
	renderer.Banner(version, cfg)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		renderer.Shutdown()
		a.Stop()
		cancel()
	}()

	err = a.Run(ctx)
	renderer.Shutdown()
	return err
}

func pickRenderer(flagValue string, a *agent.Agent) tunnelUI {
	if ui.DetectMode(flagValue, os.Stderr) == ui.ModePlain {
		return ui.NewPlain()
	}
	t := ui.NewTUI()
	t.SetTunnelProvider(a.Tunnels)
	return t
}

func buildTunnelConfig(path, flagToken, region, local, proto, name string) (*config.Config, string, error) {
	if path != "" {
		cfg, err := config.Load(path)
		return cfg, "", err
	}
	token, warning, err := security.ResolveToken(flagToken, "LOCALPORT_TOKEN")
	if err != nil {
		return nil, "", err
	}
	if local == "" {
		return nil, "", fmt.Errorf("--local is required for token-based tunnel mode")
	}
	return config.FromFlags(token, region, local, proto, name), warning, nil
}

func usageTunnel(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage: localport tunnel [flags]
       localport <proto> <port|host:port> [flags]

  Config file:
    localport tunnel --config localport.yaml

  Single endpoint, scheme in --local sets the protocol:
    localport --token <token> --local tcp://localhost:18789
    localport -t <token> -l http://localhost:3000

  Positional shorthand (proto + port or host:port):
    localport tcp 18789 -t <token>
    localport http localhost:3000 -t <token>
    localport tls 8443 -t <token>

Environment:
  LOCALPORT_TOKEN   tunnel token (alternative to --token)
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
