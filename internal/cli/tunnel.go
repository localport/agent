package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/display"
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
	fs := flag.NewFlagSet("tunnel", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		configPath = fs.String("config", "", "path to YAML config")
		token      = fs.String("token", "", "tunnel token (single-endpoint mode)")
		region     = fs.String("region", "", "edge region: eu, us, ap")
		local      = fs.String("local", "", "local service host:port")
		proto      = fs.String("proto", "http", "tunnel protocol: http, tcp, tls")
		name       = fs.String("name", "", "endpoint name (default: \"default\")")
		modeUI     = fs.String("ui", "text", "ui mode: text or tui")
		showVer    = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() { usageTunnel(fs) }

	if err := fs.Parse(args); err != nil {
		return err
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

	var renderer tunnelUI
	switch *modeUI {
	case "text":
		renderer = display.New()
	case "tui":
		renderer = ui.NewMinimal()
	default:
		return fmt.Errorf("unsupported --ui %q (use text or tui)", *modeUI)
	}
	renderer.Banner(version, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := agent.New(cfg, renderer)
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

  From a config file:
    localport tunnel --config localport.yaml

  From CLI flags:
    localport tunnel --token <token> --local <host:port> [--region <region>]

  Legacy flat form (no subcommand) is accepted:
    localport --token <token> --local <host:port>

Environment:
  LOCALPORT_TOKEN   tunnel token (alternative to --token)
  NO_COLOR          disable colored output

Flags:
`)
	fs.PrintDefaults()
}
