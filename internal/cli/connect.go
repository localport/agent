package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/localport/agent/internal/agent"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/tunnel"
	"github.com/localport/agent/internal/ui"
)

// runConnect joins this machine to a fleet as one device, or runs every tunnel
// and device in a config file. Device ports come from the dashboard.
func runConnect(version string, args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		configPath  = fs.String("config", "", "path to YAML config")
		token       = fs.String("token", "", "fleet token")
		region      = fs.String("region", "", "edge region: eu, us, ap")
		name        = fs.String("name", "", "device name (default: this machine's hostname)")
		host        = fs.String("host", "", "where this device sends traffic (default: localhost)")
		noUI        = fs.Bool("noui", false, "disable the live view and emit plain logs (auto-enabled when stdout is not a TTY)")
		noMux       = fs.Bool("no-mux", false, "send each inbound connection over its own connection instead of multiplexing them")
		noInspect   = fs.Bool("no-inspect", false, "do not inspect HTTP requests")
		logRequests = fs.Bool("log-requests", false, "log one line per HTTP request in headless mode (http ports)")
	)
	fs.StringVar(token, "t", "", "alias for --token")
	fs.Usage = func() { usageConnect(fs) }

	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := buildConnectConfig(*configPath, *token, *region, *name, *host)
	if err != nil {
		fs.Usage()
		return err
	}
	if *noMux {
		cfg.NoMux = true
	}
	cfg.AgentVersion = version

	mode := ui.DetectMode(*noUI, os.Stderr)
	cfg.NoInspect = inspectDisabled(mode, *noInspect, *logRequests)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := agent.New(cfg, nil)
	renderer := pickRenderer(mode, a)
	a.SetHandler(renderer)
	renderer.Banner(version, cfg)

	// The renderer shuts down first to restore the terminal before teardown
	// output. Stop ends all sessions at once.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		renderer.Shutdown()
		a.Stop()
		cancel()
	}()

	runErr := a.Run(ctx)
	renderer.Shutdown()

	var regErr *tunnel.RegistrationError
	if errors.As(runErr, &regErr) && regErr.Code != "" {
		return fmt.Errorf("%s [%s]", regErr.Error(), regErr.Code)
	}
	return runErr
}

func buildConnectConfig(path, flagToken, region, name, host string) (*config.Config, error) {
	if path != "" {
		return config.Load(path)
	}
	token, err := security.ResolveToken(flagToken, "LOCALPORT_TOKEN")
	if err != nil {
		return nil, err
	}
	if name == "" {
		host, _ := os.Hostname()
		name = config.DefaultDeviceName(host)
	}
	if name == "" {
		return nil, errors.New("--name is required, because this machine reports no usable hostname")
	}
	return config.DeviceFromFlags(token, region, name, host)
}

func usageConnect(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage: localport connect -t <token> [--name <device>] [--host <address>]
       localport connect --config localport.yaml

  Join a fleet as one device. The ports this device serves are set in the
  dashboard, and consumers reach them with:

    localport access <device-host> -L <local>:<remote>

  One device, named after this machine:
    localport connect -t <token>

  One device, serving another machine on this network:
    localport connect -t <token> --name plc-01 --host 192.168.1.100

  Every tunnel and device in a file:
    localport connect --config localport.yaml

Environment:
  LOCALPORT_TOKEN        fleet token (alternative to --token)
  LOCALPORT_TOKEN_FILE   file to read the token from, for systemd LoadCredential=
                         and docker secrets
  NO_COLOR               disable colored output

Flags:
`)
	fs.PrintDefaults()
}
