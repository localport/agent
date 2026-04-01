package main

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
)

// Populated via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "connect" {
		if err := runConnect(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "", "path to YAML config")
		token      = flag.String("token", "", "tunnel token (single-endpoint mode)")
		region     = flag.String("region", "", "edge region: eu, us, ap")
		local      = flag.String("local", "", "local service host:port")
		proto      = flag.String("proto", "http", "tunnel protocol: http, tcp, tls")
		name       = flag.String("name", "", "endpoint name (default: \"default\")")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = printUsage
	flag.Parse()

	if *showVer {
		fmt.Printf("localport %s (%s) built %s\n", version, commit, date)
		return nil
	}

	cfg, err := loadConfig(*configPath, *token, *region, *local, *proto, *name)
	if err != nil {
		return err
	}

	ui := display.New()
	ui.Banner(version, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := agent.New(cfg, ui)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		ui.Shutdown()
		a.Stop()
		cancel()
	}()

	return a.Run(ctx)
}

// loadConfig picks the right source: --config wins, then explicit --token,
// then LOCALPORT_TOKEN with --local.
func loadConfig(path, token, region, local, proto, name string) (*config.Config, error) {
	switch {
	case path != "":
		return config.Load(path)
	case token != "" && local != "":
		return config.FromFlags(token, region, local, proto, name), nil
	case token == "" && os.Getenv("LOCALPORT_TOKEN") != "" && local != "":
		return config.FromFlags(os.Getenv("LOCALPORT_TOKEN"), region, local, proto, name), nil
	}
	flag.Usage()
	return nil, fmt.Errorf("provide --config, or --token with --local")
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: localport [flags]

  Run from a config file:
    localport --config localport.yaml

  Run a single endpoint:
    localport --token <token> --local <host:port> [--region <region>]

  Environment:
    LOCALPORT_TOKEN   tunnel token (alternative to --token)
    NO_COLOR          disable colored output

Flags:
`)
	flag.PrintDefaults()
}
