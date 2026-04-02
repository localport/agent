package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/localport/agent/internal/connect"
)

func runConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)

	var (
		certFile   = fs.String("c", "", "client certificate (PEM)")
		keyFile    = fs.String("k", "", "client private key (PEM)")
		caFile     = fs.String("ca", "", "CA certificate that signed the edge cert")
		localPort  = fs.String("p", "0", "local TCP port to listen on")
		localAddr  = fs.String("local-addr", "127.0.0.1", "local bind address")
		configPath = fs.String("config", "", "path to a connect YAML config")
	)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: localport connect <remote-host:port> [flags]
       localport connect --config connect.yaml

  Forward a local TCP port through an mTLS tunnel. Use --config to run
  several proxies from one process.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *configPath != "" {
		return runConnectFromConfig(*configPath)
	}

	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("remote address required")
	}
	if *certFile == "" || *keyFile == "" || *caFile == "" {
		fs.Usage()
		return fmt.Errorf("-c, -k, and -ca are all required (or use --config)")
	}

	tlsCfg, err := connect.BuildTLSConfig(*certFile, *keyFile, *caFile)
	if err != nil {
		return err
	}
	remote := fs.Arg(0)
	listen := fmt.Sprintf("%s:%s", *localAddr, *localPort)

	proxy := &connect.Proxy{
		Remote:    remote,
		LocalAddr: listen,
		TLSConfig: tlsCfg,
		OnConn:    func(l, r string) { fmt.Fprintf(os.Stderr, "  ⇄  %s → %s\n", l, r) },
		OnError:   func(err error) { fmt.Fprintf(os.Stderr, "  ✕  %s\n", err) },
	}

	fmt.Fprintln(os.Stderr, "  localport connect")
	fmt.Fprintf(os.Stderr, "  listening on %s → %s (mTLS)\n", listen, remote)

	ctx, cancel := signalContext()
	defer cancel()
	return proxy.Run(ctx)
}

func runConnectFromConfig(path string) error {
	cc, err := connect.LoadConnectConfig(path)
	if err != nil {
		return err
	}

	ctx, cancel := signalContext()
	defer cancel()

	var wg sync.WaitGroup
	for _, c := range cc.Connections {
		tlsCfg, err := connect.BuildTLSConfig(c.Cert, c.Key, c.CA)
		if err != nil {
			cancel()
			return fmt.Errorf("connection %q: %w", c.Name, err)
		}

		name := c.Name
		if name == "" {
			name = c.Remote
		}
		listen := "127.0.0.1:" + c.LocalPort
		remote := c.Remote

		proxy := &connect.Proxy{
			Remote:    remote,
			LocalAddr: listen,
			TLSConfig: tlsCfg,
			OnConn:    func(l, r string) { fmt.Fprintf(os.Stderr, "  [%s] ⇄  %s → %s\n", name, l, r) },
			OnError:   func(err error) { fmt.Fprintf(os.Stderr, "  [%s] ✕  %s\n", name, err) },
		}
		fmt.Fprintf(os.Stderr, "  [%s] listening on %s → %s (mTLS)\n", name, listen, remote)

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxy.Run(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "  [%s] error: %s\n", name, err)
			}
		}()
	}
	wg.Wait()
	return nil
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()
	return ctx, cancel
}
