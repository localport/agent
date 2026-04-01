package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/localport/agent/internal/connect"
)

func runConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)

	var (
		certFile  = fs.String("c", "", "client certificate (PEM)")
		keyFile   = fs.String("k", "", "client private key (PEM)")
		caFile    = fs.String("ca", "", "CA certificate that signed the edge cert")
		localPort = fs.String("p", "0", "local TCP port to listen on")
		localAddr = fs.String("local-addr", "127.0.0.1", "local bind address")
	)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: localport connect <remote-host:port> [flags]

  Forward a local TCP port through an mTLS tunnel to the remote endpoint.

  Example:
    localport connect db.tunnel.localport.dev:5432 \
      -c client.crt -k client.key -ca mesh-ca.crt -p 5432

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("remote address required")
	}
	if *certFile == "" || *keyFile == "" || *caFile == "" {
		fs.Usage()
		return fmt.Errorf("-c, -k, and -ca are all required")
	}

	remote := fs.Arg(0)
	listen := fmt.Sprintf("%s:%s", *localAddr, *localPort)

	tlsCfg, err := connect.BuildTLSConfig(*certFile, *keyFile, *caFile)
	if err != nil {
		return err
	}

	proxy := &connect.Proxy{
		Remote:    remote,
		LocalAddr: listen,
		TLSConfig: tlsCfg,
		OnConn:    func(l, r string) { fmt.Fprintf(os.Stderr, "  ⇄  %s → %s\n", l, r) },
		OnError:   func(err error) { fmt.Fprintf(os.Stderr, "  ✕  %s\n", err) },
	}

	fmt.Fprintln(os.Stderr, "  localport connect")
	fmt.Fprintf(os.Stderr, "  listening on %s → %s (mTLS)\n", listen, remote)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	return proxy.Run(ctx)
}
