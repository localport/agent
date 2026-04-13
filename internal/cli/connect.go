package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/localport/agent/internal/connect"
)

func runConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		certFile   = fs.String("c", "", "client certificate (PEM)")
		keyFile    = fs.String("k", "", "client private key (PEM)")
		caFile     = fs.String("ca", "", "CA certificate that signed the remote cert")
		localPort  = fs.String("p", "0", "local TCP port to listen on")
		localAddr  = fs.String("local-addr", "127.0.0.1", "local bind address")
		serverName = fs.String("server-name", "", "TLS SNI / server name override")
		configPath = fs.String("config", "", "path to a connect YAML config")
	)
	fs.Usage = func() { usageConnect(fs) }

	// Accept the remote as a leading positional, but tolerate it being
	// placed after flags as well (`connect -c … host:port`).
	remoteFromHead := ""
	parsed := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		remoteFromHead = args[0]
		parsed = args[1:]
	}
	if err := fs.Parse(parsed); err != nil {
		return err
	}

	if *configPath != "" {
		return runConnectFromConfig(*configPath)
	}

	remote := remoteFromHead
	if remote == "" {
		if fs.NArg() < 1 {
			fs.Usage()
			return fmt.Errorf("remote address required")
		}
		remote = fs.Arg(0)
	}
	if (remoteFromHead == "" && fs.NArg() > 1) || (remoteFromHead != "" && fs.NArg() > 0) {
		fs.Usage()
		return fmt.Errorf("unexpected extra positional arguments")
	}

	if *certFile == "" || *keyFile == "" || *caFile == "" {
		fs.Usage()
		return fmt.Errorf("-c, -k, and -ca are all required (or use --config)")
	}

	tlsCfg, err := connect.BuildTLSConfig(*certFile, *keyFile, *caFile, remote, *serverName)
	if err != nil {
		return err
	}

	listen := fmt.Sprintf("%s:%s", *localAddr, *localPort)
	proxy := &connect.Proxy{
		Remote:    remote,
		LocalAddr: listen,
		TLSConfig: tlsCfg,
		OnConn:    func(l, r string) { fmt.Fprintf(os.Stderr, "  [conn] %s -> %s\n", l, r) },
		OnError:   func(err error) { fmt.Fprintln(os.Stderr, "  [error]", err) },
	}
	fmt.Fprintln(os.Stderr, "  localport connect")
	fmt.Fprintf(os.Stderr, "  listening on %s -> %s (mTLS)\n", listen, remote)

	ctx, cancel := signalCtx()
	defer cancel()
	return proxy.Run(ctx)
}

func runConnectFromConfig(path string) error {
	cc, err := connect.LoadConnectConfig(path)
	if err != nil {
		return err
	}

	ctx, cancel := signalCtx()
	defer cancel()

	var (
		wg       sync.WaitGroup
		firstErr error
		errMu    sync.Mutex
	)
	for _, c := range cc.Connections {
		tlsCfg, err := connect.BuildTLSConfig(c.Cert, c.Key, c.CA, c.Remote, "")
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
			OnConn:    func(l, r string) { fmt.Fprintf(os.Stderr, "  [%s] [conn] %s -> %s\n", name, l, r) },
			OnError:   func(err error) { fmt.Fprintf(os.Stderr, "  [%s] [error] %s\n", name, err) },
		}
		fmt.Fprintf(os.Stderr, "  [%s] listening on %s -> %s (mTLS)\n", name, listen, remote)

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxy.Run(ctx); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				fmt.Fprintf(os.Stderr, "  [%s] error: %s\n", name, err)
			}
		}()
	}
	wg.Wait()
	return firstErr
}

func signalCtx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()
	return ctx, cancel
}

func usageConnect(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage: localport connect <remote-host:port> [flags]
       localport connect --config connect.yaml

  Forward a local TCP port through an mTLS tunnel.

  Single target:
    localport connect db.tunnel.localport.dev:5432 \
      -c client.crt -k client.key -ca mesh-ca.crt -p 5432

  Multiple targets from one file:
    localport connect --config connect.yaml

Flags:
`)
	fs.PrintDefaults()
}
