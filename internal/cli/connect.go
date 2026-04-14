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

const defaultP12PasswordEnv = "LOCALPORT_P12_PASSWORD"

func runConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		bundleFile  = fs.String("bundle", "", "PEM bundle file (cert + key + CA)")
		p12File     = fs.String("p12", "", "PKCS#12 archive (.p12 / .pfx)")
		p12Pass     = fs.String("p12-pass", "", "PKCS#12 password (discouraged: visible in process list)")
		p12PassEnv  = fs.String("p12-pass-env", defaultP12PasswordEnv, "env var name carrying the PKCS#12 password")
		p12PassFile = fs.String("p12-pass-file", "", "file containing the PKCS#12 password")
		localPort   = fs.String("p", "0", "local TCP port to listen on")
		localAddr   = fs.String("local-addr", "127.0.0.1", "local bind address")
		serverName  = fs.String("server-name", "", "TLS SNI / server name override")
		configPath  = fs.String("config", "", "path to a connect YAML config")
	)
	fs.Usage = func() { usageConnect(fs) }

	// Accept the remote as a leading positional, but tolerate it being
	// supplied after flags as well.
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

	password, err := resolveP12Password(*p12Pass, *p12PassFile, *p12PassEnv)
	if err != nil {
		return err
	}

	tlsCfg, err := connect.BuildTLSConfig(*bundleFile, *p12File, password, remote, *serverName)
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
		password, err := resolveP12Password(c.P12Pass, c.P12PassFile, c.P12PassEnv)
		if err != nil {
			cancel()
			return fmt.Errorf("connection %q: %w", c.Name, err)
		}
		tlsCfg, err := connect.BuildTLSConfig(c.Bundle, c.P12, password, c.Remote, "")
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

// resolveP12Password reads the password in order: explicit flag, file,
// env var. An empty string is returned (not an error) so callers can
// pass it straight through to PKCS#12 decode and let that fail if the
// archive really did need a password.
func resolveP12Password(inline, filePath, envName string) (string, error) {
	if inline != "" {
		return inline, nil
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read p12 password file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	if envName == "" {
		envName = defaultP12PasswordEnv
	}
	if v, ok := os.LookupEnv(envName); ok {
		return v, nil
	}
	return "", nil
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

  PEM bundle (cert + key + CA in one file):
    localport connect db.tunnel.localport.dev:5432 \
      --bundle client-bundle.pem -p 5432

  PKCS#12 archive:
    LOCALPORT_P12_PASSWORD=… \
      localport connect db.tunnel.localport.dev:5432 \
      --p12 client.p12 -p 5432

  Multiple targets from one config file:
    localport connect --config connect.yaml

Flags:
`)
	fs.PrintDefaults()
}
