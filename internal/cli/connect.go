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
		pemFile     = fs.String("pem", "", "PEM file (client cert + key + tunnel CA)")
		p12File     = fs.String("p12", "", "PKCS#12 archive (.p12 / .pfx)")
		p12Pass     = fs.String("p12-pass", "", "PKCS#12 password (use --p12-pass-env in production)")
		p12PassEnv  = fs.String("p12-pass-env", defaultP12PasswordEnv, "env var carrying the PKCS#12 password (required for Localport-issued .p12)")
		p12PassFile = fs.String("p12-pass-file", "", "file containing the PKCS#12 password")
		localAddr   = fs.String("local-addr", "127.0.0.1", "local bind address")
		serverName  = fs.String("server-name", "", "TLS SNI / server name override")
		configPath  = fs.String("config", "", "path to a connect YAML config")
	)
	// -p and --port both set the local listen port.
	var localPort string
	fs.StringVar(&localPort, "p", "0", "local TCP port to listen on")
	fs.StringVar(&localPort, "port", "0", "local TCP port to listen on [alias of -p]")
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

	remote, err := connect.ParseRemote(remote)
	if err != nil {
		return err
	}

	password, err := resolveP12Password(*p12Pass, *p12PassFile, *p12PassEnv)
	if err != nil {
		return err
	}

	tlsCfg, err := connect.BuildTLSConfig(*pemFile, *p12File, password, remote, *serverName)
	if err != nil {
		return err
	}

	listen := fmt.Sprintf("%s:%s", *localAddr, localPort)
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
		remote, err := connect.ParseRemote(c.Remote)
		if err != nil {
			cancel()
			return fmt.Errorf("connection %q: %w", c.Name, err)
		}
		tlsCfg, err := connect.BuildTLSConfig(c.Bundle, c.P12, password, remote, "")
		if err != nil {
			cancel()
			return fmt.Errorf("connection %q: %w", c.Name, err)
		}

		name := c.Name
		if name == "" {
			name = c.Remote
		}
		listen := "127.0.0.1:" + c.LocalPort
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

// minPasswordLength is the floor Localport enforces on PKCS#12 passwords
// we issue. Shorter passwords trip a clear error rather than being passed
// to PKCS#12 decode where they would surface as opaque MAC failures.
const minPasswordLength = 12

// resolveP12Password reads the password in order: explicit flag, file,
// env var. An empty string is returned (not an error) so callers using a
// passwordless archive can still proceed; callers that need a password
// will fail at decode time with a useful error.
func resolveP12Password(inline, filePath, envName string) (string, error) {
	switch {
	case inline != "":
		return assertStrongPassword(inline)
	case filePath != "":
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read p12 password file: %w", err)
		}
		return assertStrongPassword(strings.TrimSpace(string(data)))
	}
	if envName == "" {
		envName = defaultP12PasswordEnv
	}
	v, ok := os.LookupEnv(envName)
	if !ok || v == "" {
		return "", nil
	}
	return assertStrongPassword(v)
}

func assertStrongPassword(p string) (string, error) {
	if len(p) < minPasswordLength {
		return "", fmt.Errorf("PKCS#12 password must be at least %d characters", minPasswordLength)
	}
	return p, nil
}

func signalCtx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()
	return ctx, cancel
}

func usageConnect(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage: localport connect <URL> --pem <file> -p <local-port> [flags]
       localport connect <URL> --p12 <file> -p <local-port> [flags]
       localport connect --config connect.yaml

  Reach a live mTLS tunnel as a consumer: presents your client certificate to
  the edge and forwards a local port to it. Paste the tunnel URL straight from
  the dashboard.

  <URL> accepts the dashboard forms (scheme picks the port):
    https://sub.eu.localport.dev          -> :443 (mTLS terminates at the edge)
    tcp://sub.eu.localport.dev:5432       -> :5432
    tls://sub.eu.localport.dev:5432       -> :5432
    sub.eu.localport.dev:5432             -> bare host:port also works

  Credentials (supply exactly one):
    --pem               PEM file with client cert + key + tunnel CA
    --p12               PKCS#12 archive (password via --p12-pass-env / -file)

  Examples:
    localport connect https://de8yp41s.eu.localport.dev --pem client.pem -p 3001
    localport connect tcp://de8yp41s.eu.localport.dev:5432 --pem db.pem --port 5432
    LOCALPORT_P12_PASSWORD=… \
      localport connect https://de8yp41s.eu.localport.dev --p12 client.p12 -p 3001
    localport connect --config connect.yaml   # many targets at once

Flags:
`)
	fs.PrintDefaults()
}
