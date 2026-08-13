package cli

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/localport/agent/internal/connect"
	"github.com/localport/agent/internal/identity"
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
		identityArg = fs.String("identity", "", "credential to present: `<identity>`, <team>/<identity> or <team>/<kind>/<identity>")
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

	// Decided BEFORE the signal handler is installed, because deciding it may
	// PROMPT: a blocking read on stdin does not unblock on context cancellation,
	// so Ctrl-C at the prompt would leave the process hung.
	var chosen *identity.Ref
	if *pemFile == "" && *p12File == "" {
		store, storeErr := identity.DefaultStore()
		if storeErr != nil {
			return storeErr
		}
		ref, resolveErr := resolveCredential(store, firstNonEmpty(*identityArg, os.Getenv(identityEnv)), true)
		if resolveErr != nil {
			return fmt.Errorf("%w\n  (or pass a credential file with --pem / --p12)", resolveErr)
		}
		chosen = &ref
	}

	ctx, cancel := signalCtx()
	defer cancel()

	var (
		tlsCfg *tls.Config
		source string
	)
	if *pemFile == "" && *p12File == "" {
		// No credential file named: present the identity this machine holds.
		tlsCfg, source, err = identityTLSConfig(ctx, *chosen, remote, *serverName)
	} else {
		// The password is only resolved for --p12. Reading it on the --pem path
		// would fail a PEM connect on a box where LOCALPORT_P12_PASSWORD happens
		// to be set, over a flag the caller never passed.
		var password string
		if *p12File != "" {
			password, err = resolveP12Password(*p12Pass, *p12PassFile, *p12PassEnv)
		}
		if err == nil {
			tlsCfg, err = connect.BuildTLSConfig(*pemFile, *p12File, password, remote, *serverName)
			source = "file"
		}
	}
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
	fmt.Fprintf(os.Stderr, "  listening on %s -> %s (mTLS, %s)\n", listen, remote, source)

	return proxy.Run(ctx)
}

// identityTLSConfig presents the stored credential and keeps it fresh. The
// certificate comes through a CALLBACK rather than being copied into the config,
// so a renewal by this process or by `localport identity renew` is picked up on
// the next handshake.
func identityTLSConfig(ctx context.Context, ref identity.Ref, remote, serverName string) (*tls.Config, string, error) {
	store, err := identity.DefaultStore()
	if err != nil {
		return nil, "", err
	}
	// Opened by exact Ref: resolveCredential is the one place precedence and
	// ambiguity are decided.
	cred, err := identity.OpenRef(store, ref)
	if err != nil {
		return nil, "", fmt.Errorf("%w\n  (or pass a credential file with --pem / --p12)", err)
	}
	// A refused reload means the file now holds a different principal. The process
	// keeps presenting what it opened with, so the refusal must be visible.
	cred.OnSwap(func(line string) { fmt.Fprintf(os.Stderr, "  [identity] %s\n", line) })

	cfg := connect.BaseTLSConfig(remote, serverName)
	cfg.GetClientCertificate = cred.GetClientCertificate

	meta := cred.Meta()
	if !meta.Source.Renewable() {
		// No renewal loop, so say when it ends: otherwise it stops being accepted
		// mid-session and the far side answers with an opaque TLS refusal.
		noteSignInExpiry(cred.Ref(), meta)
		return cfg, "sign-in " + meta.Identity, nil
	}

	startIdentityRenewal(ctx, store, cred.Ref())
	return cfg, "identity " + meta.Identity, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func runConnectFromConfig(path string) error {
	cc, err := connect.LoadConnectConfig(path)
	if err != nil {
		return err
	}
	store, err := identity.DefaultStore()
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
		remote, err := connect.ParseRemote(c.Remote)
		if err != nil {
			cancel()
			return fmt.Errorf("connection %q: %w", c.Name, err)
		}

		var tlsCfg *tls.Config
		if c.UsesIdentity() {
			// NEVER interactive: this loop builds several connections, so prompting
			// would ask once per entry.
			var ref identity.Ref
			if ref, err = resolveCredential(store, c.Identity, false); err == nil {
				tlsCfg, _, err = identityTLSConfig(ctx, ref, remote, "")
			}
		} else {
			var password string
			if c.P12 != "" {
				password, err = resolveP12Password(c.P12Pass, c.P12PassFile, c.P12PassEnv)
			}
			if err == nil {
				tlsCfg, err = connect.BuildTLSConfig(c.Bundle, c.P12, password, remote, "")
			}
		}
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

  Credentials. With no flag, the identity this machine holds is used, so there
  is no file to copy around. Supply a file only for a credential we did not
  issue:
    (none)              the stored identity (localport setup <TOKEN>)
    --pem               PEM file with client cert + key + tunnel CA
    --p12               PKCS#12 archive (password via --p12-pass-env / -file)

  Examples:
    localport setup lps_...           # once per machine
    localport connect https://de8yp41s.eu.localport.dev -p 3001

    localport connect https://de8yp41s.eu.localport.dev --pem client.pem -p 3001
    localport connect tcp://de8yp41s.eu.localport.dev:5432 --pem db.pem --port 5432
    LOCALPORT_P12_PASSWORD=… \
      localport connect https://de8yp41s.eu.localport.dev --p12 client.p12 -p 3001
    localport connect --config connect.yaml   # many targets at once

Flags:
`)
	fs.PrintDefaults()
}
