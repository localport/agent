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

	"github.com/localport/agent/internal/access"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
)

const defaultP12PasswordEnv = "LOCALPORT_P12_PASSWORD"

func runAccess(args []string) error {
	fs := flag.NewFlagSet("access", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		pemFile     = fs.String("pem", "", "PEM file (client cert + key + tunnel CA)")
		p12File     = fs.String("p12", "", "PKCS#12 archive (.p12 / .pfx)")
		p12Pass     = fs.String("p12-pass", "", "PKCS#12 password (use --p12-pass-env in production)")
		p12PassEnv  = fs.String("p12-pass-env", defaultP12PasswordEnv, "env var carrying the PKCS#12 password (required for Localport-issued .p12)")
		p12PassFile = fs.String("p12-pass-file", "", "file containing the PKCS#12 password")
		localAddr   = fs.String("local-addr", "127.0.0.1", "local bind address")
		serverName  = fs.String("server-name", "", "TLS SNI / server name override")
		configPath  = fs.String("config", "", "path to an access YAML config")
		identityArg = fs.String("identity", "", "credential to present: `<identity>`, <team>/<identity> or <team>/<kind>/<identity>")
		audience    = fs.String("audience", "", "OIDC audience for a CI workload identity (or "+identity.AudienceEnv+")")
		apiURL      = fs.String("api", "", "control plane base URL (CI identity only; default "+identity.DefaultAPIURL+")")
	)
	// -p and --port both set the local listen port.
	var localPort string
	fs.StringVar(&localPort, "p", "0", "local TCP port to listen on")
	fs.StringVar(&localPort, "port", "0", "local TCP port to listen on [alias of -p]")
	fs.Usage = func() { usageAccess(fs) }

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
		return runAccessFromConfig(*configPath)
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

	remote, err := access.ParseRemote(remote)
	if err != nil {
		return err
	}

	// Refused rather than ranked. Both name a credential, and silently preferring
	// one presents a principal the caller did not ask for.
	if *audience != "" && (*pemFile != "" || *p12File != "") {
		return fmt.Errorf("--audience uses the CI platform's own identity, so it cannot be combined with --pem or --p12")
	}

	// Decided before the signal handler is installed, because deciding it may
	// prompt, and a blocking read on stdin does not unblock on context
	// cancellation. Resolving later would leave Ctrl-C at the prompt hanging.
	var chosen *identity.Ref
	if *pemFile == "" && *p12File == "" && *audience == "" && os.Getenv(identity.AudienceEnv) == "" {
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
	switch {
	case *audience != "" || (*pemFile == "" && *p12File == "" && os.Getenv(identity.AudienceEnv) != ""):
		// In CI the platform mints the credential and we exchange it for a
		// short-lived certificate held in memory. Nothing on disk to rotate.
		tlsCfg, source, err = workloadTLSConfig(ctx, *audience, *apiURL, remote, *serverName)
	case *pemFile == "" && *p12File == "":
		// No credential file named: present the identity this machine holds.
		tlsCfg, source, err = identityTLSConfig(ctx, *chosen, remote, *serverName)
	default:
		// The password is only resolved for --p12. Reading it on the --pem path
		// would fail a PEM run on a box where LOCALPORT_P12_PASSWORD happens
		// to be set, over a flag the caller never passed.
		var password string
		if *p12File != "" {
			password, err = resolveP12Password(*p12Pass, *p12PassFile, *p12PassEnv)
		}
		if err == nil {
			tlsCfg, err = access.BuildTLSConfig(*pemFile, *p12File, password, remote, *serverName)
			source = "file"
		}
	}
	if err != nil {
		return err
	}

	listen := fmt.Sprintf("%s:%s", *localAddr, localPort)
	proxy := &access.Proxy{
		Remote:    remote,
		LocalAddr: listen,
		TLSConfig: tlsCfg,
		OnConn:    func(l, r string) { fmt.Fprintf(os.Stderr, "  [conn] %s -> %s\n", l, r) },
		OnError:   func(err error) { fmt.Fprintln(os.Stderr, "  [error]", err) },
	}
	fmt.Fprintln(os.Stderr, "  localport access")
	fmt.Fprintf(os.Stderr, "  listening on %s -> %s (mTLS, %s)\n", listen, remote, source)

	return proxy.Run(ctx)
}

// identityTLSConfig presents the stored credential and keeps it fresh. The
// certificate comes through a callback rather than being copied into the config,
// so a renewal by this process or by `localport identity renew` is picked up on
// the next handshake without a restart.
func identityTLSConfig(ctx context.Context, ref identity.Ref, remote, serverName string) (*tls.Config, string, error) {
	store, err := identity.DefaultStore()
	if err != nil {
		return nil, "", err
	}
	// Opened by exact Ref, since resolveCredential is the one place precedence
	// and ambiguity are decided.
	cred, err := identity.OpenRef(store, ref)
	if err != nil {
		return nil, "", fmt.Errorf("%w\n  (or pass a credential file with --pem / --p12)", err)
	}
	// A refused reload means the file now holds a different principal. The process
	// keeps presenting what it opened with, so the refusal must be visible.
	cred.OnSwap(func(line string) { fmt.Fprintf(os.Stderr, "  [identity] %s\n", line) })

	cfg := access.BaseTLSConfig(remote, serverName)
	cfg.GetClientCertificate = cred.GetClientCertificate

	meta := cred.Meta()
	if !meta.Source.Renewable() {
		// No renewal loop, so say when it ends. Otherwise it stops being accepted
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

// workloadTLSConfig exchanges the CI platform's token for a certificate and
// keeps it in memory. No file is written and no renewal loop starts: the
// certificate is scoped to the life of this process.
func workloadTLSConfig(ctx context.Context, audience, apiURL, remote, serverName string) (*tls.Config, string, error) {
	if audience == "" {
		audience = strings.TrimSpace(os.Getenv(identity.AudienceEnv))
	}

	token, err := identity.FetchWorkloadToken(ctx, audience)
	if err != nil {
		return nil, "", err
	}
	client, err := identity.NewClient(resolveAPIURL(apiURL))
	if err != nil {
		return nil, "", err
	}
	material, err := client.ExchangeWorkloadToken(ctx, token)
	if err != nil {
		// The platform token is a bearer credential for its few minutes; keep it
		// out of any log the CI system captures.
		return nil, "", security.SanitizeError(err, token)
	}

	cert, err := material.TLSCertificate()
	if err != nil {
		return nil, "", fmt.Errorf("load workload certificate: %w", err)
	}
	cfg := access.BaseTLSConfig(remote, serverName)
	cfg.Certificates = []tls.Certificate{*cert}
	return cfg, "ci identity " + material.Meta.Identity, nil
}

func runAccessFromConfig(path string) error {
	cc, err := access.LoadAccessConfig(path)
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
		remote, err := access.ParseRemote(c.Remote)
		if err != nil {
			cancel()
			return fmt.Errorf("connection %q: %w", c.Name, err)
		}

		var tlsCfg *tls.Config
		if c.UsesIdentity() {
			// Never interactive, because this loop builds several connections and
			// prompting would ask once per entry.
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
				tlsCfg, err = access.BuildTLSConfig(c.Bundle, c.P12, password, remote, "")
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
		proxy := &access.Proxy{
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

// minPasswordLength is the length of the passwords we issue with an archive.
const minPasswordLength = 12

// resolveP12Password reads the password in order, flag then file then env var.
// An empty string is not an error, so a passwordless archive still opens; one
// that needs a password fails at decode.
func resolveP12Password(inline, filePath, envName string) (string, error) {
	switch {
	case inline != "":
		return noteWeakPassword(inline), nil
	case filePath != "":
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read p12 password file: %w", err)
		}
		return noteWeakPassword(strings.TrimSpace(string(data))), nil
	}
	if envName == "" {
		envName = defaultP12PasswordEnv
	}
	v, ok := os.LookupEnv(envName)
	if !ok || v == "" {
		return "", nil
	}
	return noteWeakPassword(v), nil
}

// noteWeakPassword warns and carries on. It never refuses, because an archive
// exported elsewhere is the holder's own key management, and rejecting it here
// would block a working credential over a rule that applies to ours.
func noteWeakPassword(p string) string {
	if len(p) > 0 && len(p) < minPasswordLength {
		fmt.Fprintf(os.Stderr, "  warning: PKCS#12 password is under %d characters\n", minPasswordLength)
	}
	return p
}

func signalCtx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()
	return ctx, cancel
}

func usageAccess(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `Usage: localport access <URL> --pem <file> -p <local-port> [flags]
       localport access <URL> --p12 <file> -p <local-port> [flags]
       localport access --config access.yaml

  Reach a locked (mTLS) tunnel. Presents your client certificate and forwards a
  local port to it. Paste the tunnel URL in whatever form you copied it.

  <URL> The scheme picks the port and nothing else. This connection is always
  TLS, whatever the tunnel carries.
    https://sub.eu.localport.dev          -> :443
    tcp://sub.eu.localport.dev:5432       -> :5432
    tls://sub.eu.localport.dev:5432       -> :5432
    sub.eu.localport.dev:5432             -> bare host:port also works

  Credentials. With no flag, the identity this machine holds is used and
  renewed in the background, so there is no file to copy and nothing that
  expires while somebody is on holiday. Supply a file only for a credential we
  did not issue.
    (none)              the stored identity (localport setup <TOKEN>)
    --audience          CI, the pipeline's own OIDC identity, no secret at all
    --pem               PEM file with client cert + key + tunnel CA
    --p12               PKCS#12 archive (password via --p12-pass-env / -file)

  Examples:
    localport setup lps_...            # once per machine
    localport access https://gateway-warehouse.eu.localport.dev -p 3001

    localport access https://gateway-warehouse.eu.localport.dev --pem client.pem -p 3001
    localport access tcp://db-warehouse.eu.localport.dev:5432 --pem db.pem --port 5432
    LOCALPORT_P12_PASSWORD=... \
      localport access https://gateway-warehouse.eu.localport.dev --p12 client.p12 -p 3001
    localport access --config access.yaml   # many targets at once

  From CI, with nothing stored anywhere. On GitHub Actions add
  "permissions: { id-token: write }" to the job, and the certificate is obtained
  from the runner's own identity and kept in memory.

    localport access tcp://gateway-warehouse.eu.localport.dev:22 \
      --audience lpa_... -p 2222

  Other platforms: put the token in LOCALPORT_OIDC_TOKEN and the audience in
  LOCALPORT_OIDC_AUDIENCE.

Flags:
`)
	fs.PrintDefaults()
}
