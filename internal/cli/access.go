package cli

import (
	"context"
	"crypto/tls"
	"errors"
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
		pemFile     = fs.String("pem", "", "PEM file (client cert + key + fleet CA)")
		p12File     = fs.String("p12", "", "PKCS#12 archive (.p12 / .pfx)")
		p12Pass     = fs.String("p12-pass", "", "PKCS#12 password (use --p12-pass-env in production)")
		p12PassEnv  = fs.String("p12-pass-env", defaultP12PasswordEnv, "env var carrying the PKCS#12 password (required for Localport-issued .p12)")
		p12PassFile = fs.String("p12-pass-file", "", "file containing the PKCS#12 password")
		localAddr   = fs.String("local-addr", "127.0.0.1", "local bind address")
		stdio       = fs.Int("stdio", 0, "carry one connection to this device port over stdin and stdout, for ssh ProxyCommand")
		configPath  = fs.String("config", "", "path to an access YAML config")
		identityArg = fs.String("identity", "", "credential to present: `<identity>`, <team>/<identity> or <team>/<kind>/<identity>")
		audience    = fs.String("audience", "", "OIDC audience for a CI workload identity (or "+identity.AudienceEnv+")")
		apiURL      = fs.String("api", "", "control plane base URL (CI identity only; default "+identity.DefaultAPIURL+")")
	)
	// -L is repeatable, one listener per device port.
	var forwards stringList
	fs.Var(&forwards, "L", "forward `[local:]remote`, repeatable (5020:502, or 502 for an OS-picked local port)")
	fs.Usage = func() { usageAccess(fs) }

	// The remote is positional, before or after the flags.
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
			return errors.New("remote address required")
		}
		remote = fs.Arg(0)
	}
	if (remoteFromHead == "" && fs.NArg() > 1) || (remoteFromHead != "" && fs.NArg() > 0) {
		fs.Usage()
		return errors.New("unexpected extra positional arguments")
	}

	deviceHost, deviceAddr, err := access.ParseDevice(remote)
	if err != nil {
		return err
	}
	if len(forwards) == 0 && *stdio == 0 {
		fs.Usage()
		return errors.New("pass -L <local>:<remote>, or --stdio <port>")
	}
	if len(forwards) > 0 && *stdio != 0 {
		return errors.New("--stdio carries one connection, so it cannot be combined with -L")
	}
	parsedForwards := make([]access.Forward, 0, len(forwards))
	for _, raw := range forwards {
		f, parseErr := access.ParseForward(raw, *localAddr)
		if parseErr != nil {
			return parseErr
		}
		parsedForwards = append(parsedForwards, f)
	}

	src, err := pickCredentialSource(*pemFile, *p12File, *audience)
	if err != nil {
		return err
	}

	// Resolve before installing the signal handler. Resolving may prompt, and
	// a blocked stdin read ignores context cancellation, so Ctrl-C at the
	// prompt must use the default handler.
	var chosen identity.Ref
	if src == credentialStored {
		store, storeErr := identity.DefaultStore()
		if storeErr != nil {
			return storeErr
		}
		chosen, err = resolveCredential(store, firstNonEmpty(*identityArg, os.Getenv(identityEnv)), true)
		if err != nil {
			return fmt.Errorf("%w\n  (or pass a credential file with --pem / --p12)", err)
		}
	}

	ctx, cancel := signalCtx()
	defer cancel()

	var (
		tlsCfg *tls.Config
		source string
	)
	switch src {
	case credentialWorkload:
		// Exchange the CI platform token for a short-lived in-memory
		// certificate.
		tlsCfg, source, err = workloadTLSConfig(ctx, *audience, *apiURL, deviceAddr, deviceHost)
	case credentialStored:
		tlsCfg, source, err = identityTLSConfig(ctx, chosen, deviceAddr, deviceHost)
	case credentialFile:
		// Resolve the password only for --p12, so a stray
		// LOCALPORT_P12_PASSWORD cannot fail a --pem run.
		var password string
		if *p12File != "" {
			password, err = resolveP12Password(*p12Pass, *p12PassFile, *p12PassEnv)
		}
		if err == nil {
			tlsCfg, err = access.BuildTLSConfig(*pemFile, *p12File, password, deviceAddr, deviceHost)
			source = "file"
		}
	}
	if err != nil {
		return err
	}

	session := &access.Session{Device: deviceHost, Addr: deviceAddr, TLSConfig: tlsCfg}
	defer session.Close()

	proxy := &access.Proxy{
		Session:  session,
		Forwards: parsedForwards,
		OnListen: func(f access.Forward, addr string) {
			fmt.Fprintf(os.Stderr, "  %s -> %s:%d\n", addr, deviceHost, f.RemotePort)
		},
		OnConn: func(l string, port uint16) {
			fmt.Fprintf(os.Stderr, "  [conn] %s -> port %d\n", l, port)
		},
		OnError: func(err error) { fmt.Fprintln(os.Stderr, "  [error]", err) },
	}

	if *stdio != 0 {
		if *stdio < 1 || *stdio > 65535 {
			return errors.New("--stdio port must be 1-65535")
		}
		return proxy.ServeStdio(ctx, os.Stdin, os.Stdout, uint16(*stdio))
	}

	fmt.Fprintln(os.Stderr, "  localport access")
	fmt.Fprintf(os.Stderr, "  %s (mTLS, %s)\n", deviceHost, source)
	return proxy.Run(ctx)
}

// credentialSource is the credential `localport access` presents.
type credentialSource int

const (
	// credentialStored presents the stored identity from `localport setup`
	// or `localport login`.
	credentialStored credentialSource = iota
	// credentialWorkload exchanges the CI platform's OIDC token for a
	// short-lived certificate held in memory.
	credentialWorkload
	// credentialFile presents --pem or --p12.
	credentialFile
)

// pickCredentialSource resolves the flags to one source. The resolve and
// config steps both call it so they agree.
func pickCredentialSource(pemFile, p12File, audience string) (credentialSource, error) {
	fileNamed := pemFile != "" || p12File != ""
	// Both flags name a credential. Picking one would present a principal the
	// caller did not choose, so the combination is an error.
	if audience != "" && fileNamed {
		return 0, errors.New("--audience uses the CI platform's own identity, so it cannot be combined with --pem or --p12")
	}
	switch {
	case fileNamed:
		return credentialFile, nil
	case audience != "" || os.Getenv(identity.AudienceEnv) != "":
		return credentialWorkload, nil
	default:
		return credentialStored, nil
	}
}

// stringList collects a repeatable flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
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

// workloadTLSConfig exchanges the CI platform token for a certificate held in
// memory for the life of the process. Nothing is written and nothing renews.
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
		// The platform token is a bearer credential. Keep it out of CI logs.
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
	for _, entry := range cc.Access {
		deviceHost, deviceAddr, parseErr := access.ParseDevice(entry.Device)
		if parseErr != nil {
			cancel()
			return fmt.Errorf("device %q: %w", entry.Device, parseErr)
		}

		forwards := make([]access.Forward, 0, len(entry.Forward))
		for _, raw := range entry.Forward {
			f, forwardErr := access.ParseForward(raw, "127.0.0.1")
			if forwardErr != nil {
				cancel()
				return fmt.Errorf("device %q: %w", entry.Device, forwardErr)
			}
			forwards = append(forwards, f)
		}

		var tlsCfg *tls.Config
		if entry.UsesIdentity() {
			// Not interactive. This loop builds one session per entry.
			var ref identity.Ref
			if ref, err = resolveCredential(store, entry.Identity, false); err == nil {
				tlsCfg, _, err = identityTLSConfig(ctx, ref, deviceAddr, deviceHost)
			}
		} else {
			var password string
			if entry.P12 != "" {
				password, err = resolveP12Password(entry.P12Pass, entry.P12PassFile, entry.P12PassEnv)
			}
			if err == nil {
				tlsCfg, err = access.BuildTLSConfig(entry.PEM, entry.P12, password, deviceAddr, deviceHost)
			}
		}
		if err != nil {
			cancel()
			return fmt.Errorf("device %q: %w", entry.Device, err)
		}

		session := &access.Session{Device: deviceHost, Addr: deviceAddr, TLSConfig: tlsCfg}
		defer session.Close()

		name := deviceHost
		proxy := &access.Proxy{
			Session:  session,
			Forwards: forwards,
			OnListen: func(f access.Forward, addr string) {
				fmt.Fprintf(os.Stderr, "  [%s] %s -> port %d\n", name, addr, f.RemotePort)
			},
			OnConn: func(l string, port uint16) {
				fmt.Fprintf(os.Stderr, "  [%s] [conn] %s -> port %d\n", name, l, port)
			},
			OnError: func(err error) { fmt.Fprintf(os.Stderr, "  [%s] [error] %s\n", name, err) },
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if runErr := proxy.Run(ctx); runErr != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = runErr
				}
				errMu.Unlock()
				fmt.Fprintf(os.Stderr, "  [%s] error: %s\n", name, runErr)
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
	fmt.Fprint(os.Stderr, `Usage: localport access <device-host> -L [local:]remote [flags]
       localport access <device-host> --stdio <port> [flags]
       localport access --config access.yaml

  Reach a fleet device's ports. Every forward runs over one mTLS connection to
  the device, and the ports it serves are set in the dashboard.

  -L  [local:]remote, repeatable.
        -L 5020:502      listen on 5020, reach the device's port 502
        -L 502           reach 502 on a local port the system picks

  --stdio  Carry one connection over stdin and stdout, for ssh:
        ssh -o ProxyCommand="localport access plc-01.ap.localport.dev --stdio 22" user@plc-01

  Credentials. With no flag, the identity this machine holds is used and
  renewed in the background, so there is no file to copy and nothing that
  expires while somebody is on holiday. Supply a file only for a credential we
  did not issue.
    (none)              the stored identity (localport setup <TOKEN>)
    --audience          CI, the pipeline's own OIDC identity, no secret at all
    --pem               PEM file with client cert + key + fleet CA
    --p12               PKCS#12 archive (password via --p12-pass-env / -file)

  Examples:
    localport setup lps_...            # once per machine
    localport access plc-01-factory.ap.localport.dev -L 5020:502 -L 8080:80

    localport access plc-01-factory.ap.localport.dev --pem client.pem -L 502
    LOCALPORT_P12_PASSWORD=... \
      localport access plc-01-factory.ap.localport.dev --p12 client.p12 -L 502
    localport access --config access.yaml   # several devices at once

  From CI, with nothing stored anywhere. On GitHub Actions add
  "permissions: { id-token: write }" to the job, and the certificate is obtained
  from the runner's own identity and kept in memory.

    localport access gw-01-factory.ap.localport.dev --audience lpa_... -L 2222:22

  Other platforms: put the token in LOCALPORT_OIDC_TOKEN and the audience in
  LOCALPORT_OIDC_AUDIENCE.

Flags:
`)
	fs.PrintDefaults()
}
