package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
)

// setupTokenEnv keeps the setup token off the command line. An argument is
// visible in shell history and in `ps` to every local account, which for a
// single-use credential on a provisioning run is exactly the wrong place.
const setupTokenEnv = "LOCALPORT_SETUP_TOKEN"

// `localport setup <TOKEN>` redeems a setup token and keeps the credential.
//
// This is the once-per-machine command. Everything after it is automatic: the
// certificate renews itself, so there is no long-lived secret left on the box
// and nothing to rotate by hand.
func runSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	token := fs.String("token", "", "setup token (or "+setupTokenEnv+")")
	apiURL := fs.String("api", "", "control plane base URL (default "+identity.DefaultAPIURL+")")
	wait := fs.Duration("wait", identity.DefaultRetryBudget,
		"how long to keep retrying while the control plane is unreachable (0 = one attempt)")
	fs.Usage = usageSetup

	// The token is accepted as a leading positional, because that is what the
	// dashboard shows.
	positional := ""
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		positional, rest = args[0], args[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if positional == "" && fs.NArg() > 0 {
		positional = fs.Arg(0)
	}

	secret := positional
	if secret == "" {
		resolved, err := security.ResolveOptionalToken(*token, setupTokenEnv)
		if err != nil {
			return err
		}
		secret = resolved
	}
	if secret == "" {
		usageSetup()
		return fmt.Errorf("setup token required (argument, --token, or %s)", setupTokenEnv)
	}

	client, err := identity.NewClient(resolveAPIURL(*apiURL))
	if err != nil {
		return err
	}
	store, err := identity.DefaultStore()
	if err != nil {
		return err
	}

	ctx, cancel := signalCtx()
	defer cancel()

	notice := func(attempt int, in time.Duration, err error) {
		fmt.Fprintf(os.Stderr, "  control plane unreachable (attempt %d), retrying in %s\n",
			attempt, in.Round(time.Second))
	}
	material, err := client.RedeemSetupToken(ctx, secret, *wait, notice)
	if err != nil {
		// The token is single-use and the error may quote the request. Never let
		// it reach a terminal or a CI log.
		return security.SanitizeError(err, secret)
	}
	ref, err := store.Save(*material)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\n  set up\n")
	printCredential(store, ref, material.Meta)
	if due, renews := material.Meta.NextRenewal(); renews {
		fmt.Fprintf(os.Stderr, "  renews     %s\n", due.Format(time.RFC3339))
	}
	fmt.Fprintf(os.Stderr, "\n  next: localport connect https://<device>.<region>.localport.dev -p 3001\n")
	return nil
}

func usageSetup() {
	fmt.Fprint(os.Stderr, `Usage: localport setup <TOKEN> [--wait <duration>] [--api <url>]

  Redeem a setup token and keep the credential this machine will present to
  reach locked (mTLS) tunnels.

  An operator creates a setup token in the dashboard and gives you one string.
  This machine spends it once, keeps a private key that never leaves it, and
  renews itself from then on, so there is no long-lived secret to rotate and
  no certificate file to copy around.

    localport setup lps_...
    localport connect https://gw-01.eu.localport.dev -p 3001

  The token is single-use. Prefer the environment over an argument, which is
  visible in shell history and to "ps":

    LOCALPORT_SETUP_TOKEN=lps_... localport setup

  LOCALPORT_SETUP_TOKEN_FILE names a file to read it from instead, which is what
  systemd LoadCredential= and docker secrets provide.

  Credentials live under ~/.localport/identity/<team>/, one directory per
  identity (0700, keys 0600). Set LOCALPORT_HOME to keep them elsewhere; a
  service with no home directory falls back to a machine-wide state directory.

  --wait covers a box that boots before its network is ready. The command keeps
  retrying an unreachable control plane for that long, with backoff. A refused
  token is not retried at any setting, it fails immediately. Use --wait 0 in
  CI to make exactly one attempt.

  --api and `+identity.APIURLEnv+` point the agent at a different control plane.
  There is one in production and this is not something a customer needs, it
  exists for development against a local build. The value is remembered, so
  renewal needs it only once.
`)
}
