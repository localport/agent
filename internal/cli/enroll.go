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

// enrollTokenEnv keeps the setup token off the command line. An argument is
// visible in shell history and in `ps` to every local account, which for a
// single-use credential on a provisioning run is exactly the wrong place.
const enrollTokenEnv = "LOCALPORT_ENROLL_TOKEN"

// `localport enroll <TOKEN>` redeems a setup token and keeps the credential.
//
// This is the once-per-machine command. Everything after it is automatic: the
// certificate renews itself, so there is no long-lived secret left on the box
// and nothing to rotate by hand.
func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	token := fs.String("token", "", "setup token (or "+enrollTokenEnv+")")
	apiURL := fs.String("api", "", "control plane base URL (default "+identity.DefaultAPIURL+")")
	fs.Usage = usageEnroll

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
		resolved, err := security.ResolveOptionalToken(*token, enrollTokenEnv)
		if err != nil {
			return err
		}
		secret = resolved
	}
	if secret == "" {
		usageEnroll()
		return fmt.Errorf("setup token required (argument, --token, or %s)", enrollTokenEnv)
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

	material, err := client.RedeemSetupToken(ctx, secret)
	if err != nil {
		// The token is single-use and the error may quote the request. Never let
		// it reach a terminal or a CI log.
		return security.SanitizeError(err, secret)
	}
	ref, err := store.Save(*material)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\n  enrolled\n")
	printCredential(store, ref, material.Meta)
	fmt.Fprintf(os.Stderr, "  renews     %s\n", material.Meta.RenewAfter.Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "\n  next: localport connect https://<device>.<region>.localport.dev -p 3001\n")
	return nil
}

// printCredential reports what a credential is and where it landed.
func printCredential(store *identity.Store, ref identity.Ref, meta identity.Meta) {
	fmt.Fprintf(os.Stderr, "  identity   %s\n", meta.SpiffeID)
	fmt.Fprintf(os.Stderr, "  team       %s\n", ref.Team)
	fmt.Fprintf(os.Stderr, "  stored in  %s\n", store.Dir(ref))
	fmt.Fprintf(os.Stderr, "  expires    %s\n", meta.NotAfter.Format(time.RFC3339))
}

func resolveAPIURL(flagValue string) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv(identity.APIURLEnv)); v != "" {
		return v
	}
	return identity.DefaultAPIURL
}

func usageEnroll() {
	fmt.Fprint(os.Stderr, `Usage: localport enroll <TOKEN> [--api <url>]

  Redeem a setup token and keep the credential this machine will present to
  reach locked (mTLS) tunnels.

  An operator creates a setup token in the dashboard and gives you one string.
  This machine spends it ONCE, keeps a private key that never leaves it, and
  renews itself from then on, so there is no long-lived secret to rotate and no
  certificate file to copy around.

    localport enroll lps_...
    localport connect https://gw-01.eu.localport.dev -p 3001

  The token is single-use. Prefer the environment over an argument, which is
  visible in shell history and to "ps":

    LOCALPORT_ENROLL_TOKEN=lps_... localport enroll

  LOCALPORT_ENROLL_TOKEN_FILE names a file to read it from instead, which is
  what systemd LoadCredential= and docker secrets provide.

  Credentials live under ~/.localport/identity/<team>/, one directory per
  identity (0700, keys 0600). Set LOCALPORT_HOME to keep them elsewhere; a
  service with no home directory falls back to a machine-wide state directory.
`)
}
