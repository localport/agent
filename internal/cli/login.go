package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/localport/agent/internal/identity"
)

// `localport login` signs a person in with the device flow and stores a
// short-lived certificate. It does not renew. Running it again issues a new
// certificate. The device flow needs no localhost callback, so it works over
// SSH.
func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	apiURL := fs.String("api", "", "control plane base URL (default "+identity.DefaultAPIURL+")")
	fs.Usage = usageLogin
	if err := fs.Parse(args); err != nil {
		return err
	}

	client, err := identity.NewClient(resolveAPIURL(*apiURL))
	if err != nil {
		return err
	}
	store, err := identity.DefaultStore()
	if err != nil {
		return err
	}

	ctx, cancel := signalContext(nil)
	defer cancel()

	material, err := client.Login(ctx, func(p identity.LoginPrompt) {
		// Printed to stderr so stdout stays pipeable. The prefilled link comes
		// first. The bare address and code serve a browser on another device,
		// and the code lets the user match the approval screen.
		if p.VerificationURIComplete != "" {
			fmt.Fprintf(os.Stderr, "\n  Open %s\n", p.VerificationURIComplete)
			fmt.Fprintf(os.Stderr, "  or go to %s and enter  %s\n\n", p.VerificationURI, p.UserCode)
		} else {
			fmt.Fprintf(os.Stderr, "\n  Open %s\n", p.VerificationURI)
			fmt.Fprintf(os.Stderr, "  Enter code  %s\n\n", p.UserCode)
		}
		fmt.Fprintf(os.Stderr, "  Waiting for you to sign in...\n")
	})
	if err != nil {
		return err
	}
	ref, err := store.Save(*material)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\n  signed in\n")
	printCredential(store, ref, material.Meta)
	// The certificate expires in hours and does not renew. Print the expiry.
	fmt.Fprintf(os.Stderr, "  renews     never; run `localport login` again when it expires\n")
	fmt.Fprintf(os.Stderr, "\n  next: localport access <device>-<fleet>.<region>.localport.dev -L 5020:502\n")
	fmt.Fprintf(os.Stderr, "        one -L per port, <local>:<device>. The device's open ports are in the dashboard.\n")
	return nil
}

func usageLogin() {
	fmt.Fprint(os.Stderr, `Usage: localport login [flags]

Sign in and receive a short-lived client certificate for reaching devices.

Prints a code, you approve it in the dashboard in any browser, and the
certificate lands on this machine. Nothing needs to be copied here first,
so it works over SSH into a jump box.

Flags:
  --api <url>   control plane base URL (advanced)

The certificate expires in hours. Run this again when it does.
For a machine that should renew itself, use `+"`localport setup`"+` instead.
`)
}
