package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/localport/agent/internal/identity"
)

// `localport login` signs a PERSON in and returns a short-lived certificate.
//
// The machine counterpart is `localport enroll`, which spends one token and then
// renews itself. There is no renewal loop here. Re-running the command is how a
// person gets a fresh certificate.
//
// Nothing needs to reach the machine beforehand, which is what makes this work
// over SSH where a browser redirect to localhost does not.
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

	ctx, cancel := signalCtx()
	defer cancel()

	material, err := client.Login(ctx, func(p identity.LoginPrompt) {
		// stderr, so the command stays pipeable and the code still shows.
		//
		// The prefilled link leads because it is one click. The bare address and
		// the code follow for when the browser is on another device. The code
		// stays visible so it can be checked against the approval screen, which
		// is the step that catches somebody else's sign-in.
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
	// There is no renewal loop and the expiry is hours away, so say it here
	// rather than let it surface as a failed connection overnight.
	fmt.Fprintf(os.Stderr, "  renews     never; run `localport login` again when it expires\n")
	fmt.Fprintf(os.Stderr, "\n  next: localport connect https://<device>.<region>.localport.dev -p 3001\n")
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
For a machine that should renew itself, use `+"`localport enroll`"+` instead.
`)
}
