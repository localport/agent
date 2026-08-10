package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/localport/agent/internal/identity"
)

// identityEnv selects a credential when a machine holds several.
const identityEnv = "LOCALPORT_IDENTITY"

func runIdentity(args []string) error {
	if len(args) == 0 {
		usageIdentity()
		return fmt.Errorf("identity: subcommand required")
	}
	switch args[0] {
	case "list":
		return runIdentityList(args[1:])
	case "renew":
		return runIdentityRenew(args[1:])
	case "help", "--help", "-h":
		usageIdentity()
		return nil
	default:
		usageIdentity()
		return fmt.Errorf("identity: unknown subcommand %q", args[0])
	}
}

// runIdentityList prints every credential on this machine. The table goes to
// STDOUT, unlike every other message in the agent: it is queryable output, not
// progress commentary.
func runIdentityList(args []string) error {
	fs := flag.NewFlagSet("identity list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	selector := fs.String("identity", "", "narrow to one credential")
	fs.Usage = usageIdentity
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := identity.DefaultStore()
	if err != nil {
		return err
	}
	sel, err := identity.ParseSelector(firstNonEmpty(*selector, os.Getenv(identityEnv)))
	if err != nil {
		return err
	}
	refs, err := store.List()
	if err != nil {
		return err
	}

	now := time.Now()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IDENTITY\tKIND\tTEAM\tSOURCE\tEXPIRES\tRENEWS")
	shown := 0
	for _, ref := range refs {
		if !sel.Matches(ref) {
			continue
		}
		m, loadErr := store.Load(ref)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v\n", ref, loadErr)
			continue
		}
		shown++

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			ref.Identity, ref.Kind.Label(), ref.Team,
			m.Meta.Source, humanUntil(now, m.Meta.NotAfter), humanUntil(now, m.Meta.RenewAfter))
	}
	if err := w.Flush(); err != nil {
		return err
	}

	if shown == 0 {
		if len(refs) == 0 {
			fmt.Fprintf(os.Stderr, "\n  no credential on this machine\n")
			fmt.Fprintf(os.Stderr, "  run: localport enroll <TOKEN>\n")
		} else {
			fmt.Fprintf(os.Stderr, "\n  no credential matches; this machine holds:\n")
			for _, ref := range refs {
				fmt.Fprintf(os.Stderr, "    %s\n", ref)
			}
		}
	}
	return nil
}

func runIdentityRenew(args []string) error {
	fs := flag.NewFlagSet("identity renew", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	selector := fs.String("identity", "", "credential to renew")
	fs.Usage = usageIdentity
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := identity.DefaultStore()
	if err != nil {
		return err
	}
	sel, err := identity.ParseSelector(firstNonEmpty(*selector, os.Getenv(identityEnv)))
	if err != nil {
		return err
	}
	ref, err := store.Resolve(sel)
	if err != nil {
		return err
	}

	ctx, cancel := signalCtx()
	defer cancel()

	material, err := (&identity.Renewer{Store: store, Ref: ref}).RenewOnce(ctx)
	if errors.Is(err, identity.ErrRenewalInProgress) {
		// Not a failure: another process is already renewing, and a second
		// certificate would only be orphaned.
		fmt.Fprintf(os.Stderr, "  %s is already being renewed by another process\n", ref)
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  renewed %s, valid until %s\n", ref, material.Meta.NotAfter.Format(time.RFC3339))
	return nil
}

// printCredential reports what a credential is and where it landed.
func printCredential(store *identity.Store, ref identity.Ref, meta identity.Meta) {
	fmt.Fprintf(os.Stderr, "  identity   %s\n", meta.SpiffeID)
	fmt.Fprintf(os.Stderr, "  team       %s\n", ref.Team)
	fmt.Fprintf(os.Stderr, "  stored in  %s\n", store.Dir(ref))
	fmt.Fprintf(os.Stderr, "  expires    %s\n", meta.NotAfter.Format(time.RFC3339))
}

// humanUntil renders a deadline relative to now. "overdue" rather than a
// negative duration, which reads as arithmetic instead of a state to act on.
func humanUntil(now, t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	if d := time.Until(t); d > 0 {
		return "in " + d.Round(time.Minute).String()
	}
	return "overdue"
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

// renewalLoops records which credentials already have a renewal loop in this
// process. A config with five targets on one credential must not start five
// loops, which would renew it five times against its live-certificate cap.
var renewalLoops sync.Map

// startIdentityRenewal runs the renewal loop alongside a long-lived command, so
// a months-long `localport connect` needs no separate timer.
func startIdentityRenewal(ctx context.Context, store *identity.Store, ref identity.Ref) {
	if _, running := renewalLoops.LoadOrStore(ref, true); running {
		return
	}
	renewer := &identity.Renewer{
		Store:   store,
		Ref:     ref,
		OnEvent: func(line string) { fmt.Fprintf(os.Stderr, "  [identity] %s\n", line) },
	}
	go renewer.Run(ctx)
}

func usageIdentity() {
	fmt.Fprint(os.Stderr, `Usage: localport identity list  [--identity <selector>]
       localport identity renew [--identity <selector>]

  Inspect and manage the credentials this machine holds.

  Credentials arrive from "localport enroll <TOKEN>". They live under
  ~/.localport/identity/<team>/, one directory per identity, 0700 with keys
  0600. Set LOCALPORT_HOME to keep them elsewhere.

  A SELECTOR names one credential, in either of these forms:

    gw-01             a bare identity
    <team>/gw-01      narrowed to one team

  The shortest form that matches exactly one is enough; when several match, the
  error lists the full form of each so it can be pasted back. `+identityEnv+` sets
  a default.

  list    every credential, with team, source, expiry and when it renews.
          Prints to stdout so it can be piped.
  renew   force a renewal now. Renewal normally happens on its own inside
          "localport connect"; run this from a daily timer for a machine that is
          not always connected.
`)
}
