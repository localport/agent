package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/ui"
)

// resolveCredential picks the credential a command presents:
//
//	--identity > LOCALPORT_IDENTITY > interactive choice > error
//
// A supplied selector matching zero or several is an error, never a prompt: a
// typo must not open a menu that picks a principal. interactive is false for
// --config and anywhere a person may not be watching. consumer excludes
// device credentials.
func resolveCredential(store *identity.Store, raw string, interactive, consumer bool) (identity.Ref, error) {
	resolve, list := store.Resolve, store.List
	if consumer {
		resolve, list = store.ResolveConsumer, store.ListConsumers
	}
	sel, err := identity.ParseSelector(raw)
	if err != nil {
		return identity.Ref{}, err
	}

	// A selector was supplied: it decides, or it fails. No prompt.
	if raw != "" {
		return resolve(sel)
	}

	refs, err := list()
	if err != nil {
		return identity.Ref{}, err
	}
	switch len(refs) {
	case 1:
		return refs[0], nil
	case 0:
		return resolve(sel) // one place builds the "nothing here" message
	}

	if !interactive || !ui.IsTTY(os.Stdin) {
		return identity.Ref{}, ambiguous(refs)
	}
	return chooseCredential(os.Stdin, os.Stderr, store, refs)
}

// ambiguous is the non-interactive answer to "several match". It prints the
// exact --identity value per row, so the fix is a paste, and never reads stdin:
// a CI job blocked on a hidden prompt is worse than one that fails.
func ambiguous(refs []identity.Ref) error {
	var b strings.Builder
	for _, r := range refs {
		b.WriteString("\n    --identity " + r.String())
	}
	b.WriteString("\n\n  (a bare name or <team>/<name> works too when it names only one)")
	return errcode.New(errcode.CredentialsAmbiguous).With(nil, b.String())
}

// chooseCredential asks. A numbered list off stdin: no raw-mode terminal
// handling, and it works over SSH and inside `docker run -it`. The prompt goes
// to STDERR so stdout stays pipeable.
func chooseCredential(in io.Reader, out io.Writer, store *identity.Store, refs []identity.Ref) (identity.Ref, error) {
	fmt.Fprintf(out, "\n  Several credentials can reach this tunnel. Which one?\n\n")

	// A person is shown by username: the agent holds no personal data. The team
	// carries its id, which is what --identity accepts.
	tw := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	for i, r := range refs {
		team := r.Team
		if m, err := store.Load(r); err == nil {
			team = m.Meta.DisplayTeam()
		}
		fmt.Fprintf(tw, "    %d)\t%s\t%s\t%s\n", i+1, r.Identity, r.Kind.Label(), team)
	}
	if err := tw.Flush(); err != nil {
		return identity.Ref{}, err
	}

	reader := bufio.NewReader(in)
	for {
		fmt.Fprintf(out, "\n  Choose [1-%d]: ", len(refs))
		line, err := reader.ReadString('\n')
		if err != nil {
			// EOF or a closed terminal. Abort rather than default to a principal
			// nobody chose.
			fmt.Fprintln(out)
			return identity.Ref{}, errcode.New(errcode.NoCredentialChosen)
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(line))
		if convErr != nil || n < 1 || n > len(refs) {
			fmt.Fprintf(out, "  Enter a number between 1 and %d.\n", len(refs))
			continue
		}
		return refs[n-1], nil
	}
}

// pickerTTY reports whether up and down may ask which device; tests replace it.
var pickerTTY = func() bool { return ui.IsTTY(os.Stdin) && ui.IsTTY(os.Stderr) }

// selectDevices returns the indexes of devices that command (up or down) acts
// on: every one with all; the one selector names (identity, <team>/<prefix>,
// <tunnel>.<prefix> or a unique prefix); with no selector the only device, or
// with several and a terminal errChoiceNeeded (the caller asks with
// chooseDevices once it holds no lock), or else an error listing each exact
// command. No device at all is errNoDevice. It never reads stdin.
func selectDevices(devices []config.LocalDevice, selector string, all bool, command string) ([]int, error) {
	if len(devices) == 0 {
		return nil, errNoDevice
	}
	switch {
	case all:
		idx := make([]int, len(devices))
		for i := range devices {
			idx[i] = i
		}
		return idx, nil
	case selector != "":
		i, err := matchDevice(devices, selector)
		if err != nil {
			return nil, err
		}
		return []int{i}, nil
	case len(devices) == 1:
		return []int{0}, nil
	case !pickerTTY():
		return nil, ambiguousDevices(devices, command)
	}
	return nil, errChoiceNeeded
}

// errChoiceNeeded is selectDevices asking for a choice from the terminal.
var errChoiceNeeded = errors.New("a choice of device is needed")

// matchDevice is findDevice that also accepts <team>/<prefix>.
func matchDevice(devices []config.LocalDevice, selector string) (int, error) {
	if team, prefix, ok := strings.Cut(selector, "/"); ok && !strings.Contains(prefix, "/") {
		found := -1
		for i, d := range devices {
			_, p, _ := strings.Cut(d.Identity.Identity, ".")
			if d.Identity.Team != team || (p != prefix && d.Identity.Identity != prefix) {
				continue
			}
			if found >= 0 {
				return -1, errcode.New(errcode.DeviceAmbiguous).With(nil, fmt.Sprintf("%q; use the full identity", security.SanitizeDisplay(selector)))
			}
			found = i
		}
		if found >= 0 {
			return found, nil
		}
	}
	return findDevice(devices, selector)
}

// ambiguousDevices lists the exact command for each device and the --all
// form. command is the subcommand, up or down.
func ambiguousDevices(devices []config.LocalDevice, command string) error {
	prefix := elevatedLocalport() + " " + command
	var b strings.Builder
	if note := elevatedNote(); note != "" {
		b.WriteString(strings.TrimSpace(note) + ":")
	}
	for _, d := range devices {
		fmt.Fprintf(&b, "\n    %s %s", prefix, d.Identity)
	}
	fmt.Fprintf(&b, "\n    %s --all", prefix)
	return errcode.New(errcode.DeviceNotNamed).With(nil, b.String())
}

// chooseDevices asks on out and reads the answer from in: a number, or a for
// every device. EOF chooses nothing.
func chooseDevices(in io.Reader, out io.Writer, devices []config.LocalDevice, facts map[identity.Ref]deviceFact) ([]int, error) {
	fmt.Fprintf(out, "\n  Several devices are enrolled on this machine. Which one?\n\n")
	tw := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	for i, d := range devices {
		f := facts[d.Identity]
		target := d.Host
		if target == "" {
			target = "this machine"
		}
		state := "enabled"
		if d.Paused {
			state = "paused"
		}
		fmt.Fprintf(tw, "    %d)\t%s\t%s\t%s\t%s (%s)\t%s\n", i+1, d.Identity.Identity, valueOrUnknown(f.Host),
			security.SanitizeDisplay(target), valueOrUnknown(f.Team), d.Identity.Team, state)
	}
	fmt.Fprintf(tw, "    a)\tall\n")
	if err := tw.Flush(); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(in)
	for {
		fmt.Fprintf(out, "\n  Choose [1-%d or a]: ", len(devices))
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintln(out)
			return nil, errcode.New(errcode.NoDeviceChosen)
		}
		answer := strings.TrimSpace(line)
		if answer == "a" {
			idx := make([]int, len(devices))
			for i := range devices {
				idx[i] = i
			}
			return idx, nil
		}
		n, convErr := strconv.Atoi(answer)
		if convErr != nil || n < 1 || n > len(devices) {
			fmt.Fprintf(out, "  Enter a number between 1 and %d, or a.\n", len(devices))
			continue
		}
		return []int{n - 1}, nil
	}
}
