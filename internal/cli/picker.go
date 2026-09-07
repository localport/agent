package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/ui"
)

// resolveCredential picks the credential a command presents:
//
//	--identity > LOCALPORT_IDENTITY > interactive choice > error
//
// A supplied selector matching zero or several is an error, never a prompt: a
// typo must not open a menu that picks a principal. interactive is false for
// --config and anywhere a person may not be watching.
func resolveCredential(store *identity.Store, raw string, interactive bool) (identity.Ref, error) {
	sel, err := identity.ParseSelector(raw)
	if err != nil {
		return identity.Ref{}, err
	}

	// A selector was supplied: it decides, or it fails. No prompt.
	if raw != "" {
		return store.Resolve(sel)
	}

	refs, err := store.List()
	if err != nil {
		return identity.Ref{}, err
	}
	switch len(refs) {
	case 1:
		return refs[0], nil
	case 0:
		return store.Resolve(sel) // one place builds the "nothing here" message
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
	b.WriteString("several credentials on this machine; choose one with --identity:\n")
	for _, r := range refs {
		b.WriteString("    --identity " + r.String() + "\n")
	}
	b.WriteString("\n  (a bare name or <team>/<name> works too when it names only one)")
	return fmt.Errorf("%s", b.String())
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
			return identity.Ref{}, fmt.Errorf("no credential chosen")
		}
		n, convErr := strconv.Atoi(strings.TrimSpace(line))
		if convErr != nil || n < 1 || n > len(refs) {
			fmt.Fprintf(out, "  Enter a number between 1 and %d.\n", len(refs))
			continue
		}
		return refs[n-1], nil
	}
}
