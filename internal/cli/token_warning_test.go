package cli

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/ui"
)

// captureStderr returns what fn writes to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// A token from -t/--token is reported once, as a plain-mode startup warning.
func TestTokenFlagWarningIsAPlainModeStartupLine(t *testing.T) {
	out := captureStderr(t, func() { warnTokenFlag(ui.NewPlain(), true) })
	if !strings.Contains(out, " warning --token is readable by other local accounts") {
		t.Fatalf("plain mode should log the warning, got %q", out)
	}
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("want one line, got %d: %q", n, out)
	}

	if out := captureStderr(t, func() { warnTokenFlag(ui.NewPlain(), false) }); out != "" {
		t.Fatalf("a token from the environment or a file must not warn, got %q", out)
	}
}

// The TUI prints nothing, neither before the frame opens nor after it closes.
func TestTokenFlagWarningIsNotShownInTheTUI(t *testing.T) {
	if out := captureStderr(t, func() { warnTokenFlag(ui.NewTUI(), true) }); out != "" {
		t.Fatalf("the TUI must not print the warning, got %q", out)
	}
}

// Resolving a token writes nothing. Commands decide whether to warn.
func TestResolveTokenPrintsNothing(t *testing.T) {
	out := captureStderr(t, func() {
		if _, err := security.ResolveToken("tok_flag", "LOCALPORT_TOKEN"); err != nil {
			t.Fatal(err)
		}
	})
	if out != "" {
		t.Fatalf("ResolveToken wrote %q", out)
	}
}
