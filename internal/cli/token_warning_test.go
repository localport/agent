package cli

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/ports"
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

// warnNoPortCeiling logs one line per device without a ceiling.
func TestWarnsWithoutAllowPorts(t *testing.T) {
	devices := []config.DeviceSpec{
		{Name: "gw-01", Host: "127.0.0.1"},
		{Name: "gw-02", Host: "10.0.0.5", AllowPorts: ports.Ceiling{{From: 502, To: 502}}},
	}
	out := captureStderr(t, func() { warnNoPortCeiling(ui.NewPlain(), devices) })
	if !strings.Contains(out, `device "gw-01": no --allow-ports set`) || !strings.Contains(out, "on 127.0.0.1") {
		t.Fatalf("missing the warning for the device without a ceiling: %q", out)
	}
	if strings.Contains(out, "gw-02") || strings.Count(out, "\n") != 1 {
		t.Fatalf("want one line, for gw-01 only: %q", out)
	}
}

func TestNoWarningWithAllowPorts(t *testing.T) {
	devices := []config.DeviceSpec{{Name: "gw-02", Host: "10.0.0.5", AllowPorts: ports.Ceiling{{From: 502, To: 502}}}}
	if out := captureStderr(t, func() { warnNoPortCeiling(ui.NewPlain(), devices) }); out != "" {
		t.Fatalf("a device with a ceiling must not warn, got %q", out)
	}
	if out := captureStderr(t, func() { warnNoPortCeiling(ui.NewTUI(), []config.DeviceSpec{{Name: "gw-01"}}) }); out != "" {
		t.Fatalf("the TUI must not print the warning, got %q", out)
	}
}
