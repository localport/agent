package cli

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

func TestAppVersionAndHelp(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	if err := app.Run([]string{"version"}); err != nil {
		t.Fatalf("version: %v", err)
	}
	if err := app.Run([]string{"help"}); err != nil {
		t.Fatalf("help: %v", err)
	}
}

// Without --verbose a command's error shows its message and code and points
// at the flag when a cause was left out; with it, the full chain.
func TestErrorTextAndVerbose(t *testing.T) {
	t.Cleanup(func() { verbose = false })
	app := New("1.2.3", "abc123", "2026-04-13")
	err := errcode.New(errcode.NoTransport).With(&url.Error{Op: "Get", URL: "https://edge.localport.dev/v1/x", Err: errors.New("eof")}, "")
	text := app.ErrorText(err)
	if strings.Contains(text, "/v1/x") || !strings.Contains(text, "[AG071]") || !strings.Contains(text, "--verbose") {
		t.Fatalf("ErrorText = %q", text)
	}
	verbose = true
	if text := app.ErrorText(err); text != err.Error() {
		t.Fatalf("verbose ErrorText = %q, want %q", text, err.Error())
	}
}

func TestAppAccessRequiresRemote(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	if err := app.Run([]string{"access"}); err == nil {
		t.Fatal("access with no remote must error")
	}
}

// A file credential and a CI workload identity both name a principal, so
// supplying them together must fail rather than silently rank one.
func TestAppAccessRefusesAudienceWithCredentialFile(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	for _, flag := range []string{"--pem", "--p12"} {
		err := app.Run([]string{
			"access", "https://gateway-warehouse.eu.localport.dev",
			flag, "creds.pem", "--audience", "lpa_test", "-L", "0:22",
		})
		if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
			t.Fatalf("access with --audience and %s must be refused, got %v", flag, err)
		}
	}
}

// A config file describes everything that runs, so an endpoint flag beside it
// must be refused rather than silently dropped. Per-run switches still apply.
func TestAppConfigRefusesEndpointFlags(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	cases := [][]string{
		{"up", "--config", "x.yaml", "--enable", "terminal"},
		{"up", "--config", "x.yaml", "--allow-ports", "22"},
		{"up", "--config", "x.yaml", "--rdp"},
		{"up", "--config", "x.yaml", "--host", "192.168.1.20"},
		{"--config", "x.yaml", "--local", "localhost:3000"},
		{"--config", "x.yaml", "-l", "localhost:3000"},
		{"--config", "x.yaml", "--region", "eu"},
		{"--config", "x.yaml", "--proto", "tcp"},
		{"http", "3000", "--config", "x.yaml"},
	}
	for _, args := range cases {
		err := app.Run(args)
		if err == nil || !strings.Contains(err.Error(), "cannot be combined with --config") {
			t.Fatalf("%v must be refused, got %v", args, err)
		}
	}

	// --noui is a per-run switch, so it gets past the guard and fails only on
	// the missing file.
	err := app.Run([]string{"up", "--config", "does-not-exist.yaml", "--noui"})
	if err == nil || strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("--noui beside --config must not be refused, got %v", err)
	}
}

// A word that is neither a command nor a tunnel protocol, the removed
// `connect` included, is an unknown command, never the flat tunnel form.
func TestAppRefusesAnUnknownCommand(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	for _, args := range [][]string{{"connect"}, {"connect", "lpj_x"}, {"connect", "--config", "x.yaml"}, {"bogus", "3000"}} {
		if err := app.Run(args); !errors.Is(err, errcode.New(errcode.UnknownCommand)) {
			t.Errorf("%v = %v, want %s", args, err, errcode.UnknownCommand)
		}
	}
}

// `up` with a flag other than --all and no join token is the enrolment form
// and fails on the missing token.
func TestAppUpNeedsAToken(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	if err := app.Run([]string{"up", "--enable", "terminal"}); err == nil || !strings.Contains(err.Error(), "join token required") {
		t.Fatalf("up --enable without a token = %v, want join token required", err)
	}
}

func TestAppFlatTunnelForm(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	if err := app.Run([]string{"--token", "tok_123"}); err == nil {
		t.Fatal("the flat tunnel form without --local must error")
	}
}
