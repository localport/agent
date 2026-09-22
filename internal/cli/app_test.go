package cli

import (
	"strings"
	"testing"
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

// The flat tunnel fallthrough also errors, so the test checks the message
// names the new verb.
func TestAppOldTunnelVerbNamesItsReplacement(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	err := app.Run([]string{"tunnel", "--config", "localport.yaml"})
	if err == nil {
		t.Fatal("the retired verb must error")
	}
	if !strings.Contains(err.Error(), "localport connect") {
		t.Fatalf("the error must name the new verb, got: %v", err)
	}
}

// `connect` without a token fails on the missing token.
func TestAppConnectNeedsAToken(t *testing.T) {
	t.Setenv("LOCALPORT_TOKEN", "")
	app := New("1.2.3", "abc123", "2026-04-13")
	if err := app.Run([]string{"connect"}); err == nil {
		t.Fatal("connect without a token must error")
	}
}

func TestAppLegacyTunnelInvocation(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	if err := app.Run([]string{"--token", "tok_123"}); err == nil {
		t.Fatal("legacy tunnel call without --local must error")
	}
}
