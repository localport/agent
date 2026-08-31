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
			flag, "creds.pem", "--audience", "lpa_test", "-p", "0",
		})
		if err == nil {
			t.Fatalf("access with --audience and %s must error", flag)
		}
	}
}

// The old verb must NAME the new one. Checking only that the call errors would
// pass even with the router case deleted, because the flat tunnel fallthrough
// errors too. So this asserts the MESSAGE.
func TestAppOldConnectVerbNamesItsReplacement(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	err := app.Run([]string{"connect", "https://gateway-warehouse.eu.localport.dev", "-p", "3001"})
	if err == nil {
		t.Fatal("the retired verb must error")
	}
	if !strings.Contains(err.Error(), "localport access") {
		t.Fatalf("the error must name the new verb, got: %v", err)
	}
}

func TestAppLegacyTunnelInvocation(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	if err := app.Run([]string{"--token", "tok_123"}); err == nil {
		t.Fatal("legacy tunnel call without --local must error")
	}
}
