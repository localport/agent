package cli

import "testing"

func TestAppVersionAndHelp(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	if err := app.Run([]string{"version"}); err != nil {
		t.Fatalf("version: %v", err)
	}
	if err := app.Run([]string{"help"}); err != nil {
		t.Fatalf("help: %v", err)
	}
}

func TestAppConnectRequiresRemote(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	if err := app.Run([]string{"connect"}); err == nil {
		t.Fatal("connect with no remote must error")
	}
}

// A file credential and a CI workload identity both name a principal, so
// supplying them together must fail rather than silently rank one.
func TestAppConnectRefusesAudienceWithCredentialFile(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	for _, flag := range []string{"--pem", "--p12"} {
		err := app.Run([]string{
			"connect", "https://sub.eu.localport.dev",
			flag, "creds.pem", "--audience", "lpa_test", "-p", "0",
		})
		if err == nil {
			t.Fatalf("connect with --audience and %s must error", flag)
		}
	}
}

func TestAppLegacyTunnelInvocation(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	if err := app.Run([]string{"--token", "tok_123"}); err == nil {
		t.Fatal("legacy tunnel call without --local must error")
	}
}
