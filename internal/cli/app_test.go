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

func TestAppLegacyTunnelInvocation(t *testing.T) {
	app := New("1.2.3", "abc123", "2026-04-13")
	if err := app.Run([]string{"--token", "tok_123"}); err == nil {
		t.Fatal("legacy tunnel call without --local must error")
	}
}
