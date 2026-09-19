package identity

import (
	"context"
	"strings"
	"testing"
)

// The token URL must be https because it receives the request token.
func TestGitHubActionsTokenURLMustBeHTTPS(t *testing.T) {
	const secret = "per-job-bearer-token"

	refused := []string{
		"http://attacker.example/token",
		"ftp://attacker.example/token",
		"//attacker.example/token",
		"attacker.example/token",
	}
	for _, raw := range refused {
		t.Setenv(githubTokenURLEnv, raw)
		t.Setenv(githubRequestTokenEnv, secret)

		_, err := fetchGitHubActionsToken(context.Background(), "lpa_aud")
		if err == nil {
			t.Fatalf("%s: expected a refusal", raw)
		}
		if !strings.Contains(err.Error(), githubTokenURLEnv) {
			t.Errorf("%s: error should name the variable, got %q", raw, err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error leaked the request token: %q", raw, err)
		}
	}
}

// Errors do not include the request token.
func TestGitHubActionsMissingRequestTokenIsReported(t *testing.T) {
	t.Setenv(githubTokenURLEnv, "https://runner.example/token")
	t.Setenv(githubRequestTokenEnv, "")

	_, err := fetchGitHubActionsToken(context.Background(), "lpa_aud")
	if err == nil {
		t.Fatal("expected a refusal when the request token is absent")
	}
	if !strings.Contains(err.Error(), githubRequestTokenEnv) {
		t.Errorf("error should name the missing variable, got %q", err)
	}
}
