package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// OIDC workload identity. The agent obtains a token from the CI platform and
// exchanges it for a short-lived certificate, so no credential is stored in the
// repository, in the CI secret store, or on disk.
//
// The certificate is held in memory for the life of the process. A runner is
// ephemeral, so anything written to `~/.localport/identity` outlives the job
// that needed it.

const (
	// AudienceEnv holds the required OIDC audience shown in the dashboard when
	// the setup token is created. It is not a secret.
	AudienceEnv = "LOCALPORT_OIDC_AUDIENCE"

	// TokenEnv supplies the platform token directly, for example GitLab
	// id_tokens, Buildkite or a projected Kubernetes service account token.
	// It overrides platform detection.
	TokenEnv = "LOCALPORT_OIDC_TOKEN"

	// GitHub Actions sets both in jobs with the id-token write permission.
	githubTokenURLEnv     = "ACTIONS_ID_TOKEN_REQUEST_URL"
	githubRequestTokenEnv = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

// FetchWorkloadToken obtains an OIDC token for audience from the current CI
// platform.
func FetchWorkloadToken(ctx context.Context, audience string) (string, error) {
	if strings.TrimSpace(audience) == "" {
		return "", fmt.Errorf("an OIDC audience is required (set --audience or %s)", AudienceEnv)
	}

	// An explicit token overrides detection and supports any platform.
	if token := strings.TrimSpace(os.Getenv(TokenEnv)); token != "" {
		return token, nil
	}
	if os.Getenv(githubTokenURLEnv) != "" {
		return fetchGitHubActionsToken(ctx, audience)
	}

	return "", fmt.Errorf(
		"no CI workload identity found: set %s, or on GitHub Actions add `permissions: { id-token: write }` to the job",
		TokenEnv)
}

// fetchGitHubActionsToken calls the runner token service. The per-job request
// token is not stored or logged.
func fetchGitHubActionsToken(ctx context.Context, audience string) (string, error) {
	rawURL := os.Getenv(githubTokenURLEnv)
	requestToken := os.Getenv(githubRequestTokenEnv)
	if requestToken == "" {
		return "", fmt.Errorf("%s is set but %s is not; check `permissions: { id-token: write }` on the job",
			githubTokenURLEnv, githubRequestTokenEnv)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", githubTokenURLEnv, err)
	}
	// The URL comes from the environment and receives the request token, so
	// require https. The URL is not echoed in the error.
	if u.Scheme != "https" {
		return "", fmt.Errorf("%s must be an https URL", githubTokenURLEnv)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")

	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("request GitHub Actions OIDC token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		// The response can echo the request token. Do not include it.
		return "", fmt.Errorf("GitHub Actions OIDC token request failed with status %d", resp.StatusCode)
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Value == "" {
		return "", errors.New("GitHub Actions returned no token")
	}
	return payload.Value, nil
}

// ExchangeWorkloadToken exchanges a platform token for a short-lived
// certificate. Nothing is written to disk.
func (c *Client) ExchangeWorkloadToken(ctx context.Context, token string) (*Material, error) {
	kp, err := newKeyPair("")
	if err != nil {
		return nil, err
	}

	var resp issueResponse
	if err := retry(ctx, DefaultRetryBudget, nil, func() error {
		resp = issueResponse{}
		return c.postWithHeader(ctx, "/v1/mtls/certs", workloadTokenHeader, token, map[string]string{
			"csr_pem": string(kp.csrPEM),
		}, &resp)
	}); err != nil {
		return nil, err
	}
	if resp.CertPEM == "" {
		return nil, errors.New("control plane returned no certificate for the CSR")
	}
	return c.assemble(kp.key, issuedMaterial{
		CertPEM:    resp.CertPEM,
		ChainPEM:   resp.CAChainPEM,
		Source:     SourceOIDC,
		RenewAfter: resp.RenewAfter,
		TeamName:   resp.TeamName,
	})
}

// workloadTokenHeader must match the server's constant. A workload token is a
// different credential class from a setup token, so it travels in its own
// header rather than in Authorization.
const workloadTokenHeader = "X-Workload-Token"
