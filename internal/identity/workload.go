package identity

import (
	"context"
	"encoding/json"
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
	// AudienceEnv carries the OIDC audience, shown in the dashboard when the
	// setup token is created.
	//
	// Required, never derived: the platform stamps it into the token, so it must
	// be known before one is requested. It identifies a binding and grants
	// nothing, so it is not handled as a secret.
	AudienceEnv = "LOCALPORT_OIDC_AUDIENCE"

	// TokenEnv supplies the platform token directly, for platforms that expose
	// it as an environment variable rather than through an API: GitLab
	// `id_tokens:`, Buildkite, a projected Kubernetes service-account token.
	// Read before any detection, so it also overrides it.
	TokenEnv = "LOCALPORT_OIDC_TOKEN"

	// GitHub Actions sets both in any job declaring `permissions: id-token:
	// write`. Their presence is the detection.
	githubTokenURLEnv     = "ACTIONS_ID_TOKEN_REQUEST_URL"
	githubRequestTokenEnv = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

// WorkloadAvailable reports whether a platform token can be obtained here.
func WorkloadAvailable() bool {
	return os.Getenv(TokenEnv) != "" || os.Getenv(githubTokenURLEnv) != ""
}

// FetchWorkloadToken obtains an OIDC token for the given audience from whatever
// CI platform this process is running on.
func FetchWorkloadToken(ctx context.Context, audience string) (string, error) {
	if strings.TrimSpace(audience) == "" {
		return "", fmt.Errorf("an OIDC audience is required (set --audience or %s)", AudienceEnv)
	}

	// Explicit value wins over detection, so an unrecognised platform needs only
	// a way to pass the token it already holds.
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

// fetchGitHubActionsToken calls the runner's local token service. The request
// token is a per-job credential the runner injects; it is never stored or
// logged.
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
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")

	resp, err := (&http.Client{Timeout: requestTimeout}).Do(req)
	if err != nil {
		return "", fmt.Errorf("request GitHub Actions OIDC token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		// The response can echo the request token. Never surface it.
		return "", fmt.Errorf("GitHub Actions OIDC token request failed with status %d", resp.StatusCode)
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Value == "" {
		return "", fmt.Errorf("GitHub Actions returned no token")
	}
	return payload.Value, nil
}

// ExchangeWorkloadToken swaps a platform token for a short-lived certificate.
// The result is returned and never written to disk.
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
		return nil, fmt.Errorf("control plane returned no certificate for the CSR")
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
