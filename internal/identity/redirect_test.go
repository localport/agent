package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// redirectPair returns a server that 307s every request to a second server,
// and counters for what reaches the second one.
func redirectPair(t *testing.T) (first *httptest.Server, reached *atomic.Int32, sawCredential *atomic.Bool) {
	t.Helper()
	reached, sawCredential = &atomic.Int32{}, &atomic.Bool{}
	second := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		if r.Header.Get("X-Workload-Token") != "" || r.Header.Get("Authorization") != "" {
			sawCredential.Store(true)
		}
	}))
	t.Cleanup(second.Close)
	first = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(first.Close)
	return first, reached, sawCredential
}

// A followed 307 resends the body and credential header to the Location host.
func TestClientDoesNotFollowRedirect(t *testing.T) {
	first, reached, sawCredential := redirectPair(t)
	c := &Client{BaseURL: first.URL, HTTP: newHTTPClient()}

	err := c.postWithHeader(context.Background(), "/v1/mtls/workload", "X-Workload-Token", "secret", map[string]string{}, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing to follow") {
		t.Fatalf("err = %v, want the redirect refusal", err)
	}
	// a retry would resend the credential.
	if isRetryable(err) {
		t.Fatal("a refused redirect is retried")
	}
	if reached.Load() != 0 || sawCredential.Load() {
		t.Fatalf("the redirect target received %d requests (credential seen: %v)", reached.Load(), sawCredential.Load())
	}
}

// fetchGitHubActionsToken requires https, so this sends the same request
// through newHTTPClient directly.
func TestOIDCFetchDoesNotFollowRedirect(t *testing.T) {
	first, reached, sawCredential := redirectPair(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, first.URL+"/token?audience=localport", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer request-token")

	resp, err := newHTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !isRedirect(resp.StatusCode) {
		t.Fatalf("status = %d, want the 307 itself", resp.StatusCode)
	}
	if reached.Load() != 0 || sawCredential.Load() {
		t.Fatalf("the redirect target received %d requests (credential seen: %v)", reached.Load(), sawCredential.Load())
	}
}
