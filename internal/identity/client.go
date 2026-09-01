package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultAPIURL is the control plane. `--api` and LOCALPORT_API_URL point the
// agent elsewhere. The resolved value is stored in meta.json, so renewal is
// never told again.
const DefaultAPIURL = "https://api.localport.io"

// APIURLEnv is the environment override for DefaultAPIURL.
const APIURLEnv = "LOCALPORT_API_URL"

// maxResponseBytes bounds what we read from the control plane. A certificate
// and its chain are a few kilobytes, and the body is parsed in memory.
const maxResponseBytes = 1 << 20

// requestTimeout covers one issuance or renewal round trip. Long enough for a
// slow link, short enough that a hung control plane cannot wedge the renewal
// loop.
const requestTimeout = 60 * time.Second

// Client talks to the control plane's public mTLS credential endpoints.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient normalises the base URL and refuses anything but https. A setup
// token is a bearer secret and must never travel in the clear.
func NewClient(baseURL string) (*Client, error) {
	raw := strings.TrimSpace(baseURL)
	if raw == "" {
		raw = DefaultAPIURL
	}
	raw = strings.TrimRight(raw, "/")

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid API URL %q", baseURL)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("API URL must be https (got %q)", raw)
	}
	return &Client{BaseURL: raw, HTTP: &http.Client{Timeout: requestTimeout}}, nil
}

// errorEnvelope is the control plane's error body: a support code, a short type
// label, and a message already made generic on the server side.
type errorEnvelope struct {
	Code    string `json:"code"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// APIError is a failed control-plane call. Typed so a caller branches on the
// server's code rather than on message text, which changes.
type APIError struct {
	// Path is the endpoint that failed.
	Path string
	// Status is the HTTP status code.
	Status int
	// Code is the server's error code, for quoting in a support conversation.
	Code string
	// Message is the human-readable text.
	Message string
	// retryAfter is the server's Retry-After, 0 when absent. Read through
	// RetryAfter() so that convention has one reader.
	retryAfter time.Duration
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%s: unexpected status %d", e.Path, e.Status)
	}
	if e.Code != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Path, e.Message, e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

// errorCode returns the control plane's code for err, or "" when err did not
// come from the control plane. Wrapping-safe.
func errorCode(err error) string {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return ""
}

// RetryAfter is how long the server asked us to wait, and whether it asked.
func (e *APIError) RetryAfter() (time.Duration, bool) {
	return e.retryAfter, e.retryAfter > 0
}

// isRetryable reports whether waiting could change the answer. Transport
// failures, 5xx and 429 are retried; every other 4xx is a refusal.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusTooManyRequests || apiErr.Status >= 500
	}
	// No status at all: dial, DNS, TLS, timeout, reset, EOF mid-body.
	// Cancellation is not retried; the caller asked us to stop.
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

const (
	// retryBaseDelay and retryMaxDelay bound the exponential backoff.
	retryBaseDelay = 2 * time.Second
	retryMaxDelay  = 30 * time.Second

	// DefaultRetryBudget bounds how long a credential call waits out an
	// unreachable control plane. `--wait` extends it.
	DefaultRetryBudget = 60 * time.Second
)

// RetryNotice reports one wait before the next attempt. Optional.
type RetryNotice func(attempt int, wait time.Duration, err error)

// retry runs fn until it succeeds, hits a terminal error, or spends the budget.
// Waits carry full jitter so agents recovering from one outage do not retry in
// lockstep. A zero budget makes exactly one attempt.
func retry(ctx context.Context, budget time.Duration, onWait RetryNotice, fn func() error) error {
	deadline := time.Now().Add(budget)
	delay := retryBaseDelay

	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil || !isRetryable(err) {
			return err
		}

		wait := jitter(delay)
		// Retry-After wins, clamped below to the remaining budget so a bad
		// value cannot park the agent.
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			if asked, ok := apiErr.RetryAfter(); ok {
				wait = asked
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 || wait > remaining {
			return err
		}

		if onWait != nil {
			onWait(attempt, wait, err)
		}
		if !sleepCtx(ctx, wait) {
			return ctx.Err()
		}

		if delay *= 2; delay > retryMaxDelay {
			delay = retryMaxDelay
		}
	}
}

// jitter returns a uniformly random duration in [0, d]. math/rand: this spreads
// retries and is not a secret.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(mrand.Int64N(int64(d)))
}

// parseRetryAfter reads RFC 9110 §10.2.3: delay-seconds or an HTTP date.
// Anything else yields zero and the caller keeps its own backoff.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func (c *Client) post(ctx context.Context, path, bearer string, body, out any) error {
	header := ""
	if bearer != "" {
		header = "Authorization"
		bearer = "Bearer " + bearer
	}
	return c.postWithHeader(ctx, path, header, bearer, body, out)
}

// postWithHeader is the shared request path. Only the credential header differs:
// `Authorization: Bearer <secret>` for a setup token, `X-Workload-Token` for a
// platform-minted one.
func (c *Client) postWithHeader(ctx context.Context, path, credHeader, credValue string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if credHeader != "" && credValue != "" {
		req.Header.Set(credHeader, credValue)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("call %s: %w", path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read %s response: %w", path, err)
	}
	if resp.StatusCode >= 300 {
		apiErr := &APIError{
			Path:       path,
			Status:     resp.StatusCode,
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
		var env errorEnvelope
		if json.Unmarshal(raw, &env) == nil {
			apiErr.Code = env.Code
			// `error` is the type label and is the only text present when a
			// response carries no message.
			apiErr.Message = firstNonEmpty(env.Message, env.Error)
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("parse %s response: %w", path, err)
	}
	return nil
}

// keyPair is a freshly generated private key and the CSR over it. The key never
// leaves this process except onto local disk at 0600.
type keyPair struct {
	key    Key
	csrDER []byte
	csrPEM []byte
}

// newKeyPair generates P-256 and builds a CSR. The common name is for
// readability only: the control plane takes the identity from the credential
// presented, never from the request.
func newKeyPair(commonName string) (*keyPair, error) {
	key, err := generateKey(BackingFile)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("build certificate request: %w", err)
	}
	return &keyPair{
		key:    key,
		csrDER: csrDER,
		csrPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
