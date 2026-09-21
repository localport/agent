package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
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

// DefaultAPIURL is the control plane. `--api` and LOCALPORT_API_URL override it.
const DefaultAPIURL = "https://api.localport.io"

// APIURLEnv is the environment override for DefaultAPIURL.
const APIURLEnv = "LOCALPORT_API_URL"

// maxResponseBytes bounds what we read from the control plane. A certificate
// and its chain are a few kilobytes, and the body is parsed in memory.
const maxResponseBytes = 1 << 20

// requestTimeout covers one issuance or renewal round trip. It allows for a
// slow link and keeps a hung control plane from stalling the renewal loop.
const requestTimeout = 60 * time.Second

// Client talks to the control plane's public mTLS credential endpoints.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient normalizes the base URL and requires https, since the setup token
// is a bearer secret.
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
	return &Client{BaseURL: raw, HTTP: newHTTPClient()}, nil
}

// newHTTPClient builds the control plane client with a TLS 1.3 minimum, since
// requests carry the setup token and the renewal proof. It clones the default
// transport to keep proxy settings, timeouts and pooling.
func newHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	return &http.Client{Timeout: requestTimeout, Transport: tr}
}

// errorEnvelope is the control plane error body. It holds a support code, a
// type label and a sanitized message.
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

// isRetryable reports whether a retry could succeed. Transport failures, 5xx
// and 429 are retryable. Other 4xx responses are refusals.
//
// Cancellation is checked by retry on ctx. http.Client.Timeout also matches
// context.DeadlineExceeded, so the error cannot tell the two apart.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusTooManyRequests || apiErr.Status >= 500
	}
	// No status means a transport failure such as DNS, dial, TLS, timeout,
	// reset or truncated body.
	return true
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

// retry runs fn until it succeeds, returns a terminal error or exhausts the
// budget. Waits use full jitter to spread retries across agents. A zero budget
// makes one attempt.
func retry(ctx context.Context, budget time.Duration, onWait RetryNotice, fn func() error) error {
	deadline := time.Now().Add(budget)
	delay := retryBaseDelay

	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		// Check ctx. See isRetryable.
		if ctx.Err() != nil {
			return err
		}
		if !isRetryable(err) {
			return err
		}

		wait := jitter(delay)
		// Retry-After takes precedence, capped at the remaining budget.
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

// jitter returns a uniformly random duration in [0, d]. math/rand is
// sufficient because the value is not secret.
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

// postWithHeader sends a request with the given credential header,
// `Authorization: Bearer <secret>` for a setup token or `X-Workload-Token` for
// a platform token.
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
			// Fall back to the type label when the response has no message.
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

// newKeyPair generates a P-256 key and a CSR. The common name is cosmetic. The
// control plane takes the identity from the presented credential.
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
