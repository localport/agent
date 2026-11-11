package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
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
//
// CheckRedirect returns a 3xx as is. Following it would resend the request and
// its credential headers to the Location host.
func newHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	return &http.Client{Timeout: requestTimeout, Transport: tr, CheckRedirect: noRedirect}
}

// noRedirect stops the client at the first 3xx and returns that response.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// isRedirect reports whether status is 3xx.
func isRedirect(status int) bool { return status >= 300 && status < 400 }

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

// Retryable reports whether a retry of a control-plane call could succeed:
// a 429 or 5xx answer, a transport failure (DNS, dial, TLS, timeout, reset)
// or a truncated response body. Other 4xx answers are refusals, and local
// failures (signing, request encoding) and a malformed success body are
// final, since repeating the call repeats them.
//
// Cancellation is checked by retry on ctx. http.Client.Timeout also matches
// context.DeadlineExceeded, so the error cannot tell the two apart.
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusTooManyRequests || apiErr.Status >= 500
	}
	var transport *url.Error
	var netErr net.Error
	return errors.As(err, &transport) || errors.As(err, &netErr) || errors.Is(err, io.ErrUnexpectedEOF)
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
		// Check ctx. See Retryable.
		if ctx.Err() != nil {
			return err
		}
		if !Retryable(err) {
			return err
		}

		wait := jitter(delay)
		// Retry-After takes precedence. A wait past the remaining budget ends
		// the retries.
		if asked, ok := retryAfterWait(err); ok {
			wait = asked
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

// retryAfterWait is the server's Retry-After with jitter added, and whether
// the server sent one.
func retryAfterWait(err error) (time.Duration, bool) {
	asked, ok := serverRetryAfter(err)
	if !ok {
		return 0, false
	}
	return withJitter(asked), true
}

// serverRetryAfter is the Retry-After of a control plane refusal.
func serverRetryAfter(err error) (time.Duration, bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return 0, false
	}
	return apiErr.RetryAfter()
}

// withJitter adds up to min(d, retryMaxDelay) to d. It spreads agents behind
// one address that were refused together, without waking any of
// them before d.
func withJitter(d time.Duration) time.Duration {
	return d + jitter(min(d, retryMaxDelay))
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
	if isRedirect(resp.StatusCode) {
		// an APIError with the 3xx status is terminal for Retryable, so the
		// credential is not resent.
		return &APIError{
			Path:    path,
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("the server answered with a redirect (HTTP %d); refusing to follow it", resp.StatusCode),
		}
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

// deviceKeysContext separates the key fetch proof from every other signature
// the device key makes. It matches the control plane's constant.
const deviceKeysContext = "localport-device-keys-v1"

// ErrNoTicketKeys means a POST /v1/devices/keys response lacks `keys` or
// `keys.ticket_keys`, or holds null for either. Storing it would drop every
// key the device holds, so it is refused; an empty array is a valid set.
var ErrNoTicketKeys = errcode.New(errcode.NoTicketKeys)

// deviceKeysResponse is POST /v1/devices/keys.
type deviceKeysResponse struct {
	Keys *DeviceKeys `json:"keys"`
}

// FetchDeviceKeys fetches the device's session ticket verification set and its
// team's recording key from POST /v1/devices/keys. The request carries cur's
// certificate and its key's signature over deviceKeysDigest, which the control
// plane accepts within a minute of its clock. Transport failures, 5xx and 429
// are retried within DefaultRetryBudget; other refusals return at once as an
// *APIError. A material that is not a device returns ErrNotDeviceIdentity, and
// a response without a ticket key set returns ErrNoTicketKeys.
func (c *Client) FetchDeviceKeys(ctx context.Context, cur *Material) (*DeviceKeys, error) {
	if cur.Meta.Kind != KindDevice {
		return nil, fmt.Errorf("%w: %s", ErrNotDeviceIdentity, security.SanitizeDisplay(cur.Meta.Identity))
	}
	leaf, err := leafOf(cur.CertPEM)
	if err != nil {
		return nil, err
	}
	serial := leaf.SerialNumber.Text(16)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))

	// Sign per attempt, since a retry can cross a minute boundary.
	var resp deviceKeysResponse
	if err := retry(ctx, DefaultRetryBudget, nil, func() error {
		sig, signErr := cur.Key.Sign(rand.Reader, deviceKeysDigest(time.Now().Unix()/60, serial), crypto.SHA256)
		if signErr != nil {
			return fmt.Errorf("sign key fetch: %w", signErr)
		}
		resp = deviceKeysResponse{}
		return c.post(ctx, "/v1/devices/keys", "", map[string]string{
			"cert_pem":  certPEM,
			"signature": base64.StdEncoding.EncodeToString(sig),
		}, &resp)
	}); err != nil {
		return nil, err
	}
	if resp.Keys == nil || resp.Keys.TicketKeys == nil {
		return nil, ErrNoTicketKeys
	}
	return resp.Keys, nil
}

// deviceKeysDigest is SHA-256(deviceKeysContext || bucket as 8 bytes
// big-endian || serial in lowercase hex), the control plane's construction.
func deviceKeysDigest(bucket int64, serial string) []byte {
	h := sha256.New()
	h.Write([]byte(deviceKeysContext))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(bucket))
	h.Write(b[:])
	h.Write([]byte(serial))
	return h.Sum(nil)
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
