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

// DefaultAPIURL is the control plane. `--api` and LOCALPORT_API_URL override it
const DefaultAPIURL = "https://api.localport.io"

// APIURLEnv is the environment override for DefaultAPIURL.
const APIURLEnv = "LOCALPORT_API_URL"

// maxResponseBytes bounds a control plane response body. A certificate
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

// Error is the control plane's message and code. It leaves out Path, which
// names an internal endpoint, because logs and errors print it.
func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s (%s)", e.RemoteMessage(), e.Code)
	}
	return e.RemoteMessage()
}

// RemoteMessage is the server's message, or, when it sent none, a text
// naming the HTTP status class (errcode.Remote).
func (e *APIError) RemoteMessage() string {
	if e.Message != "" {
		return e.Message
	}
	switch {
	case e.Status >= 500:
		return "the control plane failed to answer the request (HTTP 5xx)"
	case e.Status >= 400:
		return "the control plane refused the request (HTTP 4xx)"
	}
	return "the control plane answered unexpectedly (HTTP 3xx)"
}

// RemoteCode is the server's code, empty when it sent none (errcode.Remote).
func (e *APIError) RemoteCode() string { return e.Code }

// errorCode returns the control plane's code for err, or "" when err did not
// come from the control plane. Wrapping-safe.
func errorCode(err error) string {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return ""
}

// RetryAfter is the wait the server asked for, and whether it asked.
func (e *APIError) RetryAfter() (time.Duration, bool) {
	return e.retryAfter, e.retryAfter > 0
}

var (
	// errUnreachable is a control-plane call that got no complete answer:
	// a transport failure or a failure reading the response body.
	errUnreachable = errcode.New(errcode.ControlPlaneUnreachable)
	// errAnswer is a control-plane answer the agent cannot use.
	errAnswer = errcode.New(errcode.ControlPlaneAnswer)
)

// codeIdempotencyInFlight is the control plane's 409 for a request whose
// idempotency key belongs to a request it is still running.
const codeIdempotencyInFlight = "SE037"

// InFlight reports whether err is the control plane's answer that a request
// under the same idempotency key is still running: that request may still
// complete and spend what it carries.
func InFlight(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == codeIdempotencyInFlight
}

// responseReadError is a failure reading a response body: a reset, an HTTP/2
// stream reset or GOAWAY, or a truncated body. The request may have
// completed, so only a retry under the same idempotency key is safe.
// what names the response for a person, never an internal endpoint path,
// since logs print the error.
type responseReadError struct {
	what string
	err  error
}

func (e *responseReadError) Error() string { return "read " + e.what + ": " + e.err.Error() }
func (e *responseReadError) Unwrap() error { return e.err }

// transportError is a control-plane request that failed in transport. Its
// text is the cause alone: the *url.Error it wraps names the endpoint URL,
// which logs would otherwise carry. Retryable still finds the *url.Error.
type transportError struct{ err *url.Error }

func (e *transportError) Error() string { return e.err.Err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// withoutURL wraps a *url.Error from an HTTP request in transportError.
func withoutURL(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return &transportError{err: ue}
	}
	return err
}

// Retryable reports whether a retry of a control-plane call could succeed:
// a 429 or 5xx answer, the 409 for a request still in flight under the same
// idempotency key, a transport failure (DNS, dial, TLS, timeout, reset) or a
// failure reading the response body. Other 4xx answers are refusals, and
// local failures (signing, request encoding) and a malformed success body are
// final, since repeating the call repeats them. These are also the outcomes
// the control plane does not record under an idempotency key, so a retry
// resends the same key.
//
// Cancellation is checked by retry on ctx. http.Client.Timeout also matches
// context.DeadlineExceeded, so the error cannot tell the two apart.
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusTooManyRequests || apiErr.Status >= 500 || apiErr.Code == codeIdempotencyInFlight
	}
	var transport *url.Error
	var netErr net.Error
	var readErr *responseReadError
	return errors.As(err, &transport) || errors.As(err, &netErr) || errors.As(err, &readErr)
}

// redactCause is err, or a plain error with its text redacted when the text
// holds one of secrets: encoding/json errors quote the values they reject,
// which a server echoing the request can fill with a secret.
func redactCause(err error, secrets []string) error {
	text := err.Error()
	if redacted := security.RedactString(text, secrets...); redacted != text {
		return errors.New(redacted)
	}
	return err
}

// newIdempotencyKey is one logical request's Idempotency-Key: 128 random bits
// as a Structured Field String (draft-ietf-httpapi-idempotency-key-header).
func newIdempotencyKey() string { return `"` + rand.Text() + `"` }

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
		// Retry-After takes precedence; a wait past the remaining budget ends the retries.
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
// one address that were refused together, without waking any of them before d.
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

func (c *Client) post(ctx context.Context, path, bearer, idempotencyKey string, body, out any, secrets ...string) error {
	header := ""
	if bearer != "" {
		header = "Authorization"
		secrets = append(secrets, bearer)
		bearer = "Bearer " + bearer
	}
	return c.postWithHeader(ctx, path, header, bearer, idempotencyKey, body, out, secrets...)
}

// postWithHeader sends a request with the given credential header,
// `Authorization: Bearer <secret>` for a setup token or `X-Workload-Token` for
// a platform token. idempotencyKey (newIdempotencyKey) is set on every request
// that creates state or spends a secret, and is the same on each retry of one
// logical request; empty for a read. With it, net/http may also replay the
// request on a reused connection that failed before any response.
//
// secrets are the request's secrets outside credValue (a join token in the
// body). The server can echo what it was sent, so every error text built
// from the response has them and credValue redacted.
func (c *Client) postWithHeader(ctx context.Context, path, credHeader, credValue, idempotencyKey string, body, out any, secrets ...string) error {
	secrets = append(secrets, credValue)
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
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return errUnreachable.With(withoutURL(err), "")
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return errUnreachable.With(&responseReadError{what: "the control plane's response", err: err}, "")
	}
	if isRedirect(resp.StatusCode) {
		// An APIError with the 3xx status is terminal for Retryable, so the
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
			// Server text reaches terminals and logs: strip control and bidi characters.
			apiErr.Code = security.RedactString(security.SanitizeDisplay(env.Code), secrets...)
			// Fall back to the type label when the response has no message.
			apiErr.Message = security.RedactString(security.SanitizeDisplay(firstNonEmpty(env.Message, env.Error)), secrets...)
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errAnswer.With(fmt.Errorf("parse %s response: %w", path, redactCause(err, secrets)), "")
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

// FetchDeviceKeys fetches the device's session CA key set and its
// team's recording key from POST /v1/devices/keys. The request carries cur's
// certificate and its key's signature over deviceKeysDigest, which the control
// plane accepts within a minute of its clock. Transport failures, 5xx and 429
// are retried within DefaultRetryBudget; other refusals return at once as an
// *APIError. A material that is not a device returns ErrNotDeviceIdentity, and
// a response without a session CA key set returns ErrNoTicketKeys.
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
		return c.post(ctx, "/v1/devices/keys", "", "", map[string]string{
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
