package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// requestTimeout covers one issuance round trip. Long enough for a slow link,
// short enough that a hung control plane cannot wedge the caller.
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

func (c *Client) post(ctx context.Context, path, bearer string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
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
		apiErr := &APIError{Path: path, Status: resp.StatusCode}
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
