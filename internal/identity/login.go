package identity

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

// errSignInExpired is a sign-in poll that reached its deadline.
var errSignInExpired = errcode.New(errcode.SignInExpired)

// `localport login` implements RFC 8628 device authorization: the user opens a
// page on any device, types a short code, and receives a short-lived
// certificate. A loopback redirect needs an inbound port and breaks over SSH.
//
// No renewal loop: re-authentication is the renewal.

type deviceStartResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expires_in"`
}

type deviceTokenResponse struct {
	CertPEM    string `json:"cert_pem"`
	CAChainPEM string `json:"ca_chain_pem"`
	TeamName   string `json:"team_name"`
}

// LoginPrompt is what the caller shows the human while polling. The complete
// URI prefills the code; the bare one plus the code work when the browser is on
// another device. Neither skips the approval screen.
type LoginPrompt struct {
	UserCode string
	// VerificationURI never carries the code.
	VerificationURI string
	// VerificationURIComplete carries it (RFC 8628 §3.3.1).
	VerificationURIComplete string
}

// The control-plane codes for the two RFC 8628 §3.5 polling states: normal
// outcomes, and the only answers that mean anything other than "stop". Codes
// rather than message text, which changes.
const (
	codeAuthorizationPending = "SE021"
	codeSlowDown             = "SE022"

	// slowDownStep is what §3.5 requires be added to the interval on each
	// slow_down, "for this and all subsequent requests".
	slowDownStep = 5 * time.Second
)

// hostname answers "which box am I approving" on the approval screen.
// Self-asserted and shown only; nothing gates on it, and an empty string is
// fine. The mDNS `.local` suffix is dropped, since macOS reports it for a
// machine whose owner calls it by the bare name.
func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return trimHostname(name)
}

// trimHostname removes the mDNS suffix and nothing else. Split out so the rule
// is testable off a Mac.
func trimHostname(name string) string {
	if trimmed := strings.TrimSuffix(name, ".local"); trimmed != "" {
		return trimmed
	}
	return name
}

// loginPrompt returns the sign-in text safe to print. Both addresses must be
// https on the API's registrable domain, so a hostile --api cannot send the
// user to another site.
func (c *Client) loginPrompt(start deviceStartResponse) (LoginPrompt, error) {
	api, err := url.Parse(c.BaseURL)
	if err != nil {
		return LoginPrompt{}, err
	}
	site := strings.ToLower(api.Hostname())
	// An IP or single-label host has no registrable domain: it must match exactly.
	if s, err := publicsuffix.EffectiveTLDPlusOne(site); err == nil {
		site = s
	}
	for _, raw := range []string{start.VerificationURI, start.VerificationURIComplete} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.User != nil || security.SanitizeDisplay(raw) != raw || !onSite(u.Hostname(), site) {
			return LoginPrompt{}, errAnswer.With(fmt.Errorf("verification address %q", security.SanitizeDisplay(raw)), "invalid sign-in address")
		}
	}
	return LoginPrompt{
		UserCode:                security.SanitizeDisplay(start.UserCode),
		VerificationURI:         start.VerificationURI,
		VerificationURIComplete: start.VerificationURIComplete,
	}, nil
}

// onSite reports whether host is site or one of its subdomains.
func onSite(host, site string) bool {
	host = strings.ToLower(host)
	return host == site || strings.HasSuffix(host, "."+site)
}

// Login runs the device flow and returns the credential. onPrompt is called
// once with the user code, before polling starts.
func (c *Client) Login(ctx context.Context, onPrompt func(LoginPrompt)) (*Material, error) {
	kp, err := newKeyPair("")
	if err != nil {
		return nil, err
	}

	// The CSR is sent at start and the server pins its hash, so only the
	// approved key can collect the certificate.
	var start deviceStartResponse
	startKey := newIdempotencyKey()
	if err := retry(ctx, DefaultRetryBudget, nil, func() error {
		start = deviceStartResponse{}
		return c.post(ctx, "/v1/mtls/device/start", "", startKey, map[string]string{
			"csr_pem":  string(kp.csrPEM),
			"hostname": hostname(),
			"agent_os": runtime.GOOS + "/" + runtime.GOARCH,
		}, &start)
	}); err != nil {
		return nil, err
	}
	if start.DeviceCode == "" || start.UserCode == "" || start.VerificationURI == "" || start.VerificationURIComplete == "" {
		return nil, errAnswer.With(nil, "the sign-in request has no device code, user code or verification address")
	}

	prompt, err := c.loginPrompt(start)
	if err != nil {
		return nil, err
	}
	if onPrompt != nil {
		onPrompt(prompt)
	}

	interval := time.Duration(start.Interval) * time.Second
	if interval < time.Second {
		// The server sets the interval. The floor prevents a busy loop on a
		// zero or missing value.
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	if start.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Each poll is one logical request with its own key. A poll whose outcome
	// the control plane did not record (Retryable) is repeated under the same
	// key, so a lost answer to the poll that consumed the device code returns
	// the same certificate.
	pollKey := newIdempotencyKey()

	// Recorded so an expiry after transport errors is reported as
	// unreachable, not as unapproved.
	var lastUnreachable error

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}

		if time.Now().After(deadline) {
			if lastUnreachable != nil {
				return nil, errSignInExpired.With(lastUnreachable, "the control plane could not be reached while waiting for approval")
			}
			return nil, errSignInExpired.With(nil, "")
		}

		var tok deviceTokenResponse
		err := c.post(ctx, "/v1/mtls/device/token", "", pollKey, map[string]string{
			"device_code": start.DeviceCode,
			"csr_pem":     string(kp.csrPEM),
		}, &tok)
		if err == nil {
			if tok.CertPEM == "" {
				return nil, errAnswer.With(nil, "no certificate")
			}
			// No renew_after. A sign-in does not renew.
			return consumerOnly(c.assemble(kp.key, issuedMaterial{
				CertPEM:  tok.CertPEM,
				ChainPEM: tok.CAChainPEM,
				Source:   SourceSSO,
				TeamName: tok.TeamName,
			}))
		}

		// Branch on the server error code. A proxy can also return 428.
		switch code := errorCode(err); {
		case code == codeSlowDown:
			lastUnreachable = nil
			interval += slowDownStep
			ticker.Reset(interval)
		case code == codeAuthorizationPending:
			lastUnreachable = nil
		case Retryable(err):
			// Retryable failure. The code stays valid, so keep polling.
			lastUnreachable = err
			continue
		default:
			// Refused as unknown, denied, consumed or expired.
			return nil, err
		}
		// A pending or slow_down answer is recorded and ends this poll.
		pollKey = newIdempotencyKey()
	}
}
