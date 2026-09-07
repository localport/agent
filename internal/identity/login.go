package identity

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

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
	// VerificationURIComplete carries it (RFC 8628 §3.3.1). Empty against an
	// older control plane, in which case the bare URI is the only one to show.
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

// Login runs the whole flow: start, show the code, poll, return the credential.
// onPrompt fires once, as a callback rather than a return value, because the
// code must be on screen while this function is still blocked on the poll.
func (c *Client) Login(ctx context.Context, onPrompt func(LoginPrompt)) (*Material, error) {
	kp, err := newKeyPair("")
	if err != nil {
		return nil, err
	}

	// The CSR goes up at START and the server pins its hash, so the human approves
	// one key and only that key can collect.
	var start deviceStartResponse
	if err := retry(ctx, DefaultRetryBudget, nil, func() error {
		start = deviceStartResponse{}
		return c.post(ctx, "/v1/mtls/device/start", "", map[string]string{
			"csr_pem":  string(kp.csrPEM),
			"hostname": hostname(),
			"agent_os": runtime.GOOS + "/" + runtime.GOARCH,
		}, &start)
	}); err != nil {
		return nil, err
	}
	if start.DeviceCode == "" || start.UserCode == "" {
		return nil, fmt.Errorf("control plane returned an incomplete sign-in request")
	}

	if onPrompt != nil {
		onPrompt(LoginPrompt{
			UserCode:                start.UserCode,
			VerificationURI:         start.VerificationURI,
			VerificationURIComplete: start.VerificationURIComplete,
		})
	}

	interval := time.Duration(start.Interval) * time.Second
	if interval < time.Second {
		// The server sets the cadence. This floor stops a zero or missing field
		// turning the poll into a busy loop.
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	if start.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Remembered so an expiry caused by an unreachable control plane is
	// reported as that, not as an unapproved sign-in.
	var lastUnreachable error

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}

		if time.Now().After(deadline) {
			if lastUnreachable != nil {
				return nil, fmt.Errorf("could not reach the control plane while waiting for approval: %w", lastUnreachable)
			}
			return nil, fmt.Errorf("sign-in expired before it was approved; run `localport login` again")
		}

		var tok deviceTokenResponse
		err := c.post(ctx, "/v1/mtls/device/token", "", map[string]string{
			"device_code": start.DeviceCode,
			"csr_pem":     string(kp.csrPEM),
		}, &tok)
		if err == nil {
			if tok.CertPEM == "" {
				return nil, fmt.Errorf("control plane returned no certificate")
			}
			// No renew_after: a sign-in does not renew, and synthesizing one
			// downstream would invent a deadline the control plane never issued.
			return c.assemble(kp.key, issuedMaterial{
				CertPEM:  tok.CertPEM,
				ChainPEM: tok.CAChainPEM,
				Source:   SourceSSO,
				TeamName: tok.TeamName,
			})
		}

		// Branched on the code the SERVER sent, not the status: a proxy answering
		// 428 for its own reasons must not make the agent poll forever.
		switch code := errorCode(err); {
		case code == codeSlowDown:
			lastUnreachable = nil
			interval += slowDownStep
			ticker.Reset(interval)
		case code == codeAuthorizationPending:
			lastUnreachable = nil
			// Keep waiting.
		case isRetryable(err):
			// Unreachable, not refused. The code stays valid for its window, so
			// keep polling rather than ending a sign-in already approved.
			lastUnreachable = err
		default:
			// A real refusal: unknown, denied, consumed or expired. Terminal.
			return nil, err
		}
	}
}
