package identity

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// issueResponse is POST /v1/mtls/certs. The agent always sends a CSR, so the
// material comes back inline and holds nothing secret.
type issueResponse struct {
	CertPEM    string `json:"cert_pem"`
	CAChainPEM string `json:"ca_chain_pem"`
	RenewAfter string `json:"renew_after"`
}

// issuedMaterial is one issuance response in the shape assemble consumes. A
// struct rather than positional strings, which transpose silently.
type issuedMaterial struct {
	CertPEM    string
	ChainPEM   string
	Source     Source
	RenewAfter string
}

// RedeemSetupToken spends a setup token once and returns the credential.
//
// The token is used for this call only and never written to disk; from here the
// certificate renews itself.
func (c *Client) RedeemSetupToken(ctx context.Context, token string) (*Material, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("setup token required")
	}
	kp, err := newKeyPair("")
	if err != nil {
		return nil, err
	}

	var resp issueResponse
	if err := c.post(ctx, "/v1/mtls/certs", token, map[string]string{
		"csr_pem": string(kp.csrPEM),
	}, &resp); err != nil {
		return nil, err
	}
	if resp.CertPEM == "" {
		// Failing here beats writing an empty credential and finding out at the
		// next handshake.
		return nil, fmt.Errorf("control plane returned no certificate for the CSR")
	}

	return c.assemble(kp.key, issuedMaterial{
		CertPEM:    resp.CertPEM,
		ChainPEM:   resp.CAChainPEM,
		Source:     SourceToken,
		RenewAfter: resp.RenewAfter,
	})
}

// assemble turns a response into on-disk material. Leaf first, then the chain:
// the order a PEM bundle requires.
//
// Identity, team and kind come from the CERTIFICATE, never the response body.
// The certificate is what gets presented, so it is what they have to describe.
func (c *Client) assemble(key Key, in issuedMaterial) (*Material, error) {
	bundle := []byte(ensureTrailingNewline(in.CertPEM))
	if strings.TrimSpace(in.ChainPEM) != "" {
		bundle = append(bundle, []byte(ensureTrailingNewline(in.ChainPEM))...)
	}

	leaf, err := leafOf(bundle)
	if err != nil {
		return nil, err
	}
	ref, err := RefFromCert(leaf)
	if err != nil {
		return nil, err
	}

	meta := Meta{
		Identity:   ref.Identity,
		Team:       ref.Team,
		Kind:       ref.Kind,
		SpiffeID:   SpiffeURI(leaf),
		Source:     in.Source,
		APIURL:     c.BaseURL,
		Serial:     leaf.SerialNumber.Text(16),
		NotAfter:   leaf.NotAfter.UTC(),
		RenewAfter: parseTimeOr(in.RenewAfter, defaultRenewAfter(leaf.NotBefore, leaf.NotAfter)),
	}
	return &Material{CertPEM: bundle, Key: key, Meta: meta}, nil
}

// defaultRenewAfter is the fallback when the control plane names no time: two
// thirds through the lifetime, leaving the last third as retry budget, so a
// missing field cannot mean "never renew".
func defaultRenewAfter(notBefore, notAfter time.Time) time.Time {
	life := notAfter.Sub(notBefore)
	if life <= 0 {
		return notAfter
	}
	return notBefore.Add(life * 2 / 3).UTC()
}

func parseTimeOr(raw string, fallback time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw)); err == nil {
		return t.UTC()
	}
	return fallback
}

func ensureTrailingNewline(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
