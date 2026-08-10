package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
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
	TeamName   string `json:"team_name"`
}

// renewResponse is POST /v1/mtls/certs/renew.
type renewResponse struct {
	CertPEM    string `json:"cert_pem"`
	CAChainPEM string `json:"ca_chain_pem"`
	RenewAfter string `json:"renew_after"`
	TeamName   string `json:"team_name"`
}

// issuedMaterial is one issuance response in the shape assemble consumes. A
// struct rather than positional strings, which transpose silently.
type issuedMaterial struct {
	CertPEM    string
	ChainPEM   string
	Source     Source
	RenewAfter string
	// TeamName is cosmetic and may be empty; see Meta.TeamName.
	TeamName string
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
		TeamName:   resp.TeamName,
	})
}

// Renew exchanges the credential we hold for a fresh one.
//
// No bearer token: possession of the current private key is the proof, so the
// setup token need not be kept. The certificate being replaced stays valid, so
// rollover overlaps.
func (c *Client) Renew(ctx context.Context, cur *Material) (*Material, error) {
	leaf, err := leafOf(cur.CertPEM)
	if err != nil {
		return nil, err
	}
	kp, err := newKeyPair(cur.Meta.Identity)
	if err != nil {
		return nil, err
	}

	// Sign(oldKey, SHA256(csrDER || minuteBucket || serial)). The minute bucket
	// bounds replay with no nonce store; the serial binds the signature to the one
	// certificate it was made for.
	serial := leaf.SerialNumber.Text(16)
	digest := renewalDigest(kp.csrDER, time.Now().Unix()/60, serial)
	sig, err := cur.Key.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign renewal: %w", err)
	}

	var resp renewResponse
	if err := c.post(ctx, "/v1/mtls/certs/renew", "", map[string]string{
		"cert_pem":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})),
		"csr_pem":   string(kp.csrPEM),
		"signature": base64.StdEncoding.EncodeToString(sig),
	}, &resp); err != nil {
		return nil, err
	}
	if resp.CertPEM == "" {
		return nil, fmt.Errorf("control plane returned no certificate")
	}

	// Source carried from the credential being replaced: a renewal does not change
	// how the identity was established. The team name is carried forward when the
	// response omits it, because the server resolves it best-effort and a renewal
	// may refresh the name but must never blank it.
	teamName := resp.TeamName
	if teamName == "" {
		teamName = cur.Meta.TeamName
	}
	return c.assemble(kp.key, issuedMaterial{
		CertPEM:    resp.CertPEM,
		ChainPEM:   resp.CAChainPEM,
		Source:     cur.Meta.Source,
		RenewAfter: resp.RenewAfter,
		TeamName:   teamName,
	})
}

func renewalDigest(csrDER []byte, bucket int64, serial string) []byte {
	h := sha256.New()
	h.Write(csrDER)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(bucket))
	h.Write(b[:])
	h.Write([]byte(serial))
	return h.Sum(nil)
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
		TeamName:   in.TeamName,
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
