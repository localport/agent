package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

// issueResponse is POST /v1/mtls/certs. The agent always sends a CSR, so the
// material comes back inline and holds nothing secret.
type issueResponse struct {
	CertPEM    string `json:"cert_pem"`
	CAChainPEM string `json:"ca_chain_pem"`
	RenewAfter string `json:"renew_after"`
	TeamName   string `json:"team_name"`
}

// renewResponse is POST /v1/mtls/certs/renew and POST /v1/devices/renew. Keys
// is set for a device only.
type renewResponse struct {
	CertPEM    string      `json:"cert_pem"`
	CAChainPEM string      `json:"ca_chain_pem"`
	RenewAfter string      `json:"renew_after"`
	TeamName   string      `json:"team_name"`
	Keys       *DeviceKeys `json:"keys"`
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
	// Device is set for a device credential only.
	Device *DeviceInfo
}

// RedeemSetupToken redeems a single-use setup token and returns the
// credential. The token is not written to disk. budget bounds retries against
// an unreachable control plane. Refusals are not retried. onWait reports each
// wait.
func (c *Client) RedeemSetupToken(
	ctx context.Context, token string, budget time.Duration, onWait RetryNotice,
) (*Material, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("setup token required")
	}
	kp, err := newKeyPair("")
	if err != nil {
		return nil, err
	}

	var resp issueResponse
	key := newIdempotencyKey()
	if err := retry(ctx, budget, onWait, func() error {
		resp = issueResponse{}
		return c.post(ctx, "/v1/mtls/certs", token, key, map[string]string{
			"csr_pem": string(kp.csrPEM),
		}, &resp)
	}); err != nil {
		return nil, err
	}
	if resp.CertPEM == "" {
		// Fail before writing an empty credential.
		return nil, errAnswer.With(nil, "no certificate for the CSR")
	}

	return consumerOnly(c.assemble(kp.key, issuedMaterial{
		CertPEM:    resp.CertPEM,
		ChainPEM:   resp.CAChainPEM,
		Source:     SourceToken,
		RenewAfter: resp.RenewAfter,
		TeamName:   resp.TeamName,
	}))
}

// consumerOnly refuses a device credential from a consumer issuance route
// (setup token, sign-in) with ErrDeviceCredential.
func consumerOnly(m *Material, err error) (*Material, error) {
	if err == nil && m.Meta.Kind == KindDevice {
		return nil, ErrDeviceCredential
	}
	return m, err
}

// ErrNotRenewable is a sentinel so callers can tell "never renews" from
// "renewal failed, retry": the loop backs off on the second and must stop on
// the first.
var ErrNotRenewable = errcode.New(errcode.NotRenewable)

// Renew exchanges the stored credential for a new one. The current private
// key proves possession, so no bearer token is needed. A consumer's old
// certificate stays valid until it expires.
//
// A device credential renews at /v1/devices/renew, which accepts an expired
// certificate. The result is a pending credential (see Store.Promote); the
// control plane supersedes the old certificate when the pending one registers.
//
// The new certificate must name the same credential and carry the key
// generated here, or nothing is returned to store.
func (c *Client) Renew(ctx context.Context, cur *Material) (*Material, error) {
	// All renewal paths call Renew, so the check lives here. A consumer
	// credential the control plane gave no renew_after does not renew (its
	// setup token's stop, or its own expiry, leaves no room for one); a device
	// always has one.
	if !cur.Meta.Source.Renewable() || (cur.Meta.Kind != KindDevice && cur.Meta.RenewAfter == nil) {
		return nil, ErrNotRenewable
	}

	leaf, err := leafOf(cur.CertPEM)
	if err != nil {
		return nil, err
	}
	kp, err := newKeyPair(cur.Meta.Identity)
	if err != nil {
		return nil, err
	}

	// Proof is Sign(oldKey, SHA256(csrDER || minuteBucket || serial)). The
	// minute bucket limits replay without a nonce store. The serial binds the
	// proof to one certificate.
	serial := leaf.SerialNumber.Text(16)
	path := "/v1/mtls/certs/renew"
	if cur.Meta.Kind == KindDevice {
		path = "/v1/devices/renew"
	}

	// Sign per attempt, since a retry can cross a minute boundary; the key
	// stays, and the signature is not part of what it identifies.
	var resp renewResponse
	key := newIdempotencyKey()
	if err := retry(ctx, DefaultRetryBudget, nil, func() error {
		digest := renewalDigest(kp.csrDER, time.Now().Unix()/60, serial)
		sig, signErr := cur.Key.Sign(rand.Reader, digest, crypto.SHA256)
		if signErr != nil {
			return fmt.Errorf("sign renewal: %w", signErr)
		}
		resp = renewResponse{}
		return c.post(ctx, path, "", key, map[string]string{
			"cert_pem":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})),
			"csr_pem":   string(kp.csrPEM),
			"signature": base64.StdEncoding.EncodeToString(sig),
		}, &resp)
	}); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden && cur.Meta.Kind == KindDevice {
			return nil, errcode.WithRemedy(err, "this device can no longer renew its certificate; "+errcode.NewJoinCommand)
		}
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden {
			return nil, errcode.WithRemedy(err, "this credential can no longer be renewed; run `localport setup <TOKEN>` again")
		}
		return nil, err
	}
	if resp.CertPEM == "" {
		return nil, errAnswer.With(nil, "no certificate")
	}

	// Keep the Source of the replaced credential. Keep the team name when the
	// response omits it, since the server resolves it best effort.
	teamName := resp.TeamName
	if teamName == "" {
		teamName = cur.Meta.TeamName
	}
	// Device details carry over; the response's keys go to TicketKeys when
	// the renewal is stored.
	var device *DeviceInfo
	if cur.Meta.Device != nil {
		d := *cur.Meta.Device
		device = &d
	}
	next, err := c.assemble(kp.key, issuedMaterial{
		CertPEM:    resp.CertPEM,
		ChainPEM:   resp.CAChainPEM,
		Source:     cur.Meta.Source,
		RenewAfter: resp.RenewAfter,
		TeamName:   teamName,
		Device:     device,
	})
	if err != nil {
		return nil, err
	}
	if err := checkIssued(next, Ref{Team: cur.Meta.Team, Kind: cur.Meta.Kind, Identity: cur.Meta.Identity}); err != nil {
		return nil, err
	}
	if err := deviceRenews(next); err != nil {
		return nil, err
	}
	if cur.Meta.Kind == KindDevice {
		next.DeviceKeys = issuedKeys(resp.Keys)
	}
	return next, nil
}

// checkIssued refuses an issued credential whose certificate names another
// credential than want, or does not carry the key generated for it. Either is
// a broken control plane, and storing it would replace a working credential.
func checkIssued(m *Material, want Ref) error {
	if got := (Ref{Team: m.Meta.Team, Kind: m.Meta.Kind, Identity: m.Meta.Identity}); got != want {
		// The issued name is control-plane text: it stays in the cause.
		return errAnswer.With(fmt.Errorf("the certificate is for %s, but %s was requested",
			security.SanitizeDisplay(got.String()), security.SanitizeDisplay(want.String())), "the certificate names another credential than requested")
	}
	_, err := m.TLSCertificate()
	return err
}

// assemble turns a response into on-disk material. Leaf first, then the chain:
// the order a PEM bundle requires.
//
// Identity, team and kind come from the certificate, never the response body.
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
		Identity: ref.Identity,
		Team:     ref.Team,
		TeamName: in.TeamName,
		Kind:     ref.Kind,
		SpiffeID: SpiffeURI(leaf),
		Source:   in.Source,
		APIURL:   c.BaseURL,
		Serial:   leaf.SerialNumber.Text(16),
		NotAfter: leaf.NotAfter.UTC(),
		Device:   in.Device,
	}
	// The control plane's renew_after is authoritative: absent means the
	// certificate does not renew. It is stored only for a source that renews,
	// so the field's presence and meaning never disagree.
	if raw := strings.TrimSpace(in.RenewAfter); raw != "" && in.Source.Renewable() {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return nil, errAnswer.With(fmt.Errorf("renew_after %q", security.SanitizeDisplay(raw)), "invalid renewal time")
		}
		t = t.UTC()
		meta.RenewAfter = &t
	}
	return &Material{CertPEM: bundle, Key: key, Meta: meta}, nil
}

// deviceRenews refuses a device credential the control plane gave no renewal
// time: a device always renews, so the answer is broken, and storing it would
// silently stop the device's renewals.
func deviceRenews(m *Material) error {
	if m.Meta.Kind == KindDevice && m.Meta.RenewAfter == nil {
		return errAnswer.With(nil, "no renewal time for a device certificate")
	}
	return nil
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

func leafOf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate in PEM data")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return leaf, nil
}

func ensureTrailingNewline(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
