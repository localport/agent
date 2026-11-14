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
	"strconv"
	"time"

	"github.com/localport/agent/internal/security"
)

// sessionRequestContext is the domain separator of a session certificate
// request signature, the control plane's construction.
const sessionRequestContext = "localport-session-request-v1"

// SessionRequest is one session certificate request: the device, the session
// kind and login, and the client's `ssh-ed25519` public key in authorized_keys
// form, which the certificate is issued for. ResumeCertificate, when set, is
// the certificate of the connection to resume (authorized_keys form): the
// answer is a resume certificate for the same key.
type SessionRequest struct {
	DeviceHost        string
	Kind              string
	Login             string
	ClientSSHPubKey   string
	ResumeCertificate string
}

// SessionCertificate is the control plane's answer to a SessionRequest.
type SessionCertificate struct {
	// Certificate is the OpenSSH user certificate in authorized_keys form.
	Certificate string `json:"certificate"`
	// URL is the WebSocket endpoint on the device's edge.
	URL string `json:"url"`
	// HostKey is the device's SSH host key in authorized_keys form; clients
	// accept exactly this key.
	HostKey    string `json:"host_key"`
	DeviceHost string `json:"device_host"`
}

type mintSessionBody struct {
	DeviceHost      string `json:"device_host"`
	Kind            string `json:"kind"`
	Login           string `json:"login"`
	ClientSSHPubKey string `json:"client_ssh_pubkey"`
	CertChain       string `json:"cert_chain"`
	Timestamp       int64  `json:"timestamp"`
	// ResumeCertificate is omitted on a fresh request.
	ResumeCertificate string `json:"resume_certificate,omitempty"`
	Sig               string `json:"sig"`
}

// MintSession asks POST /v1/sessions for a session certificate. The request
// carries cur's certificate and its key's signature over sessionRequestDigest,
// which the control plane accepts within a minute of its clock. Transport
// failures, 5xx and 429 are retried within DefaultRetryBudget; other refusals
// return at once as an *APIError. A device credential returns
// ErrDeviceCredential.
func (c *Client) MintSession(ctx context.Context, cur *Material, req SessionRequest) (*SessionCertificate, error) {
	if cur.Meta.Kind == KindDevice {
		return nil, ErrDeviceCredential.With(nil, security.SanitizeDisplay(cur.Meta.Identity))
	}
	leaf, err := leafOf(cur.CertPEM)
	if err != nil {
		return nil, err
	}
	body := mintSessionBody{
		DeviceHost:      req.DeviceHost,
		Kind:            req.Kind,
		Login:           req.Login,
		ClientSSHPubKey: req.ClientSSHPubKey,
		CertChain:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})),

		ResumeCertificate: req.ResumeCertificate,
	}
	// Sign per attempt, since a retry can cross a minute boundary.
	var resp SessionCertificate
	key := newIdempotencyKey()
	if err := retry(ctx, DefaultRetryBudget, nil, func() error {
		body.Timestamp = time.Now().Unix()
		sig, signErr := cur.Key.Sign(rand.Reader, sessionRequestDigest(body), crypto.SHA256)
		if signErr != nil {
			return fmt.Errorf("sign session request: %w", signErr)
		}
		body.Sig = base64.StdEncoding.EncodeToString(sig)
		resp = SessionCertificate{}
		return c.post(ctx, "/v1/sessions", "", key, body, &resp)
	}); err != nil {
		return nil, err
	}
	if resp.Certificate == "" || resp.URL == "" || resp.HostKey == "" {
		return nil, errAnswer.With(nil, "the session certificate answer has no certificate, URL or host key")
	}
	return &resp, nil
}

// sessionRequestDigest is SHA-256(sessionRequestContext || canonical request ||
// minute bucket): each of device_host, kind, login, client_ssh_pubkey,
// cert_chain, timestamp (decimal) and, only when set, resume_certificate as a
// 4-byte big-endian length and its bytes, then timestamp/60 as 8 bytes
// big-endian. A request without resume_certificate keeps the digest it had
// before the field existed.
func sessionRequestDigest(b mintSessionBody) []byte {
	h := sha256.New()
	h.Write([]byte(sessionRequestContext))
	var length [4]byte
	fields := []string{b.DeviceHost, b.Kind, b.Login, b.ClientSSHPubKey, b.CertChain, strconv.FormatInt(b.Timestamp, 10)}
	if b.ResumeCertificate != "" {
		fields = append(fields, b.ResumeCertificate)
	}
	for _, field := range fields {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		h.Write(length[:])
		h.Write([]byte(field))
	}
	var bucket [8]byte
	binary.BigEndian.PutUint64(bucket[:], uint64(b.Timestamp/60))
	h.Write(bucket[:])
	return h.Sum(nil)
}
