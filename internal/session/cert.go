package session

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

// Critical option and extension names of a session certificate, and the one
// principal of a desktop certificate. The API mints them; structured values are
// compact JSON.
const (
	optionDevice     = "device@localport.io"
	extKind          = "kind@localport.io"
	extSubject       = "subject@localport.io"
	extRec           = "rec@localport.io"
	extForwardLocal  = "port-forwarding-local@localport.io"
	extForwardRemote = "port-forwarding-remote@localport.io"
	desktopPrincipal = "localport-desktop"
)

// certSkew is the clock skew tolerated on a certificate's validity window,
// the same at the edge.
const certSkew = 30 * time.Second

// Recording policies a certificate's rec names.
const (
	RecPolicyBestEffort = "best_effort"
	RecPolicyStrict     = "strict"
)

// Device names the device a certificate must be for.
type Device struct {
	// Prefix is the device prefix the device option carries.
	Prefix string
	// SPKISHA256 is SPKIHash of the device certificate's leaf public key.
	SPKISHA256 string
}

// SPKIHash is the unpadded base64url SHA-256 of a DER SubjectPublicKeyInfo,
// the encoding a certificate's device option carries.
func SPKIHash(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// certRec is a recorded session's rec extension.
type certRec struct {
	Policy    string `json:"policy"`
	PubSHA256 string `json:"pub_sha256"`
}

// admission is what a verified certificate admits: the identity the channel
// handlers read, and the certificate's wire form, which a recording open
// forwards.
type admission struct {
	Kind    string
	Login   string
	Subject string
	Rec     *certRec
	Cert    []byte
	// ForwardLocal and ForwardRemote are the certificate's forwarding
	// extensions, honoured on an ssh connection only.
	ForwardLocal  bool
	ForwardRemote bool
}

// errCertRefused is every certificate refusal; the detail goes to the log
// only, as an SSH client learns nothing but the userauth failure.
var errCertRefused = errors.New("session certificate refused")

func refuseCert(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errCertRefused, fmt.Sprintf(format, args...))
}

// verifyCert checks a user certificate whose key possession userauth proved:
// a user certificate signed by one of cas, with exactly the serial the edge
// admitted, valid at now within certSkew, for principal user, with no
// critical option but the device option, which must name device. It returns
// the certificate's claims; the caller applies the local config.
func verifyCert(cert *ssh.Certificate, user string, cas []ed25519.PublicKey, device Device, serial uint64, now time.Time) (*admission, error) {
	if cert.CertType != ssh.UserCert {
		return nil, refuseCert("not a user certificate")
	}
	if cert.Serial != serial {
		return nil, refuseCert("serial %x is not the admitted serial %x", cert.Serial, serial)
	}
	if !signedByCA(cert, cas) {
		return nil, refuseCert("not signed by a session CA key")
	}
	after, before := time.Unix(int64(min(cert.ValidAfter, 1<<62)), 0), time.Unix(int64(min(cert.ValidBefore, 1<<62)), 0)
	if now.Add(certSkew).Before(after) || !now.Add(-certSkew).Before(before) {
		return nil, refuseCert("outside its validity window (%v to %v, now %v)", after.UTC(), before.UTC(), now.UTC())
	}
	checker := ssh.CertChecker{
		SupportedCriticalOptions: []string{optionDevice},
		// The window was checked above with the skew; CheckCert sees a time
		// inside it, and checks the signature, the principal and the options.
		Clock: func() time.Time { return clampInto(now, after, before) },
	}
	if err := checker.CheckCert(user, cert); err != nil {
		return nil, refuseCert("%v", err)
	}
	var d struct {
		Tunnel     string `json:"tunnel"`
		Prefix     string `json:"prefix"`
		SPKISHA256 string `json:"spki_sha256"`
	}
	if err := strictJSON(cert.CriticalOptions[optionDevice], &d); err != nil || d.Tunnel == "" {
		return nil, refuseCert("device option malformed")
	}
	if d.Prefix != device.Prefix || d.SPKISHA256 != device.SPKISHA256 {
		return nil, refuseCert("for device %q, not this device", d.Prefix)
	}
	a := &admission{Kind: cert.Extensions[extKind], Login: user, Cert: cert.Marshal()}
	_, a.ForwardLocal = cert.Extensions[extForwardLocal]
	_, a.ForwardRemote = cert.Extensions[extForwardRemote]
	var s struct {
		Subject string `json:"subject"`
		UserID  string `json:"user_id,omitempty"`
	}
	if err := strictJSON(cert.Extensions[extSubject], &s); err != nil || s.Subject == "" {
		return nil, refuseCert("subject extension malformed")
	}
	a.Subject = s.Subject
	if raw, ok := cert.Extensions[extRec]; ok {
		var r certRec
		if err := strictJSON(raw, &r); err != nil || (r.Policy != RecPolicyBestEffort && r.Policy != RecPolicyStrict) || r.PubSHA256 == "" {
			return nil, refuseCert("rec extension malformed")
		}
		a.Rec = &r
	}
	return a, nil
}

// signedByCA reports whether cert's signature key is one of cas. CheckCert
// verifies the signature itself.
func signedByCA(cert *ssh.Certificate, cas []ed25519.PublicKey) bool {
	ck, ok := cert.SignatureKey.(ssh.CryptoPublicKey)
	if !ok || cert.SignatureKey.Type() != ssh.KeyAlgoED25519 {
		return false
	}
	pub, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return false
	}
	for _, ca := range cas {
		if bytes.Equal(ca, pub) {
			return true
		}
	}
	return false
}

// clampInto returns t moved into [after, before).
func clampInto(t, after, before time.Time) time.Time {
	if t.Before(after) {
		return after
	}
	if !t.Before(before) {
		return before.Add(-time.Second)
	}
	return t
}

// strictJSON decodes one JSON value into v, refusing unknown fields and
// trailing data.
func strictJSON(s string, v any) error {
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}
