// Package session serves remote access sessions on a device. Server accepts
// session streams from the device's mux, verifies each ticket and records
// its jti against replay (JTILog), runs the hybrid X25519 + ML-KEM-768
// handshake, and carries the session's messages over a ChaCha20-Poly1305
// record channel. It starts terminal sessions in a pseudo-terminal and
// records them when the ticket asks for it. The client half of the handshake
// (GenerateClientKeys, Open) is here too, so tests can play the client.
package session

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/localport/agent/internal/recording"
)

// Error codes a caller matches through errors.As on *Error. The ticket codes
// are the wire codes of the agent's refused frame.
const (
	CodeTicketInvalid     = "ticket_invalid"
	CodeTicketExpired     = "ticket_expired"
	CodeTicketWrongDevice = "ticket_wrong_device"
	CodeTicketUnknownKey  = "ticket_unknown_key"
	// CodeHandshakeInvalid is a malformed accept message or ticket at the client.
	CodeHandshakeInvalid = "handshake_invalid"
	// CodeHandshakeWrongDevice is a device_spki_der whose hash is not the
	// ticket's device_spki_sha256.
	CodeHandshakeWrongDevice = "handshake_wrong_device"
	// CodeHandshakeBadSignature is an accept message the device key did not sign.
	CodeHandshakeBadSignature = "handshake_bad_signature"
	// CodeProtocolError is a record that fails authentication, is out of
	// order, oversize or carries an invalid message.
	CodeProtocolError = "protocol_error"
	// CodeTruncated is a transport that ended before a close message.
	CodeTruncated = "truncated"
)

// Error is a session failure with a code callers branch on.
type Error struct {
	Code   string
	Detail string
	// Err is the underlying cause, when there is one.
	Err error
}

func (e *Error) Error() string {
	s := e.Code + ": " + e.Detail
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

func fail(code, detail string) *Error { return &Error{Code: code, Detail: detail} }

// ticketVersion is the only payload version this package accepts.
const ticketVersion = 1

// ticketSkew is the clock skew tolerated on exp, the same on edge and agent,
// and on iat, which only the agent checks: it bounds an agent clock behind
// the API.
const ticketSkew = 30 * time.Second

// maxTicketLifetime is the longest exp - iat the agent accepts, so the jti
// hold does not depend on the lifetime the API mints.
const maxTicketLifetime = 60 * time.Second

// Lookup returns the Ed25519 ticket verification key for kid.
// (*identity.TicketKeys).Lookup has this shape.
type Lookup func(kid string) (ed25519.PublicKey, bool)

// Device names the device a ticket must be bound to.
type Device struct {
	// Prefix is the device prefix the ticket's device field carries.
	Prefix string
	// SPKISHA256 is SPKIHash of the device certificate's leaf public key.
	SPKISHA256 string
}

// Ticket is a ticket payload, with the field names and order the API signs.
// Binary fields are unpadded base64url.
type Ticket struct {
	V                int         `json:"v"`
	KID              string      `json:"kid"`
	JTI              string      `json:"jti"`
	IAT              int64       `json:"iat"`
	EXP              int64       `json:"exp"`
	Team             string      `json:"team"`
	Tunnel           string      `json:"tunnel"`
	Device           string      `json:"device"`
	DeviceSPKISHA256 string      `json:"device_spki_sha256"`
	Edge             string      `json:"edge"`
	Subject          string      `json:"subject"`
	UserID           *string     `json:"user_id"`
	Kind             string      `json:"kind"`
	Login            string      `json:"login"`
	ClientX25519     string      `json:"client_x25519"`
	ClientMLKEM      string      `json:"client_mlkem"`
	WebSession       *string     `json:"web_session"`
	Rec              *TicketRec  `json:"rec"`
	Cert             *TicketCert `json:"cert"`

	// raw is the ticket as received; the handshake transcript covers it.
	raw       []byte
	clientX   *ecdh.PublicKey
	clientKEM *mlkem.EncapsulationKey768
}

// TicketCert binds a CLI ticket to its consumer certificate.
type TicketCert struct {
	AnchorFP string `json:"anchor_fp"`
	Serial   string `json:"serial"`
	NotAfter int64  `json:"not_after"`
}

// Recording policies a ticket's rec names.
const (
	RecPolicyBestEffort = recording.PolicyBestEffort
	RecPolicyStrict     = recording.PolicyStrict
)

// TicketRec asks the agent to record the session: ID is the recording id (the
// ticket's jti), PubSHA256 the unpadded base64url SHA-256 of the team
// recording key the recording is sealed to, Policy RecPolicyBestEffort or
// RecPolicyStrict. A ticket with rec null has a nil Rec.
type TicketRec struct {
	ID        string `json:"id"`
	PubSHA256 string `json:"pub_sha256"`
	Policy    string `json:"policy"`
}

// recordingIDPattern is the canonical lowercase UUID text.
var recordingIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (r *TicketRec) validate(jti string) error {
	invalid := func(detail string) error { return fail(CodeTicketInvalid, detail) }
	if !recordingIDPattern.MatchString(r.ID) || r.ID != jti {
		return invalid("rec id is not a UUID equal to the jti")
	}
	if sum, err := base64.RawURLEncoding.Strict().DecodeString(r.PubSHA256); err != nil || len(sum) != sha256.Size {
		return invalid("rec pub_sha256 is not an unpadded base64url SHA-256")
	}
	if r.Policy != RecPolicyBestEffort && r.Policy != RecPolicyStrict {
		return invalid("rec policy is unknown")
	}
	return nil
}

// SPKIHash is the device_spki_sha256 encoding: unpadded base64url SHA-256 of a
// DER SubjectPublicKeyInfo (x509.Certificate.RawSubjectPublicKeyInfo).
func SPKIHash(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyTicket checks raw against the key lookup names for its kid, the clock
// now and the device, and returns the parsed ticket. The signature is checked
// over the exact payload bytes before the payload is trusted; only v and kid
// are read first, to pick the key. Every failure is an *Error with a ticket
// code; CodeTicketUnknownKey is the one a caller may retry after refreshing
// its keys.
func VerifyTicket(raw []byte, lookup Lookup, device Device, now time.Time) (*Ticket, error) {
	payload, sig, err := splitTicket(raw)
	if err != nil {
		return nil, err
	}
	var head struct {
		V   int    `json:"v"`
		KID string `json:"kid"`
	}
	if json.Unmarshal(payload, &head) != nil {
		return nil, fail(CodeTicketInvalid, "payload is not JSON")
	}
	if head.V != ticketVersion {
		return nil, fail(CodeTicketInvalid, fmt.Sprintf("unknown version %d", head.V))
	}
	key, ok := lookup(head.KID)
	if !ok {
		return nil, fail(CodeTicketUnknownKey, "unknown signing key")
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, payload, sig) {
		return nil, fail(CodeTicketInvalid, "bad signature")
	}
	var t Ticket
	if err := json.Unmarshal(payload, &t); err != nil {
		return nil, &Error{Code: CodeTicketInvalid, Detail: "payload does not parse", Err: err}
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	issued, expires := time.Unix(t.IAT, 0), time.Unix(t.EXP, 0)
	// The details carry the clock difference: a device without a real-time
	// clock refuses every ticket until its clock is set.
	if issued.After(now.Add(ticketSkew)) {
		return nil, fail(CodeTicketExpired, fmt.Sprintf("ticket not yet valid: issued %s ahead of this device's clock", issued.Sub(now).Round(time.Second)))
	}
	if expires.Sub(issued) > maxTicketLifetime {
		return nil, fail(CodeTicketExpired, "ticket lifetime above 60 s")
	}
	if now.After(expires.Add(ticketSkew)) {
		return nil, fail(CodeTicketExpired, fmt.Sprintf("ticket expired %s before this device's clock", now.Sub(expires).Round(time.Second)))
	}
	if t.Device != device.Prefix || t.DeviceSPKISHA256 != device.SPKISHA256 {
		return nil, fail(CodeTicketWrongDevice, "ticket is for another device")
	}
	t.raw = raw
	return &t, nil
}

// Raw is the ticket as received.
func (t *Ticket) Raw() []byte { return t.raw }

func splitTicket(raw []byte) (payload, sig []byte, err error) {
	payloadB64, sigB64, found := bytes.Cut(raw, []byte("."))
	if !found {
		return nil, nil, fail(CodeTicketInvalid, "not payload.signature")
	}
	payload = make([]byte, base64.RawURLEncoding.DecodedLen(len(payloadB64)))
	n, decodeErr := base64.RawURLEncoding.Strict().Decode(payload, payloadB64)
	if decodeErr != nil {
		return nil, nil, fail(CodeTicketInvalid, "payload is not base64url")
	}
	payload = payload[:n]
	sig = make([]byte, base64.RawURLEncoding.DecodedLen(len(sigB64)))
	n, decodeErr = base64.RawURLEncoding.Strict().Decode(sig, sigB64)
	if decodeErr != nil || n != ed25519.SignatureSize {
		return nil, nil, fail(CodeTicketInvalid, "signature is not base64url Ed25519")
	}
	return payload, sig[:n], nil
}

// validate checks the fields the agent relies on and parses the client keys.
func (t *Ticket) validate() error {
	invalid := func(detail string) error { return fail(CodeTicketInvalid, detail) }
	if t.JTI == "" || t.Tunnel == "" || t.Device == "" || t.Subject == "" {
		return invalid("missing jti, tunnel, device or subject")
	}
	switch t.Kind {
	case "terminal", "files", "ssh":
		if t.Login == "" {
			return invalid("login is empty")
		}
	case "rdp", "vnc":
	default:
		return invalid("unknown kind")
	}
	if t.Cert != nil && (t.Cert.AnchorFP == "" || t.Cert.Serial == "" || t.Cert.NotAfter == 0) {
		return invalid("incomplete cert binding")
	}
	if t.Rec != nil {
		if err := t.Rec.validate(t.JTI); err != nil {
			return err
		}
	}
	x, err := base64.RawURLEncoding.Strict().DecodeString(t.ClientX25519)
	if err != nil {
		return invalid("client_x25519 is not base64url")
	}
	if t.clientX, err = ecdh.X25519().NewPublicKey(x); err != nil {
		return invalid("client_x25519 is not a public key")
	}
	m, err := base64.RawURLEncoding.Strict().DecodeString(t.ClientMLKEM)
	if err != nil {
		return invalid("client_mlkem is not base64url")
	}
	if t.clientKEM, err = mlkem.NewEncapsulationKey768(m); err != nil {
		return invalid("client_mlkem is not an ML-KEM-768 encapsulation key")
	}
	return nil
}
