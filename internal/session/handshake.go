package session

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Handshake constants: the transcript label and the HKDF info strings.
const (
	transcriptLabel = "localport-session-v1"
	infoC2A         = "lp-session c2a"
	infoA2C         = "lp-session a2c"
	// p256ScalarSize is the byte length of r and s in a P1363 P-256 signature.
	p256ScalarSize = 32
	// x25519KeySize is the byte length of an X25519 public key.
	x25519KeySize = 32
)

// AcceptMessageType is the type field of the agent's accept first frame.
const AcceptMessageType = "accept"

// AcceptMessage is the agent's accept first frame. Binary fields are unpadded
// base64url; Sig is the IEEE P1363 (r || s) ECDSA P-256 signature over
// SHA-256 of the transcript.
type AcceptMessage struct {
	Type    string `json:"type"`
	AX25519 string `json:"a_x25519"`
	CTMLKEM string `json:"ct_mlkem"`
	Sig     string `json:"sig"`
}

// Keys are the two directional record keys of one session, 32 bytes each.
type Keys struct {
	C2A []byte
	A2C []byte
}

// ClientKeys are the client's ephemeral key pairs; both public halves go into
// the ticket request.
type ClientKeys struct {
	X25519 *ecdh.PrivateKey
	MLKEM  *mlkem.DecapsulationKey768
}

// GenerateClientKeys creates fresh ephemeral X25519 and ML-KEM-768 key pairs.
func GenerateClientKeys() (*ClientKeys, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	m, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate ml-kem key: %w", err)
	}
	return &ClientKeys{X25519: x, MLKEM: m}, nil
}

// encapsulateFunc encapsulates to a client ML-KEM key, returning the shared
// secret and the ciphertext.
type encapsulateFunc func(*mlkem.EncapsulationKey768) (sharedKey, ciphertext []byte, err error)

// Accept runs the agent side of the handshake for a verified ticket: a fresh
// X25519 key, an ML-KEM encapsulation to the client, the device signature
// over the transcript, and the session keys. device must be a P-256 key; its
// Sign returns ASN.1 DER as crypto.Signer for ECDSA does.
func Accept(t *Ticket, device crypto.Signer) (*AcceptMessage, Keys, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, Keys{}, fmt.Errorf("generate x25519 key: %w", err)
	}
	encapsulate := func(ek *mlkem.EncapsulationKey768) ([]byte, []byte, error) {
		ss, ct := ek.Encapsulate()
		return ss, ct, nil
	}
	return accept(t, device, eph, encapsulate, rand.Reader)
}

// accept is Accept with its randomness supplied, so the vectors are
// reproducible: a nil signRand makes an ECDSA signer deterministic (RFC 6979).
func accept(t *Ticket, device crypto.Signer, eph *ecdh.PrivateKey, encapsulate encapsulateFunc, signRand io.Reader) (*AcceptMessage, Keys, error) {
	if pub, ok := device.Public().(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return nil, Keys{}, errors.New("device key is not ECDSA P-256")
	}
	ssX, err := eph.ECDH(t.clientX)
	if err != nil {
		return nil, Keys{}, &Error{Code: CodeTicketInvalid, Detail: "client_x25519 is a low-order point", Err: err}
	}
	ssPQ, ct, err := encapsulate(t.clientKEM)
	if err != nil {
		return nil, Keys{}, fmt.Errorf("ml-kem encapsulate: %w", err)
	}
	aPub := eph.PublicKey().Bytes()
	tr := transcript(t.raw, aPub, ct)
	digest := sha256.Sum256(tr[:])
	der, err := device.Sign(signRand, digest[:], crypto.SHA256)
	if err != nil {
		return nil, Keys{}, fmt.Errorf("sign transcript: %w", err)
	}
	sig, err := p1363FromASN1(der)
	if err != nil {
		return nil, Keys{}, err
	}
	keys, err := deriveKeys(ssPQ, ssX, tr[:])
	if err != nil {
		return nil, Keys{}, err
	}
	enc := base64.RawURLEncoding
	return &AcceptMessage{
		Type:    AcceptMessageType,
		AX25519: enc.EncodeToString(aPub),
		CTMLKEM: enc.EncodeToString(ct),
		Sig:     enc.EncodeToString(sig),
	}, keys, nil
}

// Open runs the client side of the handshake: it checks that spkiDER is the
// key the ticket binds, verifies the device signature over the transcript and
// derives the session keys. ticket is the exact ticket string the client sent.
// Failures are *Error with a CodeHandshake* code.
func Open(ticket, spkiDER []byte, msg *AcceptMessage, ck *ClientKeys) (Keys, error) {
	invalid := func(detail string) error { return fail(CodeHandshakeInvalid, detail) }
	if msg.Type != AcceptMessageType {
		return Keys{}, invalid("not an accept message")
	}
	payload, _, err := splitTicket(ticket)
	if err != nil {
		return Keys{}, invalid("ticket does not parse")
	}
	var bound struct {
		DeviceSPKISHA256 string `json:"device_spki_sha256"`
	}
	if json.Unmarshal(payload, &bound) != nil {
		return Keys{}, invalid("ticket payload does not parse")
	}
	if SPKIHash(spkiDER) != bound.DeviceSPKISHA256 {
		return Keys{}, fail(CodeHandshakeWrongDevice, "device key is not the one the ticket binds")
	}
	parsed, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return Keys{}, invalid("device_spki_der does not parse")
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return Keys{}, invalid("device key is not ECDSA P-256")
	}
	// Every size is checked before the signature, so the transcript hashes
	// only well-formed fields.
	enc := base64.RawURLEncoding.Strict()
	aPub, errX := enc.DecodeString(msg.AX25519)
	ct, errC := enc.DecodeString(msg.CTMLKEM)
	sig, errS := enc.DecodeString(msg.Sig)
	if errX != nil || errC != nil || errS != nil ||
		len(aPub) != x25519KeySize || len(ct) != mlkem.CiphertextSize768 || len(sig) != 2*p256ScalarSize {
		return Keys{}, invalid("accept fields are not base64url of the right size")
	}
	tr := transcript(ticket, aPub, ct)
	digest := sha256.Sum256(tr[:])
	r := new(big.Int).SetBytes(sig[:p256ScalarSize])
	s := new(big.Int).SetBytes(sig[p256ScalarSize:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return Keys{}, fail(CodeHandshakeBadSignature, "device signature does not verify")
	}
	agentX, err := ecdh.X25519().NewPublicKey(aPub)
	if err != nil {
		return Keys{}, invalid("a_x25519 is not a public key")
	}
	ssX, err := ck.X25519.ECDH(agentX)
	if err != nil {
		return Keys{}, invalid("a_x25519 is a low-order point")
	}
	ssPQ, err := ck.MLKEM.Decapsulate(ct)
	if err != nil {
		return Keys{}, invalid("ct_mlkem is not an ML-KEM-768 ciphertext")
	}
	return deriveKeys(ssPQ, ssX, tr[:])
}

// transcript is T = SHA-256(label || ticket || a_x25519 || ct_mlkem).
func transcript(ticket, aPub, ct []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(transcriptLabel))
	h.Write(ticket)
	h.Write(aPub)
	h.Write(ct)
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return out
}

// deriveKeys is HKDF-SHA256 over ss_pq || ss_x (post-quantum secret first, as
// TLS X25519MLKEM768 orders it) salted with the transcript.
func deriveKeys(ssPQ, ssX, tr []byte) (Keys, error) {
	ikm := make([]byte, 0, len(ssPQ)+len(ssX))
	ikm = append(append(ikm, ssPQ...), ssX...)
	c2a, err := hkdf.Key(sha256.New, ikm, tr, infoC2A, keySize)
	if err != nil {
		return Keys{}, fmt.Errorf("derive c2a key: %w", err)
	}
	a2c, err := hkdf.Key(sha256.New, ikm, tr, infoA2C, keySize)
	if err != nil {
		return Keys{}, fmt.Errorf("derive a2c key: %w", err)
	}
	return Keys{C2A: c2a, A2C: a2c}, nil
}

// p1363FromASN1 converts an ASN.1 DER ECDSA P-256 signature to r || s.
func p1363FromASN1(der []byte) ([]byte, error) {
	var rs struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &rs)
	if err != nil || len(rest) != 0 || rs.R.Sign() <= 0 || rs.S.Sign() <= 0 ||
		rs.R.BitLen() > 8*p256ScalarSize || rs.S.BitLen() > 8*p256ScalarSize {
		return nil, errors.New("device signature is not ASN.1 ECDSA P-256")
	}
	out := make([]byte, 2*p256ScalarSize)
	rs.R.FillBytes(out[:p256ScalarSize])
	rs.S.FillBytes(out[p256ScalarSize:])
	return out, nil
}
