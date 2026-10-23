package session

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func acceptFixture(t *testing.T, f *fixture) (*Ticket, *AcceptMessage, Keys) {
	t.Helper()
	tk, err := VerifyTicket(sign(t, f.ticketKey, f.payload()), f.lookup, f.deviceID(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	msg, keys, err := Accept(tk, f.device)
	if err != nil {
		t.Fatal(err)
	}
	return tk, msg, keys
}

func TestHandshakeAgrees(t *testing.T) {
	f := newFixture(t, "a")
	tk, msg, agentKeys := acceptFixture(t, f)
	clientKeys, err := Open(tk.Raw(), f.spkiDER, msg, f.client)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(agentKeys.C2A, clientKeys.C2A) || !bytes.Equal(agentKeys.A2C, clientKeys.A2C) {
		t.Fatal("agent and client derived different keys")
	}
	if len(agentKeys.C2A) != keySize || bytes.Equal(agentKeys.C2A, agentKeys.A2C) {
		t.Fatal("directional keys are not two distinct 32-byte keys")
	}
	sig, _ := base64.RawURLEncoding.DecodeString(msg.Sig)
	if msg.Type != "accept" || len(sig) != 64 {
		t.Fatalf("accept message = %+v", msg)
	}
}

func TestOpenRefuses(t *testing.T) {
	f := newFixture(t, "a")
	tk, msg, _ := acceptFixture(t, f)
	enc := base64.RawURLEncoding

	otherX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tamperedX := *msg
	tamperedX.AX25519 = enc.EncodeToString(otherX.PublicKey().Bytes())

	sig, _ := enc.DecodeString(msg.Sig)
	sig[10] ^= 1
	flippedSig := *msg
	flippedSig.Sig = enc.EncodeToString(sig)

	ct, _ := enc.DecodeString(msg.CTMLKEM)
	ct[0] ^= 1
	tamperedCT := *msg
	tamperedCT.CTMLKEM = enc.EncodeToString(ct)

	// An impostor that signs with its own key and presents its own SPKI.
	impostor := newFixture(t, "impostor")
	impostorMsg, _, err := Accept(tk, impostor.device)
	if err != nil {
		t.Fatal(err)
	}

	notAccept := *msg
	notAccept.Type = "refused"

	// Sizes are checked before the signature: a field of the wrong size reads
	// as malformed, never as a bad signature.
	shortX := *msg
	shortX.AX25519 = enc.EncodeToString(otherX.PublicKey().Bytes()[:31])
	shortCT := *msg
	shortCT.CTMLKEM = enc.EncodeToString(ct[:len(ct)-1])
	nonCanonical := *msg
	nonCanonical.AX25519 = flipLastBits(msg.AX25519)

	cases := []struct {
		name string
		spki []byte
		msg  *AcceptMessage
		code string
	}{
		{"tampered a_x25519", f.spkiDER, &tamperedX, CodeHandshakeBadSignature},
		{"flipped signature bit", f.spkiDER, &flippedSig, CodeHandshakeBadSignature},
		{"tampered ct_mlkem", f.spkiDER, &tamperedCT, CodeHandshakeBadSignature},
		{"wrong device_spki_der", impostor.spkiDER, impostorMsg, CodeHandshakeWrongDevice},
		{"device key signs for impostor spki", f.spkiDER, impostorMsg, CodeHandshakeBadSignature},
		{"not an accept", f.spkiDER, &notAccept, CodeHandshakeInvalid},
		{"short a_x25519", f.spkiDER, &shortX, CodeHandshakeInvalid},
		{"short ct_mlkem", f.spkiDER, &shortCT, CodeHandshakeInvalid},
		{"non-canonical base64", f.spkiDER, &nonCanonical, CodeHandshakeInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Open(tk.Raw(), tc.spki, tc.msg, f.client); codeOf(err) != tc.code {
				t.Fatalf("Open = %v; want code %s", err, tc.code)
			}
		})
	}
}

func TestAcceptRefusesNonP256DeviceKey(t *testing.T) {
	f := newFixture(t, "a")
	tk, _, _ := acceptFixture(t, f)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Accept(tk, edKey); err == nil {
		t.Fatal("Accept took an Ed25519 device key")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Accept(tk, p384); err == nil {
		t.Fatal("Accept took a P-384 device key")
	}
}

// flipLastBits returns unpadded base64url s with the unused low bits of its
// last character set: the same bytes under lenient decoding, refused under
// strict decoding. len(s) must not be a multiple of 4.
func flipLastBits(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, s[len(s)-1])
	unused := map[int]int{2: 0b1111, 3: 0b11}[len(s)%4]
	return s[:len(s)-1] + string(alphabet[last|unused])
}
