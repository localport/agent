package session

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixed returns 32 deterministic bytes for label.
func fixed(label string) []byte {
	sum := sha256.Sum256([]byte("localport session test " + label))
	return sum[:]
}

// fixture holds deterministic keys for one device, one ticket signer and one
// client.
type fixture struct {
	ticketKey ed25519.PrivateKey
	device    *ecdsa.PrivateKey
	spkiDER   []byte
	client    *ClientKeys
	mlkemSeed []byte
}

func newFixture(t *testing.T, name string) *fixture {
	t.Helper()
	device, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), fixed(name+" device"))
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&device.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	x, err := ecdh.X25519().NewPrivateKey(fixed(name + " client x25519"))
	if err != nil {
		t.Fatal(err)
	}
	seed := sha512.Sum512([]byte("localport session test " + name + " client mlkem"))
	m, err := mlkem.NewDecapsulationKey768(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		ticketKey: ed25519.NewKeyFromSeed(fixed(name + " ticket key")),
		device:    device,
		spkiDER:   spki,
		client:    &ClientKeys{X25519: x, MLKEM: m},
		mlkemSeed: seed[:],
	}
}

const testIAT = 1798000000

func (f *fixture) payload() Ticket {
	enc := base64.RawURLEncoding
	user := "0190a000-0000-7000-8000-000000000001"
	web := "d2ViLXNlc3Npb24taGFzaA"
	return Ticket{
		V:                1,
		KID:              "k1",
		JTI:              "0190a000-0000-7000-8000-0000000000aa",
		IAT:              testIAT,
		EXP:              testIAT + 60,
		Team:             "team-1",
		Tunnel:           "fleet-1",
		Device:           "abc123",
		DeviceSPKISHA256: SPKIHash(f.spkiDER),
		Edge:             "edge-1",
		Subject:          "user:alice",
		UserID:           &user,
		Kind:             "terminal",
		Login:            "pi",
		ClientX25519:     enc.EncodeToString(f.client.X25519.PublicKey().Bytes()),
		ClientMLKEM:      enc.EncodeToString(f.client.MLKEM.EncapsulationKey().Bytes()),
		WebSession:       &web,
	}
}

func (f *fixture) deviceID() Device {
	return Device{Prefix: "abc123", SPKISHA256: SPKIHash(f.spkiDER)}
}

func (f *fixture) lookup(kid string) (ed25519.PublicKey, bool) {
	if kid != "k1" {
		return nil, false
	}
	return f.ticketKey.Public().(ed25519.PublicKey), true
}

// sign encodes p as the API does: base64url(payload) "." base64url(sig).
func sign(t *testing.T, key ed25519.PrivateKey, p any) []byte {
	t.Helper()
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return []byte(enc.EncodeToString(body) + "." + enc.EncodeToString(ed25519.Sign(key, body)))
}

func codeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

var testNow = time.Unix(testIAT, 0)

func TestVerifyTicketAccepts(t *testing.T) {
	f := newFixture(t, "a")
	raw := sign(t, f.ticketKey, f.payload())
	got, err := VerifyTicket(raw, f.lookup, f.deviceID(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "terminal" || got.Login != "pi" || got.JTI == "" || string(got.Raw()) != string(raw) {
		t.Fatalf("parsed ticket = %+v", got)
	}
	if got.clientX == nil || got.clientKEM == nil {
		t.Fatal("client keys not parsed")
	}
}

// recJTI is a ticket jti in the UUID form a recorded ticket carries.
const recJTI = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

// testRecKeySHA256 is the unpadded base64url SHA-256 a test rec names.
var testRecKeySHA256 = func() string {
	sum := sha256.Sum256([]byte("team recording key"))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}()

func testRec(id string) *TicketRec {
	return &TicketRec{ID: id, PubSHA256: testRecKeySHA256, Policy: RecPolicyBestEffort}
}

// A rec null and a well-formed rec of either policy verify; the rec parses
// into its typed fields.
func TestVerifyTicketAcceptsRec(t *testing.T) {
	f := newFixture(t, "a")
	if got, err := VerifyTicket(sign(t, f.ticketKey, f.payload()), f.lookup, f.deviceID(), testNow); err != nil || got.Rec != nil {
		t.Fatalf("rec null: %v, rec %+v", err, got)
	}
	for _, policy := range []string{RecPolicyBestEffort, RecPolicyStrict} {
		p := f.payload()
		p.JTI = recJTI
		p.Rec = &TicketRec{ID: recJTI, PubSHA256: testRecKeySHA256, Policy: policy}
		got, err := VerifyTicket(sign(t, f.ticketKey, p), f.lookup, f.deviceID(), testNow)
		if err != nil || got.Rec == nil || *got.Rec != *p.Rec {
			t.Fatalf("%s: %v, rec %+v", policy, err, got)
		}
	}
}

func TestVerifyTicketRefuses(t *testing.T) {
	f := newFixture(t, "a")
	other := newFixture(t, "b")
	withPayload := func(edit func(*Ticket)) []byte {
		p := f.payload()
		edit(&p)
		return sign(t, f.ticketKey, p)
	}
	valid := sign(t, f.ticketKey, f.payload())
	withRec := func(edit func(*TicketRec)) []byte {
		return withPayload(func(p *Ticket) {
			p.JTI = recJTI
			p.Rec = testRec(recJTI)
			edit(p.Rec)
		})
	}
	withRawRec := func(rec string) []byte {
		p := f.payload()
		p.JTI = recJTI
		body, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		body = []byte(strings.Replace(string(body), `"rec":null`, `"rec":`+rec, 1))
		return []byte(base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.ticketKey, body)))
	}
	tamperedPayload := func() []byte {
		payloadB64, sig, _ := strings.Cut(string(valid), ".")
		body, _ := base64.RawURLEncoding.DecodeString(payloadB64)
		body = []byte(strings.Replace(string(body), `"login":"pi"`, `"login":"root"`, 1))
		return []byte(base64.RawURLEncoding.EncodeToString(body) + "." + sig)
	}

	cases := []struct {
		name   string
		raw    []byte
		device Device
		now    time.Time
		code   string
	}{
		{"unknown version", withPayload(func(p *Ticket) { p.V = 2 }), f.deviceID(), testNow, CodeTicketInvalid},
		{"unknown kid", withPayload(func(p *Ticket) { p.KID = "k2" }), f.deviceID(), testNow, CodeTicketUnknownKey},
		{"signed by another key", sign(t, other.ticketKey, f.payload()), f.deviceID(), testNow, CodeTicketInvalid},
		{"payload changed after signing", tamperedPayload(), f.deviceID(), testNow, CodeTicketInvalid},
		{"expired beyond skew", valid, f.deviceID(), time.Unix(testIAT+60+31, 0), CodeTicketExpired},
		{"another device prefix", valid, Device{Prefix: "zzz999", SPKISHA256: SPKIHash(f.spkiDER)}, testNow, CodeTicketWrongDevice},
		{"another device key", valid, Device{Prefix: "abc123", SPKISHA256: SPKIHash(other.spkiDER)}, testNow, CodeTicketWrongDevice},
		{"no separator", []byte("abc"), f.deviceID(), testNow, CodeTicketInvalid},
		{"payload not base64url", []byte("!!." + strings.SplitN(string(valid), ".", 2)[1]), f.deviceID(), testNow, CodeTicketInvalid},
		{"short signature", []byte(strings.SplitN(string(valid), ".", 2)[0] + ".AAAA"), f.deviceID(), testNow, CodeTicketInvalid},
		{"empty login for terminal", withPayload(func(p *Ticket) { p.Login = "" }), f.deviceID(), testNow, CodeTicketInvalid},
		{"unknown kind", withPayload(func(p *Ticket) { p.Kind = "shell" }), f.deviceID(), testNow, CodeTicketInvalid},
		{"missing jti", withPayload(func(p *Ticket) { p.JTI = "" }), f.deviceID(), testNow, CodeTicketInvalid},
		{"incomplete cert", withPayload(func(p *Ticket) { p.Cert = &TicketCert{AnchorFP: "ab"} }), f.deviceID(), testNow, CodeTicketInvalid},
		{"bad client x25519", withPayload(func(p *Ticket) { p.ClientX25519 = "AAAA" }), f.deviceID(), testNow, CodeTicketInvalid},
		{"bad client mlkem", withPayload(func(p *Ticket) { p.ClientMLKEM = "AAAA" }), f.deviceID(), testNow, CodeTicketInvalid},
		{"rec id is not the jti", withRec(func(r *TicketRec) { r.ID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c" }), f.deviceID(), testNow, CodeTicketInvalid},
		{"rec id and jti not a UUID", withPayload(func(p *Ticket) { p.JTI = "jti-1"; p.Rec = testRec("jti-1") }), f.deviceID(), testNow, CodeTicketInvalid},
		{"rec id uppercase", withPayload(func(p *Ticket) {
			p.JTI = strings.ToUpper(recJTI)
			p.Rec = testRec(p.JTI)
		}), f.deviceID(), testNow, CodeTicketInvalid},
		{"rec pub_sha256 short", withRec(func(r *TicketRec) { r.PubSHA256 = r.PubSHA256[:42] }), f.deviceID(), testNow, CodeTicketInvalid},
		{"rec pub_sha256 padded", withRec(func(r *TicketRec) { r.PubSHA256 += "=" }), f.deviceID(), testNow, CodeTicketInvalid},
		{"rec pub_sha256 std alphabet", withRec(func(r *TicketRec) { r.PubSHA256 = "+" + r.PubSHA256[1:] }), f.deviceID(), testNow, CodeTicketInvalid},
		{"rec pub_sha256 trailing bits", withRec(func(r *TicketRec) { r.PubSHA256 = r.PubSHA256[:42] + "B" }), f.deviceID(), testNow, CodeTicketInvalid},
		{"rec policy unknown", withRec(func(r *TicketRec) { r.Policy = "off" }), f.deviceID(), testNow, CodeTicketInvalid},
		{"rec not an object", withRawRec(`"best_effort"`), f.deviceID(), testNow, CodeTicketInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := VerifyTicket(tc.raw, f.lookup, tc.device, tc.now)
			if got != nil || codeOf(err) != tc.code {
				t.Fatalf("VerifyTicket accepted=%t err=%v; want code %s", got != nil, err, tc.code)
			}
		})
	}
}

func TestVerifyTicketExpirySkew(t *testing.T) {
	f := newFixture(t, "a")
	raw := sign(t, f.ticketKey, f.payload())
	if _, err := VerifyTicket(raw, f.lookup, f.deviceID(), time.Unix(testIAT+60+30, 0)); err != nil {
		t.Fatalf("ticket 30 s past exp refused: %v", err)
	}
}

// iat may be at most 30 s ahead of the agent clock, and exp at most 60 s
// after iat; both refuse ticket_expired.
func TestVerifyTicketIssuedAtAndLifetime(t *testing.T) {
	f := newFixture(t, "a")
	raw := sign(t, f.ticketKey, f.payload())
	if _, err := VerifyTicket(raw, f.lookup, f.deviceID(), time.Unix(testIAT-30, 0)); err != nil {
		t.Fatalf("ticket issued 30 s ahead refused: %v", err)
	}
	if _, err := VerifyTicket(raw, f.lookup, f.deviceID(), time.Unix(testIAT-31, 0)); codeOf(err) != CodeTicketExpired {
		t.Fatalf("ticket issued 31 s ahead: %v, want %s", err, CodeTicketExpired)
	}
	p := f.payload()
	p.EXP = p.IAT + 61
	if _, err := VerifyTicket(sign(t, f.ticketKey, p), f.lookup, f.deviceID(), testNow); codeOf(err) != CodeTicketExpired {
		t.Fatalf("ticket living 61 s: %v, want %s", err, CodeTicketExpired)
	}
}

func TestVerifyTicketDesktopKindHasNoLogin(t *testing.T) {
	f := newFixture(t, "a")
	p := f.payload()
	p.Kind, p.Login = "rdp", ""
	p.UserID, p.WebSession = nil, nil
	p.Cert = &TicketCert{AnchorFP: "ab", Serial: "1f", NotAfter: testIAT + 3600}
	if _, err := VerifyTicket(sign(t, f.ticketKey, p), f.lookup, f.deviceID(), testNow); err != nil {
		t.Fatal(err)
	}
}

// Ticket segments decode strictly: a signature with non-canonical trailing
// bits is a different string for the same bytes and is refused.
func TestVerifyTicketRefusesNonCanonicalBase64(t *testing.T) {
	f := newFixture(t, "a")
	raw := string(sign(t, f.ticketKey, f.payload()))
	dot := strings.LastIndexByte(raw, '.')
	signedWith := func(edit func(*Ticket)) string {
		p := f.payload()
		edit(&p)
		return string(sign(t, f.ticketKey, p))
	}
	for name, tampered := range map[string]string{
		"signature":     raw[:dot+1] + flipLastBits(raw[dot+1:]),
		"payload":       flipLastBits(raw[:dot]) + raw[dot:],
		"client_x25519": signedWith(func(p *Ticket) { p.ClientX25519 = flipLastBits(p.ClientX25519) }),
		"client_mlkem":  signedWith(func(p *Ticket) { p.ClientMLKEM = flipLastBits(p.ClientMLKEM) }),
	} {
		if tampered == raw {
			t.Fatalf("%s: segment length leaves no unused bits", name)
		}
		if _, err := VerifyTicket([]byte(tampered), f.lookup, f.deviceID(), time.Unix(testIAT, 0)); codeOf(err) != CodeTicketInvalid {
			t.Errorf("%s: verify = %v, want %s", name, err, CodeTicketInvalid)
		}
	}
}

// A clock refusal keeps its code and records the difference in its details:
// a device without a real-time clock refuses every ticket until its clock is
// set.
func TestVerifyTicketClockRefusalsCarryTheDifference(t *testing.T) {
	f := newFixture(t, "a")
	raw := sign(t, f.ticketKey, f.payload())
	for at, want := range map[int64]string{
		testIAT - 3600:      "issued 1h0m0s ahead of this device's clock",
		testIAT + 60 + 3600: "ticket expired 1h0m0s before this device's clock",
	} {
		_, err := VerifyTicket(raw, f.lookup, f.deviceID(), time.Unix(at, 0))
		if codeOf(err) != CodeTicketExpired || !strings.Contains(err.Error(), want) {
			t.Errorf("at %d: %v, want %s with %q", at, err, CodeTicketExpired, want)
		}
	}
}
