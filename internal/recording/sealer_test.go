package recording

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const testID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

// testSessionID is the connection the test recordings belong to.
const testSessionID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60"

// newTestSealer returns a sealer for testID and the team private key its
// DEK is wrapped to.
func newTestSealer(t *testing.T) (*Sealer, hpke.PrivateKey) {
	t.Helper()
	priv, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSealer(testID, priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return s, priv
}

// contractNonceAAD builds a segment's nonce and AAD from the contract.
func contractNonceAAD(index uint32, final bool, codec byte) (nonce, aad []byte) {
	nonce = make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint32(nonce[8:], index)
	aad = append([]byte(testID), byte(index>>24), byte(index>>16), byte(index>>8), byte(index))
	f := byte(0)
	if final {
		f = 1
	}
	return nonce, append(aad, f, 2, codec)
}

// sealRaw seals padded, a padded payload as given, as a version 2 object.
func sealRaw(t *testing.T, dek []byte, index uint32, final bool, codec byte, padded []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.New(dek)
	if err != nil {
		t.Fatal(err)
	}
	nonce, aad := contractNonceAAD(index, final, codec)
	return aead.Seal([]byte{2, codec}, nonce, padded, aad)
}

var errBadPadding = errors.New("bad padded payload")

// openSegment decrypts obj with dek as segment index with the given final
// flag, building nonce and AAD from the contract, checks the padded payload
// (length within it, padme size, zero padding) and returns the inflated
// plaintext.
func openSegment(t *testing.T, dek []byte, index uint32, final bool, obj []byte) ([]byte, error) {
	t.Helper()
	if len(obj) < 2+chacha20poly1305.Overhead || obj[0] != 2 {
		t.Fatalf("object header %x", obj[:2])
	}
	aead, err := chacha20poly1305.New(dek)
	if err != nil {
		t.Fatal(err)
	}
	nonce, aad := contractNonceAAD(index, final, obj[1])
	padded, err := aead.Open(nil, nonce, obj[2:], aad)
	if err != nil {
		return nil, err
	}
	if len(padded) < 4 {
		return nil, errBadPadding
	}
	n := binary.BigEndian.Uint32(padded)
	if uint64(n) > uint64(len(padded)-4) || padme(4+int(n)) != len(padded) || !bytes.Equal(padded[4+n:], make([]byte, len(padded)-4-int(n))) {
		return nil, errBadPadding
	}
	payload := padded[4 : 4+n]
	switch obj[1] {
	case CodecNone:
		return payload, nil
	case CodecDeflate:
		return io.ReadAll(flate.NewReader(bytes.NewReader(payload)))
	default:
		t.Fatalf("codec %d", obj[1])
		return nil, nil
	}
}

func unwrapDEK(t *testing.T, priv hpke.PrivateKey, s *Sealer) []byte {
	t.Helper()
	info := append([]byte("localport-recording-v1"), testID...)
	dek, err := hpke.Open(priv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info, s.WrappedDEK())
	if err != nil {
		t.Fatalf("unwrap DEK: %v", err)
	}
	return dek
}

func TestNewSealerRefusesBadInput(t *testing.T) {
	priv, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSealer(testID[:35], priv.PublicKey().Bytes()); !errors.Is(err, ErrID) {
		t.Fatalf("short id: %v", err)
	}
	if _, err := NewSealer(testID, priv.PublicKey().Bytes()[1:]); err == nil {
		t.Fatal("truncated public key accepted")
	}
}

func TestSealNonceAADAndChain(t *testing.T) {
	s, priv := newTestSealer(t)
	pubSum := sha256.Sum256(priv.PublicKey().Bytes())
	if s.KeySHA256() != pubSum {
		t.Fatal("KeySHA256 is not SHA-256 of the public key")
	}
	dek := unwrapDEK(t, priv, s)
	if !bytes.Equal(dek, s.dek) {
		t.Fatal("unwrapped DEK differs")
	}
	if len(s.FinalHash()) != 0 {
		t.Fatal("FinalHash before any segment is not empty")
	}
	plains := [][]byte{
		bytes.Repeat([]byte("compressible "), 1000),
		[]byte("x"),
		bytes.Repeat([]byte("tail "), 100),
	}
	var chain []byte
	for i, p := range plains {
		final := i == len(plains)-1
		seg, err := s.Seal(p, final)
		if err != nil {
			t.Fatal(err)
		}
		if seg.Index != uint32(i) || seg.Final != final || seg.Hash != sha256.Sum256(seg.Object) {
			t.Fatalf("segment %d metadata %+v", i, seg.Index)
		}
		got, err := openSegment(t, dek, uint32(i), final, seg.Object)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatalf("segment %d did not open: %v", i, err)
		}
		if _, err := openSegment(t, dek, uint32(i), !final, seg.Object); err == nil {
			t.Fatalf("segment %d opened with the wrong final flag", i)
		}
		if _, err := openSegment(t, dek, uint32(i)+1, final, seg.Object); err == nil {
			t.Fatalf("segment %d opened under another index", i)
		}
		if i == 0 {
			c := sha256.Sum256(seg.Hash[:])
			chain = c[:]
		} else {
			c := sha256.Sum256(append(append([]byte(nil), chain...), seg.Hash[:]...))
			chain = c[:]
		}
		if !bytes.Equal(s.FinalHash(), chain) {
			t.Fatalf("chain after segment %d differs", i)
		}
	}
	if s.Sealed() != uint32(len(plains)) {
		t.Fatalf("Sealed = %d", s.Sealed())
	}
}

func TestSealCodec(t *testing.T) {
	s, _ := newTestSealer(t)
	seg, err := s.Seal(bytes.Repeat([]byte("a"), 4096), false)
	if err != nil || seg.Object[1] != CodecDeflate {
		t.Fatalf("compressible plaintext: codec %d, %v", seg.Object[1], err)
	}
	random := make([]byte, 4096)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	seg, err = s.Seal(random, false)
	if err != nil || seg.Object[1] != CodecNone || len(seg.Object) != 2+padme(4+len(random))+chacha20poly1305.Overhead {
		t.Fatalf("random plaintext: codec %d len %d, %v", seg.Object[1], len(seg.Object), err)
	}
}

func TestPadme(t *testing.T) {
	for _, tc := range [][2]int{{2, 2}, {4, 4}, {5, 5}, {9, 10}, {100, 104}, {1000, 1024}, {4100, 4352}, {262148, 270336}} {
		if got := padme(tc[0]); got != tc[1] {
			t.Errorf("padme(%d) = %d, want %d", tc[0], got, tc[1])
		}
	}
	for n := 2; n <= 1<<20; n++ {
		p := padme(n)
		// At most 12% overhead, and a padded length pads to itself.
		if p < n || float64(p-n) > 0.12*float64(n) || padme(p) != p {
			t.Fatalf("padme(%d) = %d", n, p)
		}
	}
}

// The padded payload is the length, the payload, then zeros; a decoder
// refuses non-zero padding and a length outside the padded size.
func TestSealPadding(t *testing.T) {
	s, priv := newTestSealer(t)
	dek := unwrapDEK(t, priv, s)
	random := make([]byte, 4096)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	seg, err := s.Seal(random, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openSegment(t, dek, 0, false, seg.Object)
	if err != nil || !bytes.Equal(got, random) {
		t.Fatalf("round trip: %v", err)
	}
	padded := make([]byte, padme(4+len(random)))
	binary.BigEndian.PutUint32(padded, uint32(len(random)))
	copy(padded[4:], random)
	if _, err := openSegment(t, dek, 1, false, sealRaw(t, dek, 1, false, CodecNone, padded)); err != nil {
		t.Fatalf("a well-formed padded payload: %v", err)
	}
	for name, edit := range map[string]func([]byte){
		"non-zero padding":       func(p []byte) { p[len(p)-1] = 1 },
		"length past the end":    func(p []byte) { binary.BigEndian.PutUint32(p, uint32(len(p))) },
		"length overflow":        func(p []byte) { binary.BigEndian.PutUint32(p, math.MaxUint32) },
		"length of another size": func(p []byte) { binary.BigEndian.PutUint32(p, 100) },
	} {
		p := bytes.Clone(padded)
		edit(p)
		if _, err := openSegment(t, dek, 1, false, sealRaw(t, dek, 1, false, CodecNone, p)); !errors.Is(err, errBadPadding) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

func TestSealSizeBound(t *testing.T) {
	s, _ := newTestSealer(t)
	full := make([]byte, MaxPlaintext)
	if _, err := rand.Read(full); err != nil {
		t.Fatal(err)
	}
	seg, err := s.Seal(full, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := 2 + padme(4+MaxPlaintext) + chacha20poly1305.Overhead; MaxObject != want || len(seg.Object) != MaxObject {
		t.Fatalf("object %d bytes, MaxObject %d, want %d", len(seg.Object), MaxObject, want)
	}
	if _, err := s.Seal(append(full, 'x'), false); !errors.Is(err, ErrPlaintextSize) {
		t.Fatalf("oversized plaintext: %v", err)
	}
	if s.Sealed() != 1 {
		t.Fatal("a refused plaintext took an index")
	}
}

// Seal refuses the segment whose successor's index would wrap to 0.
func TestSealRefusesAWrappingIndex(t *testing.T) {
	s, _ := newTestSealer(t)
	s.next = math.MaxUint32 - 1
	if seg, err := s.Seal([]byte("last index"), false); err != nil || seg.Index != math.MaxUint32-1 {
		t.Fatalf("Seal at index %d: %v", seg.Index, err)
	}
	if _, err := s.Seal([]byte("wraps"), false); !errors.Is(err, ErrSegmentCount) {
		t.Fatalf("Seal past the last index: %v", err)
	}
	if s.Sealed() != math.MaxUint32 {
		t.Fatalf("Sealed = %d", s.Sealed())
	}
}

// One compressor serves every segment of a Sealer; Discard drops it.
func TestSealReusesTheCompressor(t *testing.T) {
	s, priv := newTestSealer(t)
	dek := unwrapDEK(t, priv, s)
	var zw *flate.Writer
	for i, p := range [][]byte{bytes.Repeat([]byte("one "), 500), bytes.Repeat([]byte("two "), 500)} {
		seg, err := s.Seal(p, false)
		if err != nil || seg.Object[1] != CodecDeflate {
			t.Fatalf("segment %d: %v", i, err)
		}
		if i == 0 {
			zw = s.zw
		} else if s.zw != zw {
			t.Fatal("the second segment used a new compressor")
		}
		if got, err := openSegment(t, dek, uint32(i), false, seg.Object); err != nil || !bytes.Equal(got, p) {
			t.Fatalf("segment %d did not open: %v", i, err)
		}
	}
	s.Discard()
	if s.zw != nil || s.deflated.Cap() != 0 {
		t.Fatal("Discard kept the compressor")
	}
}

func TestDiscardZeroesDEK(t *testing.T) {
	s, _ := newTestSealer(t)
	if _, err := s.Seal([]byte("first"), false); err != nil {
		t.Fatal(err)
	}
	dek := s.dek
	s.Discard()
	if s.dek != nil || !bytes.Equal(dek, make([]byte, len(dek))) {
		t.Fatal("DEK not zeroed and dropped by Discard")
	}
	if _, err := s.Seal([]byte("more"), true); !errors.Is(err, ErrSealed) {
		t.Fatalf("Seal after Discard: %v", err)
	}
	if s.Sealed() != 1 {
		t.Fatal("a refused seal took an index")
	}
}

func TestSealZeroesDEKAfterFinal(t *testing.T) {
	s, _ := newTestSealer(t)
	dek := s.dek
	if _, err := s.Seal([]byte("last"), true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dek, make([]byte, len(dek))) {
		t.Fatal("DEK not zeroed after the final segment")
	}
	if _, err := s.Seal([]byte("more"), false); !errors.Is(err, ErrSealed) {
		t.Fatalf("Seal after final: %v", err)
	}
	if s.Sealed() != 1 {
		t.Fatal("a refused seal took an index")
	}
}

func TestDigestGoldenVectors(t *testing.T) {
	wrapped := make([]byte, 100)
	for i := range wrapped {
		wrapped[i] = byte(i)
	}
	keySum := bytes.Repeat([]byte{0xaa}, 32)
	ended := time.Unix(1767225600, 0)
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		// The control plane's tests pin the same vector.
		{"open", OpenDigest(testID, testSessionID, wrapped, keySum), "1fd36cf1ee83db594888e6f756215db9f0da2d54010de28871dd26bd07aa1b80"},
		{"open failed", OpenFailedDigest(testID, testSessionID, keySum, ReasonSpoolFull), "a307228e2e7c2275b8773203aeafef41f8c97adf675c3ad565762de0d2c72ff9"},
		{"complete incomplete", CompleteDigest(testID, wrapped, Completion{
			Segments: 3, FinalHash: bytes.Repeat([]byte{0x11}, 32), EndedAt: ended,
			Incomplete: true, Reason: ReasonSpoolFull,
		}), "92888520be1ffa46e439c6bd69fe2f649229a2fd30069502ca2d3a620dce86a9"},
		{"complete empty", CompleteDigest(testID, wrapped, Completion{EndedAt: ended}),
			"13f8d36b55dfc5860e976202b9cc377f9be382876974a2bbd5621c2db827109f"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(c.got); got != c.want {
			t.Errorf("%s digest = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestSignVerifies(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newTestSealer(t)
	sum := s.KeySHA256()
	digest := OpenDigest(s.ID(), testSessionID, s.WrappedDEK(), sum[:])
	sig, err := Sign(key, digest)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("signature is not unpadded base64url: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest, der) {
		t.Fatal("signature does not verify against the digest")
	}
}
