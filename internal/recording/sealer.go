package recording

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// ObjectVersion is the first byte of every segment object.
	ObjectVersion = 2
	// CodecNone and CodecDeflate are the second byte: the payload is the
	// plaintext as is, or raw deflate of it.
	CodecNone    = 0
	CodecDeflate = 1
	// MaxObject bounds one segment object: version, codec, the padded
	// payload of a MaxPlaintext payload (padme(4 + MaxPlaintext)), tag.
	MaxObject = 270354
	// IDLen is the length of a recording id, a canonical UUID in text form.
	IDLen = 36

	dekLen            = chacha20poly1305.KeySize
	deflateLevel      = 6
	wrapInfoContext   = "localport-recording-v1"
	openContext       = "localport-recording-open-v2"
	openFailedContext = "localport-recording-open-failed-v1"
	completeContext   = "localport-recording-complete-v1"
)

var (
	// ErrSealed is returned by Seal after the final segment was sealed or the
	// DEK was discarded.
	ErrSealed = errors.New("recording: final segment already sealed")
	// ErrPlaintextSize is returned by Seal for a plaintext over MaxPlaintext.
	ErrPlaintextSize = errors.New("recording: segment plaintext too large")
	// ErrID is returned by NewSealer for an id that is not IDLen bytes.
	ErrID = errors.New("recording: id is not a 36-character UUID")
	// ErrSegmentCount is returned by Seal once math.MaxUint32 segments were
	// sealed, where the next index would wrap.
	ErrSegmentCount = errors.New("recording: segment index exhausted")
)

// Segment is one sealed segment.
type Segment struct {
	Index uint32
	// Object is version || codec || AEAD(padded payload), the body of the
	// segment PUT; the padded payload is the payload's length (4 bytes BE),
	// the payload, then zeros to padme(4 + payload length) bytes.
	Object []byte
	// Hash is SHA-256(Object), h_i of the chain.
	Hash  [sha256.Size]byte
	Final bool
}

// Sealer holds a recording's DEK and seals its segments in index order,
// keeping the hash chain. The DEK is zeroed once the final segment is
// sealed or Discard is called. A Sealer is not safe for concurrent use.
type Sealer struct {
	id         string
	dek        []byte
	wrappedDEK []byte
	keySHA256  [sha256.Size]byte
	next       uint32
	chain      []byte
	// zw and deflated are the reused compressor and its output.
	zw       *flate.Writer
	deflated bytes.Buffer
}

// NewSealer generates a DEK for recording id and wraps it with HPKE
// (X-Wing, HKDF-SHA256, ChaCha20-Poly1305) to teamPublicKey, the team
// recording key in PublicKey.Bytes form.
func NewSealer(id string, teamPublicKey []byte) (*Sealer, error) {
	if len(id) != IDLen {
		return nil, ErrID
	}
	pub, err := hpke.MLKEM768X25519().NewPublicKey(teamPublicKey)
	if err != nil {
		return nil, fmt.Errorf("recording: team public key: %w", err)
	}
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("recording: generate DEK: %w", err)
	}
	info := append([]byte(wrapInfoContext), id...)
	wrapped, err := hpke.Seal(pub, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info, dek)
	if err != nil {
		clear(dek)
		return nil, fmt.Errorf("recording: wrap DEK: %w", err)
	}
	return &Sealer{id: id, dek: dek, wrappedDEK: wrapped, keySHA256: sha256.Sum256(teamPublicKey)}, nil
}

// ID returns the recording id.
func (s *Sealer) ID() string { return s.id }

// WrappedDEK returns the HPKE-wrapped DEK. Callers must not modify it.
func (s *Sealer) WrappedDEK() []byte { return s.wrappedDEK }

// KeySHA256 returns SHA-256 of the team public key the DEK was wrapped to.
func (s *Sealer) KeySHA256() [sha256.Size]byte { return s.keySHA256 }

// Sealed returns the number of segments sealed so far.
func (s *Sealer) Sealed() uint32 { return s.next }

// FinalHash returns the chain value of the last sealed segment, empty when
// none was sealed.
func (s *Sealer) FinalHash() []byte { return bytes.Clone(s.chain) }

// Seal compresses, pads and encrypts plaintext as the next segment. final
// marks the recording's last segment: it is bound into the AAD, the DEK is
// zeroed after it, and every later call returns ErrSealed.
func (s *Sealer) Seal(plaintext []byte, final bool) (Segment, error) {
	if s.dek == nil {
		return Segment{}, ErrSealed
	}
	if len(plaintext) > MaxPlaintext {
		return Segment{}, ErrPlaintextSize
	}
	if s.next == math.MaxUint32 {
		return Segment{}, ErrSegmentCount
	}
	codec, payload, err := s.compress(plaintext)
	if err != nil {
		return Segment{}, err
	}
	aead, err := chacha20poly1305.New(s.dek)
	if err != nil {
		return Segment{}, fmt.Errorf("recording: cipher: %w", err)
	}
	// The padded payload is built in the object's buffer and sealed in place
	// (the AEAD allows exact overlap): length, payload, zeros.
	n := padme(4 + len(payload))
	obj := make([]byte, 2+n, 2+n+aead.Overhead())
	obj[0], obj[1] = ObjectVersion, codec
	binary.BigEndian.PutUint32(obj[2:], uint32(len(payload)))
	copy(obj[6:], payload)
	index := s.next
	obj = aead.Seal(obj[:2], segmentNonce(index), obj[2:2+n], segmentAAD(s.id, index, final, codec))
	seg := Segment{Index: index, Object: obj, Hash: sha256.Sum256(obj), Final: final}
	s.chain = ChainStep(s.chain, seg.Hash)
	s.next++
	if final {
		s.Discard()
	}
	return seg, nil
}

// Discard zeroes and drops the DEK of a recording that ends without a final
// segment; every later Seal returns ErrSealed.
func (s *Sealer) Discard() {
	clear(s.dek)
	s.dek = nil
	// The compressor's window holds recent plaintext.
	s.zw, s.deflated = nil, bytes.Buffer{}
}

// compress returns raw deflate of plaintext at level 6, or plaintext with
// CodecNone when deflate is not smaller. The deflate output is valid until
// the next call.
func (s *Sealer) compress(plaintext []byte) (byte, []byte, error) {
	s.deflated.Reset()
	if s.zw == nil {
		zw, err := flate.NewWriter(&s.deflated, deflateLevel)
		if err != nil {
			return 0, nil, fmt.Errorf("recording: deflate: %w", err)
		}
		s.zw = zw
	} else {
		s.zw.Reset(&s.deflated)
	}
	if _, err := s.zw.Write(plaintext); err != nil {
		return 0, nil, fmt.Errorf("recording: deflate: %w", err)
	}
	if err := s.zw.Close(); err != nil {
		return 0, nil, fmt.Errorf("recording: deflate: %w", err)
	}
	if s.deflated.Len() >= len(plaintext) {
		return CodecNone, plaintext, nil
	}
	return CodecDeflate, s.deflated.Bytes(), nil
}

// padme returns the padded length of an n-byte message (n >= 2): n rounded
// up so that at most floor(log2(log2 n)) + 1 bits of it are significant,
// at most 12% overhead (Nikitin et al., "Reducing Metadata Leakage from
// Encrypted Files and Communication with PURBs", 2019).
func padme(n int) int {
	e := bits.Len(uint(n)) - 1 // floor(log2 n)
	s := bits.Len(uint(e))     // floor(log2 e) + 1
	mask := 1<<(e-s) - 1
	return (n + mask) &^ mask
}

// segmentNonce is the segment index as a 96-bit big-endian integer.
func segmentNonce(index uint32) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint32(n[len(n)-4:], index)
	return n
}

// segmentAAD is id || index (4 bytes BE) || final (1 byte) || version || codec.
func segmentAAD(id string, index uint32, final bool, codec byte) []byte {
	a := make([]byte, 0, len(id)+7)
	a = append(a, id...)
	a = binary.BigEndian.AppendUint32(a, index)
	return append(a, boolByte(final), ObjectVersion, codec)
}

// ChainStep returns chain_i from chain_{i-1} (nil for i = 0) and h_i:
// SHA-256(h_0) first, then SHA-256(chain_{i-1} || h_i).
func ChainStep(prev []byte, h [sha256.Size]byte) []byte {
	d := sha256.New()
	d.Write(prev)
	d.Write(h[:])
	return d.Sum(nil)
}

// Completion holds the unsigned fields of a complete request.
type Completion struct {
	Segments   uint32    `json:"segments"`
	FinalHash  []byte    `json:"final_hash"`
	EndedAt    time.Time `json:"ended_at"`
	Incomplete bool      `json:"incomplete"`
	Final      bool      `json:"final"`
	Reason     string    `json:"reason"`
}

// OpenDigest is the digest the device signs for an open of recording id of
// connection sessionID: SHA-256(lp(context) || lp(id) || lp(session_id) ||
// lp(SHA-256(wrapped_dek)) || lp(key_sha256)).
func OpenDigest(id, sessionID string, wrappedDEK, keySHA256 []byte) []byte {
	dek := sha256.Sum256(wrappedDEK)
	var msg []byte
	msg = lengthPrefixed(msg, []byte(openContext))
	msg = lengthPrefixed(msg, []byte(id))
	msg = lengthPrefixed(msg, []byte(sessionID))
	msg = lengthPrefixed(msg, dek[:])
	msg = lengthPrefixed(msg, keySHA256)
	sum := sha256.Sum256(msg)
	return sum[:]
}

// OpenFailedDigest is the digest the device signs for a failed open:
// SHA-256(lp(context) || lp(id) || lp(session_id) || lp(key_sha256) ||
// lp(reason)).
func OpenFailedDigest(id, sessionID string, keySHA256 []byte, reason string) []byte {
	var msg []byte
	msg = lengthPrefixed(msg, []byte(openFailedContext))
	msg = lengthPrefixed(msg, []byte(id))
	msg = lengthPrefixed(msg, []byte(sessionID))
	msg = lengthPrefixed(msg, keySHA256)
	msg = lengthPrefixed(msg, []byte(reason))
	sum := sha256.Sum256(msg)
	return sum[:]
}

// CompleteDigest is the digest the device signs for a complete:
// SHA-256(lp(context) || lp(id) || lp(SHA-256(wrapped_dek)) || segments (4
// bytes BE) || lp(final_hash) || ended_at (8 bytes BE, unix s) || incomplete
// (1 byte) || final (1 byte) || lp(reason)).
func CompleteDigest(id string, wrappedDEK []byte, c Completion) []byte {
	dek := sha256.Sum256(wrappedDEK)
	var msg []byte
	msg = lengthPrefixed(msg, []byte(completeContext))
	msg = lengthPrefixed(msg, []byte(id))
	msg = lengthPrefixed(msg, dek[:])
	msg = binary.BigEndian.AppendUint32(msg, c.Segments)
	msg = lengthPrefixed(msg, c.FinalHash)
	msg = binary.BigEndian.AppendUint64(msg, uint64(c.EndedAt.Unix()))
	msg = append(msg, boolByte(c.Incomplete), boolByte(c.Final))
	msg = lengthPrefixed(msg, []byte(c.Reason))
	sum := sha256.Sum256(msg)
	return sum[:]
}

// Sign signs digest with signer (the key of the certificate the carrying
// session mux presented) and returns the ASN.1 DER signature in unpadded
// base64url, the wire form of the "signature" field.
func Sign(signer crypto.Signer, digest []byte) (string, error) {
	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("recording: sign: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func lengthPrefixed(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}
