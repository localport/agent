package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var updateVectors = flag.Bool("update", false, "rewrite testdata/recording_vectors.json")

const vectorsPath = "testdata/recording_vectors.json"

// recordingVectors is the cross-language fixture the browser recording
// player checks itself against. Binary values are unpadded base64url.
type recordingVectors struct {
	Description string          `json:"description"`
	ID          string          `json:"id"`
	DEK         string          `json:"dek"`
	FinalSealed bool            `json:"final_sealed"`
	FinalHash   string          `json:"final_hash"`
	Segments    []vectorSegment `json:"segments"`
	// Asciicast is the concatenated plaintext of every segment.
	Asciicast string `json:"asciicast"`
}

type vectorSegment struct {
	Index           uint32 `json:"index"`
	Final           bool   `json:"final"`
	Codec           byte   `json:"codec"`
	Object          string `json:"object"`
	SHA256          string `json:"sha256"`
	Chain           string `json:"chain"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
}

var b64 = base64.RawURLEncoding

// recordVectorSession seals a scripted session: output, a resize, a large
// compressible output, a short line in its own segment and the end marker of
// a session closed without an exit in the final segment, so both codecs
// appear.
func recordVectorSession(t *testing.T) recordingVectors {
	t.Helper()
	sealer, priv := newTestSealer(t)
	w := NewWriter(testStart, 80, 24)
	seg := NewSegmenter(w.Header())
	var plains [][]byte
	add := func(at time.Time, lines ...[]byte) {
		for _, l := range lines {
			if cut := seg.Add(at, l); cut != nil {
				plains = append(plains, cut)
			}
		}
	}
	at := testStart.Add(250 * time.Millisecond)
	add(at, w.Output(at, []byte("$ ls\r\n"))...)
	at = at.Add(4 * time.Second)
	add(at, w.Resize(at, 120, 40))
	at = at.Add(time.Second)
	add(at, w.Output(at, bytes.Repeat([]byte("log line\r\n"), 3000))...)
	at = at.Add(6 * time.Second) // past the first segment's interval
	add(at, w.Output(at, []byte("bad \xff byte\r\n"))...)
	at = at.Add(14 * time.Second)
	add(at, w.Marker(at, "end"))
	plains = append(plains, seg.Flush())

	v := recordingVectors{
		Description: "Recording " + testID + " sealed by agent/internal/recording; regenerate with go test ./internal/recording -run TestRecordingVectors -update",
		ID:          testID,
		FinalSealed: true,
	}
	var chain, cast []byte
	for i, p := range plains {
		s, err := sealer.Seal(p, i == len(plains)-1)
		if err != nil {
			t.Fatal(err)
		}
		chain = ChainStep(chain, s.Hash)
		ph := sha256.Sum256(p)
		v.Segments = append(v.Segments, vectorSegment{
			Index: s.Index, Final: s.Final, Codec: s.Object[1],
			Object: b64.EncodeToString(s.Object), SHA256: b64.EncodeToString(s.Hash[:]),
			Chain: b64.EncodeToString(chain), PlaintextSHA256: b64.EncodeToString(ph[:]),
		})
		cast = append(cast, p...)
	}
	v.DEK = b64.EncodeToString(unwrapDEK(t, priv, sealer))
	v.FinalHash = b64.EncodeToString(sealer.FinalHash())
	v.Asciicast = string(cast)
	return v
}

func TestRecordingVectors(t *testing.T) {
	if *updateVectors {
		out, err := json.MarshalIndent(recordVectorSession(t), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s (generate with -update): %v", vectorsPath, err)
	}
	var v recordingVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if v.ID != testID || !v.FinalSealed || len(v.Segments) < 3 {
		t.Fatalf("vectors: id %q, final_sealed %v, %d segments", v.ID, v.FinalSealed, len(v.Segments))
	}
	dek := mustB64(t, v.DEK)
	var chain, cast []byte
	codecs := map[byte]bool{}
	for i, s := range v.Segments {
		obj := mustB64(t, s.Object)
		h := sha256.Sum256(obj)
		chain = ChainStep(chain, h)
		last := i == len(v.Segments)-1
		switch {
		case s.Index != uint32(i) || s.Final != last || s.Codec != obj[1]:
			t.Fatalf("segment %d: index %d, final %v, codec %d, object codec %d", i, s.Index, s.Final, s.Codec, obj[1])
		case b64.EncodeToString(h[:]) != s.SHA256 || b64.EncodeToString(chain) != s.Chain:
			t.Fatalf("segment %d: sha256 or chain differs from the object", i)
		}
		p, err := openSegment(t, dek, s.Index, s.Final, obj)
		if err != nil {
			t.Fatalf("segment %d: %v", i, err)
		}
		if ph := sha256.Sum256(p); b64.EncodeToString(ph[:]) != s.PlaintextSHA256 {
			t.Fatalf("segment %d: plaintext sha256 differs", i)
		}
		codecs[s.Codec] = true
		cast = append(cast, p...)
	}
	if b64.EncodeToString(chain) != v.FinalHash {
		t.Fatal("final_hash differs from the chain over the objects")
	}
	if string(cast) != v.Asciicast {
		t.Fatal("asciicast differs from the decrypted segments")
	}
	if !codecs[CodecNone] || !codecs[CodecDeflate] {
		t.Fatalf("codecs present %v, want both %d and %d", codecs, CodecNone, CodecDeflate)
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
