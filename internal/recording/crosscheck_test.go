package recording

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestRecordedSessionDecrypts records a scripted session, seals it, and opens
// it the way a player does: unwrap the DEK with the team private key,
// decrypt and inflate every segment, and parse the concatenated asciicast.
func TestRecordedSessionDecrypts(t *testing.T) {
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
	at = at.Add(7 * time.Second) // past the first segment's interval
	add(at, w.Output(at, []byte("bad \xff byte\r\n"))...)
	at = at.Add(time.Second)
	add(at, w.Output(at, bytes.Repeat([]byte("log line\r\n"), 40000))...)
	at = at.Add(time.Second)
	add(at, w.Exit(at, 0)...)
	plains = append(plains, seg.Flush())

	var objects []Segment
	for i, p := range plains {
		s, err := sealer.Seal(p, i == len(plains)-1)
		if err != nil {
			t.Fatal(err)
		}
		objects = append(objects, s)
	}
	if len(objects) < 3 {
		t.Fatalf("got %d segments, want at least 3", len(objects))
	}

	dek := unwrapDEK(t, priv, sealer)
	var cast []byte
	for _, o := range objects {
		p, err := openSegment(t, dek, o.Index, o.Final, o.Object)
		if err != nil {
			t.Fatalf("segment %d: %v", o.Index, err)
		}
		cast = append(cast, p...)
	}

	lines := strings.Split(strings.TrimSuffix(string(cast), "\n"), "\n")
	var header struct {
		Version int `json:"version"`
		Term    struct {
			Cols int `json:"cols"`
			Rows int `json:"rows"`
		} `json:"term"`
		Timestamp int64 `json:"timestamp"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatalf("header: %v", err)
	}
	if header.Version != 3 || header.Term.Cols != 80 || header.Term.Rows != 24 || header.Timestamp != testStart.Unix() {
		t.Fatalf("header = %+v", header)
	}
	var output strings.Builder
	var codes []string
	var totalMs float64
	for _, l := range lines[1:] {
		var ev [3]any
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatalf("event %q: %v", l, err)
		}
		totalMs += ev[0].(float64) * 1000
		code := ev[1].(string)
		if len(codes) == 0 || codes[len(codes)-1] != code {
			codes = append(codes, code)
		}
		if code == "o" {
			output.WriteString(ev[2].(string))
		}
	}
	if got := strings.Join(codes, ","); got != "o,r,o,x" {
		t.Fatalf("event codes = %s", got)
	}
	want := "$ ls\r\nbad � byte\r\n" + strings.Repeat("log line\r\n", 40000)
	if output.String() != want {
		t.Fatal("decrypted output differs from what was recorded")
	}
	if elapsed := at.Sub(testStart).Seconds() * 1000; totalMs < elapsed-1 || totalMs > elapsed+1 {
		t.Fatalf("intervals sum to %.0f ms, session lasted %.0f ms", totalMs, elapsed)
	}
}
