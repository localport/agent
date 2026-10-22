package recording

import (
	"bytes"
	"testing"
	"time"
)

func TestSegmenterHeaderOnSegmentZeroOnly(t *testing.T) {
	w := NewWriter(testStart, 80, 24)
	s := NewSegmenter(w.Header())
	if s.Flush() != nil {
		t.Fatal("a segment with only the header was cut")
	}
	s = NewSegmenter(w.Header())
	s.Add(testStart, w.Output(testStart, []byte("one"))[0])
	at := testStart.Add(SegmentInterval)
	seg0 := s.Add(at, w.Output(at, []byte("two"))[0])
	seg1 := s.Flush()
	if !bytes.HasPrefix(seg0, w.Header()) {
		t.Fatalf("segment 0 %q does not start with the header", seg0)
	}
	if bytes.Contains(seg1, []byte(`"version"`)) {
		t.Fatalf("segment 1 %q carries a header", seg1)
	}
}

func TestSegmenterCutsAtInterval(t *testing.T) {
	s := NewSegmenter(nil)
	if _, ok := s.Deadline(); ok {
		t.Fatal("empty segmenter has a deadline")
	}
	if s.Cut(testStart.Add(time.Hour)) != nil {
		t.Fatal("empty segment was cut")
	}
	first := testStart.Add(3 * time.Second)
	if s.Add(first, []byte("a\n")) != nil {
		t.Fatal("first line cut a segment")
	}
	if d, ok := s.Deadline(); !ok || !d.Equal(first.Add(SegmentInterval)) {
		t.Fatalf("Deadline = %v, %v", d, ok)
	}
	if s.Add(first.Add(SegmentInterval-time.Millisecond), []byte("b\n")) != nil {
		t.Fatal("line before the interval cut a segment")
	}
	if s.Cut(first.Add(SegmentInterval-time.Millisecond)) != nil {
		t.Fatal("Cut before the deadline returned a segment")
	}
	if got := s.Cut(first.Add(SegmentInterval)); string(got) != "a\nb\n" {
		t.Fatalf("Cut at the deadline = %q", got)
	}
	if s.Flush() != nil {
		t.Fatal("Flush after Cut returned a segment")
	}
	s.Add(first, []byte("c\n"))
	if got := s.Add(first.Add(SegmentInterval), []byte("d\n")); string(got) != "c\n" {
		t.Fatalf("Add past the interval cut %q, want \"c\\n\"", got)
	}
	if got := s.Flush(); string(got) != "d\n" {
		t.Fatalf("Flush = %q", got)
	}
}

func TestSegmenterCutsAtSize(t *testing.T) {
	w := NewWriter(testStart, 80, 24)
	header := w.Header()
	s := NewSegmenter(header)
	var all, out []byte
	all = append(all, header...)
	var segs [][]byte
	at := testStart
	for i := range 2000 {
		at = at.Add(time.Microsecond)
		data := bytes.Repeat([]byte{'a' + byte(i%26)}, 100+i*7%900)
		for _, l := range w.Output(at, data) {
			all = append(all, l...)
			if cut := s.Add(at, l); cut != nil {
				segs = append(segs, cut)
			}
		}
	}
	segs = append(segs, s.Flush())
	if len(segs) < 3 {
		t.Fatalf("got %d segments, want at least 3", len(segs))
	}
	for i, seg := range segs {
		if len(seg) == 0 || len(seg) > MaxPlaintext || seg[len(seg)-1] != '\n' {
			t.Fatalf("segment %d: %d bytes, not whole lines within MaxPlaintext", i, len(seg))
		}
		if i < len(segs)-1 && len(seg)+1100 < MaxPlaintext {
			t.Fatalf("segment %d cut at %d bytes with room left", i, len(seg))
		}
		out = append(out, seg...)
	}
	if !bytes.Equal(out, all) {
		t.Fatal("segments do not concatenate to the lines added")
	}
}

func TestSegmenterLargeEventStartsNewSegment(t *testing.T) {
	s := NewSegmenter(nil)
	small := []byte("small\n")
	big := append(bytes.Repeat([]byte("b"), MaxPlaintext-len(small)), '\n')
	s.Add(testStart, small)
	if got := s.Add(testStart, big); !bytes.Equal(got, small) {
		t.Fatalf("cut = %q, want the small segment", got)
	}
	if got := s.Flush(); !bytes.Equal(got, big) {
		t.Fatal("the large line did not start its own segment")
	}
}

func TestSegmenterLongLineSplitWithinBound(t *testing.T) {
	w := NewWriter(testStart, 80, 24)
	s := NewSegmenter(w.Header())
	var segs [][]byte
	for _, l := range w.Output(testStart, bytes.Repeat([]byte("z"), 600<<10)) {
		if cut := s.Add(testStart, l); cut != nil {
			segs = append(segs, cut)
		}
	}
	segs = append(segs, s.Flush())
	if len(segs) < 3 {
		t.Fatalf("600 KiB line gave %d segments, want at least 3", len(segs))
	}
	for i, seg := range segs {
		if len(seg) > MaxPlaintext {
			t.Fatalf("segment %d is %d bytes, over MaxPlaintext", i, len(seg))
		}
	}
}
