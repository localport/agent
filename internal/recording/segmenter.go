package recording

import "time"

const (
	// MaxPlaintext bounds one segment's plaintext.
	MaxPlaintext = 256 << 10
	// SegmentInterval is how long a segment collects events after its first
	// one before it is cut.
	SegmentInterval = 10 * time.Second
)

// Segmenter packs asciicast lines into segment plaintexts of whole lines,
// cut at SegmentInterval after the segment's first event or before a line
// that would take it past MaxPlaintext. Segment 0 starts with the header.
// A segment with no events is never cut. A Segmenter is not safe for
// concurrent use.
type Segmenter struct {
	buf []byte
	// first is the time of the open segment's first event; zero when the
	// segment has none.
	first time.Time
}

// NewSegmenter returns a Segmenter whose segment 0 starts with header.
func NewSegmenter(header []byte) *Segmenter {
	return &Segmenter{buf: append([]byte(nil), header...)}
}

// Add appends one event line (as the Writer emits, at most MaxLine bytes)
// recorded at at. When the open segment is due or has no room for line, it
// is returned as cut and line starts the next segment; otherwise cut is
// nil.
func (s *Segmenter) Add(at time.Time, line []byte) (cut []byte) {
	if !s.first.IsZero() && (!at.Before(s.first.Add(SegmentInterval)) || len(s.buf)+len(line) > MaxPlaintext) {
		cut = s.take()
	}
	if s.first.IsZero() {
		s.first = at
	}
	s.buf = append(s.buf, line...)
	return cut
}

// Deadline returns when the open segment is due, and false when it holds no
// events.
func (s *Segmenter) Deadline() (time.Time, bool) {
	if s.first.IsZero() {
		return time.Time{}, false
	}
	return s.first.Add(SegmentInterval), true
}

// Cut returns the open segment when it holds events and is due at now, else
// nil.
func (s *Segmenter) Cut(now time.Time) []byte {
	if s.first.IsZero() || now.Before(s.first.Add(SegmentInterval)) {
		return nil
	}
	return s.take()
}

// Flush returns the open segment when it holds events, else nil. It is the
// last call: what it returns is the segment to seal as final.
func (s *Segmenter) Flush() []byte {
	if s.first.IsZero() {
		return nil
	}
	return s.take()
}

func (s *Segmenter) take() []byte {
	seg := s.buf
	s.buf = nil
	s.first = time.Time{}
	return seg
}
