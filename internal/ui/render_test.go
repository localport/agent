package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/localport/agent/internal/tunnel"
)

func sampleReqs(n int) []tunnel.RequestInfo {
	reqs := make([]tunnel.RequestInfo, n)
	for i := range reqs {
		reqs[i] = tunnel.RequestInfo{
			Method:    "GET",
			Path:      "/health",
			Status:    200,
			Duration:  time.Millisecond,
			StartedAt: time.Now(),
		}
	}
	return reqs
}

// TestRenderRequestTableSqueezed guards the render path against a squeezed bottom
// panel: capacity 1 leaves room for the header alone, so the overflow marker must
// not be written to a body row that does not exist.
func TestRenderRequestTableSqueezed(t *testing.T) {
	pal := NewPalette(ColorOff)
	for _, capacity := range []int{0, 1, 2, 3} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("capacity=%d panicked: %v", capacity, r)
				}
			}()
			rows := renderRequestTable(sampleReqs(10), capacity, 100, pal)
			if capacity <= 0 && rows != nil {
				t.Fatalf("capacity=%d: want nil, got %d rows", capacity, len(rows))
			}
			if len(rows) > capacity {
				t.Fatalf("capacity=%d: produced %d rows, over budget", capacity, len(rows))
			}
		}()
	}
}

func TestRenderRequestTableOverflowMarker(t *testing.T) {
	pal := NewPalette(ColorOff)
	rows := renderRequestTable(sampleReqs(10), 4, 100, pal) // header + 3 body
	if len(rows) != 4 {
		t.Fatalf("want 4 rows, got %d", len(rows))
	}
	// 10 requests, room for 3 body rows: the first body row marks the hidden older ones.
	if !strings.Contains(rows[1], "earlier") {
		t.Errorf("expected an '…earlier' marker on the first body row, got %q", rows[1])
	}
}

func TestRenderRequestTableFits(t *testing.T) {
	pal := NewPalette(ColorOff)
	rows := renderRequestTable(sampleReqs(2), 10, 100, pal) // header + 2, room to spare
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (header + 2), got %d", len(rows))
	}
	for _, r := range rows[1:] {
		if strings.Contains(r, "earlier") {
			t.Errorf("no marker expected when everything fits: %q", r)
		}
	}
}

func TestHumanLatency(t *testing.T) {
	cases := map[time.Duration]string{
		500 * time.Nanosecond:   "0µs",
		250 * time.Microsecond:  "250µs",
		3 * time.Millisecond:    "3ms",
		1500 * time.Millisecond: "1.5s",
		42 * time.Second:        "42s",
	}
	for d, want := range cases {
		if got := humanLatency(d); got != want {
			t.Errorf("humanLatency(%v) = %q, want %q", d, got, want)
		}
	}
}
