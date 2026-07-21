package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// echoService accepts one connection and echoes it back, standing in for the
// tunnelled local service.
func echoService(t *testing.T) (dial func() (net.Conn, error), stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return func() (net.Conn, error) {
			return net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		}, func() {
			ln.Close()
		}
}

// A stream must carry bytes to the local service and its reply back, which is
// the whole contract the dial-back path used to provide.
func TestMuxServerPipesStreamToLocalService(t *testing.T) {
	dial, stop := echoService(t)
	defer stop()

	srv := &muxServer{dialLocal: dial}

	payload := "the quick brown fox"
	req := httptest.NewRequest(http.MethodPost, "/v1/stream", bytes.NewReader([]byte(payload)))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != payload {
		t.Errorf("echoed %q, want %q", got, payload)
	}
}

// An unreachable local service must be reported as a gateway failure rather
// than a hung stream, so the visitor gets an error instead of a timeout.
func TestMuxServerReportsUnreachableLocalService(t *testing.T) {
	srv := &muxServer{
		dialLocal: func() (net.Conn, error) {
			return nil, net.ErrClosed
		},
	}

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/stream", nil))

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

// recordingTracker stands in for the tunnel's live connection view.
type recordingTracker struct {
	began  []string
	ended  int
	stream *activeConn
}

func (r *recordingTracker) Begin(remote string) *activeConn {
	r.began = append(r.began, remote)
	r.stream = &activeConn{id: "test-stream", remote: remote, startedAt: time.Now()}
	return r.stream
}

func (r *recordingTracker) End(ac *activeConn, err error) { r.ended++ }

// Byte counts feed the TUI and the usage view. They must be folded in as bytes
// move, both per stream and into the tunnel totals, or a muxed tunnel reports
// nothing until every stream has finished.
func TestMuxServerCountsBytesPerStreamAndTotal(t *testing.T) {
	dial, stop := echoService(t)
	defer stop()

	tracker := &recordingTracker{}
	var totalIn, totalOut atomic.Int64
	srv := &muxServer{
		dialLocal: dial,
		tracker:   tracker,
		totalIn:   &totalIn,
		totalOut:  &totalOut,
	}

	payload := bytes.Repeat([]byte("x"), 4096)
	srv.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/v1/stream", bytes.NewReader(payload)))

	want := int64(len(payload))
	if got := tracker.stream.bytesIn.Load(); got != want {
		t.Errorf("per-stream bytes in = %d, want %d", got, want)
	}
	if got := tracker.stream.bytesOut.Load(); got != want {
		t.Errorf("per-stream bytes out = %d, want %d", got, want)
	}
	if got := totalIn.Load(); got != want {
		t.Errorf("tunnel total in = %d, want %d", got, want)
	}
	if got := totalOut.Load(); got != want {
		t.Errorf("tunnel total out = %d, want %d", got, want)
	}
}

// Every stream must appear in the live view and leave it again, so a muxed
// tunnel shows connections exactly as a dial-back one does.
func TestMuxServerTracksStreamLifecycle(t *testing.T) {
	dial, stop := echoService(t)
	defer stop()

	tracker := &recordingTracker{}
	srv := &muxServer{dialLocal: dial, tracker: tracker}

	req := httptest.NewRequest(http.MethodPost, "/v1/stream", nil)
	req.Header.Set(headerVisitorAddr, "203.0.113.7:54321")
	srv.ServeHTTP(httptest.NewRecorder(), req)

	if len(tracker.began) != 1 || tracker.began[0] != "203.0.113.7:54321" {
		t.Errorf("began = %v, want one stream from 203.0.113.7:54321", tracker.began)
	}
	if tracker.ended != 1 {
		t.Errorf("ended = %d, want 1: a finished stream must leave the live view", tracker.ended)
	}
}

// Backoff must grow and then settle, so a repeatedly dropping connection does
// not turn into a reconnect loop against the edge.
func TestMuxRetryBackoffGrowsAndCaps(t *testing.T) {
	first := muxRetryBackoff(0)
	second := muxRetryBackoff(1)
	if second <= first {
		t.Errorf("backoff did not grow: %v then %v", first, second)
	}

	// Large and negative attempts must both land somewhere sane rather than
	// overflowing into a negative or absurd duration.
	for _, attempt := range []int{-1, 30, 62, 64, 1000} {
		d := muxRetryBackoff(attempt)
		if d <= 0 || d > 30*time.Second {
			t.Errorf("muxRetryBackoff(%d) = %v, want a bounded positive duration", attempt, d)
		}
	}
}

// A cancelled session must not wait out the backoff before giving up.
func TestSleepCtxReturnsEarlyWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if sleepCtx(ctx, 5*time.Second) {
		t.Error("sleepCtx reported completion on a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("sleepCtx waited %v on a cancelled context", elapsed)
	}
}
