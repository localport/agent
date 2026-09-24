package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
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

// A stream carries bytes to the local service and back.
func TestMuxServerPipesStreamToLocalService(t *testing.T) {
	dial, stop := echoService(t)
	defer stop()

	srv := &muxServer{dialTarget: tunnelTarget(dial)}

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

// An unreachable local service returns 502.
func TestMuxServerReportsUnreachableLocalService(t *testing.T) {
	srv := &muxServer{
		dialTarget: tunnelTarget(func() (net.Conn, error) {
			return nil, net.ErrClosed
		}),
	}

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/stream", nil))

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

// tunnelTarget adapts a plain dialer to the dialTarget signature.
func tunnelTarget(dial func() (net.Conn, error)) func(uint16) (net.Conn, int, error) {
	return func(uint16) (net.Conn, int, error) {
		conn, err := dial()
		if err != nil {
			return nil, http.StatusBadGateway, err
		}
		return conn, http.StatusOK, nil
	}
}

// recordingTracker stands in for the tunnel's live connection view.
type recordingTracker struct {
	began  []string
	ended  int
	stream *activeConn
}

func (r *recordingTracker) Begin(remote string, _ connTarget, _ net.Conn) *activeConn {
	r.began = append(r.began, remote)
	r.stream = &activeConn{id: "test-stream", remote: remote, startedAt: time.Now()}
	return r.stream
}

func (r *recordingTracker) End(ac *activeConn, err error) { r.ended++ }

// Stream and tunnel byte counters update while bytes move.
func TestMuxServerCountsBytesPerStreamAndTotal(t *testing.T) {
	dial, stop := echoService(t)
	defer stop()

	tracker := &recordingTracker{}
	var totalIn, totalOut atomic.Int64
	srv := &muxServer{
		dialTarget: tunnelTarget(dial),
		tracker:    tracker,
		totalIn:    &totalIn,
		totalOut:   &totalOut,
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

// Each stream enters and leaves the live view, as on dial-back.
func TestMuxServerTracksStreamLifecycle(t *testing.T) {
	dial, stop := echoService(t)
	defer stop()

	tracker := &recordingTracker{}
	srv := &muxServer{dialTarget: tunnelTarget(dial), tracker: tracker}

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

// muxClient speaks HTTP/2 with prior knowledge over conn, as the edge does.
func muxClient(t *testing.T, conn net.Conn) *http.ClientConn {
	t.Helper()
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	tr := &http.Transport{
		Protocols: &protocols,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		},
	}
	cc, err := tr.NewClientConn(context.Background(), "http", "mux.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	return cc
}

// tlsCarrier stands in for the control carrier's *tls.Conn, whose ALPN is the
// agent control protocol rather than h2.
type tlsCarrier struct{ net.Conn }

func (tlsCarrier) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{HandshakeComplete: true, NegotiatedProtocol: "localport-agent"}
}

// serveMux speaks HTTP/2 with prior knowledge over either carrier and returns
// when the connection closes.
func TestServeMuxServesStreamsOverTheCarrier(t *testing.T) {
	for name, wrap := range map[string]func(net.Conn) net.Conn{
		"plain": func(c net.Conn) net.Conn { return c },
		"tls":   func(c net.Conn) net.Conn { return tlsCarrier{c} },
	} {
		t.Run(name, func(t *testing.T) {
			dial, stop := echoService(t)
			defer stop()
			local, err := dial()
			if err != nil {
				t.Fatal(err)
			}
			addr := local.RemoteAddr().String()
			local.Close()

			tn := New(Options{Local: addr})
			client, server := net.Pipe()
			done := make(chan struct{})
			go func() {
				tn.serveMux(wrap(server))
				close(done)
			}()

			cc := muxClient(t, client)
			req, err := http.NewRequest(http.MethodPost, "http://mux.invalid/v1/stream", strings.NewReader("hello"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 5)
			if _, err := io.ReadFull(resp.Body, got); err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if string(got) != "hello" {
				t.Fatalf("echoed %q, want %q", got, "hello")
			}

			cc.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("serveMux did not return after the connection closed")
			}
		})
	}
}

// The server advertises the mux stream limit and flow control windows.
func TestServeMuxAdvertisesStreamLimitAndWindows(t *testing.T) {
	tn := New(Options{Local: "127.0.0.1:1"})
	client, server := net.Pipe()
	defer client.Close()
	go tn.serveMux(server)

	go func() {
		if _, err := io.WriteString(client, http2.ClientPreface); err != nil {
			return
		}
		_ = http2.NewFramer(client, nil).WriteSettings()
	}()

	fr := http2.NewFramer(nil, client)
	var settings, window bool
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetReadDeadline(deadline)
	for !settings || !window {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			settings = true
			if v, ok := f.Value(http2.SettingMaxConcurrentStreams); !ok || v != maxConcurrentDataConns {
				t.Errorf("MAX_CONCURRENT_STREAMS = %d, want %d", v, maxConcurrentDataConns)
			}
			if v, ok := f.Value(http2.SettingInitialWindowSize); !ok || v != muxUploadBufferPerStream {
				t.Errorf("INITIAL_WINDOW_SIZE = %d, want %d", v, muxUploadBufferPerStream)
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID != 0 {
				continue
			}
			window = true
			if want := uint32(muxUploadBufferPerConnection - 65535); f.Increment != want {
				t.Errorf("connection WINDOW_UPDATE = %d, want %d", f.Increment, want)
			}
		}
	}
}

// A stream the edge resets with CANCEL reaches the handler as a stdlib
// StreamError, which ignoreClosed treats as a normal close.
func TestIgnoreClosedDropsAStreamCancelledByTheEdge(t *testing.T) {
	readErr := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		_, err := io.Copy(io.Discard, r.Body)
		readErr <- err
	})
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	client, server := net.Pipe()
	srv := &http.Server{Handler: handler, Protocols: &protocols}
	go func() { _ = srv.Serve(&muxListener{conn: server}) }()
	defer srv.Close()

	cc := muxClient(t, client)
	defer cc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	body, bodyW := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://mux.invalid/v1/stream", body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bodyW.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	cancel()
	resp.Body.Close()

	select {
	case err := <-readErr:
		var streamErr http2.StreamError
		if !errors.As(err, &streamErr) || streamErr.Code != http2.ErrCodeCancel {
			t.Fatalf("handler read error = %v, want a CANCEL StreamError", err)
		}
		if got := ignoreClosed(err); got != nil {
			t.Fatalf("ignoreClosed(%v) = %v, want nil", err, got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never saw the reset")
	}
}
