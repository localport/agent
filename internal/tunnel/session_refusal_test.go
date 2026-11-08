package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// refusingHandler answers one refusal under a handshake deadline and returns,
// as a first connect or a resume that is refused does.
type refusingHandler struct {
	refusal []byte
	done    chan struct{}
}

func (h *refusingHandler) Serve(stream net.Conn, _ [16]byte, _ uint64) {
	defer close(h.done)
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = stream.Write(h.refusal)
}
func (h *refusingHandler) Shutdown(context.Context) error { return nil }
func (h *refusingHandler) LiveSessions() int              { return 0 }
func (h *refusingHandler) RecordingClientUp()             {}

// streamHookHandler runs serve on each stream.
type streamHookHandler struct{ serve func(net.Conn) }

func newStreamHookHandler(serve func(net.Conn)) *streamHookHandler {
	return &streamHookHandler{serve: serve}
}

func (h *streamHookHandler) Serve(stream net.Conn, _ [16]byte, _ uint64) { h.serve(stream) }
func (h *streamHookHandler) Shutdown(context.Context) error              { return nil }
func (h *streamHookHandler) LiveSessions() int                           { return 0 }
func (h *streamHookHandler) RecordingClientUp()                          {}

func isDeadline(err error) bool { return errors.Is(err, os.ErrDeadlineExceeded) }

// A refusal written just before the handler returns reaches the edge over a
// session stream, whose Close resets it.
func TestSessionRefusalReachesTheEdgeBeforeTheStreamResets(t *testing.T) {
	for i := range 200 {
		edge := newFakeSessionEdge(t)
		d := &pipeSessionDial{edge: edge}
		h := &refusingHandler{refusal: []byte("refused: not admitted"), done: make(chan struct{})}
		startTestSessionMux(t, h, d.dial)
		edge.expectAccept(t)
		edge.sendNotice(t, notice([sessionIDLen]byte{byte(i + 1)}))
		s := edge.expectSession(t)
		got := make([]byte, len(h.refusal))
		if _, err := io.ReadFull(s.body, got); err != nil || string(got) != string(h.refusal) {
			t.Fatalf("round %d: refusal %q, %v", i, got, err)
		}
		select {
		case <-h.done:
		case <-time.After(3 * time.Second):
			t.Fatal("Serve did not return")
		}
		edge.close()
	}
}

// An expired deadline ends a session stream for good, and the failure is the
// deadline's.
func TestSessionStreamDeadlineIsFinal(t *testing.T) {
	edge := newFakeSessionEdge(t)
	d := &pipeSessionDial{edge: edge}
	errs := make(chan error, 2)
	h := newStreamHookHandler(func(stream net.Conn) {
		_ = stream.SetDeadline(time.Now().Add(20 * time.Millisecond))
		_, err := stream.Read(make([]byte, 1))
		errs <- err
		_ = stream.SetDeadline(time.Time{})
		_, err = stream.Read(make([]byte, 1))
		errs <- err
	})
	startTestSessionMux(t, h, d.dial)
	edge.expectAccept(t)
	edge.sendNotice(t, notice([sessionIDLen]byte{9}))
	edge.expectSession(t)
	for range 2 {
		select {
		case err := <-errs:
			if !isDeadline(err) {
				t.Fatalf("read after the deadline = %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("the read did not end")
		}
	}
}
