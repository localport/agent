package tunnel

import (
	"context"
	"io"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// streamEchoHandler echoes each stream. Its Shutdown runs shutdown, by
// default a farewell: write "bye", half-close, and wait for every Serve.
type streamEchoHandler struct {
	mu       sync.Mutex
	live     map[net.Conn]chan struct{}
	served   atomic.Int32
	serving  chan struct{}
	shutdown func(ctx context.Context) error

	shutdownCalls atomic.Int32
	recordingUps  atomic.Int32
	farewellErr   chan error
}

func newStreamEchoHandler() *streamEchoHandler {
	h := &streamEchoHandler{
		live:        make(map[net.Conn]chan struct{}),
		serving:     make(chan struct{}, 8),
		farewellErr: make(chan error, 8),
	}
	h.shutdown = h.farewell
	return h
}

func (h *streamEchoHandler) Serve(stream net.Conn) {
	done := make(chan struct{})
	h.mu.Lock()
	h.live[stream] = done
	h.mu.Unlock()
	h.served.Add(1)
	h.serving <- struct{}{}
	defer func() {
		h.mu.Lock()
		delete(h.live, stream)
		h.mu.Unlock()
		close(done)
	}()
	_, _ = io.Copy(stream, stream)
}

func (h *streamEchoHandler) Shutdown(ctx context.Context) error {
	h.shutdownCalls.Add(1)
	return h.shutdown(ctx)
}

func (h *streamEchoHandler) RecordingClientUp() { h.recordingUps.Add(1) }

func (h *streamEchoHandler) LiveSessions() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.live)
}

func (h *streamEchoHandler) snapshot() map[net.Conn]chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	return maps.Clone(h.live)
}

func (h *streamEchoHandler) farewell(ctx context.Context) error {
	for stream, done := range h.snapshot() {
		_, err := stream.Write([]byte("bye"))
		if err == nil {
			err = stream.(interface{ CloseWrite() error }).CloseWrite()
		}
		h.farewellErr <- err
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (h *streamEchoHandler) waitServing(t *testing.T) {
	t.Helper()
	select {
	case <-h.serving:
	case <-time.After(3 * time.Second):
		t.Fatal("the stream did not reach the handler")
	}
}
