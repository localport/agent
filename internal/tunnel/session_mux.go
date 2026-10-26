package tunnel

import (
	"context"
	"net"
)

// SessionHandler serves the session streams of a device's session mux. One
// handler serves every control session of the tunnel: each session mux calls
// Shutdown when its control session ends, and the next control session's mux
// calls Serve again on the same handler.
//
// Serve runs on its own goroutine per stream and must return once the stream
// fails. The session mux closes stream after Serve returns. Shutdown ends the
// sessions the handler holds when it is called and must return once ctx ends.
// It is not terminal: Serve may be called again after Shutdown returns, for
// the next control session. No stream of the stopping
// mux is handed to Serve once Shutdown has been called, but a Serve started
// just before may still be running when Shutdown begins.
//
// LiveSessions returns the number of sessions the handler serves now; a
// certificate rollover that is not forced waits while it is above zero.
//
// RecordingClientUp is called each time the mux publishes the recording
// client of a new conn; it must not block.
type SessionHandler interface {
	Serve(stream net.Conn)
	Shutdown(ctx context.Context) error
	LiveSessions() int
	RecordingClientUp()
}
