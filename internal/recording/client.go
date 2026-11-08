package recording

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrNoSessionMux reports that no session mux is up to carry a recording
// request. The caller retries once a mux is up.
var ErrNoSessionMux = errors.New("recording: no session mux is up")

// ErrTransport reports a recording request that got no usable answer: a
// network or stream failure, a 408, or a body that is not the contract's. The
// caller keeps the entry and retries with backoff.
var ErrTransport = errors.New("recording: request failed in transport")

// Refusal is a refusal the edge answered with a known recording code at that
// code's status. RetryAfter is zero when the body carries none.
type Refusal struct {
	Status     int
	Code       string
	RetryAfter time.Duration
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("recording refused: %s (%d)", r.Code, r.Status)
}

// Result is a 200 answer. Chain is set on an open only, empty when the server
// holds no segment.
type Result struct {
	Status   string
	Segments uint32
	Chain    []byte
}

// MaxCertificate bounds the SSH user certificate an open carries, as the
// edge reads it from the first WebSocket message.
const MaxCertificate = 8 << 10

// Client sends recording requests on one session mux conn and signs open and
// complete with the key of the certificate that conn presented. Errors are
// ErrNoSessionMux, an error wrapping ErrTransport, or a *Refusal.
type Client interface {
	// Open sends the open of recording id of connection sessionID with the
	// connection's certificate (Meta.SessionID, Meta.Certificate). channels,
	// when positive, is the stream's cumulative recorded start count.
	Open(ctx context.Context, id, sessionID string, wrappedDEK, keySHA256, certificate []byte, channels int32) (Result, error)
	// OpenFailed reports that recording id never started, on the background
	// control slot, signed over the failure and its reason.
	OpenFailed(ctx context.Context, f FailedOpen) (Result, error)
	Complete(ctx context.Context, id string, wrappedDEK []byte, done Completion) (Result, error)
	// PutSegment sends a live session's segment.
	PutSegment(ctx context.Context, id string, seg Segment) (Result, error)
	// PutSpooledSegment sends the segment load reads back from the spool. At
	// most one such request is in flight per conn, and load runs only once it
	// holds that place, so waiting requests hold no segment in memory. A load
	// error is returned unchanged.
	PutSpooledSegment(ctx context.Context, id string, load func() (Segment, error)) (Result, error)
}
