package tunnel

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/localport/agent/internal/recording"
)

// Recording request targets and headers on the session mux (PROTOCOL.md,
// recording wire).
const (
	recordingOpenPath     = "/v1/recording/open"
	recordingSegmentPath  = "/v1/recording/segment"
	recordingCompletePath = "/v1/recording/complete"

	recordingIDHeader            = "Localport-Recording-Id"
	recordingSegmentIndexHeader  = "Localport-Segment-Index"
	recordingSegmentSHA256Header = "Localport-Segment-Sha256"
	recordingFailedHeader        = "Localport-Recording-Failed"
	recordingSessionHeader       = "Localport-Recording-Session"
	sessionChannelsHeader        = "Localport-Session-Channels"

	// recordingMaxResponse bounds every recording response body the agent reads.
	recordingMaxResponse = 4 << 10

	// In-flight requests per conn, within the edge's 22 streams: 2 segment
	// requests, of which at most 1 drains the spool, 1 open, and 1 complete or
	// failed open (the clipboard notice batch holds its own).
	recordingSegmentSlots    = 2
	recordingDrainSlots      = 1
	recordingOpenSlots       = 1
	recordingBackgroundSlots = 1
)

// RecordingClient sends recording requests on one session mux conn and
// implements recording.Client. Open and complete are signed when sent with
// the key of the certificate that conn presented. Its slots belong to the
// conn: a request waiting for one returns recording.ErrNoSessionMux once
// the conn is gone. Safe for concurrent use.
type RecordingClient struct {
	cc     *http.ClientConn
	signer crypto.Signer
	closed <-chan struct{}

	// open is held by opens only, so a complete cannot delay a live open.
	open       chan struct{}
	background chan struct{}
	segments   chan struct{}
	drain      chan struct{}
}

var _ recording.Client = (*RecordingClient)(nil)

func newRecordingClient(connCtx context.Context, cc *http.ClientConn, signer crypto.Signer) *RecordingClient {
	return &RecordingClient{
		cc:         cc,
		signer:     signer,
		closed:     connCtx.Done(),
		open:       make(chan struct{}, recordingOpenSlots),
		background: make(chan struct{}, recordingBackgroundSlots),
		segments:   make(chan struct{}, recordingSegmentSlots),
		drain:      make(chan struct{}, recordingDrainSlots),
	}
}

// RecordingClient returns the recording client of the session mux conn up
// now, or recording.ErrNoSessionMux.
func (t *Tunnel) RecordingClient() (*RecordingClient, error) {
	if m := t.sessionMux.Load(); m != nil {
		if c := m.rec.Load(); c != nil {
			return c, nil
		}
	}
	return nil, recording.ErrNoSessionMux
}

type recordingOpenBody struct {
	WrappedDEK  string `json:"wrapped_dek"`
	Signature   string `json:"signature"`
	Certificate string `json:"certificate,omitempty"`
	SessionID   string `json:"session_id"`
}

type recordingCompleteBody struct {
	Segments   uint32 `json:"segments"`
	FinalHash  string `json:"final_hash"`
	EndedAt    int64  `json:"ended_at"`
	Incomplete bool   `json:"incomplete"`
	Final      bool   `json:"final"`
	Reason     string `json:"reason"`
	Signature  string `json:"signature"`
}

// Open sends the signed open of recording id of connection sessionID. keySHA256
// is the SHA-256 of the team key the DEK is wrapped to; certificate is the
// connection's SSH user certificate, from which the control plane creates the
// recording at the first open. channels, when positive, travels in headers the
// edge reads before it takes a slot.
func (c *RecordingClient) Open(ctx context.Context, id, sessionID string, wrappedDEK, keySHA256, certificate []byte, channels int32) (recording.Result, error) {
	sig, err := recording.Sign(c.signer, recording.OpenDigest(id, sessionID, wrappedDEK, keySHA256))
	if err != nil {
		return recording.Result{}, fmt.Errorf("sign recording open: %w", err)
	}
	body, err := json.Marshal(recordingOpenBody{
		WrappedDEK:  base64.RawURLEncoding.EncodeToString(wrappedDEK),
		Signature:   sig,
		Certificate: base64.RawURLEncoding.EncodeToString(certificate),
		SessionID:   sessionID,
	})
	if err != nil {
		return recording.Result{}, err
	}
	return c.sendControl(ctx, c.open, recordingOpenPath, id, body, true, channelHeaders(sessionID, channels))
}

// OpenFailed sends the signed report that recording id never started: an open
// with no wrapped DEK and the reason in a header the edge reads before it
// takes a slot.
func (c *RecordingClient) OpenFailed(ctx context.Context, f recording.FailedOpen) (recording.Result, error) {
	sig, err := recording.Sign(c.signer, recording.OpenFailedDigest(f.ID, f.SessionID, f.KeySHA256, f.Reason))
	if err != nil {
		return recording.Result{}, fmt.Errorf("sign recording failed open: %w", err)
	}
	body, err := json.Marshal(recordingOpenBody{
		Signature:   sig,
		Certificate: base64.RawURLEncoding.EncodeToString(f.Certificate),
		SessionID:   f.SessionID,
	})
	if err != nil {
		return recording.Result{}, err
	}
	headers := channelHeaders(f.SessionID, f.Channels)
	if headers == nil {
		headers = http.Header{}
	}
	headers.Set(recordingFailedHeader, f.Reason)
	return c.sendControl(ctx, c.background, recordingOpenPath, f.ID, body, false, headers)
}

// channelHeaders carries a live start's cumulative channel count; nil for an
// open that has none.
func channelHeaders(sessionID string, channels int32) http.Header {
	if channels <= 0 {
		return nil
	}
	h := http.Header{}
	h.Set(recordingSessionHeader, sessionID)
	h.Set(sessionChannelsHeader, strconv.FormatInt(int64(channels), 10))
	return h
}

// Complete sends the signed complete of recording id.
func (c *RecordingClient) Complete(ctx context.Context, id string, wrappedDEK []byte, done recording.Completion) (recording.Result, error) {
	sig, err := recording.Sign(c.signer, recording.CompleteDigest(id, wrappedDEK, done))
	if err != nil {
		return recording.Result{}, fmt.Errorf("sign recording complete: %w", err)
	}
	body, err := json.Marshal(recordingCompleteBody{
		Segments:   done.Segments,
		FinalHash:  base64.RawURLEncoding.EncodeToString(done.FinalHash),
		EndedAt:    done.EndedAt.Unix(),
		Incomplete: done.Incomplete,
		Final:      done.Final,
		Reason:     done.Reason,
		Signature:  sig,
	})
	if err != nil {
		return recording.Result{}, err
	}
	return c.sendControl(ctx, c.background, recordingCompletePath, id, body, false, nil)
}

// PutSegment sends a live session's segment of recording id.
func (c *RecordingClient) PutSegment(ctx context.Context, id string, seg recording.Segment) (recording.Result, error) {
	return c.putSegment(ctx, id, seg)
}

// PutSpooledSegment sends the segment load reads back from the spool. At most
// one such request is in flight per conn, so a live segment always finds one
// of the two segment slots free of spool drain, and load runs only inside
// that place, so waiting requests hold no segment in memory.
func (c *RecordingClient) PutSpooledSegment(ctx context.Context, id string, load func() (recording.Segment, error)) (recording.Result, error) {
	release, err := c.acquire(ctx, c.drain)
	if err != nil {
		return recording.Result{}, err
	}
	defer release()
	seg, err := load()
	if err != nil {
		return recording.Result{}, err
	}
	return c.putSegment(ctx, id, seg)
}

func (c *RecordingClient) putSegment(ctx context.Context, id string, seg recording.Segment) (recording.Result, error) {
	release, err := c.acquire(ctx, c.segments)
	if err != nil {
		return recording.Result{}, err
	}
	defer release()
	req, err := newSessionMuxRequest(ctx, http.MethodPut, recordingSegmentPath, bytes.NewReader(seg.Object))
	if err != nil {
		return recording.Result{}, err
	}
	req.Header.Set(recordingIDHeader, id)
	req.Header.Set(recordingSegmentIndexHeader, strconv.FormatUint(uint64(seg.Index), 10))
	req.Header.Set(recordingSegmentSHA256Header, base64.RawURLEncoding.EncodeToString(seg.Hash[:]))
	return c.roundTrip(req, false)
}

func (c *RecordingClient) sendControl(ctx context.Context, slots chan struct{}, path, id string, body []byte, wantChain bool, headers http.Header) (recording.Result, error) {
	release, err := c.acquire(ctx, slots)
	if err != nil {
		return recording.Result{}, err
	}
	defer release()
	req, err := newSessionMuxRequest(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return recording.Result{}, err
	}
	for name, values := range headers {
		req.Header[name] = values
	}
	req.Header.Set(recordingIDHeader, id)
	return c.roundTrip(req, wantChain)
}

// acquire takes a slot of slots, waiting until one frees, ctx ends or the
// conn closes. The returned function gives the slot back.
func (c *RecordingClient) acquire(ctx context.Context, slots chan struct{}) (func(), error) {
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, recording.ErrNoSessionMux
	}
}

func (c *RecordingClient) roundTrip(req *http.Request, wantChain bool) (recording.Result, error) {
	resp, err := c.cc.RoundTrip(req)
	if err != nil {
		return recording.Result{}, fmt.Errorf("%w: %w", recording.ErrTransport, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, recordingMaxResponse+1))
	if err != nil {
		return recording.Result{}, fmt.Errorf("%w: read answer: %w", recording.ErrTransport, err)
	}
	if len(raw) > recordingMaxResponse {
		return recording.Result{}, fmt.Errorf("%w: answer %d over %d bytes", recording.ErrTransport, resp.StatusCode, recordingMaxResponse)
	}
	return parseRecordingAnswer(resp.StatusCode, raw, wantChain)
}

// parseRecordingAnswer classifies an answer. A refusal counts only when it
// carries a known code at that code's status, so a 408 is a transport failure
// the uploader retries, not a 400 refusal that drops the recording.
func parseRecordingAnswer(status int, raw []byte, wantChain bool) (recording.Result, error) {
	if status == http.StatusOK {
		var a struct {
			Status   string  `json:"status"`
			Segments uint32  `json:"segments"`
			Chain    *string `json:"chain"`
		}
		if json.Unmarshal(raw, &a) != nil || a.Status == "" {
			return recording.Result{}, fmt.Errorf("%w: unreadable 200 answer", recording.ErrTransport)
		}
		res := recording.Result{Status: a.Status, Segments: a.Segments}
		if wantChain {
			if a.Chain == nil {
				return recording.Result{}, fmt.Errorf("%w: open answer without chain", recording.ErrTransport)
			}
			chain, err := base64.RawURLEncoding.Strict().DecodeString(*a.Chain)
			if err != nil || (a.Segments == 0) != (len(chain) == 0) || (len(chain) != 0 && len(chain) != sha256.Size) {
				return recording.Result{}, fmt.Errorf("%w: open answer with a malformed chain", recording.ErrTransport)
			}
			res.Chain = chain
		}
		return res, nil
	}
	var r struct {
		Code       string `json:"code"`
		RetryAfter uint32 `json:"retry_after"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return recording.Result{}, fmt.Errorf("%w: unreadable %d answer", recording.ErrTransport, status)
	}
	if want, ok := recording.Status(r.Code); !ok || want != status {
		return recording.Result{}, fmt.Errorf("%w: edge answered %d with code %q", recording.ErrTransport, status, r.Code)
	}
	return recording.Result{}, &recording.Refusal{
		Status:     status,
		Code:       r.Code,
		RetryAfter: time.Duration(r.RetryAfter) * time.Second,
	}
}
