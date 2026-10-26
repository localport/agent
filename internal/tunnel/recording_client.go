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

	// recordingMaxResponse bounds every recording response body the agent reads.
	recordingMaxResponse = 4 << 10

	// In-flight requests per conn, within the edge's 20 streams: 2 segment
	// requests, of which at most 1 drains the spool, and 1 open or complete.
	recordingSegmentSlots = 2
	recordingDrainSlots   = 1
	recordingControlSlots = 1
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

	control  chan struct{}
	segments chan struct{}
	drain    chan struct{}
}

var _ recording.Client = (*RecordingClient)(nil)

func newRecordingClient(connCtx context.Context, cc *http.ClientConn, signer crypto.Signer) *RecordingClient {
	return &RecordingClient{
		cc:       cc,
		signer:   signer,
		closed:   connCtx.Done(),
		control:  make(chan struct{}, recordingControlSlots),
		segments: make(chan struct{}, recordingSegmentSlots),
		drain:    make(chan struct{}, recordingDrainSlots),
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
	WrappedDEK string `json:"wrapped_dek"`
	Signature  string `json:"signature"`
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

// Open sends the signed open of recording id. keySHA256 is the SHA-256 of the
// team key the DEK is wrapped to.
func (c *RecordingClient) Open(ctx context.Context, id string, wrappedDEK, keySHA256 []byte) (recording.Result, error) {
	sig, err := recording.Sign(c.signer, recording.OpenDigest(id, wrappedDEK, keySHA256))
	if err != nil {
		return recording.Result{}, fmt.Errorf("sign recording open: %w", err)
	}
	body, err := json.Marshal(recordingOpenBody{
		WrappedDEK: base64.RawURLEncoding.EncodeToString(wrappedDEK),
		Signature:  sig,
	})
	if err != nil {
		return recording.Result{}, err
	}
	return c.sendControl(ctx, recordingOpenPath, id, body, true)
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
	return c.sendControl(ctx, recordingCompletePath, id, body, false)
}

// PutSegment sends a live session's segment of recording id.
func (c *RecordingClient) PutSegment(ctx context.Context, id string, seg recording.Segment) (recording.Result, error) {
	return c.putSegment(ctx, id, seg)
}

// PutSpooledSegment sends a segment read back from the spool. At most one
// such request is in flight per conn, so a live segment always finds one of
// the two segment slots free of spool drain.
func (c *RecordingClient) PutSpooledSegment(ctx context.Context, id string, seg recording.Segment) (recording.Result, error) {
	release, err := c.acquire(ctx, c.drain)
	if err != nil {
		return recording.Result{}, err
	}
	defer release()
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

func (c *RecordingClient) sendControl(ctx context.Context, path, id string, body []byte, wantChain bool) (recording.Result, error) {
	release, err := c.acquire(ctx, c.control)
	if err != nil {
		return recording.Result{}, err
	}
	defer release()
	req, err := newSessionMuxRequest(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return recording.Result{}, err
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
