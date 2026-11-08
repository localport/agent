package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/recording"
)

const testRecordingID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

// testSessionID is the connection the test recording belongs to.
const testSessionID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60"

// testCertificate stands for the session certificate an open carries.
var testCertificate = []byte("session certificate bytes")

// recordingRequest is one recording request as the stub edge received it.
type recordingRequest struct {
	method  string
	path    string
	header  http.Header
	body    []byte
	release chan struct{}
}

// unhold lets the held handler of this request, and no other, answer.
func (r recordingRequest) unhold() { close(r.release) }

// recordingEdge serves /v1/recording/* on a fakeSessionEdge. Every request is
// reported on reqs once its body is read; with hold set, the handler then
// waits for its own unhold (or the stream's end) before it answers. With
// ignoreCancel set, a held handler waits for its unhold only, the way a handler
// stays parked until the client's stream reset reaches the edge.
type recordingEdge struct {
	reqs         chan recordingRequest
	hold         bool
	ignoreCancel atomic.Bool
	answer       func(recordingRequest) (int, string)
}

func newRecordingEdge(answer func(recordingRequest) (int, string)) *recordingEdge {
	return &recordingEdge{reqs: make(chan recordingRequest, 16), answer: answer}
}

func (s *recordingEdge) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	req := recordingRequest{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), body: body, release: make(chan struct{})}
	s.reqs <- req
	if s.hold {
		streamEnd := r.Context().Done()
		if s.ignoreCancel.Load() {
			streamEnd = nil
		}
		select {
		case <-req.release:
		case <-streamEnd:
			return
		}
	}
	status, answer := s.answer(req)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, answer)
}

func (s *recordingEdge) expect(t *testing.T) recordingRequest {
	t.Helper()
	select {
	case r := <-s.reqs:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("no recording request reached the edge")
		return recordingRequest{}
	}
}

// expectNone fails when a recording request reaches the edge within 150 ms.
func (s *recordingEdge) expectNone(t *testing.T) {
	t.Helper()
	select {
	case r := <-s.reqs:
		t.Fatalf("%s %s reached the edge, want it held by the agent's limit", r.method, r.path)
	case <-time.After(150 * time.Millisecond):
	}
}

func answerOK(recordingRequest) (int, string) {
	return http.StatusOK, `{"status":"open","segments":0,"chain":""}`
}

func testDeviceKey(t *testing.T) (*ecdsa.PrivateKey, *identity.Presentation) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, &identity.Presentation{Certificate: &tls.Certificate{PrivateKey: key}, Serial: "aa"}
}

// startRecordingTunnel starts a device tunnel's session mux against edge,
// registered with presented, and returns the mux's stop function.
func startRecordingTunnel(t *testing.T, edge *fakeSessionEdge, presented *identity.Presentation) (*Tunnel, func()) {
	t.Helper()
	tn := sessionDeviceTunnel(Options{SessionHandler: newStreamEchoHandler(), Capabilities: []string{"terminal"}})
	tn.mu.Lock()
	tn.sessionID, tn.edgeAddr, tn.presented = "s1", "connect.eu.localport.dev:443", presented
	tn.dialer = &bindingDialer{edge: edge, purposes: make(chan string, 16)}
	tn.mu.Unlock()
	stop := tn.startSessionMux(context.Background())
	t.Cleanup(stop)
	return tn, stop
}

func waitRecordingClient(t *testing.T, tn *Tunnel) *RecordingClient {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := tn.RecordingClient()
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("no recording client: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func verifySignature(t *testing.T, key *ecdsa.PrivateKey, digest []byte, sig string) bool {
	t.Helper()
	der, err := base64.RawURLEncoding.Strict().DecodeString(sig)
	if err != nil {
		t.Fatalf("signature %q is not unpadded base64url: %v", sig, err)
	}
	return ecdsa.VerifyASN1(&key.PublicKey, digest, der)
}

func testSegment(index uint32) recording.Segment {
	obj := bytes.Repeat([]byte{byte(index)}, 18)
	return recording.Segment{Index: index, Object: obj, Hash: [32]byte{byte(index), 0xee}}
}

// Open, segment and complete reach the edge with the contract's method, path,
// headers and body, signed with the conn's key, and their 200s parse.
func TestRecordingRequestsOnTheWire(t *testing.T) {
	edge := newFakeSessionEdge(t)
	chain := bytes.Repeat([]byte{0x11}, 32)
	rec := newRecordingEdge(func(r recordingRequest) (int, string) {
		switch r.path {
		case recordingOpenPath:
			return http.StatusOK, `{"status":"open","segments":2,"chain":"` + base64.RawURLEncoding.EncodeToString(chain) + `"}`
		case recordingSegmentPath:
			return http.StatusOK, `{"status":"open","segments":8}`
		}
		return http.StatusOK, `{"status":"complete","segments":8}`
	})
	edge.recording = rec.serve
	key, presented := testDeviceKey(t)
	tn, _ := startRecordingTunnel(t, edge, presented)
	edge.expectAccept(t)
	c := waitRecordingClient(t, tn)
	ctx := context.Background()

	wrapped := []byte("wrapped dek bytes")
	keySum := bytes.Repeat([]byte{0xaa}, 32)
	res, err := c.Open(ctx, testRecordingID, testSessionID, wrapped, keySum, testCertificate, 0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if res.Status != "open" || res.Segments != 2 || !bytes.Equal(res.Chain, chain) {
		t.Fatalf("Open = %+v", res)
	}
	r := rec.expect(t)
	if r.method != http.MethodPost || r.path != recordingOpenPath || r.header.Get(recordingIDHeader) != testRecordingID {
		t.Fatalf("open request %s %s id %q", r.method, r.path, r.header.Get(recordingIDHeader))
	}
	var open map[string]string
	if err := json.Unmarshal(r.body, &open); err != nil || len(open) != 4 {
		t.Fatalf("open body %s: %v", r.body, err)
	}
	if open["wrapped_dek"] != base64.RawURLEncoding.EncodeToString(wrapped) ||
		open["certificate"] != base64.RawURLEncoding.EncodeToString(testCertificate) || open["session_id"] != testSessionID {
		t.Fatalf("wrapped_dek = %q certificate = %q session_id = %q", open["wrapped_dek"], open["certificate"], open["session_id"])
	}
	if !verifySignature(t, key, recording.OpenDigest(testRecordingID, testSessionID, wrapped, keySum), open["signature"]) {
		t.Fatal("open signature does not verify against the open digest")
	}

	seg := testSegment(7)
	res, err = c.PutSegment(ctx, testRecordingID, seg)
	if err != nil || res.Status != "open" || res.Segments != 8 || res.Chain != nil {
		t.Fatalf("PutSegment = %+v, %v", res, err)
	}
	r = rec.expect(t)
	if r.method != http.MethodPut || r.path != recordingSegmentPath || r.header.Get(recordingIDHeader) != testRecordingID ||
		r.header.Get(recordingSegmentIndexHeader) != "7" ||
		r.header.Get(recordingSegmentSHA256Header) != base64.RawURLEncoding.EncodeToString(seg.Hash[:]) ||
		!bytes.Equal(r.body, seg.Object) {
		t.Fatalf("segment request %s %s headers %v body %x", r.method, r.path, r.header, r.body)
	}

	done := recording.Completion{
		Segments: 8, FinalHash: chain, EndedAt: time.Unix(1767225600, 0),
		Incomplete: true, Final: false, Reason: recording.ReasonSpoolFull,
	}
	res, err = c.Complete(ctx, testRecordingID, wrapped, done)
	if err != nil || res.Status != "complete" || res.Segments != 8 {
		t.Fatalf("Complete = %+v, %v", res, err)
	}
	r = rec.expect(t)
	if r.method != http.MethodPost || r.path != recordingCompletePath || r.header.Get(recordingIDHeader) != testRecordingID {
		t.Fatalf("complete request %s %s", r.method, r.path)
	}
	var complete map[string]any
	if err := json.Unmarshal(r.body, &complete); err != nil || len(complete) != 7 {
		t.Fatalf("complete body %s: %v", r.body, err)
	}
	want := map[string]any{
		"segments": float64(8), "final_hash": base64.RawURLEncoding.EncodeToString(chain), "ended_at": float64(1767225600),
		"incomplete": true, "final": false, "reason": recording.ReasonSpoolFull,
	}
	for k, v := range want {
		if complete[k] != v {
			t.Fatalf("complete %s = %v, want %v", k, complete[k], v)
		}
	}
	sig, _ := complete["signature"].(string)
	if !verifySignature(t, key, recording.CompleteDigest(testRecordingID, wrapped, done), sig) {
		t.Fatal("complete signature does not verify against the complete digest")
	}
}

// A renewal while the mux is up leaves its conns signing with the key they
// presented; the next control session's mux signs with the new key.
func TestRecordingSignerFollowsTheConnCertificate(t *testing.T) {
	edge := newFakeSessionEdge(t)
	rec := newRecordingEdge(answerOK)
	edge.recording = rec.serve
	oldKey, oldPresented := testDeviceKey(t)
	newKey, newPresented := testDeviceKey(t)
	wrapped, keySum := []byte("dek"), bytes.Repeat([]byte{0xaa}, 32)
	digest := recording.OpenDigest(testRecordingID, testSessionID, wrapped, keySum)

	signedBy := func(c *RecordingClient) map[string]string {
		t.Helper()
		if _, err := c.Open(context.Background(), testRecordingID, testSessionID, wrapped, keySum, testCertificate, 0); err != nil {
			t.Fatalf("Open: %v", err)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.expect(t).body, &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	tn, stop := startRecordingTunnel(t, edge, oldPresented)
	edge.expectAccept(t)
	old := waitRecordingClient(t, tn)
	tn.mu.Lock()
	tn.presented = newPresented
	tn.mu.Unlock()
	if sig := signedBy(old)["signature"]; !verifySignature(t, oldKey, digest, sig) {
		t.Fatal("the old conn did not sign with the key it presented")
	}

	stop()
	if _, err := tn.RecordingClient(); !errors.Is(err, recording.ErrNoSessionMux) {
		t.Fatalf("RecordingClient after stop: %v, want ErrNoSessionMux", err)
	}
	if _, err := old.Open(context.Background(), testRecordingID, testSessionID, wrapped, keySum, testCertificate, 0); err == nil {
		t.Fatal("Open on a closed conn succeeded")
	}

	next := tn.startSessionMux(context.Background())
	t.Cleanup(next)
	edge.expectAccept(t)
	sig := signedBy(waitRecordingClient(t, tn))["signature"]
	if !verifySignature(t, newKey, digest, sig) {
		t.Fatal("the new conn did not sign with the new key")
	}
	if verifySignature(t, oldKey, digest, sig) {
		t.Fatal("the new conn signed with the old key")
	}
}

// Publishing a conn's recording client tells the handler once, and a dropped
// conn unpublishes it while the mux waits to redial, so no caller is handed a
// client of a dead conn.
func TestRecordingClientIsUnpublishedWhenTheConnDrops(t *testing.T) {
	edge := newFakeSessionEdge(t)
	var dials atomic.Int32
	handler := newStreamEchoHandler()
	m := newSessionMux(context.Background(), "test", handler, func(context.Context) (net.Conn, error) {
		if dials.Add(1) > 1 {
			return nil, errors.New("mux bind refused: test")
		}
		agentSide, edgeSide := net.Pipe()
		go edge.serveConn(edgeSide)
		return agentSide, nil
	})
	m.sleep = func(ctx context.Context, _ time.Duration) bool { <-ctx.Done(); return false }
	key, _ := testDeviceKey(t)
	m.signer = key
	m.start()
	t.Cleanup(m.stop)
	edge.expectAccept(t)
	deadline := time.Now().Add(3 * time.Second)
	for handler.recordingUps.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the handler was not told of the published recording client")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if m.rec.Load() == nil || handler.recordingUps.Load() != 1 {
		t.Fatalf("published %v, handler told %d times; want one published client, told once", m.rec.Load() != nil, handler.recordingUps.Load())
	}
	edge.close()
	for m.rec.Load() != nil {
		if time.Now().After(deadline) {
			t.Fatal("the recording client of a dropped conn is still published")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRecordingClientWithoutAMuxIsATypedError(t *testing.T) {
	tn := sessionDeviceTunnel(Options{SessionHandler: newStreamEchoHandler(), Capabilities: []string{"terminal"}})
	if _, err := tn.RecordingClient(); !errors.Is(err, recording.ErrNoSessionMux) {
		t.Fatalf("RecordingClient = %v, want ErrNoSessionMux", err)
	}
}

func startHeldRecordingClient(t *testing.T) (*recordingEdge, *RecordingClient, func()) {
	t.Helper()
	edge := newFakeSessionEdge(t)
	rec := newRecordingEdge(answerOK)
	rec.hold = true
	edge.recording = rec.serve
	_, presented := testDeviceKey(t)
	tn, stop := startRecordingTunnel(t, edge, presented)
	edge.expectAccept(t)
	return rec, waitRecordingClient(t, tn), stop
}

// The agent holds a third segment request, a second spool drain and a failed
// open behind a running complete until a slot frees; held requests never
// fail. An open goes past a held complete and a held failed open.
func TestRecordingRequestsWaitForAFreeSlot(t *testing.T) {
	rec, c, _ := startHeldRecordingClient(t)
	ctx := context.Background()
	results := make(chan error, 8)
	put := func(index uint32, spooled bool) {
		go func() {
			var err error
			if spooled {
				_, err = c.PutSpooledSegment(ctx, testRecordingID, func() (recording.Segment, error) { return testSegment(index), nil })
			} else {
				_, err = c.PutSegment(ctx, testRecordingID, testSegment(index))
			}
			results <- err
		}()
	}
	finish := func(r recordingRequest) {
		t.Helper()
		r.unhold()
		if err := <-results; err != nil {
			t.Fatalf("request failed: %v", err)
		}
	}

	put(0, true)
	firstDrain := rec.expect(t)
	put(1, true) // a second drain waits even with a segment slot free
	rec.expectNone(t)
	put(2, false) // a live segment takes the free slot
	live := rec.expect(t)
	put(3, false)
	rec.expectNone(t)
	finish(firstDrain)
	admitted := rec.expect(t)
	finish(live)
	last := rec.expect(t)
	finish(admitted)
	finish(last)

	go func() {
		_, err := c.Complete(ctx, testRecordingID, []byte("dek"), recording.Completion{EndedAt: time.Unix(1, 0)})
		results <- err
	}()
	complete := rec.expect(t)
	if complete.path != recordingCompletePath {
		t.Fatalf("first request %s, want the complete", complete.path)
	}
	failedOpen := func() {
		go func() {
			_, err := c.OpenFailed(ctx, recording.FailedOpen{ID: testRecordingID, SessionID: testSessionID, KeySHA256: make([]byte, 32), Reason: recording.ReasonSpoolFull})
			results <- err
		}()
	}
	failedOpen()
	rec.expectNone(t) // the failed open shares the complete's slot
	expectOpen := func() {
		t.Helper()
		go func() {
			_, err := c.Open(ctx, testRecordingID, testSessionID, []byte("dek"), make([]byte, 32), nil, 0)
			results <- err
		}()
		open := rec.expect(t)
		if open.path != recordingOpenPath {
			t.Fatalf("request %s, want the open", open.path)
		}
		finish(open)
	}
	expectOpen() // past the held complete
	finish(complete)
	failed := rec.expect(t)
	if failed.path != recordingOpenPath {
		t.Fatalf("request %s, want the failed open", failed.path)
	}
	expectOpen() // past the held failed open
	finish(failed)
}

// A cancelled request gives its slot back, in flight or still waiting, and a
// waiter returns ErrNoSessionMux when the conn goes away.
func TestRecordingSlotIsReleasedOnCancelAndConnClose(t *testing.T) {
	rec, c, stop := startHeldRecordingClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan error, 8)
	go func() {
		_, err := c.Complete(ctx, testRecordingID, []byte("dek"), recording.Completion{EndedAt: time.Unix(1, 0)})
		results <- err
	}()
	rec.expect(t)
	waitCtx, cancelWait := context.WithCancel(context.Background())
	go func() {
		_, err := c.Complete(waitCtx, testRecordingID, []byte("dek"), recording.Completion{EndedAt: time.Unix(1, 0)})
		results <- err
	}()
	rec.expectNone(t)
	cancelWait()
	if err := <-results; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting complete = %v, want context.Canceled", err)
	}
	cancel()
	if err := <-results; !errors.Is(err, context.Canceled) || !errors.Is(err, recording.ErrTransport) {
		t.Fatalf("cancelled complete = %v, want a transport failure wrapping context.Canceled", err)
	}

	go func() {
		_, err := c.Open(context.Background(), testRecordingID, testSessionID, []byte("dek"), make([]byte, 32), nil, 0)
		results <- err
	}()
	rec.expect(t).unhold()
	if err := <-results; err != nil {
		t.Fatalf("open after the cancels: %v", err)
	}

	go func() {
		_, err := c.Complete(context.Background(), testRecordingID, []byte("dek"), recording.Completion{EndedAt: time.Unix(1, 0)})
		results <- err
	}()
	rec.expect(t)
	go func() {
		_, err := c.Complete(context.Background(), testRecordingID, []byte("dek"), recording.Completion{EndedAt: time.Unix(1, 0)})
		results <- err
	}()
	rec.expectNone(t)
	stop()
	for range 2 {
		if err := <-results; !errors.Is(err, recording.ErrNoSessionMux) && !errors.Is(err, recording.ErrTransport) {
			t.Fatalf("request on a closed conn = %v", err)
		}
	}
}

// A cancelled request frees its slot at once, while its handler at the edge can
// stay parked until the stream reset arrives. The next request's unhold must
// reach that request, not the parked one.
func TestRecordingUnholdReachesOnlyItsRequest(t *testing.T) {
	rec, c, _ := startHeldRecordingClient(t)
	rec.ignoreCancel.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan error, 2)
	go func() {
		_, err := c.Complete(ctx, testRecordingID, []byte("dek"), recording.Completion{EndedAt: time.Unix(1, 0)})
		results <- err
	}()
	parked := rec.expect(t)
	t.Cleanup(parked.unhold)
	cancel()
	if err := <-results; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled complete = %v, want context.Canceled", err)
	}

	go func() {
		_, err := c.Open(context.Background(), testRecordingID, testSessionID, []byte("dek"), make([]byte, 32), nil, 0)
		results <- err
	}()
	rec.expect(t).unhold()
	select {
	case err := <-results:
		if err != nil {
			t.Fatalf("open after the cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the open never answered: its unhold reached the parked handler")
	}
}

// Every refusal code at its status is a recording.Refusal; anything else that
// is not a contract 200 is a transport failure.
func TestRecordingAnswersAreClassified(t *testing.T) {
	codes := []string{
		recording.CodeNotFound, recording.CodeBadRequest, recording.CodeProofInvalid, recording.CodeConflict,
		recording.CodeOutOfOrder, recording.CodeMismatch, recording.CodeClosed, recording.CodeLimit,
		recording.CodeQuota, recording.CodeBusy, recording.CodeStorage, recording.CodeUnavailable,
	}
	for _, code := range codes {
		status, _ := recording.Status(code)
		body := `{"code":"` + code + `"}`
		if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
			body = `{"code":"` + code + `","retry_after":42}`
		}
		_, err := parseRecordingAnswer(status, []byte(body), false)
		var refusal *recording.Refusal
		if !errors.As(err, &refusal) || refusal.Code != code || refusal.Status != status {
			t.Fatalf("%s at %d = %v, want a refusal", code, status, err)
		}
		if strings.Contains(body, "retry_after") != (refusal.RetryAfter == 42*time.Second) {
			t.Fatalf("%s retry after = %v", code, refusal.RetryAfter)
		}
	}

	for _, tc := range []struct {
		name      string
		status    int
		body      string
		wantChain bool
	}{
		{"408 read deadline", http.StatusRequestTimeout, `{"code":"recording_bad_request"}`, false},
		{"unknown code", http.StatusServiceUnavailable, `{"code":"recording_mystery","retry_after":5}`, false},
		{"code at another status", http.StatusBadRequest, `{"code":"recording_busy"}`, false},
		{"refusal not json", http.StatusBadGateway, `bad gateway`, false},
		{"negative retry", http.StatusTooManyRequests, `{"code":"recording_quota","retry_after":-1}`, false},
		{"200 not json", http.StatusOK, `ok`, false},
		{"200 without status", http.StatusOK, `{"segments":1}`, false},
		{"open without chain", http.StatusOK, `{"status":"open","segments":0}`, true},
		{"chain padded", http.StatusOK, `{"status":"open","segments":1,"chain":"` + base64.URLEncoding.EncodeToString(make([]byte, 32)) + `"}`, true},
		{"chain short", http.StatusOK, `{"status":"open","segments":1,"chain":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 31)) + `"}`, true},
		{"chain with no segments", http.StatusOK, `{"status":"open","segments":0,"chain":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`, true},
		{"no chain with segments", http.StatusOK, `{"status":"open","segments":3,"chain":""}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRecordingAnswer(tc.status, []byte(tc.body), tc.wantChain)
			var refusal *recording.Refusal
			if !errors.Is(err, recording.ErrTransport) || errors.As(err, &refusal) {
				t.Fatalf("err = %v, want a transport failure", err)
			}
		})
	}
}

// A 408 and an answer over 4 KiB on the wire are transport failures.
func TestRecordingWireTransportFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"408", http.StatusRequestTimeout, `{"code":"recording_bad_request"}`},
		{"oversized", http.StatusOK, `{"status":"open","segments":1,"pad":"` + strings.Repeat("x", recordingMaxResponse) + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edge := newFakeSessionEdge(t)
			rec := newRecordingEdge(func(recordingRequest) (int, string) { return tc.status, tc.body })
			edge.recording = rec.serve
			_, presented := testDeviceKey(t)
			tn, _ := startRecordingTunnel(t, edge, presented)
			edge.expectAccept(t)
			_, err := waitRecordingClient(t, tn).PutSegment(context.Background(), testRecordingID, testSegment(0))
			if !errors.Is(err, recording.ErrTransport) {
				t.Fatalf("PutSegment = %v, want a transport failure", err)
			}
		})
	}
}
