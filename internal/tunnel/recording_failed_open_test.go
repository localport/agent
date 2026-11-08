package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/localport/agent/internal/recording"
)

// A failed open carries its reason and the channel count in headers, has no
// wrapped DEK, and is signed over the failure.
func TestRecordingOpenFailedCarriesItsSignedReasonAndCount(t *testing.T) {
	edge := newFakeSessionEdge(t)
	rec := newRecordingEdge(answerOK)
	edge.recording = rec.serve
	key, presented := testDeviceKey(t)
	tn, _ := startRecordingTunnel(t, edge, presented)
	edge.expectAccept(t)
	c := waitRecordingClient(t, tn)

	keySum := bytes.Repeat([]byte{0xaa}, 32)
	f := recording.FailedOpen{ID: testRecordingID, SessionID: testSessionID, KeySHA256: keySum, Certificate: testCertificate, Reason: recording.ReasonDiskLow, Channels: 3}
	if _, err := c.OpenFailed(context.Background(), f); err != nil {
		t.Fatalf("OpenFailed: %v", err)
	}
	r := rec.expect(t)
	if r.path != recordingOpenPath || r.header.Get(recordingFailedHeader) != recording.ReasonDiskLow ||
		r.header.Get(recordingSessionHeader) != testSessionID || r.header.Get(sessionChannelsHeader) != "3" {
		t.Fatalf("failed open %s headers %v", r.path, r.header)
	}
	var body map[string]string
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatalf("body %s: %v", r.body, err)
	}
	if body["wrapped_dek"] != "" || body["session_id"] != testSessionID {
		t.Fatalf("body %v", body)
	}
	if !verifySignature(t, key, recording.OpenFailedDigest(testRecordingID, testSessionID, keySum, recording.ReasonDiskLow), body["signature"]) {
		t.Fatal("the failed open is not signed over its reason")
	}
}

// A live open carries the count; an open without one, as after a restart,
// carries neither header.
func TestRecordingOpenCarriesTheChannelCountOnlyWhenItHasOne(t *testing.T) {
	edge := newFakeSessionEdge(t)
	rec := newRecordingEdge(answerOK)
	edge.recording = rec.serve
	_, presented := testDeviceKey(t)
	tn, _ := startRecordingTunnel(t, edge, presented)
	edge.expectAccept(t)
	c := waitRecordingClient(t, tn)
	ctx := context.Background()

	if _, err := c.Open(ctx, testRecordingID, testSessionID, []byte("dek"), make([]byte, 32), nil, 2); err != nil {
		t.Fatalf("Open: %v", err)
	}
	r := rec.expect(t)
	if r.header.Get(recordingSessionHeader) != testSessionID || r.header.Get(sessionChannelsHeader) != "2" || r.header.Get(recordingFailedHeader) != "" {
		t.Fatalf("live open headers %v", r.header)
	}
	if _, err := c.Open(ctx, testRecordingID, testSessionID, []byte("dek"), make([]byte, 32), nil, 0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	r = rec.expect(t)
	if r.header.Get(recordingSessionHeader) != "" || r.header.Get(sessionChannelsHeader) != "" {
		t.Fatalf("resumed open headers %v", r.header)
	}
}

// Spooled segments waiting for the drain place have not been read: the
// waiters hold no segment in memory.
func TestSpooledSegmentIsReadOnlyInsideTheDrainSlot(t *testing.T) {
	rec, c, _ := startHeldRecordingClient(t)
	const waiters = 8
	var loads atomic.Int32
	results := make(chan error, waiters)
	for i := range uint32(waiters) {
		go func() {
			_, err := c.PutSpooledSegment(context.Background(), testRecordingID, func() (recording.Segment, error) {
				loads.Add(1)
				return testSegment(i), nil
			})
			results <- err
		}()
	}
	for done := 1; done <= waiters; done++ {
		r := rec.expect(t)
		rec.expectNone(t)
		if got := int(loads.Load()); got != done {
			t.Fatalf("%d segments read with %d admitted to the drain", got, done)
		}
		r.unhold()
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("spooled segment: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("spooled segment did not finish")
		}
	}
}
