package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/localport/agent/internal/recording"
)

// runRecordingUploader runs an uploader over spool that reaches the edge
// through tn's session mux, and returns its stop function.
func runRecordingUploader(t *testing.T, tn *Tunnel, spool *recording.Spool, scan *recording.Scan) (*recording.Uploader, func()) {
	t.Helper()
	up := recording.NewUploader(recording.UploaderConfig{
		Spool: spool,
		Client: func(string) (recording.Client, error) {
			c, err := tn.RecordingClient()
			if err != nil {
				return nil, err
			}
			return c, nil
		},
		Configured: func(string) bool { return true },
	})
	if scan != nil {
		up.Resume(*scan)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		up.Run(ctx)
	}()
	stop := func() {
		cancel()
		<-done
	}
	t.Cleanup(stop)
	return up, stop
}

func signatureOf(t *testing.T, r recordingRequest) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatalf("%s body %s: %v", r.path, r.body, err)
	}
	sig, _ := body["signature"].(string)
	return sig
}

// A recording opened under one certificate and spooled while the mux is down
// is resumed by the next agent start after a renewal: open, the spooled
// segment and complete travel the real recording client and session mux,
// open and complete signed with the new certificate's key.
func TestRecordingUploaderResumesAfterRenewal(t *testing.T) {
	edge := newFakeSessionEdge(t)
	rec := newRecordingEdge(func(r recordingRequest) (int, string) {
		switch r.path {
		case recordingOpenPath:
			return http.StatusOK, `{"status":"open","segments":0,"chain":""}`
		case recordingSegmentPath:
			return http.StatusOK, `{"status":"open","segments":1}`
		}
		return http.StatusOK, `{"status":"complete","segments":1}`
	})
	edge.recording = rec.serve
	oldKey, oldPresented := testDeviceKey(t)
	newKey, newPresented := testDeviceKey(t)
	tn, stopMux := startRecordingTunnel(t, edge, oldPresented)
	edge.expectAccept(t)
	waitRecordingClient(t, tn)

	root := t.TempDir()
	dir := filepath.Join(root, "recordings")
	spool, _, err := recording.OpenSpool(root, dir, true)
	if err != nil {
		t.Fatalf("OpenSpool: %v", err)
	}
	up, stopUploader := runRecordingUploader(t, tn, spool, nil)
	wrapped, keySum := []byte("wrapped dek"), bytes.Repeat([]byte{0xaa}, 32)
	h, err := up.BeginOpen(context.Background(), recording.Meta{
		ID: testRecordingID, SessionID: testSessionID, Identifier: "device-1",
		LastAcceptedAt: time.Now(), WrappedDEK: wrapped, KeySHA256: keySum, Policy: recording.PolicyBestEffort,
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	openDigest := recording.OpenDigest(testRecordingID, testSessionID, wrapped, keySum)
	if !verifySignature(t, oldKey, openDigest, signatureOf(t, rec.expect(t))) {
		t.Fatal("the first open was not signed with the presented key")
	}

	stopMux()
	if _, err := tn.RecordingClient(); !errors.Is(err, recording.ErrNoSessionMux) {
		t.Fatalf("RecordingClient after stop: %v, want ErrNoSessionMux", err)
	}
	seg := testSegment(0)
	seg.Hash = sha256.Sum256(seg.Object)
	if err := h.Segment(seg); err != nil {
		t.Fatalf("Segment: %v", err)
	}
	done := recording.Completion{Segments: 1, FinalHash: recording.ChainStep(nil, seg.Hash), EndedAt: time.Unix(1767225600, 0), Final: true}
	if err := h.End(done); err != nil {
		t.Fatalf("End: %v", err)
	}
	stopUploader()

	tn.mu.Lock()
	tn.presented = newPresented
	tn.mu.Unlock()
	next := tn.startSessionMux(context.Background())
	t.Cleanup(next)
	edge.expectAccept(t)
	waitRecordingClient(t, tn)

	spool, scan, err := recording.OpenSpool(root, dir, true)
	if err != nil {
		t.Fatalf("OpenSpool after restart: %v", err)
	}
	if len(scan.Entries) != 1 || len(scan.Entries[0].Indices) != 1 {
		t.Fatalf("spool at restart = %+v", scan.Entries)
	}
	runRecordingUploader(t, tn, spool, &scan)

	open := rec.expect(t)
	if open.path != recordingOpenPath || !verifySignature(t, newKey, openDigest, signatureOf(t, open)) {
		t.Fatalf("resumed open %s not signed with the new key", open.path)
	}
	put := rec.expect(t)
	if put.path != recordingSegmentPath || put.header.Get(recordingSegmentIndexHeader) != "0" || !bytes.Equal(put.body, seg.Object) {
		t.Fatalf("resumed segment request %s index %q", put.path, put.header.Get(recordingSegmentIndexHeader))
	}
	complete := rec.expect(t)
	sig := signatureOf(t, complete)
	if complete.path != recordingCompletePath || !verifySignature(t, newKey, recording.CompleteDigest(testRecordingID, wrapped, done), sig) {
		t.Fatalf("resumed complete %s not signed with the new key over the spooled fields", complete.path)
	}
	if verifySignature(t, oldKey, recording.CompleteDigest(testRecordingID, wrapped, done), sig) {
		t.Fatal("the resumed complete was signed with the old key")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, testRecordingID)); errors.Is(err, fs.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("spool entry not removed after complete")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
