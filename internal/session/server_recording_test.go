package session

import (
	"context"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/localport/agent/internal/recording"
)

// recordingEdge is a recording.Client that logs every call in order and
// answers each with an empty 200 result.
type recordingEdge struct {
	mu         sync.Mutex
	calls      []string
	segs       []recording.Segment
	wrappedDEK []byte
	done       *recording.Completion
	completed  chan struct{}
}

func (e *recordingEdge) Open(_ context.Context, _ string, wrappedDEK, _ []byte) (recording.Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, "open")
	e.wrappedDEK = wrappedDEK
	return recording.Result{}, nil
}

func (e *recordingEdge) Complete(_ context.Context, _ string, _ []byte, done recording.Completion) (recording.Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, "complete")
	if e.done == nil {
		e.done = &done
		close(e.completed)
	}
	return recording.Result{}, nil
}

func (e *recordingEdge) PutSegment(_ context.Context, _ string, seg recording.Segment) (recording.Result, error) {
	return e.segment(seg)
}

func (e *recordingEdge) PutSpooledSegment(_ context.Context, _ string, seg recording.Segment) (recording.Result, error) {
	return e.segment(seg)
}

func (e *recordingEdge) segment(seg recording.Segment) (recording.Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, fmt.Sprintf("segment %d", seg.Index))
	e.segs = append(e.segs, seg)
	return recording.Result{}, nil
}

// completedRecording waits for the complete call, requires the calls in
// order (open, each segment once from index 0, complete with Final and the
// segment count) and returns the segments and the wrapped key.
func (e *recordingEdge) completedRecording(t *testing.T) ([]recording.Segment, []byte) {
	t.Helper()
	select {
	case <-e.completed:
	case <-time.After(10 * time.Second):
		t.Fatal("the recording was not completed")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	want := []string{"open"}
	for i := range e.segs {
		want = append(want, fmt.Sprintf("segment %d", i))
	}
	want = append(want, "complete")
	if len(e.segs) == 0 || strings.Join(e.calls, ", ") != strings.Join(want, ", ") {
		t.Fatalf("calls %q, want open, at least one segment in order, complete", e.calls)
	}
	if !e.done.Final || e.done.Incomplete || e.done.Segments != uint32(len(e.segs)) {
		t.Fatalf("complete %+v, want final with %d segments", *e.done, len(e.segs))
	}
	return e.segs, e.wrappedDEK
}

// recordedSessions is a server set up to record tickets with rec.
type recordedSessions struct {
	edge *recordingEdge
	priv hpke.PrivateKey
	// spool is the uploader's spool directory.
	spool     string
	keySHA256 string
	policy    string
}

// recordSessions gives ts a recording key and an uploader over a spool in a
// temporary directory whose client is a recordingEdge. With run the uploader
// delivers until the test ends; without it every segment stays in memory.
func recordSessions(t *testing.T, ts *testServer, policy string, run bool) *recordedSessions {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "recordings")
	spool, _, err := recording.OpenSpool(root, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	edge := &recordingEdge{completed: make(chan struct{})}
	up := recording.NewUploader(recording.UploaderConfig{
		Spool:      spool,
		Client:     func(string) (recording.Client, error) { return edge, nil },
		Configured: func(string) bool { return true },
	})
	if run {
		ctx, cancel := context.WithCancel(context.Background())
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			up.Run(ctx)
		}()
		t.Cleanup(func() {
			cancel()
			<-stopped
		})
	}
	priv, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	sum := sha256.Sum256(pub)
	ts.cfg.RecordingKey = func() ([]byte, [sha256.Size]byte, bool) { return pub, sum, true }
	ts.cfg.Uploader = up
	ts.cfg.Identifier = "client.device"
	return &recordedSessions{edge: edge, priv: priv, spool: dir, keySHA256: base64.RawURLEncoding.EncodeToString(sum[:]), policy: policy}
}

// ticket gives a ticket the rec of this server's key and policy, with the
// recording ID decryptRecording expects.
func (rs *recordedSessions) ticket(p *Ticket) {
	p.JTI = recJTI
	p.Rec = &TicketRec{ID: testRecordingID, PubSHA256: rs.keySHA256, Policy: rs.policy}
}

// A Best effort session is recorded end to end: the uploader opens the
// recording, delivers every segment in order and completes it final, and the
// segments decrypt to the session's output.
func TestServeRecordsABestEffortSession(t *testing.T) {
	ts := newTestKindServer(t, nil)
	rs := recordSessions(t, ts.testServer, RecPolicyBestEffort, true)
	c := ts.open(t, ts.ticket(t, rs.ticket))
	k := ts.kind(t)
	c.echo(t, "recorded-output")
	k.selfEnd <- CloseExited
	c.expectClose(t, CloseExited)
	waitDone(t, c.done)
	segs, wrapped := rs.edge.completedRecording(t)
	if text := decryptRecording(t, rs.priv, wrapped, segs); !strings.Contains(text, `"o", "recorded-output"`) && !strings.Contains(text, `"o","recorded-output"`) {
		t.Fatalf("recording %q lacks the output event", text)
	}
}

// A Strict session whose recording memory is full while the spool refuses
// the next segment closes recording_failed. The uploader does not run, so no
// segment leaves memory, and the spool directory is removed under it.
func TestServeClosesAStrictSessionWhoseRecordingFails(t *testing.T) {
	ts := newTestKindServer(t, nil)
	rs := recordSessions(t, ts.testServer, RecPolicyStrict, false)
	c := ts.open(t, ts.ticket(t, rs.ticket))
	ts.kind(t)
	if err := os.RemoveAll(rs.spool); err != nil {
		t.Fatal(err)
	}
	// Random data keeps the sealed segments near their plaintext size.
	raw := make([]byte, 24<<10)
	for sent := 0; ; sent++ {
		if sent == 256 {
			t.Fatalf("no close after %d records", sent)
		}
		_, _ = rand.Read(raw)
		chunk := base64.StdEncoding.EncodeToString(raw)
		if err := c.ch.WriteMessage(TypeData, []byte(chunk)); err != nil {
			t.Fatal(err)
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		m, err := c.ch.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if m.Type == TypeData {
			continue
		}
		if m.Type != TypeClose || m.Reason != CloseRecordingFailed {
			t.Fatalf("got %v %q; want close %q", m.Type, m.Reason, CloseRecordingFailed)
		}
		break
	}
	waitDone(t, c.done)
	rs.edge.mu.Lock()
	defer rs.edge.mu.Unlock()
	if strings.Join(rs.edge.calls, ", ") != "open" {
		t.Fatalf("calls %q, want the Strict open only", rs.edge.calls)
	}
}
