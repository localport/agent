package tunnel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

const (
	testClipSession = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	testClipDevice  = "tun12345.gw-01"
)

// clipboardEdge serves /v1/clipboard on a fakeSessionEdge: each batch is
// reported on batches, then answered with the next status of answers (204
// once they run out).
type clipboardEdge struct {
	batches chan []clipboardWire
	answers chan int
}

func newClipboardEdge() *clipboardEdge {
	return &clipboardEdge{batches: make(chan []clipboardWire, 16), answers: make(chan int, 16)}
}

func (c *clipboardEdge) serve(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	var body clipboardBatchBody
	if err := json.Unmarshal(raw, &body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	c.batches <- body.Notices
	status := http.StatusNoContent
	select {
	case status = <-c.answers:
	default:
	}
	w.WriteHeader(status)
}

func (c *clipboardEdge) expect(t *testing.T) []clipboardWire {
	t.Helper()
	select {
	case b := <-c.batches:
		return b
	case <-time.After(3 * time.Second):
		t.Fatal("no clipboard batch reached the edge")
		return nil
	}
}

func (c *clipboardEdge) expectNone(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case b := <-c.batches:
		t.Fatalf("a batch of %d notices reached the edge, want none", len(b))
	case <-time.After(within):
	}
}

// startClipboardTunnel runs a device tunnel's session mux against a fake edge
// serving clipboard batches, and notices whose sender reaches it.
func startClipboardTunnel(t *testing.T, flushEvery time.Duration) (*clipboardEdge, *ClipboardNotices, *Tunnel, func()) {
	t.Helper()
	edge := newFakeSessionEdge(t)
	clip := newClipboardEdge()
	edge.clipboard = clip.serve
	notices := NewClipboardNotices(nil)
	notices.flushEvery = flushEvery
	tn := sessionDeviceTunnel(Options{
		SessionHandler: newStreamEchoHandler(), Capabilities: []string{"desktop"}, ClipboardNotices: notices,
		Identity: testClipDevice,
	})
	notices.client = func(identifier string) (*ClipboardClient, error) {
		if identifier != testClipDevice {
			t.Errorf("sender asked for device %q, want %q", identifier, testClipDevice)
		}
		return tn.ClipboardClient()
	}
	tn.mu.Lock()
	tn.sessionID, tn.edgeAddr = "s1", "connect.eu.localport.dev:443"
	tn.dialer = &bindingDialer{edge: edge, purposes: make(chan string, 16)}
	tn.mu.Unlock()
	stop := tn.startSessionMux(context.Background())
	t.Cleanup(stop)
	edge.expectAccept(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		notices.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitClipboardClient(t, tn)
	return clip, notices, tn, stop
}

func waitClipboardClient(t *testing.T, tn *Tunnel) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := tn.ClipboardClient(); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no clipboard client")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func testClipNotice(n int64) ClipboardNotice {
	return ClipboardNotice{
		SessionID: testClipSession, Kind: "rdp", Direction: "copy", Outcome: "allowed", Bytes: n,
		At: time.UnixMilli(1_790_000_000_000 + n),
	}
}

// Ids increase in mint order within one millisecond, past the 12-bit
// sequence, and when the clock steps back; every id is a version 7 UUID.
func TestClipboardIDsIncreaseInMintOrder(t *testing.T) {
	var g clipboardIDs
	at := time.UnixMilli(1_790_000_000_000)
	prev := ""
	for i := range 5000 {
		now := at
		if i == 4500 {
			at = at.Add(-time.Hour)
			now = at
		}
		id := g.next(now)
		if len(id) != 36 || id[14] != '7' || (id[19] != '8' && id[19] != '9' && id[19] != 'a' && id[19] != 'b') {
			t.Fatalf("id %d = %s, not a version 7 RFC 9562 UUID", i, id)
		}
		if id <= prev {
			t.Fatalf("id %d = %s is not after %s", i, id, prev)
		}
		prev = id
	}
}

// Notices go out in batches of at most 64, in queue order, with every field.
func TestClipboardNoticesSendInBatches(t *testing.T) {
	clip, notices, _, _ := startClipboardTunnel(t, 20*time.Millisecond)
	for i := range int64(70) {
		notices.Note(testClipDevice, testClipNotice(i))
	}
	first, second := clip.expect(t), clip.expect(t)
	if len(first) != clipboardMaxBatch || len(second) != 6 {
		t.Fatalf("batches of %d and %d notices, want 64 and 6", len(first), len(second))
	}
	all := append(first, second...)
	for i, n := range all {
		want := testClipNotice(int64(i))
		if n.SessionID != want.SessionID || n.Kind != "rdp" || n.Direction != "copy" || n.Outcome != "allowed" ||
			n.Bytes != int64(i) || n.Time != want.At.UnixMilli() || n.Dropped != 0 {
			t.Fatalf("notice %d = %+v, want %+v", i, n, want)
		}
		if i > 0 && n.ID <= all[i-1].ID {
			t.Fatalf("notice %d id %s is not after %s", i, n.ID, all[i-1].ID)
		}
	}
}

// A batch the edge did not take is sent again, unchanged, before the notices
// queued after it.
func TestClipboardNoticesResendAFailedBatchFirst(t *testing.T) {
	clip, notices, _, _ := startClipboardTunnel(t, 20*time.Millisecond)
	clip.answers <- http.StatusServiceUnavailable
	notices.Note(testClipDevice, testClipNotice(1))
	failed := clip.expect(t)
	notices.Note(testClipDevice, testClipNotice(2))
	again := clip.expect(t)
	if len(failed) != 1 || len(again) != 1 || again[0] != failed[0] {
		t.Fatalf("resent %+v after %+v, want the failed batch unchanged", again, failed)
	}
	if next := clip.expect(t); len(next) != 1 || next[0].Bytes != 2 || next[0].ID <= failed[0].ID {
		t.Fatalf("next batch %+v, want the later notice after the resent one", next)
	}
}

// A batch the edge rejects as malformed is dropped, never resent.
func TestClipboardNoticesDropARejectedBatch(t *testing.T) {
	clip, notices, _, _ := startClipboardTunnel(t, 20*time.Millisecond)
	clip.answers <- http.StatusBadRequest
	notices.Note(testClipDevice, testClipNotice(1))
	clip.expect(t)
	clip.expectNone(t, 150*time.Millisecond)
	notices.Note(testClipDevice, testClipNotice(2))
	if next := clip.expect(t); len(next) != 1 || next[0].Bytes != 2 {
		t.Fatalf("next batch %+v, want the later notice only", next)
	}
}

// A full queue counts the decisions it refuses per session and reports each
// count once, after the last queued notice, with a newer id.
func TestClipboardQueueOverflowReportsTheDroppedCount(t *testing.T) {
	notices := NewClipboardNotices(nil)
	for i := range int64(clipboardQueueLen + 5) {
		notices.Note(testClipDevice, testClipNotice(i))
	}
	other := testClipNotice(0)
	other.SessionID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c"
	for range 3 {
		notices.Note(testClipDevice, other)
	}
	d := notices.devices[testClipDevice]
	var sent []clipboardWire
	for {
		body := notices.takeBatch(d)
		if body == nil {
			break
		}
		var b clipboardBatchBody
		if err := json.Unmarshal(body, &b); err != nil {
			t.Fatal(err)
		}
		sent = append(sent, b.Notices...)
	}
	if len(sent) != clipboardQueueLen+2 {
		t.Fatalf("sent %d notices, want %d queued and 2 counts", len(sent), clipboardQueueLen)
	}
	counts := map[string]int64{}
	for i, n := range sent {
		if i > 0 && n.ID <= sent[i-1].ID {
			t.Fatalf("notice %d id %s is not after %s", i, n.ID, sent[i-1].ID)
		}
		if i < clipboardQueueLen {
			if n.Dropped != 0 {
				t.Fatalf("notice %d is a count before the queue drained", i)
			}
			continue
		}
		if n.Direction != "" || n.Outcome != "" || n.Bytes != 0 || n.Kind != "rdp" {
			t.Fatalf("count %+v carries a decision", n)
		}
		counts[n.SessionID] = n.Dropped
	}
	if counts[testClipSession] != 5 || counts[other.SessionID] != 3 {
		t.Fatalf("dropped counts %v, want 5 and 3", counts)
	}
}

// A session mux that stops sends the queued notices before its conn closes,
// without waiting for the batch timer.
func TestSessionMuxFlushesClipboardNoticesBeforeItsConnCloses(t *testing.T) {
	clip, notices, _, stop := startClipboardTunnel(t, time.Hour)
	notices.Note(testClipDevice, testClipNotice(1))
	clip.expectNone(t, 100*time.Millisecond)
	stop()
	select {
	case b := <-clip.batches:
		if len(b) != 1 || b[0].Bytes != 1 {
			t.Fatalf("flushed %+v, want the queued notice", b)
		}
	default:
		t.Fatal("the mux stopped without flushing the queued notice")
	}
}

// The mux's connection window covers its 22 streams, the clipboard batch's
// included.
func TestSessionMuxWindowCoversTheClipboardStream(t *testing.T) {
	if sessionMuxConnWindow != (1+maxSessionOpens+recordingSegmentSlots+recordingOpenSlots+recordingBackgroundSlots+clipboardSlots)*sessionMuxStreamWindow {
		t.Fatalf("connection window %d does not cover every stream", sessionMuxConnWindow)
	}
}
