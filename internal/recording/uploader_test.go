package recording

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock drives the uploader's timers: Advance fires every timer due.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at      time.Time
	ch      chan time.Time
	stopped bool
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) (<-chan time.Time, func() bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{at: c.now.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		t.ch <- c.now
	} else {
		c.timers = append(c.timers, t)
	}
	return t.ch, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		t.stopped = true
		return true
	}
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.timers[:0]
	for _, t := range c.timers {
		switch {
		case t.stopped:
		case !t.at.After(c.now):
			t.ch <- c.now
		default:
			kept = append(kept, t)
		}
	}
	c.timers = kept
}

// fakeEdge is an in-memory Client: every request waits for the test's reply.
type fakeEdge struct {
	up    atomic.Bool
	calls chan *edgeCall
}

type edgeCall struct {
	op    string
	id    string
	index uint32
	hash  [32]byte
	done  Completion
	// reason is a failed open's.
	reason string
	reply  chan edgeReply
}

type edgeReply struct {
	res Result
	err error
}

func (f *fakeEdge) lookup(string) (Client, error) {
	if !f.up.Load() {
		return nil, ErrNoSessionMux
	}
	return f, nil
}

func (f *fakeEdge) do(ctx context.Context, c *edgeCall) (Result, error) {
	c.reply = make(chan edgeReply, 1)
	select {
	case f.calls <- c:
	case <-ctx.Done():
		return Result{}, fmt.Errorf("%w: %w", ErrTransport, ctx.Err())
	}
	select {
	case r := <-c.reply:
		return r.res, r.err
	case <-ctx.Done():
		return Result{}, fmt.Errorf("%w: %w", ErrTransport, ctx.Err())
	}
}

func (f *fakeEdge) Open(ctx context.Context, id, _ string, _, _, _ []byte, _ int32) (Result, error) {
	return f.do(ctx, &edgeCall{op: "open", id: id})
}

func (f *fakeEdge) OpenFailed(ctx context.Context, fo FailedOpen) (Result, error) {
	return f.do(ctx, &edgeCall{op: "failed", id: fo.ID, reason: fo.Reason})
}

func (f *fakeEdge) Complete(ctx context.Context, id string, _ []byte, done Completion) (Result, error) {
	return f.do(ctx, &edgeCall{op: "complete", id: id, done: done})
}

func (f *fakeEdge) PutSegment(ctx context.Context, id string, seg Segment) (Result, error) {
	return f.do(ctx, &edgeCall{op: "segment", id: id, index: seg.Index, hash: seg.Hash})
}

func (f *fakeEdge) PutSpooledSegment(ctx context.Context, id string, load func() (Segment, error)) (Result, error) {
	seg, err := load()
	if err != nil {
		return Result{}, err
	}
	if sha256.Sum256(seg.Object) != seg.Hash {
		return Result{}, errors.New("spooled segment hash mismatch")
	}
	return f.do(ctx, &edgeCall{op: "spooled", id: id, index: seg.Index, hash: seg.Hash})
}

func (f *fakeEdge) expect(t *testing.T, op, id string, index uint32) *edgeCall {
	t.Helper()
	select {
	case c := <-f.calls:
		if c.op != op || c.id != id || c.index != index {
			t.Fatalf("request %s %s #%d, want %s %s #%d", c.op, c.id, c.index, op, id, index)
		}
		return c
	case <-time.After(5 * time.Second):
		t.Fatalf("no %s %s #%d request", op, id, index)
		return nil
	}
}

// expectNone asserts no request arrives within a short real-time window.
func (f *fakeEdge) expectNone(t *testing.T) {
	t.Helper()
	select {
	case c := <-f.calls:
		t.Fatalf("unexpected request %s %s #%d", c.op, c.id, c.index)
	case <-time.After(100 * time.Millisecond):
	}
}

func ok(c *edgeCall, segments uint32) {
	c.reply <- edgeReply{res: Result{Status: "ok", Segments: segments}}
}

func refuse(c *edgeCall, status int, code string, retryAfter time.Duration) {
	c.reply <- edgeReply{err: &Refusal{Status: status, Code: code, RetryAfter: retryAfter}}
}

type uploaderFixture struct {
	u      *Uploader
	edge   *fakeEdge
	clock  *fakeClock
	spool  *Spool
	dir    string
	cancel context.CancelFunc
	done   chan struct{}
	logs   *syncBuffer

	jitterMu   sync.Mutex
	jitterArgs []time.Duration
}

// syncBuffer is a log sink safe for the uploader's goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var fixtureStart = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

// startUploader runs an uploader over a fresh spool with a fake clock, a fake
// edge that is up, and a jitter source returning 0 unless a test sets maxJitter.
// Each edit changes the uploader before Run starts.
func startUploader(t *testing.T, maxJitter bool, edits ...func(*Uploader)) *uploaderFixture {
	t.Helper()
	return runUploader(t, spoolDir(t), maxJitter, nil, func(string) bool { return true }, edits...)
}

// restartUploader opens the spool in dir again and resumes its entries, as an
// agent start does, with the fake clock at start.
func restartUploader(t *testing.T, dir string, start time.Time, configured func(string) bool) *uploaderFixture {
	t.Helper()
	return runUploader(t, dir, false, &start, configured)
}

func runUploader(t *testing.T, dir string, maxJitter bool, resumeAt *time.Time, configured func(string) bool, edits ...func(*Uploader)) *uploaderFixture {
	t.Helper()
	s, scan := openTestSpool(t, dir)
	f := &uploaderFixture{
		edge:  &fakeEdge{calls: make(chan *edgeCall, 16)},
		clock: &fakeClock{now: fixtureStart},
		spool: s,
		dir:   dir,
		done:  make(chan struct{}),
		logs:  &syncBuffer{},
	}
	if resumeAt != nil {
		f.clock.now = *resumeAt
	}
	f.edge.up.Store(true)
	f.u = NewUploader(UploaderConfig{
		Spool: s, Client: f.edge.lookup, Configured: configured,
		Log: slog.New(slog.NewTextHandler(f.logs, nil)),
	})
	f.u.now = f.clock.Now
	f.u.newTimer = f.clock.NewTimer
	f.u.jitter = func(n time.Duration) time.Duration {
		f.jitterMu.Lock()
		defer f.jitterMu.Unlock()
		f.jitterArgs = append(f.jitterArgs, n)
		if maxJitter && n > 0 {
			return n - 1
		}
		return 0
	}
	for _, edit := range edits {
		edit(f.u)
	}
	if resumeAt != nil {
		f.u.Resume(scan)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	go func() {
		defer close(f.done)
		f.u.Run(ctx)
	}()
	t.Cleanup(f.stop)
	return f
}

func (f *uploaderFixture) stop() {
	f.cancel()
	<-f.done
}

// begin opens recording id and answers its open.
func (f *uploaderFixture) begin(t *testing.T, id, policy string) *Handoff {
	t.Helper()
	m := testMeta(id)
	m.Policy = policy
	m.LastAcceptedAt = f.clock.Now()
	type begun struct {
		h   *Handoff
		err error
	}
	done := make(chan begun, 1)
	go func() {
		h, err := f.u.BeginOpen(context.Background(), m)
		done <- begun{h, err}
	}()
	ok(f.edge.expect(t, "open", id, 0), 0)
	b := <-done
	if b.err != nil {
		t.Fatalf("BeginOpen: %v", b.err)
	}
	return b.h
}

// resumeEmpty restarts an uploader over one crashed entry with no segment, so
// its open is the uploader's own and is retried.
func resumeEmpty(t *testing.T, maxJitter bool, edits ...func(*Uploader)) *uploaderFixture {
	t.Helper()
	dir := seedEntry(t, crashedMeta(spoolID1, 0))
	return runUploader(t, dir, maxJitter, &fixtureStart, allConfigured, edits...)
}

func (f *uploaderFixture) spooled(id string, index uint32) bool {
	_, err := f.spool.ReadSegment(id, index)
	return err == nil
}

func (f *uploaderFixture) entryGone(id string) bool {
	_, err := os.Stat(filepath.Join(f.dir, id))
	return errors.Is(err, fs.ErrNotExist)
}

// waitBackoff waits until the uploader applied a failed request of id and set
// its next attempt, so a following Advance is measured from that time.
func (f *uploaderFixture) waitBackoff(t *testing.T, id string) {
	t.Helper()
	waitFor(t, "backoff of "+id, func() bool {
		f.u.mu.Lock()
		defer f.u.mu.Unlock()
		e := f.u.entries[id]
		return e != nil && !e.busy && !e.next.IsZero()
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func testSeg(index uint32, size int) Segment {
	obj := bytes.Repeat([]byte{byte(index) + 1}, size)
	return Segment{Index: index, Object: obj, Hash: sha256.Sum256(obj)}
}

func chainOf(segs ...Segment) []byte {
	var chain []byte
	for _, s := range segs {
		chain = ChainStep(chain, s.Hash)
	}
	return chain
}

func handSegment(t *testing.T, h *Handoff, seg Segment) {
	t.Helper()
	if err := h.Segment(seg); err != nil {
		t.Fatalf("Segment(%d): %v", seg.Index, err)
	}
}

func TestUploaderDeliversOpenSegmentsCompleteInOrder(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	handSegment(t, h, testSeg(0, 64))
	handSegment(t, h, testSeg(1, 64))
	c0 := f.edge.expect(t, "segment", spoolID1, 0)
	f.edge.expectNone(t) // one segment in flight per recording
	ok(c0, 1)
	ok(f.edge.expect(t, "segment", spoolID1, 1), 2)
	last := testSeg(1, 64)
	done := Completion{Segments: 2, FinalHash: last.Hash[:], EndedAt: f.clock.Now(), Final: true}
	if err := h.End(done); err != nil {
		t.Fatalf("End: %v", err)
	}
	c := f.edge.expect(t, "complete", spoolID1, 0)
	if c.done.Segments != 2 || !c.done.Final {
		t.Fatalf("complete = %+v", c.done)
	}
	if f.spooled(spoolID1, 0) || f.spooled(spoolID1, 1) {
		t.Fatal("an acknowledged segment was written to the spool")
	}
	ok(c, 2)
	waitFor(t, "entry removed after complete", func() bool { return f.entryGone(spoolID1) })
}

func TestUploaderSpillsSegmentUnacknowledgedAfterAckTimeout(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	handSegment(t, h, testSeg(0, 64))
	c := f.edge.expect(t, "segment", spoolID1, 0)
	f.clock.Advance(AckTimeout - time.Millisecond)
	if f.spooled(spoolID1, 0) {
		t.Fatal("segment spooled before AckTimeout")
	}
	f.clock.Advance(time.Millisecond)
	waitFor(t, "segment spooled at AckTimeout", func() bool { return f.spooled(spoolID1, 0) })
	ok(c, 1)
	waitFor(t, "acknowledged segment removed from the spool", func() bool { return !f.spooled(spoolID1, 0) })
}

func TestUploaderSpoolsWithoutMuxThenDrains(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	f.edge.up.Store(false)
	handSegment(t, h, testSeg(0, 64))
	if !f.spooled(spoolID1, 0) {
		t.Fatal("segment produced without a mux was not spooled at once")
	}
	f.waitBackoff(t, spoolID1)
	f.edge.up.Store(true)
	f.clock.Advance(maxBackoff)
	ok(f.edge.expect(t, "spooled", spoolID1, 0), 1)
	waitFor(t, "drained segment removed", func() bool { return !f.spooled(spoolID1, 0) })
}

// A segment whose hash has no room in the spool is refused with
// ErrSpoolFull, even with memory free, and the refusal leaves the count as
// it was; once room frees, the next segment is taken.
func TestUploaderRefusesASegmentWithoutRoomForItsHash(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	if err := f.spool.CreateEntry(testMeta(spoolID2)); err != nil {
		t.Fatal(err)
	}
	if err := f.spool.WriteSegment(spoolID2, Segment{Index: 0, Object: make([]byte, SpoolCap-f.spool.Used())}); err != nil {
		t.Fatal(err)
	}
	used := f.spool.Used()
	if err := h.Segment(testSeg(0, 64)); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("Segment on a full spool = %v, want ErrSpoolFull", err)
	}
	if f.spool.Used() != used {
		t.Fatalf("count %d after the refusal, want %d", f.spool.Used(), used)
	}
	if err := f.spool.Remove(spoolID2); err != nil {
		t.Fatal(err)
	}
	handSegment(t, h, testSeg(0, 64))
	ok(f.edge.expect(t, "segment", spoolID1, 0), 1)
}

// A published recording client makes the device's entries that found no mux
// due at once, without waiting out their backoff; another device's
// publication does not.
func TestUploaderClientUpWakesEntriesWaitingForTheMux(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	f.edge.up.Store(false)
	handSegment(t, h, testSeg(0, 64))
	f.waitBackoff(t, spoolID1)
	f.edge.up.Store(true)
	f.u.ClientUp("another-device")
	f.edge.expectNone(t)
	f.u.ClientUp(testMeta(spoolID1).Identifier)
	ok(f.edge.expect(t, "spooled", spoolID1, 0), 1)
}

// A request of each kind the edge never answers ends at its deadline and
// backs off.
func TestUploaderRequestEndsAtItsDeadline(t *testing.T) {
	short := func(u *Uploader) { u.requestTimeout = func(int) time.Duration { return 300 * time.Millisecond } }
	t.Run("open", func(t *testing.T) {
		f := resumeEmpty(t, false, short)
		f.edge.expect(t, "open", spoolID1, 0)
		f.waitBackoff(t, spoolID1)
	})
	t.Run("segment", func(t *testing.T) {
		f := startUploader(t, false, short)
		h := f.begin(t, spoolID1, PolicyBestEffort)
		handSegment(t, h, testSeg(0, 64))
		f.edge.expect(t, "segment", spoolID1, 0)
		f.waitBackoff(t, spoolID1)
	})
	t.Run("complete", func(t *testing.T) {
		f := startUploader(t, false, short)
		h := f.begin(t, spoolID1, PolicyBestEffort)
		if err := h.End(Completion{EndedAt: fixtureStart, Final: true}); err != nil {
			t.Fatal(err)
		}
		f.edge.expect(t, "complete", spoolID1, 0)
		f.waitBackoff(t, spoolID1)
	})
	t.Run("spooled", func(t *testing.T) {
		segs := []Segment{testSeg(0, 64)}
		f := runUploader(t, seedEntry(t, crashedMeta(spoolID1, 0, segs...), segs...), false, &fixtureStart, allConfigured, short)
		answerOpen(f.edge.expect(t, "open", spoolID1, 0), 0, nil)
		f.edge.expect(t, "spooled", spoolID1, 0)
		f.waitBackoff(t, spoolID1)
	})
}

func TestUploaderRequestTimeoutCountsTheBody(t *testing.T) {
	u := NewUploader(UploaderConfig{})
	for _, c := range []struct {
		body int
		want time.Duration
	}{
		{0, 30 * time.Second},
		{64 << 10, 31 * time.Second},
		{MaxObject, 30*time.Second + time.Duration(MaxObject)*time.Second/(64<<10)},
	} {
		if got := u.requestTimeout(c.body); got != c.want {
			t.Errorf("requestTimeout(%d) = %v, want %v", c.body, got, c.want)
		}
	}
}

// A spooled segment that fails its read-back check is lost: the entry is
// completed at the server's count and the segment is never sent or retried.
func TestUploaderCutsAtASpooledSegmentThatFailsItsCheck(t *testing.T) {
	segs := []Segment{testSeg(0, 64), testSeg(1, 64)}
	for name, spooled := range map[string]Segment{
		"corrupt":   {Index: 1, Object: bytes.Repeat([]byte{0xee}, 64)},
		"oversized": {Index: 1, Object: make([]byte, MaxObject+1)},
	} {
		t.Run(name, func(t *testing.T) {
			m := crashedMeta(spoolID1, 0, segs...)
			if name == "oversized" {
				m.Hashes[1] = func() []byte { h := sha256.Sum256(spooled.Object); return h[:] }()
			}
			done := Completion{Segments: 2, FinalHash: m.Chain(), EndedAt: fixtureStart, Final: true}
			m.Complete = &done
			f := restartUploader(t, seedEntry(t, m, segs[0], spooled), fixtureStart, allConfigured)
			answerOpen(f.edge.expect(t, "open", spoolID1, 0), 1, chainOf(segs[0]))
			c := f.edge.expect(t, "complete", spoolID1, 0)
			wantCompletion(t, c, Completion{Segments: 1, FinalHash: chainOf(segs[0]), EndedAt: fixtureStart, Incomplete: true, Reason: ReasonAgentRestart})
			ok(c, 1)
			waitFor(t, "entry removed after complete", func() bool { return f.entryGone(spoolID1) })
			if !strings.Contains(f.logs.String(), "spooled segment lost") {
				t.Fatalf("no lost-segment log: %s", f.logs)
			}
		})
	}
}

// A 409 recording_out_of_order is resolved through open: delivery resumes at
// the server's count, resending the segment it lacks rather than skipping it.
func TestUploaderOutOfOrderResyncsThroughOpen(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	segs := []Segment{testSeg(0, 64), testSeg(1, 64), testSeg(2, 64)}
	for _, s := range segs {
		handSegment(t, h, s)
	}
	ok(f.edge.expect(t, "segment", spoolID1, 0), 1)
	refuse(f.edge.expect(t, "segment", spoolID1, 1), http.StatusConflict, CodeOutOfOrder, 0)
	f.waitBackoff(t, spoolID1)
	f.clock.Advance(minBackoff)
	open := f.edge.expect(t, "open", spoolID1, 0)
	open.reply <- edgeReply{res: Result{Status: "ok", Segments: 1, Chain: chainOf(segs[0])}}
	ok(f.edge.expect(t, "segment", spoolID1, 1), 2)
	ok(f.edge.expect(t, "segment", spoolID1, 2), 3)
}

func TestUploaderOpenOfANewRecordingWithSegmentsFails(t *testing.T) {
	f := startUploader(t, false)
	errc := make(chan error, 1)
	go func() {
		m := testMeta(spoolID1)
		m.LastAcceptedAt = f.clock.Now()
		_, err := f.u.BeginOpen(context.Background(), m)
		errc <- err
	}()
	open := f.edge.expect(t, "open", spoolID1, 0)
	open.reply <- edgeReply{res: Result{Status: "ok", Segments: 1, Chain: chainOf(testSeg(0, 64))}}
	if err := <-errc; err == nil {
		t.Fatal("BeginOpen accepted an open that answered segments")
	}
	if !f.entryGone(spoolID1) {
		t.Fatal("the refused open left a spool entry")
	}
}

func TestUploaderRefusalsDropTheEntry(t *testing.T) {
	cases := []struct {
		status int
		code   string
	}{
		{http.StatusNotFound, CodeNotFound},
		{http.StatusGone, CodeClosed},
		{http.StatusRequestEntityTooLarge, CodeLimit},
		{http.StatusBadRequest, CodeBadRequest},
		{http.StatusUnauthorized, CodeProofInvalid},
		{http.StatusConflict, CodeMismatch},
		{http.StatusConflict, CodeConflict},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			f := startUploader(t, false)
			h := f.begin(t, spoolID1, PolicyBestEffort)
			handSegment(t, h, testSeg(0, 64))
			refuse(f.edge.expect(t, "segment", spoolID1, 0), tc.status, tc.code, 0)
			waitFor(t, "entry dropped", func() bool { return f.entryGone(spoolID1) })
			if err := h.Segment(testSeg(1, 64)); !errors.Is(err, ErrNoEntry) {
				t.Fatalf("Segment after drop = %v, want ErrNoEntry", err)
			}
		})
	}
}

func TestUploaderQuotaWaitsRetryAfterPlusJitter(t *testing.T) {
	f := resumeEmpty(t, true)
	refuse(f.edge.expect(t, "open", spoolID1, 0), http.StatusTooManyRequests, CodeQuota, 30*time.Second)
	waitFor(t, "quota jitter drawn", func() bool {
		f.jitterMu.Lock()
		defer f.jitterMu.Unlock()
		return len(f.jitterArgs) == 1
	})
	if got := f.jitterArgs[0]; got != quotaJitter+1 {
		t.Fatalf("quota jitter range %v, want [0, %v]", got, quotaJitter)
	}
	f.clock.Advance(30*time.Second + quotaJitter - time.Nanosecond)
	f.edge.expectNone(t)
	if f.entryGone(spoolID1) {
		t.Fatal("429 dropped the spool")
	}
	f.clock.Advance(time.Nanosecond)
	f.edge.expect(t, "open", spoolID1, 0)
}

func TestUploaderBusyBacksOffWithRetryAfterFloor(t *testing.T) {
	f := resumeEmpty(t, false)
	refuse(f.edge.expect(t, "open", spoolID1, 0), http.StatusServiceUnavailable, CodeBusy, 5*time.Second)
	f.waitBackoff(t, spoolID1)
	f.clock.Advance(4 * time.Second)
	f.edge.expectNone(t)
	f.clock.Advance(time.Second)
	refuse(f.edge.expect(t, "open", spoolID1, 0), http.StatusBadGateway, CodeStorage, 0)
	f.waitBackoff(t, spoolID1)
	// Second attempt: full jitter up to 2 s, here 1 s with zero jitter.
	f.clock.Advance(time.Second)
	f.edge.expect(t, "open", spoolID1, 0)
}

func TestUploaderEntryInBackoffDoesNotBlockAnother(t *testing.T) {
	f := resumeEmpty(t, false)
	refuse(f.edge.expect(t, "open", spoolID1, 0), http.StatusServiceUnavailable, CodeBusy, time.Minute)
	f.waitBackoff(t, spoolID1)
	f.begin(t, spoolID2, PolicyBestEffort)
}

// Spool drain uses PutSpooledSegment, a live segment PutSegment, and an open
// goes out while drain is in flight.
func TestUploaderDrainLeavesSlotsForStrictOpen(t *testing.T) {
	f := startUploader(t, false)
	a := f.begin(t, spoolID1, PolicyBestEffort)
	f.edge.up.Store(false)
	handSegment(t, a, testSeg(0, 64))
	f.waitBackoff(t, spoolID1)
	f.edge.up.Store(true)
	f.clock.Advance(maxBackoff)
	drain := f.edge.expect(t, "spooled", spoolID1, 0)
	handSegment(t, a, testSeg(1, 64))

	f.begin(t, spoolID2, PolicyStrict) // answered while the drain is in flight
	ok(drain, 1)
	ok(f.edge.expect(t, "segment", spoolID1, 1), 2)
}

func TestUploaderStrictOpenFailureRemovesEntry(t *testing.T) {
	f := startUploader(t, false)
	errc := make(chan error, 1)
	go func() {
		m := testMeta(spoolID1)
		m.Policy = PolicyStrict
		m.LastAcceptedAt = f.clock.Now()
		_, err := f.u.BeginOpen(context.Background(), m)
		errc <- err
	}()
	refuse(f.edge.expect(t, "open", spoolID1, 0), http.StatusServiceUnavailable, CodeUnavailable, 5*time.Second)
	var ref *Refusal
	if err := <-errc; !errors.As(err, &ref) || ref.Code != CodeUnavailable {
		t.Fatalf("Strict Begin = %v, want the refusal", err)
	}
	if !f.entryGone(spoolID1) {
		t.Fatal("failed Strict open left a spool entry")
	}
}

func TestUploaderStopSpoolsMemorySegments(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	handSegment(t, h, testSeg(0, 64))
	f.edge.expect(t, "segment", spoolID1, 0)
	handSegment(t, h, testSeg(1, 64))
	f.stop()
	if !f.spooled(spoolID1, 0) || !f.spooled(spoolID1, 1) {
		t.Fatal("stop did not spool the in-memory segments")
	}
	handSegment(t, h, testSeg(2, 64))
	if !f.spooled(spoolID1, 2) {
		t.Fatal("segment handed over after stop was not spooled")
	}
	_, scan := openTestSpool(t, f.dir)
	if len(scan.Entries) != 1 || scan.Entries[0].Meta.Sealed != 3 || len(scan.Entries[0].Indices) != 3 {
		t.Fatalf("spool after stop = %+v", scan.Entries)
	}
}

func TestUploaderMemoryCapWithSpoolRefusalReportsStop(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	const size = MaxUnacked / 4
	for i := range uint32(4) {
		handSegment(t, h, testSeg(i, size))
	}
	f.spool.freeBytes = func(string) (uint64, error) { return MinFreeSpace - 1, nil }
	used := f.spool.Used()
	if err := h.Segment(testSeg(4, size)); !errors.Is(err, ErrDiskLow) {
		t.Fatalf("Segment past the memory cap with a refusing spool = %v, want ErrDiskLow", err)
	}
	if f.spool.Used() != used {
		t.Fatalf("count %d after the refused segment, want %d: its hash reservation was kept", f.spool.Used(), used)
	}
	f.spool.freeBytes = plentyFree
	handSegment(t, h, testSeg(4, size)) // the refused index was not consumed
	if !f.spooled(spoolID1, 4) {
		t.Fatal("segment past the memory cap was not spooled")
	}
}

// An entry dropped while its handoff's spool write is held refuses the
// segment once the write returns, and its directory is removed.
func TestUploaderSegmentOfEntryDroppedDuringItsSpoolWrite(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	const size = MaxUnacked / 4
	for i := range uint32(4) {
		handSegment(t, h, testSeg(i, size))
	}
	inFlight := f.edge.expect(t, "segment", spoolID1, 0)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	f.spool.freeBytes = func(string) (uint64, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return 1 << 40, nil
	}
	segDone := make(chan error, 1)
	go func() { segDone <- h.Segment(testSeg(4, size)) }()
	<-entered
	refuse(inFlight, http.StatusNotFound, CodeNotFound, 0)
	waitFor(t, "entry forgotten", func() bool {
		f.u.mu.Lock()
		defer f.u.mu.Unlock()
		return f.u.entries[spoolID1] == nil
	})
	close(release)
	if err := <-segDone; !errors.Is(err, ErrNoEntry) {
		t.Fatalf("Segment of a dropped entry = %v, want ErrNoEntry", err)
	}
	waitFor(t, "entry removed", func() bool { return f.entryGone(spoolID1) })
}

func allConfigured(string) bool { return true }

// crashedMeta is the meta of an entry whose sealed segments are segs, the
// first acked of them acknowledged.
func crashedMeta(id string, acked int, segs ...Segment) Meta {
	m := testMeta(id)
	m.Sealed, m.Acked = uint32(len(segs)), uint32(acked)
	m.AckedChain = chainOf(segs[:acked]...)
	for _, s := range segs[acked:] {
		m.Hashes = append(m.Hashes, bytes.Clone(s.Hash[:]))
	}
	return m
}

// seedEntry leaves the spool in a new directory as a crashed agent would: meta
// m and the segment files of spooled. It returns the directory.
func seedEntry(t *testing.T, m Meta, spooled ...Segment) string {
	t.Helper()
	dir := spoolDir(t)
	s, _ := openTestSpool(t, dir)
	if err := s.CreateEntry(testMeta(m.ID)); err != nil {
		t.Fatalf("CreateEntry: %v", err)
	}
	for _, seg := range spooled {
		if err := s.WriteSegment(m.ID, seg); err != nil {
			t.Fatalf("WriteSegment(%d): %v", seg.Index, err)
		}
	}
	if err := s.WriteMeta(m); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
	return dir
}

func answerOpen(c *edgeCall, segments uint32, chain []byte) {
	c.reply <- edgeReply{res: Result{Status: "open", Segments: segments, Chain: chain}}
}

func wantCompletion(t *testing.T, c *edgeCall, want Completion) {
	t.Helper()
	got := c.done
	if got.Segments != want.Segments || !bytes.Equal(got.FinalHash, want.FinalHash) || !got.EndedAt.Equal(want.EndedAt) ||
		got.Incomplete != want.Incomplete || got.Final != want.Final || got.Reason != want.Reason {
		t.Fatalf("complete = %+v, want %+v", got, want)
	}
}

// A crash between a segment write and its meta write leaves a file at the
// sealed count: it is adopted, delivered and counted.
func TestUploaderRestartAdoptsASegmentWrittenBeforeItsMeta(t *testing.T) {
	segs := []Segment{testSeg(0, 64), testSeg(1, 64)}
	f := restartUploader(t, seedEntry(t, crashedMeta(spoolID1, 0, segs[:1]...), segs...), fixtureStart, allConfigured)
	answerOpen(f.edge.expect(t, "open", spoolID1, 0), 0, nil)
	ok(f.edge.expect(t, "spooled", spoolID1, 0), 1)
	ok(f.edge.expect(t, "spooled", spoolID1, 1), 2)
	c := f.edge.expect(t, "complete", spoolID1, 0)
	wantCompletion(t, c, Completion{Segments: 2, FinalHash: chainOf(segs...), EndedAt: fixtureStart, Incomplete: true, Reason: ReasonAgentRestart})
}

// A file past a gap, or any file of an entry whose complete fields are
// written, is not adopted.
func TestUploaderRestartRemovesSegmentsItCannotAdopt(t *testing.T) {
	segs := []Segment{testSeg(0, 64), testSeg(1, 64), testSeg(2, 64)}
	t.Run("past a gap", func(t *testing.T) {
		f := restartUploader(t, seedEntry(t, crashedMeta(spoolID1, 0, segs[:1]...), segs[0], segs[2]), fixtureStart, allConfigured)
		waitFor(t, "segment 2 removed", func() bool { return !f.spooled(spoolID1, 2) })
		answerOpen(f.edge.expect(t, "open", spoolID1, 0), 0, nil)
		ok(f.edge.expect(t, "spooled", spoolID1, 0), 1)
		c := f.edge.expect(t, "complete", spoolID1, 0)
		if c.done.Segments != 1 {
			t.Fatalf("complete with %d segments, want 1", c.done.Segments)
		}
	})
	t.Run("completed entry", func(t *testing.T) {
		m := crashedMeta(spoolID1, 0, segs[:1]...)
		m.Complete = &Completion{Segments: 1, FinalHash: chainOf(segs[0]), EndedAt: fixtureStart, Final: true}
		f := restartUploader(t, seedEntry(t, m, segs[0], segs[1]), fixtureStart, allConfigured)
		waitFor(t, "segment 1 removed", func() bool { return !f.spooled(spoolID1, 1) })
	})
}

// The final segment is on disk, and named final in the meta, before it can be
// sent.
func TestUploaderSpoolsTheFinalSegmentBeforeSendingIt(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	seg := testSeg(0, 64)
	seg.Final = true
	handSegment(t, h, seg)
	if !f.spooled(spoolID1, 0) {
		t.Fatal("the final segment was not spooled")
	}
	f.edge.expect(t, "spooled", spoolID1, 0)
	_, scan := openTestSpool(t, f.dir)
	if len(scan.Entries) != 1 || scan.Entries[0].Meta.FinalIndex == nil || *scan.Entries[0].Meta.FinalIndex != 0 {
		t.Fatalf("persisted meta %+v does not name the final segment", scan.Entries)
	}
}

// A crash after the final segment was delivered and before End's meta write
// completes as final.
func TestUploaderRestartAfterTheFinalSegmentCompletesFinal(t *testing.T) {
	segs := []Segment{testSeg(0, 64), testSeg(1, 64)}
	final := uint32(1)
	t.Run("final segment delivered", func(t *testing.T) {
		m := crashedMeta(spoolID1, 2, segs...)
		m.FinalIndex = &final
		f := restartUploader(t, seedEntry(t, m), fixtureStart, allConfigured)
		answerOpen(f.edge.expect(t, "open", spoolID1, 0), 2, chainOf(segs...))
		c := f.edge.expect(t, "complete", spoolID1, 0)
		wantCompletion(t, c, Completion{Segments: 2, FinalHash: chainOf(segs...), EndedAt: fixtureStart, Final: true})
	})
	t.Run("final segment file written, meta not", func(t *testing.T) {
		m := crashedMeta(spoolID1, 1, segs[:1]...)
		m.FinalIndex = &final
		f := restartUploader(t, seedEntry(t, m, segs[1]), fixtureStart, allConfigured)
		answerOpen(f.edge.expect(t, "open", spoolID1, 0), 1, chainOf(segs[0]))
		ok(f.edge.expect(t, "spooled", spoolID1, 1), 2)
		c := f.edge.expect(t, "complete", spoolID1, 0)
		wantCompletion(t, c, Completion{Segments: 2, FinalHash: chainOf(segs...), EndedAt: fixtureStart, Final: true})
	})
	t.Run("final segment named, crash before its write", func(t *testing.T) {
		m := crashedMeta(spoolID1, 1, segs[:1]...)
		m.FinalIndex = &final
		f := restartUploader(t, seedEntry(t, m), fixtureStart, allConfigured)
		answerOpen(f.edge.expect(t, "open", spoolID1, 0), 1, chainOf(segs[0]))
		c := f.edge.expect(t, "complete", spoolID1, 0)
		wantCompletion(t, c, Completion{Segments: 1, FinalHash: chainOf(segs[0]), EndedAt: fixtureStart, Incomplete: true, Reason: ReasonAgentRestart})
	})
	t.Run("final segment lost", func(t *testing.T) {
		m := crashedMeta(spoolID1, 1, segs...)
		m.FinalIndex = &final
		f := restartUploader(t, seedEntry(t, m), fixtureStart, allConfigured)
		answerOpen(f.edge.expect(t, "open", spoolID1, 0), 1, chainOf(segs[0]))
		c := f.edge.expect(t, "complete", spoolID1, 0)
		wantCompletion(t, c, Completion{Segments: 1, FinalHash: chainOf(segs[0]), EndedAt: fixtureStart, Incomplete: true, Reason: ReasonAgentRestart})
	})
}

func TestUploaderRestartSendsSpooledSegmentsFromTheServerCount(t *testing.T) {
	segs := []Segment{testSeg(0, 64), testSeg(1, 64), testSeg(2, 64)}
	m := crashedMeta(spoolID1, 0, segs...)
	done := Completion{Segments: 3, FinalHash: chainOf(segs...), EndedAt: fixtureStart, Final: true}
	m.Complete = &done
	f := restartUploader(t, seedEntry(t, m, segs...), fixtureStart, allConfigured)
	answerOpen(f.edge.expect(t, "open", spoolID1, 0), 1, chainOf(segs[0]))
	ok(f.edge.expect(t, "spooled", spoolID1, 1), 2)
	ok(f.edge.expect(t, "spooled", spoolID1, 2), 3)
	c := f.edge.expect(t, "complete", spoolID1, 0)
	wantCompletion(t, c, done)
	ok(c, 3)
	waitFor(t, "entry removed after complete", func() bool { return f.entryGone(spoolID1) })
}

// A crash after the server committed segment 1 and before its
// acknowledgement: the server is one ahead of the persisted count.
func TestUploaderRestartAfterLostAcknowledgement(t *testing.T) {
	segs := []Segment{testSeg(0, 64), testSeg(1, 64)}
	done := Completion{Segments: 2, FinalHash: chainOf(segs...), EndedAt: fixtureStart, Final: true}
	seed := func(t *testing.T) string {
		m := crashedMeta(spoolID1, 1, segs...)
		m.Complete = &done
		return seedEntry(t, m, segs[1])
	}
	t.Run("matching chain completes", func(t *testing.T) {
		f := restartUploader(t, seed(t), fixtureStart, allConfigured)
		answerOpen(f.edge.expect(t, "open", spoolID1, 0), 2, chainOf(segs...))
		c := f.edge.expect(t, "complete", spoolID1, 0)
		wantCompletion(t, c, done)
		ok(c, 2)
		waitFor(t, "entry removed after complete", func() bool { return f.entryGone(spoolID1) })
	})
	t.Run("mismatched chain drops", func(t *testing.T) {
		f := restartUploader(t, seed(t), fixtureStart, allConfigured)
		answerOpen(f.edge.expect(t, "open", spoolID1, 0), 2, chainOf(segs[0], testSeg(9, 64)))
		waitFor(t, "entry dropped", func() bool { return f.entryGone(spoolID1) })
		f.edge.expectNone(t)
		if !strings.Contains(f.logs.String(), "code="+CodeMismatch) {
			t.Fatalf("drop log lacks the %s code: %s", CodeMismatch, f.logs)
		}
	})
}

// Segment 1 was only in memory at the crash: the recording completes at the
// server's count and the spooled segment 2 goes with the entry.
func TestUploaderRestartWithLostSegmentsCompletesAtTheServerCount(t *testing.T) {
	segs := []Segment{testSeg(0, 64), testSeg(1, 64), testSeg(2, 64)}
	f := restartUploader(t, seedEntry(t, crashedMeta(spoolID1, 0, segs...), segs[2]), fixtureStart, allConfigured)
	answerOpen(f.edge.expect(t, "open", spoolID1, 0), 1, chainOf(segs[0]))
	c := f.edge.expect(t, "complete", spoolID1, 0)
	wantCompletion(t, c, Completion{Segments: 1, FinalHash: chainOf(segs[0]), EndedAt: fixtureStart, Incomplete: true, Reason: ReasonAgentRestart})
	ok(c, 1)
	waitFor(t, "entry removed after complete", func() bool { return f.entryGone(spoolID1) })
}

func TestUploaderRestartWithoutCompleteEndsAgentRestart(t *testing.T) {
	seg := testSeg(0, 64)
	f := restartUploader(t, seedEntry(t, crashedMeta(spoolID1, 0, seg), seg), fixtureStart, allConfigured)
	answerOpen(f.edge.expect(t, "open", spoolID1, 0), 0, nil)
	ok(f.edge.expect(t, "spooled", spoolID1, 0), 1)
	c := f.edge.expect(t, "complete", spoolID1, 0)
	wantCompletion(t, c, Completion{Segments: 1, FinalHash: chainOf(seg), EndedAt: fixtureStart, Incomplete: true, Reason: ReasonAgentRestart})
	ok(c, 1)
	waitFor(t, "entry removed after complete", func() bool { return f.entryGone(spoolID1) })
}

// Segments delivered from memory leave no hashes in the persisted meta: the
// recording completes from the server's count and chain.
func TestUploaderRestartCompletesFromTheServerPastThePersistedCount(t *testing.T) {
	f := restartUploader(t, seedEntry(t, testMeta(spoolID1)), fixtureStart, allConfigured)
	server := chainOf(testSeg(0, 64), testSeg(1, 64))
	answerOpen(f.edge.expect(t, "open", spoolID1, 0), 2, server)
	c := f.edge.expect(t, "complete", spoolID1, 0)
	wantCompletion(t, c, Completion{Segments: 2, FinalHash: server, EndedAt: fixtureStart, Incomplete: true, Reason: ReasonAgentRestart})
}

func TestUploaderRestartGoneOnFirstOpenDrops(t *testing.T) {
	f := restartUploader(t, seedEntry(t, testMeta(spoolID1)), fixtureStart, allConfigured)
	refuse(f.edge.expect(t, "open", spoolID1, 0), http.StatusGone, CodeClosed, 0)
	waitFor(t, "entry dropped", func() bool { return f.entryGone(spoolID1) })
	f.edge.expectNone(t)
}

// last_accepted_at is persisted only at meta writes, so a resumed entry's
// local deadline runs from the uploader's start when that is later.
func TestUploaderRestartDeadlineRunsFromUploaderStart(t *testing.T) {
	m := testMeta(spoolID1)
	m.LastAcceptedAt = fixtureStart.Add(-30 * time.Hour)
	f := restartUploader(t, seedEntry(t, m), fixtureStart, allConfigured)
	refuse(f.edge.expect(t, "open", spoolID1, 0), http.StatusServiceUnavailable, CodeBusy, 0)
	f.waitBackoff(t, spoolID1)
	f.clock.Advance(LocalDeadline + time.Second)
	waitFor(t, "entry dropped at the deadline", func() bool { return f.entryGone(spoolID1) })
	f.edge.expectNone(t)
}

func TestUploaderRestartDropsEntryOfUnconfiguredDevice(t *testing.T) {
	f := restartUploader(t, seedEntry(t, testMeta(spoolID1)), fixtureStart, func(string) bool { return false })
	waitFor(t, "entry dropped", func() bool { return f.entryGone(spoolID1) })
	f.edge.expectNone(t)
}

// A segment whose 200 was lost is sent again with the same index and hash;
// the server answers a stored segment with 200.
func TestUploaderRetriesLastIndexAfterLostResponse(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	seg := testSeg(0, 64)
	handSegment(t, h, seg)
	f.edge.expect(t, "segment", spoolID1, 0).reply <- edgeReply{err: fmt.Errorf("%w: response lost", ErrTransport)}
	f.waitBackoff(t, spoolID1)
	f.clock.Advance(minBackoff)
	again := f.edge.expect(t, "segment", spoolID1, 0)
	if again.hash != seg.Hash {
		t.Fatal("the retry carried another hash")
	}
	ok(again, 1)
	if err := h.End(Completion{Segments: 1, FinalHash: chainOf(seg), EndedAt: fixtureStart, Final: true}); err != nil {
		t.Fatalf("End: %v", err)
	}
	ok(f.edge.expect(t, "complete", spoolID1, 0), 1)
	waitFor(t, "entry removed after complete", func() bool { return f.entryGone(spoolID1) })
}

// A spool write of one recording, held in the free-space check, does not
// delay another recording's handoff or its delivery.
func TestUploaderHandoffDoesNotWaitOnAnotherEntrysSpoolWrite(t *testing.T) {
	f := startUploader(t, false)
	ha := f.begin(t, spoolID1, PolicyBestEffort)
	hb := f.begin(t, spoolID2, PolicyBestEffort)
	const size = MaxUnacked / 4
	for i := range uint32(4) {
		handSegment(t, ha, testSeg(i, size))
	}
	f.edge.expect(t, "segment", spoolID1, 0) // held: the memory of spoolID1 stays full

	entered, release := make(chan struct{}, 1), make(chan struct{})
	f.spool.freeBytes = func(string) (uint64, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return 1 << 40, nil
	}
	aDone := make(chan error, 1)
	go func() { aDone <- ha.Segment(testSeg(4, size)) }()
	<-entered
	bDone := make(chan error, 1)
	go func() { bDone <- hb.Segment(testSeg(0, 64)) }()
	select {
	case err := <-bDone:
		if err != nil {
			close(release)
			t.Fatalf("Segment of the other recording: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("a handoff waited on another recording's spool write")
	}
	f.edge.expect(t, "segment", spoolID2, 0)
	close(release)
	if err := <-aDone; err != nil {
		t.Fatalf("Segment past the memory cap: %v", err)
	}
	if !f.spooled(spoolID1, 4) {
		t.Fatal("segment past the memory cap was not spooled")
	}
}
