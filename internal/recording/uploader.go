package recording

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net/http"
	"slices"
	"sync"
	"time"
)

// Uploader bounds and timings.
const (
	// AckTimeout is how long a sealed segment stays only in memory before it
	// is written to the spool while unacknowledged.
	AckTimeout = 5 * time.Second
	// MaxUnacked bounds the unacknowledged sealed segments one recording
	// holds in memory; past it a segment goes to the spool at once.
	MaxUnacked = 1 << 20
	// LocalDeadline drops an entry whose last_accepted_at, or the uploader
	// start when later, is older, mirroring the server's upload window.
	LocalDeadline = 24 * time.Hour

	minBackoff  = time.Second
	maxBackoff  = time.Minute
	quotaJitter = 15 * time.Minute

	// A recording request, slot wait included, is bounded by requestBase plus
	// its body at requestRate bytes per second.
	requestBase = 30 * time.Second
	requestRate = 64 << 10
)

// ErrHandoff reports a handoff out of the recorder's order: a segment index
// other than the next one, a segment or end after the end, or an end whose
// segment count differs from the segments handed over.
var ErrHandoff = errors.New("recording: handoff out of order")

// errSegmentLost marks a spooled segment that cannot be sent: its file is
// missing, unreadable, over MaxObject or differs from its persisted hash.
// The entry is cut at its acknowledged count, never retried.
var errSegmentLost = errors.New("recording: spooled segment lost")

// UploaderConfig holds the uploader's dependencies.
type UploaderConfig struct {
	Spool *Spool
	// Client returns the recording client of the live session mux of the
	// device with identifier (Meta.Identifier), or ErrNoSessionMux.
	Client func(identifier string) (Client, error)
	// Configured reports whether the device with identifier (Meta.Identifier,
	// known from the local config before any registration) is still
	// configured on this agent.
	Configured func(identifier string) bool
	// Log receives drop and spool failure lines; nil means slog.Default().
	Log *slog.Logger
}

// Uploader delivers recordings: open, segments in index order, complete, one
// request in flight per recording. Each entry has its own next-attempt time
// and the entry due first is served. Segments unacknowledged after AckTimeout
// or handed over while no mux is up go to the spool. Run owns every request
// goroutine; the handoff methods are safe for concurrent use.
//
// Lock order: an entry's io lock, then mu. No spool call runs with mu held:
// Run performs the spool work its decisions queue after releasing mu, and a
// handoff writes with only its own entry's io lock held, so one recording's
// disk I/O never delays another recording's handoff.
type Uploader struct {
	spool      *Spool
	client     func(string) (Client, error)
	configured func(string) bool
	log        *slog.Logger

	now      func() time.Time
	newTimer func(time.Duration) (<-chan time.Time, func() bool)
	// jitter returns a uniform duration in [0, n), 0 for n <= 0.
	jitter func(n time.Duration) time.Duration
	// requestTimeout bounds a request with a body of n bytes.
	requestTimeout func(n int) time.Duration

	wake chan struct{}

	mu      sync.Mutex
	entries map[string]*upload
	// control counts the uploader's open, complete and failed open requests in
	// flight per device identifier (one session mux each); strict counts the
	// opens BeginOpen waits on or has in flight per device identifier. The
	// uploader starts a control request only when both are zero, so such an
	// open never queues behind one it started later.
	control map[string]int
	strict  map[string]int
	// failed holds the failed opens to report, oldest first.
	failed  []*failedOpen
	stopped bool
	// diskWork holds the spool removals decided under mu; Run performs them
	// after releasing it.
	diskWork []func()
}

// upload is one recording's delivery state, guarded by Uploader.mu.
// meta.Hashes covers Acked..Sealed-1; meta is written to the spool at open, on
// spool writes and at the end. Each index in Acked..Sealed-1 is in mem or in
// onDisk, never both, except a resumed entry's indices the crash lost, which
// are in neither.
type upload struct {
	// io serializes this entry's meta snapshots with their spool writes, so
	// meta.json is written in the order the snapshots were taken.
	io sync.Mutex

	meta     Meta
	live     bool
	opened   bool
	mem      map[uint32]*memSegment
	memBytes int
	onDisk   map[uint32]struct{}
	// resumed marks an entry from the start-up scan until its first open is
	// accepted; since is the uploader start, from which its local deadline
	// also runs because last_accepted_at is persisted only at meta writes.
	resumed bool
	since   time.Time
	// cut marks an entry completed at its acknowledged count because a
	// segment to send was lost; further handoffs are refused.
	cut bool

	busy    bool
	next    time.Time
	attempt int
	// noMux marks an entry whose last request found no session mux;
	// ClientUp makes it due at once.
	noMux bool
}

type memSegment struct {
	seg     Segment
	spillAt time.Time
	// pinned marks a segment the spool refused at AckTimeout; it stays in
	// memory until it is acknowledged or the uploader stops.
	pinned bool
	// spilling marks a segment being written to the spool by Run.
	spilling bool
}

type op int

const (
	opOpen op = iota
	opSegment
	opComplete
)

type result struct {
	e *upload
	// failed replaces e when the request was a failed-open report.
	failed *failedOpen
	op     op
	index  uint32
	res    Result
	err    error
}

// NewUploader returns an uploader; Resume hands it the spool's entries and
// Run starts its delivery.
func NewUploader(cfg UploaderConfig) *Uploader {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Uploader{
		spool:      cfg.Spool,
		client:     cfg.Client,
		configured: cfg.Configured,
		log:        log,
		now:        time.Now,
		newTimer: func(d time.Duration) (<-chan time.Time, func() bool) {
			t := time.NewTimer(d)
			return t.C, t.Stop
		},
		jitter: func(n time.Duration) time.Duration {
			if n <= 0 {
				return 0
			}
			return rand.N(n)
		},
		requestTimeout: func(n int) time.Duration {
			return requestBase + time.Duration(n)*time.Second/requestRate
		},
		wake:    make(chan struct{}, 1),
		entries: make(map[string]*upload),
		control: make(map[string]int),
		strict:  make(map[string]int),
	}
}

// Resume takes over the entries of the spool's start-up scan; call it once,
// before Run. Each entry repeats its open to learn the server's segments and
// chain, sends its spooled segments from the server's count on and
// completes; one without complete fields completes incomplete with reason
// agent_restart, or final when its final segment was the last delivered. A
// segment file at the sealed count, written by a crash before its meta write,
// is adopted with the hash of its content, as is each contiguous one after
// it. Any other segment file below the acknowledged count or past the sealed
// count is removed.
func (u *Uploader) Resume(scan Scan) {
	now := u.now()
	for _, en := range scan.Entries {
		e := &upload{meta: en.Meta, resumed: true, since: now, mem: make(map[uint32]*memSegment), onDisk: make(map[uint32]struct{})}
		m := &e.meta
		// en.Indices is ascending, so each adoption moves Sealed to the next.
		for _, idx := range en.Indices {
			if (idx >= m.Acked && idx < m.Sealed) || u.adoptSegment(e, idx) {
				e.onDisk[idx] = struct{}{}
				continue
			}
			if err := u.spool.RemoveSegment(m.ID, idx); err != nil {
				u.log.Error("recording segment outside the entry's range not removed",
					slog.String("recording", m.ID), slog.Uint64("index", uint64(idx)), slog.Any("error", err))
			}
		}
		u.mu.Lock()
		u.entries[m.ID] = e
		u.mu.Unlock()
	}
	u.poke()
}

// adoptSegment takes the spooled segment idx into e when it is the next to
// seal and the entry has no complete fields. The file is whole, since the
// spool writes by rename. The next meta write spends the hash reservation.
func (u *Uploader) adoptSegment(e *upload, idx uint32) bool {
	m := &e.meta
	if idx != m.Sealed || m.Complete != nil {
		return false
	}
	obj, err := u.spool.ReadSegment(m.ID, idx)
	if err != nil {
		u.log.Warn("recording segment past the sealed count not readable", slog.String("recording", m.ID), slog.Uint64("index", uint64(idx)), slog.Any("error", err))
		return false
	}
	if err := u.spool.ReserveHash(m.ID); err != nil {
		u.log.Warn("recording segment past the sealed count has no room for its hash", slog.String("recording", m.ID), slog.Uint64("index", uint64(idx)), slog.Any("error", err))
		return false
	}
	hash := sha256.Sum256(obj)
	m.Hashes = append(m.Hashes, hash[:])
	m.Sealed++
	return true
}

// Handoff is the recorder's side of one recording: segments in index order,
// then End.
type Handoff struct {
	u *Uploader
	e *upload
}

// BeginOpen writes m as the entry's meta.json, hands the recording over and
// sends the open now, ahead of any open or complete the uploader has not
// started on that device: the first open creates the recording from
// m.Certificate, which verifies only within its short validity, so a queued
// open could come too late. m carries no segment yet. On failure it removes
// the entry and returns the error; the caller decides whether the session
// runs unrecorded.
func (u *Uploader) BeginOpen(ctx context.Context, m Meta) (*Handoff, error) {
	if m.Sealed != 0 || m.Acked != 0 || m.Complete != nil {
		return nil, fmt.Errorf("%w: begin with segments or completion", ErrHandoff)
	}
	if err := u.spool.CreateEntry(m); err != nil {
		return nil, err
	}
	if err := u.openStrict(ctx, m); err != nil {
		if rmErr := u.spool.Remove(m.ID); rmErr != nil {
			u.log.Error("recording entry not removed", slog.String("recording", m.ID), slog.Any("error", rmErr))
		}
		return nil, err
	}
	e := &upload{meta: m, live: true, opened: true, mem: make(map[uint32]*memSegment), onDisk: make(map[uint32]struct{})}
	u.mu.Lock()
	u.entries[m.ID] = e
	u.mu.Unlock()
	u.poke()
	return &Handoff{u: u, e: e}, nil
}

func (u *Uploader) openStrict(ctx context.Context, m Meta) error {
	u.mu.Lock()
	u.strict[m.Identifier]++
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		if u.strict[m.Identifier]--; u.strict[m.Identifier] == 0 {
			delete(u.strict, m.Identifier)
		}
		u.mu.Unlock()
		u.poke()
	}()
	c, err := u.client(m.Identifier)
	if err != nil {
		return err
	}
	res, err := c.Open(ctx, m.ID, m.SessionID, m.WrappedDEK, m.KeySHA256, m.Certificate, m.Channels)
	if err != nil {
		return err
	}
	if res.Segments != 0 {
		return fmt.Errorf("recording: open of a new recording answered %d segments", res.Segments)
	}
	return nil
}

// Segment hands over the next sealed segment; the uploader owns seg.Object
// afterwards. When the spool has no room for the segment's hash in meta.json,
// or the recording's memory is full and the spool refuses the segment, it
// returns an error wrapping ErrSpoolFull or ErrDiskLow and the segment is not
// taken: the recording holds seg.Index segments. A recording the uploader
// dropped, or completed early because a segment was lost, returns ErrNoEntry.
func (h *Handoff) Segment(seg Segment) error {
	u, e := h.u, h.e
	e.io.Lock()
	defer e.io.Unlock()
	// Reserved before the take, so the meta writes that carry its hash fit.
	if err := u.spool.ReserveHash(e.meta.ID); err != nil {
		return err
	}
	taken := false
	defer func() {
		if !taken {
			u.spool.ReleaseHash(e.meta.ID)
		}
	}()
	u.mu.Lock()
	if err := u.handoffErrLocked(e); err != nil {
		u.mu.Unlock()
		return err
	}
	if seg.Index != e.meta.Sealed {
		u.mu.Unlock()
		return fmt.Errorf("%w: segment %d after %d sealed", ErrHandoff, seg.Index, e.meta.Sealed)
	}
	memFull := e.memBytes+len(seg.Object) > MaxUnacked
	// The final segment is always spooled: a crash that leaves it delivered
	// without End's meta write still completes as final, through FinalIndex.
	if !seg.Final && !memFull && !u.stopped && !u.noMux(e.meta.Identifier) {
		e.takeLocked(seg, &memSegment{seg: seg, spillAt: u.now().Add(AckTimeout)})
		taken = true
		u.mu.Unlock()
		u.poke()
		return nil
	}
	if seg.Final {
		e.meta.FinalIndex = &seg.Index
	}
	// The index is taken only after the write, so the segment cannot be sent,
	// and so acknowledged, before it is on disk.
	meta := e.meta.snapshot()
	u.mu.Unlock()
	if seg.Final {
		u.writeMeta(meta)
	}
	meta.Sealed++
	meta.Hashes = append(meta.Hashes, bytes.Clone(seg.Hash[:]))

	err := u.spool.WriteSegment(meta.ID, seg)
	if err == nil {
		u.writeMeta(meta)
		// The meta write spent the reservation, or the next one will.
		taken = true
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	if u.entries[meta.ID] != e || e.cut {
		return ErrNoEntry
	}
	switch {
	case err == nil:
		e.takeLocked(seg, nil)
		e.onDisk[seg.Index] = struct{}{}
	case memFull:
		return err
	default:
		u.log.Warn("recording segment kept in memory, spool refused it",
			slog.String("recording", meta.ID), slog.Uint64("index", uint64(seg.Index)), slog.Any("error", err))
		e.takeLocked(seg, &memSegment{seg: seg, pinned: true})
	}
	taken = true
	u.poke()
	return nil
}

// End hands over the complete fields; done.Segments is the count of segments
// handed over. A recording the uploader dropped, or completed early because a
// segment was lost, returns ErrNoEntry.
func (h *Handoff) End(done Completion) error {
	u, e := h.u, h.e
	e.io.Lock()
	defer e.io.Unlock()
	u.mu.Lock()
	if err := u.handoffErrLocked(e); err != nil {
		u.mu.Unlock()
		return err
	}
	if done.Segments != e.meta.Sealed {
		u.mu.Unlock()
		return fmt.Errorf("%w: end with %d segments, %d sealed", ErrHandoff, done.Segments, e.meta.Sealed)
	}
	e.live = false
	e.meta.Complete = &done
	meta := e.meta.snapshot()
	u.mu.Unlock()
	u.writeMeta(meta)
	u.poke()
	return nil
}

// Abort removes a recording whose session was refused after Begin: the entry
// and its spool directory, before any segment was handed over. A recording
// already opened at the control plane is never completed.
func (h *Handoff) Abort() error {
	u, e := h.u, h.e
	e.io.Lock()
	defer e.io.Unlock()
	u.mu.Lock()
	if err := u.handoffErrLocked(e); err != nil {
		u.mu.Unlock()
		return err
	}
	if e.meta.Sealed != 0 {
		u.mu.Unlock()
		return fmt.Errorf("%w: abort after %d sealed", ErrHandoff, e.meta.Sealed)
	}
	e.live = false
	delete(u.entries, e.meta.ID)
	u.mu.Unlock()
	return u.spool.Remove(e.meta.ID)
}

func (u *Uploader) handoffErrLocked(e *upload) error {
	if u.entries[e.meta.ID] != e || e.cut {
		return ErrNoEntry
	}
	if !e.live {
		return fmt.Errorf("%w: handoff after the end", ErrHandoff)
	}
	return nil
}

// takeLocked records seg as sealed; ms, when set, holds it in memory.
func (e *upload) takeLocked(seg Segment, ms *memSegment) {
	e.meta.Sealed++
	e.meta.Hashes = append(e.meta.Hashes, bytes.Clone(seg.Hash[:]))
	if ms != nil {
		e.mem[seg.Index] = ms
		e.memBytes += len(seg.Object)
	}
}

// snapshot copies the meta for a write outside Uploader.mu. Hash elements and
// the chain are never modified in place, so sharing them is safe.
func (m *Meta) snapshot() Meta {
	s := *m
	s.Hashes = slices.Clone(m.Hashes)
	return s
}

// ClientUp makes the entries of the device with identifier that wait for a
// session mux due at once, with their backoff reset. The session mux calls it
// when it publishes a recording client; it does not block.
func (u *Uploader) ClientUp(identifier string) {
	u.mu.Lock()
	for _, e := range u.entries {
		if e.noMux && e.meta.Identifier == identifier {
			e.noMux = false
			e.attempt = 0
			e.next = time.Time{}
		}
	}
	u.resetFailedOpensLocked(identifier)
	u.mu.Unlock()
	u.poke()
}

func (u *Uploader) noMux(identifier string) bool {
	_, err := u.client(identifier)
	return errors.Is(err, ErrNoSessionMux)
}

func (u *Uploader) poke() {
	select {
	case u.wake <- struct{}{}:
	default:
	}
}

// Run delivers recordings until ctx ends, then waits for its requests (each
// bound to ctx) and writes every segment still only in memory to the spool.
// Handoffs after Run returns go to the spool directly.
func (u *Uploader) Run(ctx context.Context) {
	results := make(chan result)
	var wg sync.WaitGroup
	for {
		u.mu.Lock()
		wait, ok, spills := u.dispatchLocked(ctx, results, &wg)
		work := u.takeDiskWorkLocked()
		u.mu.Unlock()
		for _, e := range spills {
			u.spill(e, false)
		}
		runAll(work)
		var timer <-chan time.Time
		stop := func() bool { return false }
		if ok {
			timer, stop = u.newTimer(wait)
		}
		select {
		case <-ctx.Done():
			stop()
			u.shutdown(results, &wg)
			return
		case <-u.wake:
		case r := <-results:
			u.apply(r)
		case <-timer:
		}
		stop()
	}
}

func (u *Uploader) apply(r result) {
	u.mu.Lock()
	u.applyLocked(r)
	work := u.takeDiskWorkLocked()
	u.mu.Unlock()
	runAll(work)
}

func (u *Uploader) shutdown(results chan result, wg *sync.WaitGroup) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	for waiting := true; waiting; {
		select {
		case r := <-results:
			u.apply(r)
		case <-done:
			waiting = false
		}
	}
	u.mu.Lock()
	u.stopped = true
	u.dropFailedOpensLocked()
	var held []*upload
	for _, e := range u.entries {
		if len(e.mem) != 0 {
			held = append(held, e)
		}
	}
	work := u.takeDiskWorkLocked()
	u.mu.Unlock()
	runAll(work)
	for _, e := range held {
		u.spill(e, true)
	}
}

// dispatchLocked marks segments past AckTimeout for spilling, starts a
// request for each due entry in due order, and returns the wait until the
// next deadline and the entries with segments to spill.
func (u *Uploader) dispatchLocked(ctx context.Context, results chan<- result, wg *sync.WaitGroup) (time.Duration, bool, []*upload) {
	now := u.now()
	var due, spills []*upload
	var wake time.Time
	later := func(t time.Time) {
		if wake.IsZero() || t.Before(wake) {
			wake = t
		}
	}
	for _, e := range u.entries {
		spill := false
		for _, m := range e.mem {
			switch {
			case m.pinned || m.spilling:
			case !m.spillAt.After(now):
				m.spilling = true
				spill = true
			default:
				later(m.spillAt)
			}
		}
		if spill {
			spills = append(spills, e)
		}
		if e.busy || !e.pending() {
			continue
		}
		if e.next.After(now) {
			later(e.next)
			continue
		}
		due = append(due, e)
	}
	slices.SortFunc(due, func(a, b *upload) int { return a.next.Compare(b.next) })
	for _, e := range due {
		u.startLocked(ctx, e, now, results, wg)
	}
	u.dispatchFailedOpensLocked(ctx, now, later, results, wg)
	if wake.IsZero() {
		return 0, false, spills
	}
	return wake.Sub(now), true, spills
}

// pending reports whether the entry has a request to send. An entry that is
// not live always ends with a complete.
func (e *upload) pending() bool {
	return !e.opened || e.meta.Acked < e.meta.Sealed || e.meta.Complete != nil || !e.live
}

// holds reports whether the segment with index idx is in memory or spooled.
func (e *upload) holds(idx uint32) bool {
	if _, ok := e.mem[idx]; ok {
		return true
	}
	_, ok := e.onDisk[idx]
	return ok
}

func (e *upload) nextOp() op {
	switch {
	case !e.opened:
		return opOpen
	case e.meta.Acked < e.meta.Sealed:
		return opSegment
	default:
		return opComplete
	}
}

func (u *Uploader) startLocked(ctx context.Context, e *upload, now time.Time, results chan<- result, wg *sync.WaitGroup) {
	m := &e.meta
	if !u.configured(m.Identifier) {
		u.dropLocked(e, slog.LevelWarn, "recording dropped, device no longer configured", "")
		return
	}
	if now.Sub(laterOf(m.LastAcceptedAt, e.since)) > LocalDeadline {
		u.dropLocked(e, slog.LevelWarn, "recording dropped, nothing accepted for 24 h", "")
		return
	}
	lost := m.Acked < m.Sealed && !e.holds(m.Acked)
	if e.opened && !e.live && (lost || (m.Acked == m.Sealed && m.Complete == nil)) {
		u.cutLocked(e, now)
	}
	o := e.nextOp()
	if o != opSegment {
		if u.control[m.Identifier] != 0 || u.strict[m.Identifier] != 0 {
			return
		}
		u.control[m.Identifier]++
	}
	e.busy = true
	r := result{e: e, op: o, index: m.Acked}
	id, sessionID, identifier, dek, keySHA, cert := m.ID, m.SessionID, m.Identifier, m.WrappedDEK, m.KeySHA256, m.Certificate
	var done Completion
	if m.Complete != nil {
		done = *m.Complete
	}
	var live *Segment
	var want []byte
	if ms, ok := e.mem[m.Acked]; ok {
		live = &ms.seg
	} else if o == opSegment {
		want = m.Hashes[0]
	}
	final := m.FinalIndex != nil && *m.FinalIndex == m.Acked
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.res, r.err = u.send(ctx, r.op, identifier, id, sessionID, dek, keySHA, cert, done, r.index, live, want, final)
		results <- r
	}()
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// send makes one request. A spooled segment (live nil) is read and checked
// against want, its persisted hash, before it is sent.
func (u *Uploader) send(ctx context.Context, o op, identifier, id, sessionID string, dek, keySHA, cert []byte, done Completion, index uint32, live *Segment, want []byte, final bool) (Result, error) {
	c, err := u.client(identifier)
	if err != nil {
		return Result{}, err
	}
	switch o {
	case opOpen:
		ctx, cancel := context.WithTimeout(ctx, u.requestTimeout(0))
		defer cancel()
		return c.Open(ctx, id, sessionID, dek, keySHA, cert, 0)
	case opComplete:
		ctx, cancel := context.WithTimeout(ctx, u.requestTimeout(0))
		defer cancel()
		return c.Complete(ctx, id, dek, done)
	}
	if live != nil {
		ctx, cancel := context.WithTimeout(ctx, u.requestTimeout(len(live.Object)))
		defer cancel()
		return c.PutSegment(ctx, id, *live)
	}
	ctx, cancel := context.WithTimeout(ctx, u.requestTimeout(MaxObject))
	defer cancel()
	return c.PutSpooledSegment(ctx, id, func() (Segment, error) {
		obj, err := u.spool.ReadSegment(id, index)
		if err != nil {
			return Segment{}, fmt.Errorf("%w: read segment %d: %w", errSegmentLost, index, err)
		}
		seg := Segment{Index: index, Object: obj, Hash: sha256.Sum256(obj), Final: final}
		if !bytes.Equal(seg.Hash[:], want) {
			return Segment{}, fmt.Errorf("%w: segment %d differs from its persisted hash", errSegmentLost, index)
		}
		return seg, nil
	})
}

func (u *Uploader) applyLocked(r result) {
	if r.failed != nil {
		u.applyFailedOpenLocked(r)
		return
	}
	e := r.e
	e.busy = false
	if r.op != opSegment {
		if u.control[e.meta.Identifier]--; u.control[e.meta.Identifier] == 0 {
			delete(u.control, e.meta.Identifier)
		}
	}
	if u.entries[e.meta.ID] != e {
		return
	}
	e.noMux = errors.Is(r.err, ErrNoSessionMux)
	if r.err == nil {
		u.acceptLocked(e, r)
		return
	}
	var ref *Refusal
	if !errors.As(r.err, &ref) {
		if errors.Is(r.err, errSegmentLost) {
			u.log.Warn("recording spooled segment lost", slog.String("recording", e.meta.ID), slog.Any("error", r.err))
			u.cutLocked(e, u.now())
			e.next = time.Time{}
			return
		}
		u.backoffLocked(e, 0)
		return
	}
	switch ref.Status {
	case http.StatusNotFound, http.StatusGone, http.StatusRequestEntityTooLarge:
		u.dropLocked(e, slog.LevelWarn, "recording dropped by the server", ref.Code)
	case http.StatusConflict:
		if ref.Code == CodeOutOfOrder {
			// The server's count differs: learn it through open, never skip.
			e.opened = false
			u.backoffLocked(e, 0)
			return
		}
		u.dropLocked(e, slog.LevelError, "recording dropped, server refused it", ref.Code)
	case http.StatusBadRequest, http.StatusUnauthorized:
		u.dropLocked(e, slog.LevelError, "recording dropped, server refused it", ref.Code)
	case http.StatusTooManyRequests:
		e.next = u.now().Add(ref.RetryAfter + u.jitter(quotaJitter+1))
	default:
		u.backoffLocked(e, ref.RetryAfter)
	}
}

func (u *Uploader) acceptLocked(e *upload, r result) {
	now := u.now()
	switch r.op {
	case opOpen:
		e.opened = true
		e.next = time.Time{}
		if e.resumed {
			e.resumed = false
			u.resumeLocked(e, r.res)
			return
		}
		u.resyncLocked(e, r.res)
		return
	case opComplete:
		u.removeEntryLocked(e)
		return
	}
	if r.index == e.meta.Acked {
		u.ackLocked(e)
	}
	e.meta.LastAcceptedAt = now
	e.attempt = 0
	e.next = time.Time{}
}

// resumeLocked applies the first open after a restart. A server count within
// the persisted sealed count resyncs with the chain check. A count past it
// means segments delivered from memory whose hashes the crash lost: delivery
// takes the server's count and chain and completes there.
func (u *Uploader) resumeLocked(e *upload, res Result) {
	m := &e.meta
	if res.Segments <= m.Sealed {
		u.resyncLocked(e, res)
		return
	}
	if m.Complete != nil || len(res.Chain) != sha256.Size {
		u.dropLocked(e, slog.LevelError, fmt.Sprintf("recording dropped, server holds %d segments, %d sealed", res.Segments, m.Sealed), "")
		return
	}
	for idx := range e.onDisk {
		u.removeSegmentLocked(e, idx)
	}
	clear(e.onDisk)
	m.Acked, m.Sealed = res.Segments, res.Segments
	m.AckedChain = bytes.Clone(res.Chain)
	m.Hashes = nil
}

// resyncLocked moves the entry to the server's segment count after an open:
// what the server holds is dropped and delivery resumes at its count, after
// checking that its chain matches the hashes held for that range.
func (u *Uploader) resyncLocked(e *upload, res Result) {
	m := &e.meta
	if res.Segments > m.Sealed || res.Segments < m.Acked {
		u.dropLocked(e, slog.LevelError, fmt.Sprintf("recording dropped, server holds %d segments, %d acknowledged, %d sealed", res.Segments, m.Acked, m.Sealed), "")
		return
	}
	chain := m.AckedChain
	if len(chain) == 0 {
		chain = nil
	}
	for _, h := range m.Hashes[:res.Segments-m.Acked] {
		chain = ChainStep(chain, [32]byte(h))
	}
	if !bytes.Equal(chain, res.Chain) {
		u.dropLocked(e, slog.LevelError, "recording dropped, server chain differs", CodeMismatch)
		return
	}
	for m.Acked < res.Segments {
		u.ackLocked(e)
	}
}

// cutLocked completes the entry at its acknowledged count when the segment to
// send next was lost (a crash before it reached the spool, or a spooled file
// that failed its read-back, see errSegmentLost) or a resumed entry has no
// complete fields. That is incomplete, unless the crash came after the final
// segment was delivered: then only End's meta write is missing and the
// recording is whole. The segments past that count are dropped with the entry
// once complete is accepted.
func (u *Uploader) cutLocked(e *upload, now time.Time) {
	m := &e.meta
	if m.Acked < m.Sealed {
		u.log.Warn("recording completed early, segment lost",
			slog.String("recording", m.ID), slog.Uint64("index", uint64(m.Acked)), slog.Uint64("sealed", uint64(m.Sealed)))
	}
	endedAt := now
	if m.Complete != nil {
		endedAt = m.Complete.EndedAt
	}
	final := !e.live && m.Complete == nil && m.Acked == m.Sealed && m.FinalIndex != nil && *m.FinalIndex+1 == m.Acked
	done := Completion{Segments: m.Acked, FinalHash: bytes.Clone(m.AckedChain), EndedAt: endedAt, Final: final}
	if !final {
		done.Incomplete, done.Reason = true, ReasonAgentRestart
		if e.live {
			done.Reason = ReasonRecordingFailed
		}
	}
	m.Complete = &done
	m.Sealed = m.Acked
	m.Hashes = nil
	clear(e.mem)
	e.memBytes = 0
	e.live = false
	e.cut = true
}

// ackLocked records the server's acknowledgement of segment meta.Acked.
func (u *Uploader) ackLocked(e *upload) {
	m := &e.meta
	idx := m.Acked
	chain := m.AckedChain
	if len(chain) == 0 {
		chain = nil
	}
	m.AckedChain = ChainStep(chain, [32]byte(m.Hashes[0]))
	m.Hashes = m.Hashes[1:]
	m.Acked++
	if ms, ok := e.mem[idx]; ok {
		e.memBytes -= len(ms.seg.Object)
		delete(e.mem, idx)
	}
	if _, ok := e.onDisk[idx]; ok {
		delete(e.onDisk, idx)
		u.removeSegmentLocked(e, idx)
	}
}

func (u *Uploader) backoffLocked(e *upload, floor time.Duration) {
	limit := maxBackoff
	if e.attempt < 6 {
		limit = min(maxBackoff, minBackoff<<e.attempt)
	}
	e.attempt++
	d := max(minBackoff+u.jitter(limit-minBackoff+1), floor)
	e.next = u.now().Add(d)
}

// spill writes the entry's segments marked spilling (with all, every segment in
// memory) to the spool, then its meta. A refused write pins the segment in
// memory. It runs on Run's goroutine (or after Run's requests ended), so no
// acknowledgement or cut changes mem during the writes, and the entry's io lock
// keeps its handoffs out.
func (u *Uploader) spill(e *upload, all bool) {
	e.io.Lock()
	defer e.io.Unlock()
	u.mu.Lock()
	id := e.meta.ID
	var segs []Segment
	for _, idx := range slices.Sorted(maps.Keys(e.mem)) {
		ms := e.mem[idx]
		if all {
			ms.spilling = true
		}
		if ms.spilling {
			segs = append(segs, ms.seg)
		}
	}
	u.mu.Unlock()
	if len(segs) == 0 {
		return
	}
	errs := make([]error, len(segs))
	for i, seg := range segs {
		errs[i] = u.spool.WriteSegment(id, seg)
	}

	u.mu.Lock()
	wrote := false
	for i, seg := range segs {
		if err := errs[i]; err != nil {
			e.mem[seg.Index].spilling, e.mem[seg.Index].pinned = false, true
			if !errors.Is(err, ErrNoEntry) {
				u.log.Warn("recording segment kept in memory, spool refused it",
					slog.String("recording", id), slog.Uint64("index", uint64(seg.Index)), slog.Any("error", err))
			}
			continue
		}
		e.memBytes -= len(seg.Object)
		delete(e.mem, seg.Index)
		e.onDisk[seg.Index] = struct{}{}
		wrote = true
	}
	var meta Meta
	wrote = wrote && u.entries[id] == e
	if wrote {
		meta = e.meta.snapshot()
	}
	u.mu.Unlock()

	if wrote {
		u.writeMeta(meta)
	}
}

func (u *Uploader) writeMeta(m Meta) {
	if err := u.spool.WriteMeta(m); err != nil && !errors.Is(err, ErrNoEntry) {
		u.log.Error("recording meta not written", slog.String("recording", m.ID), slog.Any("error", err))
	}
}

func (u *Uploader) removeSegment(id string, idx uint32) {
	if err := u.spool.RemoveSegment(id, idx); err != nil && !errors.Is(err, ErrNoEntry) {
		u.log.Error("acknowledged recording segment not removed from the spool",
			slog.String("recording", id), slog.Uint64("index", uint64(idx)), slog.Any("error", err))
	}
}

func (u *Uploader) removeSegmentLocked(e *upload, idx uint32) {
	id := e.meta.ID
	u.diskWork = append(u.diskWork, func() { u.removeSegment(id, idx) })
}

// removeEntryLocked forgets the entry and queues the removal of its spool
// directory.
func (u *Uploader) removeEntryLocked(e *upload) {
	id := e.meta.ID
	delete(u.entries, id)
	u.diskWork = append(u.diskWork, func() {
		if err := u.spool.Remove(id); err != nil {
			u.log.Error("recording entry not removed", slog.String("recording", id), slog.Any("error", err))
		}
	})
}

func (u *Uploader) takeDiskWorkLocked() []func() {
	work := u.diskWork
	u.diskWork = nil
	return work
}

func runAll(work []func()) {
	for _, f := range work {
		f()
	}
}

func (u *Uploader) dropLocked(e *upload, level slog.Level, msg, code string) {
	attrs := []any{slog.String("recording", e.meta.ID)}
	if code != "" {
		attrs = append(attrs, slog.String("code", code))
	}
	u.log.Log(context.Background(), level, msg, attrs...)
	u.removeEntryLocked(e)
}
