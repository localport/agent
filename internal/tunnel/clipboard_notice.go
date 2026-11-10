package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Clipboard notices: the agent reports each clipboard transfer decision of a
// desktop session to the edge, which stores it as an access-log row
// (docs/PROTOCOL.md "Clipboard notices"). Notices queue per device and a
// sender per device posts them in batches on the device's session mux, one
// request at a time. Sending never blocks the desktop relay: a full queue
// counts the decisions it could not take per session and reports the count
// once the queue has drained.
const (
	clipboardPath = "/v1/clipboard"
	// clipboardMaxBatch is the edge's per-batch bound.
	clipboardMaxBatch = 64
	// clipboardQueueLen bounds one device's queued notices.
	clipboardQueueLen = 1024
	// clipboardFlushEvery is how long a notice waits for its batch to fill.
	clipboardFlushEvery = 2 * time.Second
	// clipboardRequestTimeout bounds one batch request.
	clipboardRequestTimeout = 10 * time.Second
	// clipboardFinalFlush bounds the flush a session mux runs after its
	// sessions ended and before its conn closes.
	clipboardFinalFlush = 2 * time.Second
	// clipboardMaxResponse bounds what is read of an answer.
	clipboardMaxResponse = 4 << 10
	// clipboardSlots is the one stream a batch holds within the edge's
	// session mux streams.
	clipboardSlots = 1
)

// errClipboardRejected is the edge's 400 (a malformed batch) or 404 (an edge
// without the route): the batch is dropped, never resent.
var errClipboardRejected = errors.New("clipboard notices: the edge rejected the batch")

// ClipboardClient posts clipboard notice batches on one session mux conn.
// Its slot belongs to the conn. Safe for concurrent use.
type ClipboardClient struct {
	cc     *http.ClientConn
	closed <-chan struct{}
	slot   chan struct{}
}

func newClipboardClient(connCtx context.Context, cc *http.ClientConn) *ClipboardClient {
	return &ClipboardClient{cc: cc, closed: connCtx.Done(), slot: make(chan struct{}, clipboardSlots)}
}

// ClipboardClient returns the clipboard client of the session mux conn up
// now, or errNoClipboardClient.
func (t *Tunnel) ClipboardClient() (*ClipboardClient, error) {
	if m := t.sessionMux.Load(); m != nil {
		if c := m.clip.Load(); c != nil {
			return c, nil
		}
	}
	return nil, ErrNoClipboardClient
}

// ErrNoClipboardClient means the device has no session mux conn up.
var ErrNoClipboardClient = errors.New("clipboard notices: no session mux")

// send posts one batch: nil on 204, errClipboardRejected on 400 or 404, any
// other error for a batch to send again.
func (c *ClipboardClient) send(ctx context.Context, body []byte) error {
	select {
	case c.slot <- struct{}{}:
		defer func() { <-c.slot }()
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return ErrNoClipboardClient
	}
	req, err := newSessionMuxRequest(ctx, http.MethodPost, clipboardPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.cc.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("clipboard notices: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, clipboardMaxResponse))
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusBadRequest, http.StatusNotFound:
		return errClipboardRejected
	}
	return fmt.Errorf("clipboard notices: edge answered %d", resp.StatusCode)
}

// ClipboardNotice is one decision a desktop session reports: SessionID is
// the canonical UUID of the stream the connection runs on, Kind vnc or rdp,
// Direction copy or paste, Outcome allowed, denied_policy, denied_size or
// denied_format, and Bytes the text size the decision was about.
type ClipboardNotice struct {
	SessionID string
	Kind      string
	Direction string
	Outcome   string
	Bytes     int64
	At        time.Time
}

// clipboardWire is one notice of a batch body; Dropped > 0 is a count of
// decisions the queue could not take, with no direction or outcome.
type clipboardWire struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Kind      string `json:"kind"`
	Direction string `json:"direction,omitempty"`
	Outcome   string `json:"outcome,omitempty"`
	Bytes     int64  `json:"bytes"`
	Time      int64  `json:"time"`
	Dropped   int64  `json:"dropped,omitempty"`
}

type clipboardBatchBody struct {
	Notices []clipboardWire `json:"notices"`
}

// ClipboardNotices queues every device's clipboard notices and runs one
// sender per device with notices to send. Run starts the senders; Note
// before Run only queues.
type ClipboardNotices struct {
	// client returns the clipboard client of the device with that
	// identifier, or an error while it has none.
	client func(identifier string) (*ClipboardClient, error)
	// flushEvery is how long a notice waits for its batch; tests shorten it.
	flushEvery time.Duration
	// senderStarted, when set, runs under mu each time a sender starts.
	// Tests set it; nil otherwise.
	senderStarted func()

	mu      sync.Mutex
	ids     clipboardIDs
	devices map[string]*clipboardQueue
	// ctx is Run's context, nil before Run; senders stop when it ends.
	// stopped is set once Run waits for its senders; no sender starts after.
	ctx     context.Context
	stopped bool
	senders sync.WaitGroup
}

// clipboardQueue is one device's notices, guarded by ClipboardNotices.mu.
type clipboardQueue struct {
	identifier string
	notices    []clipboardWire
	// dropped counts, per session, the decisions the full queue refused.
	dropped map[clipboardSession]int64
	// idle is non-nil while a sender owns the queue and closed when it
	// returns.
	idle chan struct{}
	// flushing counts the Flush calls waiting; while it is positive the
	// sender sends batch after batch without waiting, on flushClient.
	flushing    int
	flushClient *ClipboardClient
	// wake wakes the sender when a batch is full or a Flush waits.
	wake chan struct{}
}

func (d *clipboardQueue) empty() bool { return len(d.notices) == 0 && len(d.dropped) == 0 }

func (d *clipboardQueue) wakeSender() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

type clipboardSession struct{ id, kind string }

// NewClipboardNotices returns the queues; client resolves a device's
// clipboard client at each send.
func NewClipboardNotices(client func(identifier string) (*ClipboardClient, error)) *ClipboardNotices {
	return &ClipboardNotices{
		client:     client,
		flushEvery: clipboardFlushEvery,
		devices:    make(map[string]*clipboardQueue),
	}
}

// Note queues n for the device identifier without blocking. The notice's id
// is minted here, in queue order, so every id of a session is newer than the
// ones queued before it.
func (q *ClipboardNotices) Note(identifier string, n ClipboardNotice) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	d := q.devices[identifier]
	if d == nil {
		d = &clipboardQueue{identifier: identifier, dropped: make(map[clipboardSession]int64), wake: make(chan struct{}, 1)}
		q.devices[identifier] = d
	}
	if len(d.notices) >= clipboardQueueLen {
		d.dropped[clipboardSession{n.SessionID, n.Kind}]++
	} else {
		d.notices = append(d.notices, clipboardWire{
			ID: q.ids.next(n.At), SessionID: n.SessionID, Kind: n.Kind,
			Direction: n.Direction, Outcome: n.Outcome, Bytes: n.Bytes, Time: n.At.UnixMilli(),
		})
		if len(d.notices) >= clipboardMaxBatch {
			d.wakeSender()
		}
	}
	q.startLocked(d)
}

// startLocked starts d's sender once Run runs and none owns d.
func (q *ClipboardNotices) startLocked(d *clipboardQueue) {
	if d.idle != nil || q.ctx == nil || q.stopped {
		return
	}
	idle := make(chan struct{})
	d.idle = idle
	if q.senderStarted != nil {
		q.senderStarted()
	}
	q.senders.Go(func() {
		defer close(idle)
		q.sendLoop(d)
	})
}

// Run starts a sender for every device with queued notices, then waits for
// ctx and for every sender to return. Notices still queued then are lost.
func (q *ClipboardNotices) Run(ctx context.Context) {
	q.mu.Lock()
	q.ctx = ctx
	for _, d := range q.devices {
		if !d.empty() {
			q.startLocked(d)
		}
	}
	q.mu.Unlock()
	<-ctx.Done()
	// Under mu, so no Note or Flush starts a sender once Wait may run.
	q.mu.Lock()
	q.stopped = true
	q.mu.Unlock()
	q.senders.Wait()
}

// Flush sends what the device identifier has queued on c, batch after batch,
// and returns once its queue is empty or ctx ends. The session mux calls it
// with its conn's client after its sessions ended and before its conn closes
// (sessionMux.stop); a nil c sends nothing.
func (q *ClipboardNotices) Flush(ctx context.Context, identifier string, c *ClipboardClient) {
	if q == nil || c == nil {
		return
	}
	q.mu.Lock()
	d := q.devices[identifier]
	if d == nil || (d.empty() && d.idle == nil) {
		q.mu.Unlock()
		return
	}
	q.startLocked(d)
	idle := d.idle
	if idle == nil {
		q.mu.Unlock()
		return
	}
	d.flushing++
	d.flushClient = c
	d.wakeSender()
	q.mu.Unlock()
	select {
	case <-idle:
	case <-ctx.Done():
	}
	q.mu.Lock()
	if d.flushing--; d.flushing == 0 {
		d.flushClient = nil
	}
	q.mu.Unlock()
}

// sendLoop owns d until d is empty or Run's context ends. It sends when a
// batch is full, a Flush waits, or flushEvery after its last attempt; it
// sends batch after batch while a full batch or a Flush waits. A batch that
// failed is sent again before any other, so the edge sees each session's ids
// in order.
func (q *ClipboardNotices) sendLoop(d *clipboardQueue) {
	var pending []byte
	timer := time.NewTimer(q.flushEvery)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
		case <-d.wake:
		case <-q.ctx.Done():
			q.release(d)
			return
		}
		for {
			if pending == nil {
				if pending = q.takeBatch(d); pending == nil {
					break
				}
			}
			err := q.sendBatch(q.ctx, d, pending)
			if err != nil && !errors.Is(err, errClipboardRejected) {
				break
			}
			if err != nil {
				slog.Warn("clipboard notices dropped: the edge rejected the batch", slog.String("device", d.identifier))
			}
			pending = nil
			if !q.sendAgain(d) {
				break
			}
		}
		q.mu.Lock()
		if pending == nil && d.empty() {
			d.idle = nil
			q.mu.Unlock()
			return
		}
		q.mu.Unlock()
		timer.Reset(q.flushEvery)
	}
}

// sendAgain reports whether the sender sends the next batch at once: a full
// batch is queued or a Flush waits.
func (q *ClipboardNotices) sendAgain(d *clipboardQueue) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return !d.empty() && (len(d.notices) >= clipboardMaxBatch || d.flushing > 0)
}

// release gives d up at Run's end.
func (q *ClipboardNotices) release(d *clipboardQueue) {
	q.mu.Lock()
	d.idle = nil
	q.mu.Unlock()
}

// sendBatch posts body for d on the client a Flush handed over, else on the
// device's current one.
func (q *ClipboardNotices) sendBatch(ctx context.Context, d *clipboardQueue, body []byte) error {
	q.mu.Lock()
	c := d.flushClient
	q.mu.Unlock()
	if c == nil {
		var err error
		if c, err = q.client(d.identifier); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, clipboardRequestTimeout)
	defer cancel()
	return c.send(ctx, body)
}

// takeBatch removes up to clipboardMaxBatch notices from d and returns them
// as a request body, nil when d is empty. The dropped counts join the batch
// that empties the queue, after its notices, so a count's id is newer than
// every notice queued before it.
func (q *ClipboardNotices) takeBatch(d *clipboardQueue) []byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := min(len(d.notices), clipboardMaxBatch)
	batch := make([]clipboardWire, n, clipboardMaxBatch)
	copy(batch, d.notices[:n])
	rest := copy(d.notices, d.notices[n:])
	clear(d.notices[rest:])
	d.notices = d.notices[:rest]
	if rest == 0 {
		now := time.Now()
		for s, count := range d.dropped {
			if len(batch) == clipboardMaxBatch {
				break
			}
			batch = append(batch, clipboardWire{
				ID: q.ids.next(now), SessionID: s.id, Kind: s.kind, Time: now.UnixMilli(), Dropped: count,
			})
			delete(d.dropped, s)
		}
	}
	if len(batch) == 0 {
		return nil
	}
	body, err := json.Marshal(clipboardBatchBody{Notices: batch})
	if err != nil {
		return nil
	}
	return body
}

// clipboardIDs mints UUIDv7 ids (RFC 9562 5.7) that increase in mint order:
// 48-bit Unix milliseconds, then a 12-bit sequence in rand_a that counts the
// ids of one millisecond (method 1 of 6.2), then 62 random bits. A clock that
// steps back keeps the last millisecond and counts on. Guarded by the
// owner's lock.
type clipboardIDs struct {
	ms  uint64
	seq uint16
}

func (g *clipboardIDs) next(now time.Time) string {
	ms := uint64(max(now.UnixMilli(), 0))
	if ms > g.ms {
		g.ms, g.seq = ms, 0
	} else if g.seq++; g.seq > 0xfff {
		g.ms, g.seq = g.ms+1, 0
	}
	var id [16]byte
	_, _ = rand.Read(id[8:]) // crypto/rand.Read never returns an error
	id[0], id[1], id[2] = byte(g.ms>>40), byte(g.ms>>32), byte(g.ms>>24)
	id[3], id[4], id[5] = byte(g.ms>>16), byte(g.ms>>8), byte(g.ms)
	id[6], id[7] = 0x70|byte(g.seq>>8), byte(g.seq)
	id[8] = id[8]&0x3f | 0x80
	h := hex.EncodeToString(id[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
