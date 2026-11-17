package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/recording"
)

// CloseRecordingFailed ends a Strict connection whose recording failed: a
// segment could not be sealed or handed over, the terminal output waited
// strictBackpressure for queue space, or the recorder panicked.
const CloseRecordingFailed = "recording_failed"

// CloseRecordingRequired ends a connection whose resume names a recording that
// a running channel or forwards helper does not have, and refuses a start in
// progress across such a resume.
const CloseRecordingRequired = "recording_required"

// recordingState is how a started channel or forwards helper is recorded.
type recordingState uint8

const (
	// recordingNever: started under an admission that names no recording.
	recordingNever recordingState = iota
	// recordingLive: a recorder is running, or ended normally.
	recordingLive
	// recordingFailed: attempted, and the start or the recorder failed.
	recordingFailed
)

// recordingStateOf is the state of a start that attempted a recording or not
// and holds rec, nil when it runs unrecorded.
func recordingStateOf(rec *sessionRecorder, attempted bool) recordingState {
	switch {
	case rec != nil && rec.failedByError():
		return recordingFailed
	case rec != nil:
		return recordingLive
	case attempted:
		return recordingFailed
	}
	return recordingNever
}

// violatedBy reports whether state cannot run under a: a recording that was
// never attempted, under either policy, or one that failed under Strict.
func (a *connAdmission) violatedBy(state recordingState) bool {
	if a.Rec == nil {
		return false
	}
	return state == recordingNever || (state == recordingFailed && a.Rec.Policy == RecPolicyStrict)
}

const (
	// recorderQueueBytes bounds the terminal output queued for one recorder:
	// two segments' worth. Start, resize and exit events always fit.
	recorderQueueBytes = 2 * recording.MaxPlaintext
)

// Recorder timings, variables so tests shorten them.
var (
	// strictOpenTimeout caps the open a recorded connection sends before any
	// channel, for either policy.
	strictOpenTimeout = 5 * time.Second
	// strictBackpressure is how long Strict terminal output waits for queue
	// space before the recording fails and the session ends.
	strictBackpressure = 5 * time.Second
	// recorderEndTimeout bounds end and abort waiting for the recorder
	// goroutine; past it the recorder is abandoned.
	recorderEndTimeout = 3 * time.Second
)

// wrapRecordingHandoff, when set by a test, wraps the uploader handoff of
// every recording the server starts.
var wrapRecordingHandoff atomic.Pointer[func(recordingHandoff) recordingHandoff]

// errRecordingUnavailable reports a recording that could not start.
var errRecordingUnavailable = errcode.New(errcode.RecordingUnavailable)

// newRecordingSealer makes a recording's sealer; tests replace it.
var newRecordingSealer = recording.NewSealer

// startRecording creates the entry of recording id, one session channel of
// connection sessionID, and hands it to the uploader with the admitting
// certificate, from which the first open creates the recording, and sends that
// open, bounded by strictOpenTimeout. channels is the stream's cumulative
// recorded start count, which the open carries. The entry exists only when it
// returns a recorder. A start that fails with an uploader present queues one
// failed open, as does a later abort of the returned recorder.
func (s *Server) startRecording(id, sessionID string, adm *admission, start time.Time, channels int32) (*sessionRecorder, error) {
	if s.cfg.Uploader == nil || s.cfg.RecordingKey == nil {
		return nil, errRecordingUnavailable.With(nil, "no uploader")
	}
	reportFailed := func(reason string) { s.reportFailedOpen(id, sessionID, adm, reason, channels) }
	key, sum, ok := s.cfg.RecordingKey()
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != adm.Rec.PubSHA256 {
		reportFailed(recording.ReasonRecordingFailed)
		return nil, errRecordingUnavailable.With(nil, "the held recording key changed")
	}
	// Both policies open before the channel's helper starts; the edge attests
	// the live connection, so the control plane checks the certificate at its
	// admission however late the channel starts. strictOpenTimeout bounds the
	// wait.
	strict := adm.Rec.Policy == RecPolicyStrict
	ctx, cancel := context.WithTimeout(context.Background(), strictOpenTimeout)
	defer cancel()
	sealer, err := newRecordingSealer(id, key)
	if err != nil {
		reportFailed(recording.ReasonRecordingFailed)
		return nil, errRecordingUnavailable.With(err, "")
	}
	h, err := s.cfg.Uploader.BeginOpen(ctx, recording.Meta{
		ID:             id,
		SessionID:      sessionID,
		Identifier:     s.cfg.Identifier,
		LastAcceptedAt: start,
		WrappedDEK:     sealer.WrappedDEK(),
		KeySHA256:      sum[:],
		Policy:         adm.Rec.Policy,
		Certificate:    adm.Cert,
		Channels:       channels,
	})
	if err != nil {
		sealer.Discard()
		reportFailed(startFailureReason(err))
		return nil, errRecordingUnavailable.With(err, "")
	}
	var handoff recordingHandoff = h
	if wrap := wrapRecordingHandoff.Load(); wrap != nil {
		handoff = (*wrap)(handoff)
	}
	r := newSessionRecorder(handoff, sealer, strict, s.log)
	r.onAbort = func() { reportFailed(recording.ReasonRecordingFailed) }
	return r, nil
}

// startFailureReason is the reason a failed start reports: a spool refusal
// names itself, anything else, an open timeout included, is recording_failed.
func startFailureReason(err error) string {
	switch {
	case errors.Is(err, recording.ErrSpoolFull):
		return recording.ReasonSpoolFull
	case errors.Is(err, recording.ErrDiskLow):
		return recording.ReasonDiskLow
	}
	return recording.ReasonRecordingFailed
}

// reportFailedOpen queues the failed open of recording id. The key hash is
// the one the certificate names, which the control plane checks the
// signature against.
func (s *Server) reportFailedOpen(id, sessionID string, adm *admission, reason string, channels int32) {
	sum, err := base64.RawURLEncoding.DecodeString(adm.Rec.PubSHA256)
	if err != nil {
		s.log("session: recording %s: failed start not reported: %v", id, err)
		return
	}
	s.cfg.Uploader.ReportFailedOpen(recording.FailedOpen{
		ID: id, SessionID: sessionID, Identifier: s.cfg.Identifier,
		KeySHA256: sum, Certificate: adm.Cert, Reason: reason, Channels: channels,
	})
}

// recordingHandoff is the uploader's side of one recording
// (*recording.Handoff); tests replace it.
type recordingHandoff interface {
	Segment(seg recording.Segment) error
	End(done recording.Completion) error
	Abort() error
}

// sessionRecorder records one session channel. The taps (start, output,
// resize, exit, file) stamp each event and append it to one ordered queue;
// the recorder goroutine (run) owns the writer, segmenter and cut timer and
// makes every handoff and sealing call. Only a Strict output tap on a full
// queue waits for the spool, at most strictBackpressure. Segments are cut at
// recording.SegmentInterval or recording.MaxPlaintext, sealed and handed to
// the uploader; end seals the final segment and hands over the complete
// fields. The taps, end, abort and failedC are safe for concurrent use and
// no-ops on a nil recorder, so an unrecorded session passes nil.
//
// The first close (end, abort, or a failure) decides how the recording ends;
// later ones are no-ops.
type sessionRecorder struct {
	handoff recordingHandoff
	sealer  *recording.Sealer
	strict  bool
	log     func(format string, args ...any)
	// onAbort reports the failed start after abort; nil in tests.
	onAbort func()

	// failed is closed when a Strict recording fails; the server then ends
	// the session with CloseRecordingFailed.
	failed chan struct{}
	// closed is closed by the first close.
	closed chan struct{}
	// wake tells run that an event or a close is queued; space tells a
	// waiting output tap that run took queued output.
	wake  chan struct{}
	space chan struct{}
	// exited is closed when run returns.
	exited chan struct{}
	// abandoned is set when end or abort stopped waiting for run; a segment
	// handoff returning after it makes run end the entry incomplete.
	abandoned atomic.Bool
	// handed and handedChain are the count and chain of the segments the
	// handoff took; run owns them.
	handed      uint32
	handedChain []byte

	mu     sync.Mutex
	queue  []recEvent
	queued int
	how    recClose
	reason string
}

type recEventKind uint8

const (
	evStart recEventKind = iota
	evOutput
	evResize
	evExit
	evFile
	evForward
	// evMarker carries its label in data: a connection detach or attach.
	evMarker
)

// recEvent is one tap, stamped when the terminal produced it.
type recEvent struct {
	kind       recEventKind
	at         time.Time
	data       []byte
	cols, rows uint16
	status     uint32
}

// recClose is how a recording ends; recOpen while it runs.
type recClose uint8

const (
	recOpen recClose = iota
	// recEnd records what is queued, then the final segment.
	recEnd
	// recAbort removes the recording; queued events are dropped.
	recAbort
	// recFail completes the recording incomplete; queued events are dropped.
	recFail
)

// newSessionRecorder starts the recorder goroutine of a begun recording.
func newSessionRecorder(h recordingHandoff, sealer *recording.Sealer, strict bool, log func(string, ...any)) *sessionRecorder {
	r := &sessionRecorder{
		handoff: h, sealer: sealer, strict: strict, log: log,
		failed: make(chan struct{}),
		closed: make(chan struct{}),
		wake:   make(chan struct{}, 1),
		space:  make(chan struct{}, 1),
		exited: make(chan struct{}),
	}
	go r.run()
	return r
}

// failedByError reports whether the recording ended by a failure; a normal
// end or abort is not one.
func (r *sessionRecorder) failedByError() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.how == recFail
}

// failedC delivers the Strict failure; nil, which never fires, without one.
func (r *sessionRecorder) failedC() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.failed
}

// start begins the asciicast at at with a cols x rows terminal.
func (r *sessionRecorder) start(at time.Time, cols, rows uint16) {
	r.enqueue(recEvent{kind: evStart, at: at, cols: cols, rows: rows})
}

// output queues a copy of p. When the queue holds recorderQueueBytes, a
// Best effort recording fails at once and a Strict tap waits for space, at
// most strictBackpressure, then fails the recording. The wait also ends when
// halt closes (the session is ending) or the recording closes.
func (r *sessionRecorder) output(p []byte, halt <-chan struct{}) {
	r.tap(evOutput, p, halt)
}

// file queues one files-log event (a validated launcher.FileEvent in JSON)
// under the same bounds as output.
func (r *sessionRecorder) file(event []byte, halt <-chan struct{}) {
	r.tap(evFile, event, halt)
}

// forward queues one port forward event (a forwardEvent in JSON) under the
// same bounds as output.
func (r *sessionRecorder) forward(event []byte, halt <-chan struct{}) {
	r.tap(evForward, event, halt)
}

// tap queues a copy of p as an event of kind, bounded by recorderQueueBytes.
func (r *sessionRecorder) tap(kind recEventKind, p []byte, halt <-chan struct{}) {
	if r == nil {
		return
	}
	at := time.Now()
	var ev recEvent
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		r.mu.Lock()
		if r.how != recOpen {
			r.mu.Unlock()
			return
		}
		if r.queued == 0 || r.queued+len(p) <= recorderQueueBytes {
			if ev.data == nil {
				ev = recEvent{kind: kind, at: at, data: bytes.Clone(p)}
			}
			r.queue = append(r.queue, ev)
			r.queued += len(p)
			r.mu.Unlock()
			r.poke()
			return
		}
		if !r.strict {
			r.closeLocked(recFail, recording.ReasonRecordingFailed)
			r.mu.Unlock()
			r.log("session: recording %s stopped (%s): the recording queue is full", r.sealer.ID(), recording.ReasonRecordingFailed)
			return
		}
		r.mu.Unlock()
		if timer == nil {
			timer = time.NewTimer(strictBackpressure)
		}
		select {
		case <-r.space:
		case <-r.closed:
		case <-halt:
			return
		case <-timer.C:
			r.closeWith(recFail, recording.ReasonRecordingFailed)
			r.log("session: recording %s stopped (%s): channel output waited %v for the recording queue", r.sealer.ID(), recording.ReasonRecordingFailed, strictBackpressure)
			return
		}
	}
}

func (r *sessionRecorder) resize(cols, rows uint16) {
	r.enqueue(recEvent{kind: evResize, at: time.Now(), cols: cols, rows: rows})
}

func (r *sessionRecorder) exit(status uint32) {
	r.enqueue(recEvent{kind: evExit, at: time.Now(), status: status})
}

// Marker labels: a resumable connection's stream changes, and the close of a
// recording whose shell did not exit.
const (
	markerDetach = "detach"
	markerAttach = "attach"
	markerEnd    = "end"
)

// marker queues an asciicast marker; it always fits, like resize.
func (r *sessionRecorder) marker(label string) {
	r.enqueue(recEvent{kind: evMarker, at: time.Now(), data: []byte(label)})
}

// enqueue appends an event that always fits. A resize queued right after
// another replaces it, so resizes cannot grow a stalled queue past one per
// queued output.
func (r *sessionRecorder) enqueue(ev recEvent) {
	if r == nil {
		return
	}
	r.mu.Lock()
	open := r.how == recOpen
	switch {
	case !open:
	case ev.kind == evResize && len(r.queue) > 0 && r.queue[len(r.queue)-1].kind == evResize:
		r.queue[len(r.queue)-1] = ev
	default:
		r.queue = append(r.queue, ev)
	}
	r.mu.Unlock()
	if open {
		r.poke()
	}
}

func (r *sessionRecorder) poke() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// end seals the final segment (what is queued and buffered, with the
// partial-sequence flush and the end marker when the shell did not exit, or
// an empty plaintext)
// and hands over the complete fields. It runs after the kind's last tap.
func (r *sessionRecorder) end() { r.closeAndWait(recEnd) }

// abort removes the recording of a session refused after it started.
func (r *sessionRecorder) abort() {
	if r == nil {
		return
	}
	r.closeAndWait(recAbort)
	if r.onAbort != nil {
		r.onAbort()
	}
}

// closeAndWait closes the recording with how and waits for run, at most
// recorderEndTimeout. Past that the recorder is abandoned: the session never
// calls into the handoff itself, so a handoff blocked on the spool does not
// hold the session's end.
func (r *sessionRecorder) closeAndWait(how recClose) {
	if r == nil {
		return
	}
	r.closeWith(how, "")
	timer := time.NewTimer(recorderEndTimeout)
	defer timer.Stop()
	select {
	case <-r.exited:
	case <-timer.C:
		r.abandoned.Store(true)
		r.log("session: recording %s abandoned: its final segment was not handed over within %v", r.sealer.ID(), recorderEndTimeout)
	}
}

func (r *sessionRecorder) closeWith(how recClose, reason string) {
	r.mu.Lock()
	r.closeLocked(how, reason)
	r.mu.Unlock()
}

// closeLocked records the first close; a Strict failure also ends the
// session.
func (r *sessionRecorder) closeLocked(how recClose, reason string) {
	if r.how != recOpen {
		return
	}
	r.how, r.reason = how, reason
	if how != recEnd {
		r.queue, r.queued = nil, 0
	}
	close(r.closed)
	if how == recFail && r.strict {
		close(r.failed)
	}
	r.poke()
}

// next pops the next event to record. ok is false when there is none: the
// recording is still open with an empty queue, or it closed with how and
// reason and has nothing left to record.
func (r *sessionRecorder) next() (ev recEvent, how recClose, reason string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.how == recAbort || r.how == recFail || len(r.queue) == 0 {
		return recEvent{}, r.how, r.reason, false
	}
	ev = r.queue[0]
	r.queue[0] = recEvent{}
	r.queue = r.queue[1:]
	if ev.kind == evOutput || ev.kind == evFile || ev.kind == evForward {
		r.queued -= len(ev.data)
		select {
		case r.space <- struct{}{}:
		default:
		}
	}
	return ev, r.how, r.reason, true
}

// recorderState is the asciicast state run owns. w and seg are nil until
// the start event.
type recorderState struct {
	w      *recording.Writer
	seg    *recording.Segmenter
	exited bool
	timer  *time.Timer
	due    time.Time
}

// run records the queued events until the recording closes. It is the only
// caller of the handoff and of the sealer's sealing methods.
func (r *sessionRecorder) run() {
	defer close(r.exited)
	st := &recorderState{}
	defer func() {
		if st.timer != nil {
			st.timer.Stop()
		}
	}()
	defer func() {
		if p := recover(); p != nil {
			r.log("session: recording %s panic: %v", r.sealer.ID(), p)
			r.closeWith(recFail, recording.ReasonRecordingFailed)
			r.stop(recording.ReasonRecordingFailed)
		}
	}()
	for {
		ev, how, reason, ok := r.next()
		switch {
		case ok:
			if !r.record(st, ev) {
				return
			}
			continue
		case how == recAbort:
			r.sealer.Discard()
			if err := r.handoff.Abort(); err != nil {
				r.log("session: recording %s not removed: %v", r.sealer.ID(), err)
			}
			return
		case how == recFail:
			r.stop(reason)
			return
		case how == recEnd:
			r.finish(st)
			return
		}
		var cut <-chan time.Time
		if st.timer != nil {
			cut = st.timer.C
		}
		select {
		case <-r.wake:
		case <-cut:
			st.due = time.Time{}
			if c := st.seg.Cut(time.Now()); c != nil && !r.seal(c, false) {
				return
			}
			r.arm(st)
		}
	}
}

// record adds one event to the asciicast; false means the recording stopped.
func (r *sessionRecorder) record(st *recorderState, ev recEvent) bool {
	switch ev.kind {
	case evStart:
		if st.w == nil {
			st.w = recording.NewWriter(ev.at, ev.cols, ev.rows)
			st.seg = recording.NewSegmenter(st.w.Header())
		}
		return true
	case evOutput:
		if st.w != nil {
			return r.add(st, ev.at, st.w.Output(ev.at, ev.data)...)
		}
	case evResize:
		if st.w != nil {
			return r.add(st, ev.at, st.w.Resize(ev.at, ev.cols, ev.rows))
		}
	case evExit:
		if st.w != nil && !st.exited {
			st.exited = true
			return r.add(st, ev.at, st.w.Exit(ev.at, ev.status)...)
		}
	case evFile:
		if st.w != nil {
			return r.add(st, ev.at, st.w.File(ev.at, ev.data))
		}
	case evForward:
		if st.w != nil {
			return r.add(st, ev.at, st.w.Forward(ev.at, ev.data))
		}
	case evMarker:
		if st.w != nil {
			return r.add(st, ev.at, st.w.Marker(ev.at, string(ev.data)))
		}
	}
	return true
}

// add appends lines and seals the segment each cut returns, then arms the
// cut timer for the open segment.
func (r *sessionRecorder) add(st *recorderState, at time.Time, lines ...[]byte) bool {
	for _, line := range lines {
		if cut := st.seg.Add(at, line); cut != nil && !r.seal(cut, false) {
			return false
		}
	}
	r.arm(st)
	return true
}

func (r *sessionRecorder) arm(st *recorderState) {
	due, ok := st.seg.Deadline()
	if !ok || due.Equal(st.due) {
		return
	}
	st.due = due
	if st.timer == nil {
		st.timer = time.NewTimer(time.Until(due))
		return
	}
	st.timer.Reset(time.Until(due))
}

// seal seals plaintext and hands it over. A refusal, a close by failure or
// an abandonment while the handoff ran stops the recording and returns false.
func (r *sessionRecorder) seal(plaintext []byte, final bool) bool {
	seg, err := r.sealer.Seal(plaintext, final)
	if err == nil {
		err = r.handoff.Segment(seg)
	}
	if err != nil {
		reason := recording.ReasonRecordingFailed
		switch {
		case r.strict:
		case errors.Is(err, recording.ErrSpoolFull):
			reason = recording.ReasonSpoolFull
		case errors.Is(err, recording.ErrDiskLow):
			reason = recording.ReasonDiskLow
		}
		r.log("session: recording %s stopped (%s): %v", r.sealer.ID(), reason, err)
		r.closeWith(recFail, reason)
		r.stop(reason)
		return false
	}
	r.handed, r.handedChain = r.sealer.Sealed(), r.sealer.FinalHash()
	if r.abandoned.Load() {
		r.stop(recording.ReasonRecordingFailed)
		return false
	}
	r.mu.Lock()
	how, reason := r.how, r.reason
	r.mu.Unlock()
	if how == recFail {
		r.stop(reason)
		return false
	}
	return true
}

// stop ends the recording early at the segments the handoff took,
// completing it incomplete with reason, and discards the DEK.
func (r *sessionRecorder) stop(reason string) {
	r.sealer.Discard()
	if err := r.handoff.End(recording.Completion{
		Segments: r.handed, FinalHash: r.handedChain, EndedAt: time.Now(), Incomplete: true, Reason: reason,
	}); err != nil && !errors.Is(err, recording.ErrNoEntry) {
		r.log("session: recording %s end: %v", r.sealer.ID(), err)
	}
}

// finish seals the final segment and hands over the complete fields. When
// the shell did not exit, the recording ends with the partial-sequence flush
// and an end marker at the close time, so its length is the session's.
func (r *sessionRecorder) finish(st *recorderState) {
	at := time.Now()
	var final []byte
	if st.w != nil {
		if !st.exited {
			lines := [][]byte{st.w.Flush(at), st.w.Marker(at, markerEnd)}
			for _, line := range lines {
				if line == nil {
					continue
				}
				if cut := st.seg.Add(at, line); cut != nil && !r.seal(cut, false) {
					return
				}
			}
		}
		final = st.seg.Flush()
	}
	if !r.seal(final, true) {
		return
	}
	if err := r.handoff.End(recording.Completion{
		Segments: r.sealer.Sealed(), FinalHash: r.sealer.FinalHash(), EndedAt: at, Final: true,
	}); err != nil && !errors.Is(err, recording.ErrNoEntry) {
		r.log("session: recording %s end: %v", r.sealer.ID(), err)
	}
}
