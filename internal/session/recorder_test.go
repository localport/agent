package session

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/localport/agent/internal/recording"
	"golang.org/x/crypto/chacha20poly1305"
)

// fakeHandoff records what the recorder hands over; refuse, when set,
// answers each Segment from its index on.
type fakeHandoff struct {
	mu       sync.Mutex
	segs     []recording.Segment
	done     *recording.Completion
	aborted  bool
	refuseAt int
	refuse   error
}

func (f *fakeHandoff) Segment(seg recording.Segment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse != nil && int(seg.Index) >= f.refuseAt {
		return f.refuse
	}
	f.segs = append(f.segs, seg)
	return nil
}

// End checks the count and chain against the taken segments.
func (f *fakeHandoff) End(done recording.Completion) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if int(done.Segments) != len(f.segs) {
		return fmt.Errorf("%w: end with %d segments, %d taken", recording.ErrHandoff, done.Segments, len(f.segs))
	}
	var chain []byte
	for _, seg := range f.segs {
		chain = recording.ChainStep(chain, seg.Hash)
	}
	if !bytes.Equal(done.FinalHash, chain) {
		return fmt.Errorf("%w: end with a final hash other than the chain of the taken segments", recording.ErrHandoff)
	}
	f.done = &done
	return nil
}

func (f *fakeHandoff) Abort() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aborted = true
	return nil
}

const testRecordingID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

func newTestRecorder(t *testing.T, policy string, h recordingHandoff) (*sessionRecorder, hpke.PrivateKey) {
	t.Helper()
	priv, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := recording.NewSealer(testRecordingID, priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return newSessionRecorder(h, sealer, policy == RecPolicyStrict, t.Logf), priv
}

// decryptRecording opens every segment with the shared parameters and
// returns the asciicast text.
func decryptRecording(t *testing.T, priv hpke.PrivateKey, wrapped []byte, segs []recording.Segment) string {
	t.Helper()
	dek, err := hpke.Open(priv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), append([]byte("localport-recording-v1"), testRecordingID...), wrapped)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(dek)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, s := range segs {
		nonce := make([]byte, chacha20poly1305.NonceSize)
		binary.BigEndian.PutUint32(nonce[8:], s.Index)
		aad := binary.BigEndian.AppendUint32([]byte(testRecordingID), s.Index)
		f := byte(0)
		if s.Final {
			f = 1
		}
		aad = append(aad, f, s.Object[0], s.Object[1])
		plain, err := aead.Open(nil, nonce, s.Object[2:], aad)
		if err != nil {
			t.Fatalf("segment %d: %v", s.Index, err)
		}
		if s.Object[1] == recording.CodecDeflate {
			if plain, err = io.ReadAll(flate.NewReader(bytes.NewReader(plain))); err != nil {
				t.Fatalf("segment %d: inflate: %v", s.Index, err)
			}
		}
		out.Write(plain)
	}
	return out.String()
}

// A recorded session decrypts to an asciicast whose lines parse: the header,
// output, resize and exit; the last segment carries the final flag and the
// complete is not incomplete.
func TestRecorderRecordsADecryptableSession(t *testing.T) {
	h := &fakeHandoff{}
	r, priv := newTestRecorder(t, RecPolicyBestEffort, h)
	r.start(time.Now(), 80, 24)
	r.output([]byte("hello\r\n"), nil)
	r.resize(100, 30)
	r.exit(0)
	r.end()
	r.output([]byte("after the end"), nil)
	if len(h.segs) == 0 || !h.segs[len(h.segs)-1].Final || h.done == nil || h.done.Incomplete || !h.done.Final || int(h.done.Segments) != len(h.segs) {
		t.Fatalf("segments %d, completion %+v; want a final segment and a clean complete", len(h.segs), h.done)
	}
	text := decryptRecording(t, priv, r.sealer.WrappedDEK(), h.segs)
	lines := bytes.Split(bytes.TrimSuffix([]byte(text), []byte("\n")), []byte("\n"))
	if len(lines) != 4 {
		t.Fatalf("asciicast %q: want header, o, r, x", text)
	}
	for i, want := range []string{"", "o", "r", "x"} {
		var v any
		if err := json.Unmarshal(lines[i], &v); err != nil {
			t.Fatalf("line %d %q: %v", i, lines[i], err)
		}
		if ev, ok := v.([]any); want != "" && (!ok || len(ev) != 3 || ev[1] != want) {
			t.Fatalf("line %d %q: want event %q", i, lines[i], want)
		}
	}
}

// A session that ends with nothing buffered still seals a final segment:
// an empty plaintext, the 18-byte object.
func TestRecorderSealsAnEmptyFinalSegment(t *testing.T) {
	h := &fakeHandoff{}
	r, _ := newTestRecorder(t, RecPolicyBestEffort, h)
	r.end()
	if len(h.segs) != 1 || !h.segs[0].Final || len(h.segs[0].Object) != 18 || h.done == nil || !h.done.Final || h.done.Segments != 1 {
		t.Fatalf("segments %+v, completion %+v; want one empty final segment", h.segs, h.done)
	}
}

// Best effort: a spool refusal stops the recording, completes it incomplete
// with the refusal's reason at the segments taken, and leaves the session
// running. Strict: the same refusal ends the session with recording_failed.
func TestRecorderStopsOnASpoolRefusal(t *testing.T) {
	for _, c := range []struct {
		policy, reason string
		refuse         error
		fails          bool
	}{
		{RecPolicyBestEffort, recording.ReasonSpoolFull, recording.ErrSpoolFull, false},
		{RecPolicyBestEffort, recording.ReasonDiskLow, recording.ErrDiskLow, false},
		{RecPolicyStrict, recording.ReasonRecordingFailed, recording.ErrSpoolFull, true},
	} {
		t.Run(c.policy+"/"+c.reason, func(t *testing.T) {
			h := &fakeHandoff{refuseAt: 1, refuse: c.refuse}
			r, _ := newTestRecorder(t, c.policy, h)
			r.start(time.Now(), 80, 24)
			big := bytes.Repeat([]byte("x"), recording.MaxLine/2)
			for range 8 {
				r.output(big, nil)
				waitQueueEmpty(t, r)
			}
			if c.fails {
				select {
				case <-r.failedC():
				case <-time.After(5 * time.Second):
					t.Fatal("a Strict stop did not end the session")
				}
			}
			r.end()
			select {
			case <-r.failedC():
				if !c.fails {
					t.Fatal("a Best effort stop ended the session")
				}
			default:
			}
			if len(h.segs) != 1 || h.done == nil || !h.done.Incomplete || h.done.Final || h.done.Reason != c.reason || h.done.Segments != 1 || !bytes.Equal(h.done.FinalHash, recording.ChainStep(nil, h.segs[0].Hash)) {
				t.Fatalf("segments %d, completion %+v; want incomplete %s at 1 segment", len(h.segs), h.done, c.reason)
			}
			if _, err := r.sealer.Seal(nil, true); !errors.Is(err, recording.ErrSealed) {
				t.Fatalf("Seal after the stop: %v, want ErrSealed (DEK discarded)", err)
			}
		})
	}
}

func TestRecorderAbortDiscardsTheDEK(t *testing.T) {
	h := &fakeHandoff{}
	r, _ := newTestRecorder(t, RecPolicyBestEffort, h)
	r.start(time.Now(), 80, 24)
	r.output([]byte("hello"), nil)
	r.abort()
	if !h.aborted {
		t.Fatal("abort did not reach the handoff")
	}
	select {
	case <-r.exited:
	default:
		t.Fatal("the recorder goroutine runs after abort")
	}
	if _, err := r.sealer.Seal(nil, true); !errors.Is(err, recording.ErrSealed) {
		t.Fatalf("Seal after abort: %v, want ErrSealed (DEK discarded)", err)
	}
}

// stallHandoff blocks every Segment until release is closed; entered is
// closed when the first Segment call arrives.
type stallHandoff struct {
	fakeHandoff
	entered     chan struct{}
	enteredOnce sync.Once
	release     chan struct{}
}

func newStallHandoff() *stallHandoff {
	return &stallHandoff{entered: make(chan struct{}), release: make(chan struct{})}
}

func (h *stallHandoff) Segment(seg recording.Segment) error {
	h.enteredOnce.Do(func() { close(h.entered) })
	<-h.release
	return h.fakeHandoff.Segment(seg)
}

func (h *stallHandoff) unblock() {
	select {
	case <-h.release:
	default:
		close(h.release)
	}
}

// stallRecorder starts a recorder on a stalled handoff and fills it until
// its goroutine is blocked in the first Segment and the queue is full. The
// cleanup releases the handoff and waits for the goroutine.
func stallRecorder(t *testing.T, policy string) (*sessionRecorder, *stallHandoff, []byte) {
	t.Helper()
	h := newStallHandoff()
	r, _ := newTestRecorder(t, policy, h)
	t.Cleanup(func() {
		h.unblock()
		r.end()
		<-r.exited
	})
	r.start(time.Now(), 80, 24)
	chunk := bytes.Repeat([]byte("x"), maxTerminalOutput)
	for range recording.MaxPlaintext/len(chunk) + 1 {
		r.output(chunk, nil)
	}
	select {
	case <-h.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the recorder did not cut its first segment")
	}
	for queued(r)+len(chunk) <= recorderQueueBytes {
		r.output(chunk, nil)
	}
	return r, h, chunk
}

func queued(r *sessionRecorder) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.queued
}

// waitQueueEmpty waits until the recorder goroutine took every queued event.
func waitQueueEmpty(t *testing.T, r *sessionRecorder) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		empty := len(r.queue) == 0 || r.how != recOpen
		r.mu.Unlock()
		if empty {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the recorder did not take its queued events")
		}
		time.Sleep(time.Millisecond)
	}
}

// Once the handoff stalls and the queue is full, Best effort output never
// waits and the recording stops with the session running; Strict output
// waits strictBackpressure, then the session ends with recording_failed.
func TestRecorderBackpressureOnAStalledHandoff(t *testing.T) {
	t.Run("best effort", func(t *testing.T) {
		r, _, chunk := stallRecorder(t, RecPolicyBestEffort)
		began := time.Now()
		r.output(chunk, nil)
		if took := time.Since(began); took > time.Second {
			t.Fatalf("Best effort output waited %v on a full queue", took)
		}
		select {
		case <-r.closed:
		default:
			t.Fatal("a full Best effort queue did not stop the recording")
		}
		select {
		case <-r.failedC():
			t.Fatal("a Best effort stop ended the session")
		default:
		}
	})
	t.Run("strict", func(t *testing.T) {
		old := strictBackpressure
		strictBackpressure = 300 * time.Millisecond
		t.Cleanup(func() { strictBackpressure = old })
		r, _, chunk := stallRecorder(t, RecPolicyStrict)
		returned := make(chan time.Duration, 1)
		began := time.Now()
		go func() {
			r.output(chunk, nil)
			returned <- time.Since(began)
		}()
		select {
		case took := <-returned:
			if took < strictBackpressure {
				t.Fatalf("Strict output returned after %v, before its %v bound", took, strictBackpressure)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Strict output still waits past its bound")
		}
		select {
		case <-r.failedC():
		default:
			t.Fatal("the Strict timeout did not end the session")
		}
	})
}

// A Strict output tap waiting for queue space returns as soon as the
// session's end path closes halt.
func TestRecorderStrictWaitEndsWithTheSession(t *testing.T) {
	r, _, chunk := stallRecorder(t, RecPolicyStrict)
	halt := make(chan struct{})
	returned := make(chan struct{})
	go func() {
		r.output(chunk, halt)
		close(returned)
	}()
	select {
	case <-returned:
		t.Fatal("output did not wait on a full Strict queue")
	case <-time.After(100 * time.Millisecond):
	}
	close(halt)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("the Strict wait did not end with the session")
	}
}

// Events queued behind a stalled handoff keep their order and the times
// they were tapped at.
func TestRecorderKeepsOrderAndTimesThroughABacklog(t *testing.T) {
	h := newStallHandoff()
	r, priv := newTestRecorder(t, RecPolicyBestEffort, h)
	t.Cleanup(h.unblock)
	began := time.Now()
	r.start(began, 80, 24)
	r.output(bytes.Repeat([]byte("x"), recording.MaxPlaintext), nil)
	select {
	case <-h.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the recorder did not cut its first segment")
	}
	r.output([]byte("first"), nil)
	time.Sleep(100 * time.Millisecond)
	r.resize(100, 30)
	time.Sleep(100 * time.Millisecond)
	r.output([]byte("second"), nil)
	tapped := time.Since(began)
	time.Sleep(300 * time.Millisecond)
	h.unblock()
	r.end()

	text := decryptRecording(t, priv, r.sealer.WrappedDEK(), h.segs)
	var events []string
	var times []int64
	var elapsed float64
	for _, line := range bytes.Split(bytes.TrimSuffix([]byte(text), []byte("\n")), []byte("\n"))[1:] {
		var ev []any
		if err := json.Unmarshal(line, &ev); err != nil || len(ev) != 3 {
			t.Fatalf("line %q: %v", line, err)
		}
		elapsed += ev[0].(float64)
		if data, _ := ev[2].(string); data == "first" || data == "second" || ev[1] == "r" {
			events = append(events, ev[1].(string)+":"+data)
			times = append(times, int64(elapsed*1000))
		}
	}
	if want := []string{"o:first", "r:100x30", "o:second"}; len(events) != 3 || events[0] != want[0] || events[1] != want[1] || events[2] != want[2] {
		t.Fatalf("events %q, want %q", events, want)
	}
	if times[1]-times[0] < 90 || times[2]-times[1] < 90 {
		t.Fatalf("event times %v ms: want the 100 ms gaps they were tapped at", times)
	}
	if times[2] > tapped.Milliseconds()+50 {
		t.Fatalf("the last event is at %d ms, later than it was tapped at %v", times[2], tapped)
	}
}

// end returns within recorderEndTimeout while the handoff is stalled; once
// the stalled call returns, the abandoned recorder ends the entry
// incomplete and exits.
func TestRecorderEndIsBoundedOnAStalledHandoff(t *testing.T) {
	old := recorderEndTimeout
	recorderEndTimeout = 200 * time.Millisecond
	t.Cleanup(func() { recorderEndTimeout = old })
	h := newStallHandoff()
	r, _ := newTestRecorder(t, RecPolicyBestEffort, h)
	t.Cleanup(h.unblock)
	r.start(time.Now(), 80, 24)
	r.output([]byte("hello"), nil)
	ended := make(chan time.Duration, 1)
	began := time.Now()
	go func() {
		r.end()
		ended <- time.Since(began)
	}()
	select {
	case took := <-ended:
		if took < recorderEndTimeout {
			t.Fatalf("end returned after %v with the final segment not handed over", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("end still waits on a stalled handoff")
	}
	h.unblock()
	select {
	case <-r.exited:
	case <-time.After(5 * time.Second):
		t.Fatal("the abandoned recorder did not exit")
	}
	if h.done == nil || !h.done.Incomplete || h.done.Final || h.done.Reason != recording.ReasonRecordingFailed {
		t.Fatalf("completion %+v, want incomplete %s", h.done, recording.ReasonRecordingFailed)
	}
}

// Resizes queued behind a stalled handoff collapse into the latest one, so
// they cannot grow the queue without output between them.
func TestRecorderCollapsesQueuedResizes(t *testing.T) {
	r, _, _ := stallRecorder(t, RecPolicyBestEffort)
	r.mu.Lock()
	n := len(r.queue)
	r.mu.Unlock()
	for i := range 1000 {
		r.resize(uint16(80+i%50), 24)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queue) != n+1 || r.queue[n].kind != evResize || r.queue[n].cols != 80+999%50 {
		t.Fatalf("queue %d events after 1000 resizes, want %d ending with the last resize", len(r.queue), n+1)
	}
}

// panicHandoff panics on every Segment.
type panicHandoff struct{ fakeHandoff }

func (h *panicHandoff) Segment(recording.Segment) error { panic("test handoff") }

// A panic in the recorder goroutine stops the recording as a handoff
// failure does: the entry ends incomplete and a Strict session ends.
func TestRecorderPanicIsAHandoffFailure(t *testing.T) {
	h := &panicHandoff{}
	r, _ := newTestRecorder(t, RecPolicyStrict, h)
	r.start(time.Now(), 80, 24)
	r.output(bytes.Repeat([]byte("x"), recording.MaxPlaintext), nil)
	select {
	case <-r.failedC():
	case <-time.After(5 * time.Second):
		t.Fatal("the panic did not end the Strict session")
	}
	r.end()
	select {
	case <-r.exited:
	default:
		t.Fatal("the recorder goroutine runs after the panic")
	}
	if h.done == nil || !h.done.Incomplete || h.done.Reason != recording.ReasonRecordingFailed {
		t.Fatalf("completion %+v, want incomplete %s", h.done, recording.ReasonRecordingFailed)
	}
}

// blockingClient holds every open until its context ends.
type blockingClient struct{ opened chan struct{} }

func (c *blockingClient) Open(ctx context.Context, _ string, _, _ []byte) (recording.Result, error) {
	close(c.opened)
	<-ctx.Done()
	return recording.Result{}, ctx.Err()
}

func (c *blockingClient) Complete(context.Context, string, []byte, recording.Completion) (recording.Result, error) {
	return recording.Result{}, errors.New("unexpected complete")
}

func (c *blockingClient) PutSegment(context.Context, string, recording.Segment) (recording.Result, error) {
	return recording.Result{}, errors.New("unexpected segment")
}

func (c *blockingClient) PutSpooledSegment(context.Context, string, recording.Segment) (recording.Result, error) {
	return recording.Result{}, errors.New("unexpected segment")
}

// A Strict open slower than the first-frame budget refuses the session
// recording_unavailable inside the edge's 10 s, before the accept frame: no
// kind starts, no spool entry stays, and the ticket is spent.
func TestServeRefusesAStrictSessionWhoseOpenIsLate(t *testing.T) {
	root := t.TempDir()
	spool, _, err := recording.OpenSpool(root, filepath.Join(root, "recordings"), false)
	if err != nil {
		t.Fatal(err)
	}
	client := &blockingClient{opened: make(chan struct{})}
	up := recording.NewUploader(recording.UploaderConfig{
		Spool:      spool,
		Client:     func(string) (recording.Client, error) { return client, nil },
		Configured: func(string) bool { return true },
	})
	priv, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	sum := sha256.Sum256(pub)
	ts := newTestKindServer(t, func(cfg *ServerConfig) {
		cfg.Capabilities = []string{"terminal"}
		cfg.RecordingKey = func() ([]byte, [sha256.Size]byte, bool) { return pub, sum, true }
		cfg.Uploader = up
		cfg.Identifier = "client.device"
	})
	terminal := ts.kinds("terminal")
	ts.kinds = func(string) prepareKind { return terminal }
	raw := ts.ticket(t, func(p *Ticket) {
		p.JTI = recJTI
		p.Rec = testRec(recJTI)
		p.Rec.PubSHA256 = base64.RawURLEncoding.EncodeToString(sum[:])
		p.Rec.Policy = RecPolicyStrict
	})
	began := time.Now()
	if got := ts.refusal(t, raw); got != CodeRecordingUnavailable {
		t.Fatalf("answered %q, want %q", got, CodeRecordingUnavailable)
	}
	if took := time.Since(began); took >= firstFrameTimeout-time.Second {
		t.Fatalf("refused after %v, want inside the first-frame budget", took)
	}
	select {
	case <-client.opened:
	default:
		t.Fatal("the Strict open was not sent")
	}
	select {
	case <-ts.made:
		t.Fatal("a kind started for a refused Strict session")
	default:
	}
	if entries, err := os.ReadDir(filepath.Join(root, "recordings")); err != nil || len(entries) != 0 {
		t.Fatalf("spool holds %v, %v; want nothing", entries, err)
	}
	if !ts.spent(recJTI) {
		t.Fatal("the ticket is not spent")
	}
}
