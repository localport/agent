//go:build linux || darwin

package session

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/recording"
)

func waitChannelStarted(t *testing.T, s *Server) *channel {
	t.Helper()
	e := onlyConn(t, s)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ch := startedChannel(s, e); ch != nil {
			return ch
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no channel started")
	return nil
}

func startedChannel(s *Server, e *resumable) *channel {
	s.mu.Lock()
	c := e.conn
	s.mu.Unlock()
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for ch := range c.channels {
		ch.mu.Lock()
		started := ch.started
		ch.mu.Unlock()
		if started {
			return ch
		}
	}
	return nil
}

func wantConnectionEnded(t *testing.T, f *sshFixture) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f.srv.LiveSessions() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the connection did not end")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// startHeldChannel starts a helper that stays running and returns its channel.
func startHeldChannel(t *testing.T, f *sshFixture, rc *resumeConn) *channel {
	t.Helper()
	s, err := rc.client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start("hold"); err != nil {
		t.Fatal(err)
	}
	return waitChannelStarted(t, f.srv)
}

func withRec(rec *certRec) func(*certOpts) {
	return func(o *certOpts) { o.kind, o.rec = "ssh", rec }
}

// A channel started under an admission with no recording ends the connection
// at a resume that names one, under either policy.
func TestAResumeNamingARecordingEndsANeverRecordedChannel(t *testing.T) {
	for _, policy := range []string{RecPolicyStrict, RecPolicyBestEffort} {
		t.Run(policy, func(t *testing.T) {
			client := &captureClient{opens: make(chan capturedOpen, 2)}
			f, keySum, _ := recordingFixture(t, client)
			o := f.defaults()
			o.kind = "ssh"
			rc := f.connectResumableAs(t, o)
			startHeldChannel(t, f, rc)
			rc.cut(t)
			if err := rc.resume(t, withRec(&certRec{Policy: policy, PubSHA256: keySum})); resumeCode(err) != CloseResumeLost {
				t.Fatalf("resume = %v, want %s", err, CloseResumeLost)
			}
			wantConnectionEnded(t, f)
		})
	}
}

// A forwards helper with no recording is the same.
func TestAResumeNamingARecordingEndsANeverRecordedForward(t *testing.T) {
	for _, policy := range []string{RecPolicyStrict, RecPolicyBestEffort} {
		t.Run(policy, func(t *testing.T) {
			client := &captureClient{opens: make(chan capturedOpen, 2)}
			f, keySum, _ := recordingFixture(t, client)
			f.cfg.Capabilities = []string{"terminal", "forwarding"}
			f.srv = NewServer(*f.cfg)
			serveForwards(t, f.launcher)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = f.srv.Shutdown(ctx)
			})
			tcp := echoServer(t, "tcp", "127.0.0.1:0")
			rc := f.connectResumableAs(t, f.forwardOpts(true, false))
			fc, err := rc.client.Dial("tcp", tcp.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			pingPong(t, fc)
			rc.cut(t)
			err = rc.resume(t, func(o *certOpts) {
				o.kind, o.fwdLocal, o.rec = "ssh", true, &certRec{Policy: policy, PubSHA256: keySum}
			})
			if resumeCode(err) != CloseResumeLost {
				t.Fatalf("resume = %v, want %s", err, CloseResumeLost)
			}
			wantConnectionEnded(t, f)
		})
	}
}

// recordedResumeCase connects a Best effort recorded connection with one
// running channel, edits that channel, and resumes under policy.
func recordedResumeCase(t *testing.T, sealerFails bool, edit func(*channel), policy string) (*sshFixture, *resumeConn, error) {
	t.Helper()
	savedSealer := newRecordingSealer
	if sealerFails {
		newRecordingSealer = func(string, []byte) (*recording.Sealer, error) { return nil, errors.New("no sealer") }
	}
	t.Cleanup(func() { newRecordingSealer = savedSealer })
	client := &captureClient{opens: make(chan capturedOpen, 2), failedOpens: make(chan recording.FailedOpen, 2)}
	f, keySum, _ := recordingFixture(t, client)
	o := f.defaults()
	o.kind, o.rec = "ssh", &certRec{Policy: RecPolicyBestEffort, PubSHA256: keySum}
	rc := f.connectResumableAs(t, o)
	ch := startHeldChannel(t, f, rc)
	if edit != nil {
		edit(ch)
	}
	rc.cut(t)
	return f, rc, rc.resume(t, withRec(&certRec{Policy: policy, PubSHA256: keySum}))
}

// A recording that failed, at the start or mid-stream, ends the connection at
// a Strict resume and survives a Best effort one.
func TestAResumeWithAFailedRecording(t *testing.T) {
	failMidStream := func(ch *channel) {
		ch.mu.Lock()
		rec := ch.rec
		ch.mu.Unlock()
		rec.closeWith(recFail, recording.ReasonRecordingFailed)
	}
	for _, tc := range []struct {
		name        string
		sealerFails bool
		edit        func(*channel)
	}{{"failed start", true, nil}, {"failed mid-stream", false, failMidStream}} {
		t.Run(tc.name+"/strict", func(t *testing.T) {
			f, _, err := recordedResumeCase(t, tc.sealerFails, tc.edit, RecPolicyStrict)
			if resumeCode(err) != CloseResumeLost {
				t.Fatalf("resume = %v, want %s", err, CloseResumeLost)
			}
			wantConnectionEnded(t, f)
		})
		t.Run(tc.name+"/best effort", func(t *testing.T) {
			_, rc, err := recordedResumeCase(t, tc.sealerFails, tc.edit, RecPolicyBestEffort)
			if err != nil || !rc.alive() {
				t.Fatalf("resume = %v, alive %v", err, rc.alive())
			}
		})
	}
}

// Live recordings resume under Strict.
func TestAResumeWithLiveRecordingsContinues(t *testing.T) {
	_, rc, err := recordedResumeCase(t, false, nil, RecPolicyStrict)
	if err != nil || !rc.alive() {
		t.Fatalf("resume = %v, alive %v", err, rc.alive())
	}
}

// Only a running forwards helper counts: none started, or one that ended, does
// not meet a resume that names a recording.
func TestForwarderRecordingViolationNeedsARunningHelper(t *testing.T) {
	s := NewServer(ServerConfig{})
	c := &conn{s: s, failed: make(chan string, 1), channels: map[*channel]struct{}{}}
	var wg sync.WaitGroup
	c.fwd = newForwarder(c, nil, &wg)
	strict := &connAdmission{admission: &admission{Kind: "ssh", Rec: &certRec{Policy: RecPolicyStrict}}}
	if c.fwd.recordingViolatedLocked(strict) {
		t.Fatal("a connection with no forwards helper is a violation")
	}
	ours, theirs, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer theirs.Close()
	client, err := launcher.NewForwardClient(ours, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	c.fwd.client = client
	if !c.fwd.recordingViolatedLocked(strict) {
		t.Fatal("a running unrecorded helper is not a violation")
	}
	c.fwd.failed = true
	if c.fwd.recordingViolatedLocked(strict) {
		t.Fatal("an ended helper is a violation")
	}
}

// A stopped channel no longer counts.
func TestAResumeIgnoresAStoppedChannel(t *testing.T) {
	client := &captureClient{opens: make(chan capturedOpen, 2)}
	f, keySum, _ := recordingFixture(t, client)
	o := f.defaults()
	o.kind = "ssh"
	rc := f.connectResumableAs(t, o)
	ch := startHeldChannel(t, f, rc)
	ch.stopped.Store(true)
	rc.cut(t)
	if err := rc.resume(t, withRec(&certRec{Policy: RecPolicyStrict, PubSHA256: keySum})); err != nil || !rc.alive() {
		t.Fatalf("resume = %v", err)
	}
	ch.stopped.Store(false)
}

func TestRecordingStateOf(t *testing.T) {
	ended, _ := newTestRecorder(t, RecPolicyStrict, &fakeHandoff{})
	ended.closeWith(recEnd, "")
	failed, _ := newTestRecorder(t, RecPolicyBestEffort, &fakeHandoff{})
	failed.closeWith(recFail, recording.ReasonRecordingFailed)
	aborted, _ := newTestRecorder(t, RecPolicyStrict, &fakeHandoff{})
	aborted.closeWith(recAbort, "")
	for _, tc := range []struct {
		rec       *sessionRecorder
		attempted bool
		want      recordingState
	}{
		{nil, false, recordingNever},
		{nil, true, recordingFailed},
		{ended, true, recordingLive},
		{aborted, true, recordingLive},
		{failed, true, recordingFailed},
	} {
		if got := recordingStateOf(tc.rec, tc.attempted); got != tc.want {
			t.Errorf("recordingStateOf(%v, %v) = %d, want %d", tc.rec, tc.attempted, got, tc.want)
		}
	}
	strict := &connAdmission{admission: &admission{Rec: &certRec{Policy: RecPolicyStrict}}}
	best := &connAdmission{admission: &admission{Rec: &certRec{Policy: RecPolicyBestEffort}}}
	none := &connAdmission{admission: &admission{}}
	for _, tc := range []struct {
		a     *connAdmission
		state recordingState
		want  bool
	}{
		{strict, recordingNever, true}, {strict, recordingFailed, true}, {strict, recordingLive, false},
		{best, recordingNever, true}, {best, recordingFailed, false}, {best, recordingLive, false},
		{none, recordingNever, false}, {none, recordingFailed, false},
	} {
		if got := tc.a.violatedBy(tc.state); got != tc.want {
			t.Errorf("violatedBy(%d) = %v, want %v", tc.state, got, tc.want)
		}
	}
}

// A resume that lands while a channel starts is met at the channel's hand-off.
func TestAResumeDuringAChannelStartRefusesThatStart(t *testing.T) {
	client := &captureClient{opens: make(chan capturedOpen, 2)}
	f, keySum, _ := recordingFixture(t, client)
	f.launcher.hold, f.launcher.starting = make(chan struct{}), make(chan struct{}, 1)
	f.launcher.helperDone = make(chan struct{}, 1)
	o := f.defaults()
	o.kind = "ssh"
	rc := f.connectResumableAs(t, o)
	sess, err := rc.client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stderr, _ := sess.StderrPipe()
	started := make(chan error, 1)
	go func() { started <- sess.Start("ls -l /tmp") }()
	select {
	case <-f.launcher.starting:
	case <-time.After(5 * time.Second):
		t.Fatal("the launcher was not asked")
	}
	rc.cut(t)
	if err := rc.resume(t, withRec(&certRec{Policy: RecPolicyStrict, PubSHA256: keySum})); err != nil {
		t.Fatalf("resume: %v", err)
	}
	close(f.launcher.hold)
	if err := <-started; err == nil {
		t.Fatal("a channel with no recording was handed off under a resume that names one")
	}
	readFor(t, stderr, "localport: "+CloseRecordingRequired+"\r\n")
	select {
	case <-f.launcher.helperDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the helper of the refused start was never ended")
	}
}

// A resume that lands during ensure refuses that forward without failing the
// forwarder: the next forward starts under the new admission and records.
func TestAResumeDuringEnsureRefusesOnlyThatForward(t *testing.T) {
	client := &captureClient{opens: make(chan capturedOpen, 2)}
	f, keySum, _ := recordingFixture(t, client)
	f.cfg.Capabilities = []string{"terminal", "forwarding"}
	f.srv = NewServer(*f.cfg)
	serveForwards(t, f.launcher)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = f.srv.Shutdown(ctx)
	})
	f.launcher.hold, f.launcher.starting = make(chan struct{}), make(chan struct{}, 2)
	tcp := echoServer(t, "tcp", "127.0.0.1:0")
	rc := f.connectResumableAs(t, f.forwardOpts(true, false))
	dialed := make(chan error, 1)
	go func() {
		_, err := rc.client.Dial("tcp", tcp.Addr().String())
		dialed <- err
	}()
	select {
	case <-f.launcher.starting:
	case <-time.After(5 * time.Second):
		t.Fatal("the launcher was not asked")
	}
	rc.cut(t)
	rec := &certRec{Policy: RecPolicyStrict, PubSHA256: keySum}
	if err := rc.resume(t, func(o *certOpts) { o.kind, o.fwdLocal, o.rec = "ssh", true, rec }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	close(f.launcher.hold)
	if err := <-dialed; err == nil {
		t.Fatal("a forward with no recording started under a resume that names one")
	}
	fc, err := rc.client.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatalf("the next forward: %v", err)
	}
	pingPong(t, fc)
	select {
	case open := <-client.opens:
		if open.sessionID != uuidText(streamID(77)) || open.channels != 1 {
			t.Fatalf("forwards recording open %+v", open)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the next forward opened no recording")
	}
}

// The first forward after a resume records under the resume stream.
func TestAForwardAfterAResumeRecordsUnderTheResumeStream(t *testing.T) {
	client := &captureClient{opens: make(chan capturedOpen, 2)}
	f, keySum, _ := recordingFixture(t, client)
	f.cfg.Capabilities = []string{"terminal", "forwarding"}
	f.srv = NewServer(*f.cfg)
	serveForwards(t, f.launcher)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = f.srv.Shutdown(ctx)
	})
	tcp := echoServer(t, "tcp", "127.0.0.1:0")
	rec := &certRec{Policy: RecPolicyStrict, PubSHA256: keySum}
	o := f.forwardOpts(true, false)
	o.rec = rec
	rc := f.connectResumableAs(t, o)
	rc.cut(t)
	if err := rc.resume(t, func(o *certOpts) { o.kind, o.fwdLocal, o.rec = "ssh", true, rec }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	fc, err := rc.client.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pingPong(t, fc)
	select {
	case got := <-client.opens:
		if got.sessionID != uuidText(streamID(77)) || !bytesEqual(got.cert, rc.resumeCert) {
			t.Fatalf("open session %s, want the resume stream's", got.sessionID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the forward opened no recording")
	}
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// narrowingChannel is an ssh.Channel whose stderr write blocks.
type narrowingChannel struct {
	ssh.Channel
	stderr *blockedWriter
}

func (c narrowingChannel) Stderr() io.ReadWriter { return c.stderr }
func (c narrowingChannel) Close() error          { return nil }

type blockedWriter struct {
	release chan struct{}
	writing chan struct{}
}

func (w *blockedWriter) Read([]byte) (int, error) { return 0, errors.New("no read") }
func (w *blockedWriter) Write(p []byte) (int, error) {
	close(w.writing)
	<-w.release
	return len(p), nil
}

// helperPipe is a helper channel whose closed fires when the agent closes it.
type helperPipe struct {
	file   *os.File
	closed chan struct{}
}

func newHelperPipe(t *testing.T) *helperPipe {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	p := &helperPipe{file: w, closed: make(chan struct{})}
	go func() {
		_, _ = io.Copy(io.Discard, r)
		close(p.closed)
	}()
	return p
}

func newNarrowingFixture(t *testing.T, stopped bool) (*conn, *channel, *blockedWriter, *helperPipe, *sessionRecorder) {
	t.Helper()
	w := &blockedWriter{release: make(chan struct{}), writing: make(chan struct{})}
	t.Cleanup(func() { close(w.release) })
	helper := newHelperPipe(t)
	rec, _ := newTestRecorder(t, RecPolicyBestEffort, &fakeHandoff{})
	s := NewServer(ServerConfig{})
	c := &conn{s: s, failed: make(chan string, 1), channels: map[*channel]struct{}{}}
	c.adm.Store(&connAdmission{admission: &admission{Kind: "ssh"}})
	c.fwd = newForwarder(c, nil, nil)
	ch := &channel{
		c: c, ch: narrowingChannel{stderr: w}, helper: helper.file, halted: make(chan struct{}), started: true, rec: rec,
		kind: launcher.KindSFTP, files: filesAccess{Download: true, Upload: true},
	}
	if stopped {
		ch.stopped.Store(true)
	}
	c.channels[ch] = struct{}{}
	return c, ch, w, helper, rec
}

// A narrowing end does not wait on the detached send buffer: the helper
// closes first and readmit returns while the reason's write is blocked.
func TestNarrowingEndDoesNotWaitOnTheSendBuffer(t *testing.T) {
	c, _, w, helper, _ := newNarrowingFixture(t, false)
	returned := make(chan bool, 1)
	go func() {
		returned <- c.readmit(&connAdmission{admission: &admission{Kind: "ssh", Files: filesAccess{Download: true}}})
	}()
	select {
	case violated := <-returned:
		if violated {
			t.Fatal("a narrowing resume reported a recording violation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readmit waited on the send buffer")
	}
	select {
	case <-helper.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("the helper did not close while the write blocked")
	}
	select {
	case <-w.writing:
	case <-time.After(3 * time.Second):
		t.Fatal("the reason was never written")
	}
}

// A stopped channel gets no files_narrowed marker.
func TestNarrowingSkipsAStoppedChannel(t *testing.T) {
	c, _, _, helper, rec := newNarrowingFixture(t, true)
	if c.readmit(&connAdmission{admission: &admission{Kind: "ssh", Files: filesAccess{Download: true}}}) {
		t.Fatal("reported a violation")
	}
	rec.mu.Lock()
	queued := len(rec.queue)
	rec.mu.Unlock()
	if queued != 0 {
		t.Fatalf("%d events queued on a stopped channel's recording", queued)
	}
	select {
	case <-helper.closed:
		t.Fatal("the stopped channel was ended again")
	case <-time.After(100 * time.Millisecond):
	}
}

// A violation neither writes nor stalls: the channel loop is not reached.
func TestAViolationDoesNotTouchTheChannels(t *testing.T) {
	c, ch, _, helper, _ := newNarrowingFixture(t, false)
	ch.mu.Lock()
	ch.rec, ch.recAttempted = nil, false
	ch.mu.Unlock()
	returned := make(chan bool, 1)
	go func() {
		returned <- c.readmit(&connAdmission{admission: &admission{Kind: "ssh", Files: filesAccess{Download: true}, Rec: &certRec{Policy: RecPolicyStrict}}})
	}()
	select {
	case violated := <-returned:
		if !violated {
			t.Fatal("a never-recorded channel was not a violation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the refusal stalled")
	}
	select {
	case <-helper.closed:
		t.Fatal("the channel loop ran on a violation")
	case <-time.After(100 * time.Millisecond):
	}
}

// With a resume holding the connection, its stream's handler releasing arms
// no detach timer.
func TestAStreamReleaseUnderAResumeArmsNoTimer(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = &manualClock{} })
	rc := f.connectResumable(t)
	e := onlyConn(t, f.srv)
	if got, status := f.srv.beginResume(e.handle); got != e || status != statusOK {
		t.Fatalf("beginResume = %v, %d", got, status)
	}
	e.rc.Detach()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.srv.mu.Lock()
		running, armed := e.running, e.stopTimer != nil
		f.srv.mu.Unlock()
		if armed {
			t.Fatal("a detach timer was armed while a resume held the connection")
		}
		if running == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("running = %d, the stream's handler did not release", running)
		}
		time.Sleep(time.Millisecond)
	}
	f.srv.endAttempt(e, true)
	_ = rc
}

// endAttempt clears the claim and releases the hold in one critical section:
// a resume arriving between them finds the connection expired, not claimable.
func TestEndAttemptIsOneCriticalSection(t *testing.T) {
	clock := &manualClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	rc := f.connectResumable(t)
	rc.cut(t)
	e := onlyConn(t, f.srv)
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.srv.mu.Lock()
		armed := e.stopTimer != nil
		f.srv.mu.Unlock()
		if armed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no detach timer")
		}
		time.Sleep(time.Millisecond)
	}
	if _, status := f.srv.beginResume(e.handle); status != statusOK {
		t.Fatalf("beginResume = %d", status)
	}
	clock.advance(detachTimeout + time.Second)
	statuses := make(chan uint32, 1)
	hook := func() {
		afterAttemptClaimCleared.Store(nil)
		go func() {
			_, status := f.srv.beginResume(e.handle)
			statuses <- status
		}()
		time.Sleep(50 * time.Millisecond)
	}
	afterAttemptClaimCleared.Store(&hook)
	t.Cleanup(func() { afterAttemptClaimCleared.Store(nil) })
	f.srv.endAttempt(e, true)
	if status := <-statuses; status != statusLost {
		t.Fatalf("a resume during endAttempt = %d, want statusLost", status)
	}
}

// Keyboard-interactive has its own bound: a slow person succeeds past the
// handshake bound, and the prompt still ends at its own.
func TestKeyboardInteractiveHasItsOwnBound(t *testing.T) {
	savedHandshake, savedInteractive := handshakeTimeout, interactiveAuthTimeout
	t.Cleanup(func() { handshakeTimeout, interactiveAuthTimeout = savedHandshake, savedInteractive })
	handshakeTimeout, interactiveAuthTimeout = 200*time.Millisecond, 3*time.Second
	f := newSSHFixture(t, func(c *ServerConfig) { c.PasswordLogins = []string{testLogin} })
	o := f.defaults()
	o.kind = "ssh"
	signer, _ := f.mint(t, o)
	answer := func(delay time.Duration) ssh.KeyboardInteractiveChallenge {
		return func(string, string, []string, []bool) ([]string, error) {
			time.Sleep(delay)
			return []string{"s3cret"}, nil
		}
	}
	// In a goroutine: past a bound the agent ends the connection and the test
	// client stays blocked, one it could still resume.
	dialed := make(chan error, 1)
	go func() {
		_, err := f.dial(t, o.serial, signer, func(c *ssh.ClientConfig) {
			c.Auth = append(c.Auth, ssh.KeyboardInteractive(answer(600*time.Millisecond)))
		})
		dialed <- err
	}()
	select {
	case err := <-dialed:
		if err != nil {
			t.Fatalf("a slow answer inside the prompt's bound: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the agent ended the handshake during the prompt")
	}
	_ = f.srv.Shutdown(context.Background())
	interactiveAuthTimeout = 200 * time.Millisecond
	wantServerEndsHandshake(t, f, o.serial, signer, func(c *ssh.ClientConfig) {
		c.Auth = append(c.Auth, ssh.KeyboardInteractive(answer(30*time.Second)))
	})
}

// wantServerEndsHandshake dials and waits for the agent to end the connection
// by its handshake bound. The test client stays blocked: an ended connection
// is one it could still resume.
func wantServerEndsHandshake(t *testing.T, f *sshFixture, serial uint64, signer ssh.Signer, edit func(*ssh.ClientConfig)) {
	t.Helper()
	go func() { _, _ = f.dial(t, serial, signer, edit) }()
	deadline := time.Now().Add(5 * time.Second)
	seen := false
	for time.Now().Before(deadline) {
		live := f.srv.LiveSessions()
		if seen && live == 0 {
			return
		}
		seen = seen || live > 0
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the agent did not end the handshake (connection seen: %v)", seen)
}

// A stalled handshake outside the prompt ends at the handshake bound.
func TestAStalledHandshakeEndsAtItsBound(t *testing.T) {
	saved := handshakeTimeout
	t.Cleanup(func() { handshakeTimeout = saved })
	handshakeTimeout = 200 * time.Millisecond
	f := newSSHFixture(t, nil)
	o := f.defaults()
	o.kind = "ssh"
	signer, _ := f.mint(t, o)
	wantServerEndsHandshake(t, f, o.serial, signer, func(c *ssh.ClientConfig) {
		c.Auth = []ssh.AuthMethod{ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			time.Sleep(30 * time.Second)
			return []ssh.Signer{signer}, nil
		})}
	})
}
