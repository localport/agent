//go:build linux || darwin

package session

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// validAt returns a certificate edit valid at the agent's clock now.
func validAt(clock *idleClock) func(*certOpts) {
	now := clock.Now()
	return func(o *certOpts) { o.after, o.before = now.Add(-30*time.Second), now.Add(time.Minute) }
}

// openShell opens a shell on the resumable connection and returns its stderr.
func openShell(t *testing.T, rc *resumeConn) io.Reader {
	t.Helper()
	sess, err := rc.client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	_ = sess.RequestPty("xterm", 24, 80, nil)
	stderr, _ := sess.StderrPipe()
	if _, err := sess.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	return stderr
}

// endDetachedIdle ends a cut resumable connection idle while it is detached
// and waits for the end.
func endDetachedIdle(t *testing.T, f *sshFixture, clock *idleClock, ends <-chan string) *resumeConn {
	t.Helper()
	rc := f.connectResumable(t)
	clock.waitArmed(t, func(d time.Duration) bool { return d == testIdleTimeout }, "no idle timer")
	cutDetached(t, rc)
	clock.advance(testIdleTimeout + time.Second)
	clock.fireIdle()
	wantEnd(t, ends, CloseIdle)
	return rc
}

// cutDetached cuts rc's stream and waits until the agent detached it.
func cutDetached(t *testing.T, rc *resumeConn) {
	t.Helper()
	rc.cut(t)
	rc.f.srv.mu.Lock()
	e := rc.f.srv.conns[string(rc.cr.handle)]
	rc.f.srv.mu.Unlock()
	onlyDeadline(t, rc.f.srv, e)
}

// idleCheck is one idle decision run made: on the idle timer (timer) or a
// readmit signal, and whether it ended the connection.
type idleCheck struct{ timer, decided bool }

// idleChecks records f's server's idle decisions for the rest of the test.
func idleChecks(t *testing.T, f *sshFixture) <-chan idleCheck {
	t.Helper()
	ch := make(chan idleCheck, 16)
	hook := func(s *Server, timer, decided bool) {
		if s != f.srv {
			return
		}
		// Never stalls run; a test reads the first few decisions only.
		select {
		case ch <- idleCheck{timer, decided}:
		default:
		}
	}
	afterIdleCheck.Store(&hook)
	t.Cleanup(func() { afterIdleCheck.Store(nil) })
	return ch
}

// heldIdleCheck waits, in a test hook, for run's next idle decision on the
// timer (timer) or a readmit signal and describes what went wrong: "" when
// that decision held off the idle end.
func heldIdleCheck(checks <-chan idleCheck, timer bool) string {
	until := time.After(5 * time.Second)
	for {
		select {
		case c := <-checks:
			if c.timer != timer {
				continue
			}
			if c.decided {
				return "run decided an idle end while the resume held it"
			}
			return ""
		case <-until:
			return "run made no idle decision"
		}
	}
}

// A resume of a connection idle past its timeout is installed and then ends
// `idle` over the resumed stream, as an attached idle end does.
func TestResumePastIdleEndsIdleOverTheStream(t *testing.T) {
	clock := &idleClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	ends := connEnds(t)
	rc := f.connectResumable(t)
	stderr := openShell(t, rc)
	clock.waitArmed(t, func(d time.Duration) bool { return d == testIdleTimeout }, "no idle timer")
	// Idle past the timeout before the cut, so the detach deadline starts
	// from the advanced clock; advancing after the detach would pass it.
	clock.advance(testIdleTimeout + time.Second)
	cutDetached(t, rc)
	// Waits for run's decision on the readmit signal before the install; the
	// resume holds it, so it must not end the connection idle there.
	checks := idleChecks(t, f)
	early := make(chan string, 1)
	hook := func(*resumable) {
		afterResumeReadmit.Store(nil)
		early <- heldIdleCheck(checks, false)
	}
	afterResumeReadmit.Store(&hook)
	t.Cleanup(func() { afterResumeReadmit.Store(nil) })
	if err := rc.resume(t, validAt(clock)); err != nil {
		t.Fatalf("resume past the idle timeout = %v, want it installed", err)
	}
	if problem := <-early; problem != "" {
		t.Fatalf("between readmit and install: %s", problem)
	}
	readFor(t, stderr, "\r\nlocalport: session ended: idle\r\n")
	wantEnd(t, ends, CloseIdle)
}

// An idle timer that fires while a resume is between readmit and its settled
// install decides nothing then; the settled resume decides it, and the
// connection ends `idle`.
func TestIdleFiredDuringAResumeEndsAfterTheInstall(t *testing.T) {
	clock := &idleClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	ends := connEnds(t)
	rc := f.connectResumable(t)
	clock.waitArmed(t, func(d time.Duration) bool { return d == testIdleTimeout }, "no idle timer")
	rc.cut(t)
	checks := idleChecks(t, f)
	held := make(chan string, 1)
	hook := func(*resumable) {
		afterResumeInstall.Store(nil)
		clock.advance(testIdleTimeout + time.Second)
		clock.fireIdle()
		held <- heldIdleCheck(checks, true)
	}
	afterResumeInstall.Store(&hook)
	t.Cleanup(func() { afterResumeInstall.Store(nil) })
	if err := rc.resume(t, nil); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if problem := <-held; problem != "" {
		t.Fatalf("before the resume settled: %s", problem)
	}
	wantEnd(t, ends, CloseIdle)
}

// A connection that ends idle while detached is reported to its next resume,
// after the proof, as ended idle; the record is then gone.
func TestResumeAfterADetachedIdleEndIsEnded(t *testing.T) {
	clock := &idleClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	ends := connEnds(t)
	rc := endDetachedIdle(t, f, clock, ends)
	if err := rc.resume(t, validAt(clock)); endedReason(err) != CloseIdle {
		t.Fatalf("resume after a detached idle end = %v, want ended %s", err, CloseIdle)
	}
	if err := rc.resume(t, validAt(clock)); resumeCode(err) != CloseResumeLost {
		t.Fatalf("a second resume = %v, want %s once the record is spent", err, CloseResumeLost)
	}
}

// A connection that ends detached while a close resume of it is between its
// proof and its answer is answered from the record, which is then gone.
func TestACloseResumeRacingADetachedEndSpendsTheRecord(t *testing.T) {
	clock := &idleClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	ends := connEnds(t)
	rc := f.connectResumable(t)
	clock.waitArmed(t, func(d time.Duration) bool { return d == testIdleTimeout }, "no idle timer")
	cutDetached(t, rc)
	hook := func(*resumable) {
		afterResumeProof.Store(nil)
		clock.advance(testIdleTimeout + time.Second)
		clock.fireIdle()
		wantEnd(t, ends, CloseIdle)
	}
	afterResumeProof.Store(&hook)
	t.Cleanup(func() { afterResumeProof.Store(nil) })
	if err := rc.closeResume(t, validAt(clock), nil); err != nil {
		t.Fatalf("close resume: %v", err)
	}
	f.srv.mu.Lock()
	left := len(f.srv.ended)
	f.srv.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d end records left after the close resume, want the record spent", left)
	}
}

// A connection that Shutdown ends before run decided an end leaves its record
// when it is removed, attached or not: the abort tells no client.
func TestRemovingAConnectionShutdownEndedLeavesARecord(t *testing.T) {
	old := closeFlushTimeout
	closeFlushTimeout = 10 * time.Millisecond
	t.Cleanup(func() { closeFlushTimeout = old })
	for name, tc := range map[string]struct {
		stoppedBy, want string
		attached        bool
	}{
		"shutdown ended the handshake":         {CloseShutdown, CloseShutdown, false},
		"shutdown ended an attached handshake": {CloseConfigChanged, CloseConfigChanged, true},
		// A handshake that failed on its own, removed after a later Shutdown
		// stopped the handler: no shutdown record.
		"handshake failed": {"", "", false},
	} {
		s := NewServer(ServerConfig{clock: &manualClock{}})
		e := &resumable{rc: NewResumableConn(), handle: "h", ended: make(chan string, 1)}
		if tc.attached {
			agentSide, clientSide := net.Pipe()
			t.Cleanup(func() { _ = clientSide.Close() })
			if run, _ := e.rc.Install(agentSide, 0); run == nil || !e.rc.Attached() {
				t.Fatalf("%s: the stream was not installed", name)
			}
		}
		h := &handler{stop: make(chan struct{}), stopped: true, stopReason: CloseShutdown}
		s.mu.Lock()
		s.conns[e.handle], s.handlers[h], s.sessions = e, struct{}{}, 1
		s.mu.Unlock()
		s.removeConn(e, h, tc.stoppedBy)
		s.mu.Lock()
		r := s.ended[e.handle]
		s.mu.Unlock()
		if got := ""; r != nil {
			got = r.reason
			if got != tc.want {
				t.Fatalf("%s: record %q, want %q", name, got, tc.want)
			}
		} else if tc.want != "" {
			t.Fatalf("%s: no record, want %q", name, tc.want)
		}
	}
}

// A connection records one end. Once its end is decided, by a record (even
// one a resume spent), by run, by an end its resume stream answered or by the
// proof failure limit, a later expiry records nothing.
func TestAConnectionRecordsOneEnd(t *testing.T) {
	for name, decide := range map[string]func(*Server, *resumable){
		"spent record": func(s *Server, e *resumable) {
			s.mu.Lock()
			s.recordEndLocked(e, CloseIdle)
			s.dropRecordLocked(e.handle, s.ended[e.handle])
			s.mu.Unlock()
		},
		// A detached client close leaves no record; run's decision is what
		// keeps the expiry from leaving one.
		"run decided an end with no record": func(s *Server, e *resumable) { s.decideEnd(e, "") },
		"answered resume_lost":              func(s *Server, e *resumable) { s.endAnswered(e, CloseResumeLost) },
		"answered recording_required":       func(s *Server, e *resumable) { s.endAnswered(e, CloseRecordingRequired) },
		"answered close resume":             func(s *Server, e *resumable) { s.decideAnsweredEnd(e) },
		"proof failure limit": func(s *Server, e *resumable) {
			for range maxProofFailures {
				s.proofFailed(e)
			}
		},
	} {
		s := NewServer(ServerConfig{clock: &manualClock{}})
		e := &resumable{rc: NewResumableConn(), handle: "h", ended: make(chan string, 1)}
		decide(s, e)
		s.mu.Lock()
		s.expireLocked(e)
		r := s.ended[e.handle]
		s.mu.Unlock()
		if r != nil {
			t.Fatalf("%s: expiry left record %q, want none", name, r.reason)
		}
	}
}

// A detached connection whose resume attempts reach the proof failure limit
// as its detach deadline passes ends resume_refused with no record, whichever
// of run's end and the attempt's expiry comes first: a correct resume is lost.
func TestRefusedProofsAtTheDeadlineLeaveNoRecord(t *testing.T) {
	clock := &manualClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	rc := f.connectResumable(t)
	cutDetached(t, rc)
	attempts := 0
	hook := func() {
		if attempts++; attempts == maxProofFailures {
			clock.advance(detachTimeout + time.Second)
		}
	}
	afterAttemptClaimCleared.Store(&hook)
	t.Cleanup(func() { afterAttemptClaimCleared.Store(nil) })
	token := rc.cr.token
	rc.cr.token = bytes.Repeat([]byte{9}, len(token))
	for range maxProofFailures {
		if err := rc.resume(t, nil); resumeCode(err) != CloseResumeRefused {
			t.Fatalf("a wrong proof = %v, want %s", err, CloseResumeRefused)
		}
	}
	afterAttemptClaimCleared.Store(nil)
	rc.cr.token = token
	if err := rc.resume(t, nil); resumeCode(err) != CloseResumeLost {
		t.Fatalf("a correct proof after the limit at the deadline = %v, want %s", err, CloseResumeLost)
	}
}

// A close resume whose attempt outlives the detach deadline leaves no record
// and ends as a client's close: the client was told the connection closed.
func TestACloseResumeAtTheDeadlineLeavesNoRecord(t *testing.T) {
	clock := &manualClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	ends := connEnds(t)
	rc := f.connectResumable(t)
	cutDetached(t, rc)
	hook := func(*resumable) {
		afterResumeProof.Store(nil)
		clock.advance(detachTimeout + time.Second)
	}
	afterResumeProof.Store(&hook)
	t.Cleanup(func() { afterResumeProof.Store(nil) })
	// Holds run's end until the attempt's release expired the connection, so
	// only the close resume's own decision keeps that expiry from recording.
	hold := func(s *Server, e *resumable) {
		if s != f.srv {
			return
		}
		beforeRunDecidesEnd.Store(nil)
		for until := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
			s.mu.Lock()
			expired := e.expired
			s.mu.Unlock()
			if expired {
				return
			}
			if time.Now().After(until) {
				t.Error("the close resume's release did not expire the connection")
				return
			}
		}
	}
	beforeRunDecidesEnd.Store(&hold)
	t.Cleanup(func() { beforeRunDecidesEnd.Store(nil) })
	if err := rc.closeResume(t, nil, nil); err != nil {
		t.Fatalf("close resume: %v", err)
	}
	noClaim(t, f.srv)
	f.srv.mu.Lock()
	left := len(f.srv.ended)
	f.srv.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d end records after a close resume at the deadline, want none", left)
	}
	wantEnd(t, ends, "")
}

// A record lives detachTimeout from the end: a resume after it is lost.
func TestAnExpiredEndRecordIsLost(t *testing.T) {
	clock := &idleClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	ends := connEnds(t)
	rc := endDetachedIdle(t, f, clock, ends)
	clock.advance(detachTimeout)
	if err := rc.resume(t, validAt(clock)); resumeCode(err) != CloseResumeLost {
		t.Fatalf("resume after the record expired = %v, want %s", err, CloseResumeLost)
	}
}

// A failed proof against a record is refused as against a live handle; at
// maxProofFailures the record is deleted and a correct proof is lost.
func TestFailedProofsDeleteTheEndRecord(t *testing.T) {
	clock := &idleClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	ends := connEnds(t)
	rc := endDetachedIdle(t, f, clock, ends)
	token := rc.cr.token
	rc.cr.token = bytes.Repeat([]byte{9}, len(token))
	for range maxProofFailures {
		if err := rc.resume(t, validAt(clock)); resumeCode(err) != CloseResumeRefused {
			t.Fatalf("a wrong proof against a record = %v, want %s", err, CloseResumeRefused)
		}
	}
	rc.cr.token = token
	if err := rc.resume(t, validAt(clock)); resumeCode(err) != CloseResumeLost {
		t.Fatalf("a correct proof after the limit = %v, want %s", err, CloseResumeLost)
	}
}

// At maxSessions records the oldest is evicted: a resume of it is lost, the
// newer ones are still answered.
func TestEndRecordsAreCapped(t *testing.T) {
	clock := &manualClock{}
	s := NewServer(ServerConfig{clock: clock})
	handles := make([]string, maxSessions+1)
	for i := range handles {
		handle := make([]byte, resumeHandleLen)
		_, _ = rand.Read(handle)
		handles[i] = string(handle)
		s.mu.Lock()
		s.recordEndLocked(&resumable{rc: NewResumableConn(), handle: handles[i]}, CloseIdle)
		s.mu.Unlock()
		clock.advance(time.Second)
	}
	if _, rec, status := s.beginResume(&handler{}, handles[0]); rec != nil || status != statusLost {
		t.Fatalf("the oldest record: %v, %d; want it evicted", rec, status)
	}
	for _, handle := range handles[1:] {
		if _, rec, status := s.beginResume(&handler{}, handle); rec == nil || status != statusOK {
			t.Fatalf("a newer record: %v, %d; want it claimed", rec, status)
		}
	}
	if n := len(s.ended); n != maxSessions {
		t.Fatalf("%d records, want %d", n, maxSessions)
	}
}

// Before the proof a resume of a record gets exactly the replies a live
// handle's gets: an ok resume reply of the same shape, and a wrong proof's
// refusal with no reason. The end is told only after a verified proof.
func TestAnEndRecordRevealsNothingBeforeTheProof(t *testing.T) {
	clock := &idleClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	ends := connEnds(t)
	live := f.connectResumable(t)
	clock.waitArmed(t, func(d time.Duration) bool { return d == testIdleTimeout }, "no idle timer")
	live.cut(t)
	liveReply, liveProof := rawResume(t, live, validAt(clock))

	ended := endDetachedIdle(t, f, clock, ends)
	endedReply, endedProof := rawResume(t, ended, validAt(clock))

	// Unmarshal refuses trailing data, so a decoded reply carries nothing else.
	for name, raw := range map[string][]byte{"live": liveReply, "ended": endedReply} {
		var reply resumeReplyMsg
		if err := ssh.Unmarshal(raw, &reply); err != nil || reply.Status != statusOK || len(reply.AgentKey) != 32 {
			t.Fatalf("%s resume reply = %+v, %v; want statusOK with a key and nothing else", name, reply, err)
		}
	}
	if !bytes.Equal(liveProof, endedProof) {
		t.Fatalf("wrong-proof replies differ:\nlive  %x\nended %x", liveProof, endedProof)
	}
}

// rawResume sends a resume of rc's handle with a wrong proof and returns the
// raw resume reply and proof reply.
func rawResume(t *testing.T, rc *resumeConn, edit func(*certOpts)) (reply, proofReply []byte) {
	t.Helper()
	o := rc.f.defaults()
	o.key, o.serial, o.resumes = rc.key, 77, "2a"
	edit(&o)
	signer, cert := rc.f.mint(t, o)
	stream := rc.f.serveStream(t, 77)
	defer stream.Close()
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	msg := resumeMsg{Version: preludeVersion, Handle: rc.cr.handle, ClientKey: priv.PublicKey().Bytes(),
		Position: rc.cr.Conn.Received(), Cert: cert.Marshal()}
	var err error
	if msg.Sig, err = signPrelude(signer, clientSigContext, transcript(msg.noSig())); err != nil {
		t.Fatal(err)
	}
	if err := writePrelude(stream, msg); err != nil {
		t.Fatal(err)
	}
	if reply, err = readPreludeRaw(stream); err != nil {
		t.Fatal(err)
	}
	if err := writePrelude(stream, proofMsg{Proof: make([]byte, 32)}); err != nil {
		t.Fatal(err)
	}
	if proofReply, err = readPreludeRaw(stream); err != nil {
		t.Fatal(err)
	}
	noClaim(t, rc.f.srv)
	return reply, proofReply
}
