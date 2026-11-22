//go:build linux || darwin

package session

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
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

// A resume of a connection idle past its timeout is installed and then ends
// `idle` over the resumed stream, as an attached idle end does.
func TestResumePastIdleEndsIdleOverTheStream(t *testing.T) {
	clock := &idleClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	ends := connEnds(t)
	rc := f.connectResumable(t)
	stderr := openShell(t, rc)
	clock.waitArmed(t, func(d time.Duration) bool { return d == testIdleTimeout }, "no idle timer")
	rc.cut(t)
	clock.advance(testIdleTimeout + time.Second)
	// Gives run the time to decide the readmitted admission before the
	// install; it must not decide an idle end there.
	early := make(chan string, 1)
	hook := func(*resumable) {
		afterResumeReadmit.Store(nil)
		select {
		case reason := <-ends:
			early <- reason
		case <-time.After(100 * time.Millisecond):
			early <- ""
		}
	}
	afterResumeReadmit.Store(&hook)
	t.Cleanup(func() { afterResumeReadmit.Store(nil) })
	if err := rc.resume(t, validAt(clock)); err != nil {
		t.Fatalf("resume past the idle timeout = %v, want it installed", err)
	}
	if reason := <-early; reason != "" {
		t.Fatalf("the connection ended %q between readmit and install", reason)
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
	held := make(chan string, 1)
	hook := func(*resumable) {
		afterResumeInstall.Store(nil)
		clock.advance(testIdleTimeout + time.Second)
		clock.fireIdle()
		select {
		case reason := <-ends:
			held <- reason
		case <-time.After(100 * time.Millisecond):
			held <- ""
		}
	}
	afterResumeInstall.Store(&hook)
	t.Cleanup(func() { afterResumeInstall.Store(nil) })
	if err := rc.resume(t, nil); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if reason := <-held; reason != "" {
		t.Fatalf("the connection ended %q before the resume settled", reason)
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

// A detached connection that Shutdown ends before run decided an end leaves
// its record when it is removed.
func TestRemovingAConnectionShutdownEndedLeavesARecord(t *testing.T) {
	old := closeFlushTimeout
	closeFlushTimeout = 10 * time.Millisecond
	t.Cleanup(func() { closeFlushTimeout = old })
	for name, tc := range map[string]struct {
		stoppedBy, want string
	}{
		"shutdown ended the handshake": {CloseShutdown, CloseShutdown},
		// A handshake that failed on its own, removed after a later Shutdown
		// stopped the handler: no shutdown record.
		"handshake failed": {"", ""},
	} {
		s := NewServer(ServerConfig{clock: &manualClock{}})
		e := &resumable{rc: NewResumableConn(), handle: "h", ended: make(chan string, 1)}
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

// A connection records one end: once a record was made (even if a resume
// spent it) or run decided an attached end, a later expiry records nothing.
func TestAConnectionRecordsOneEnd(t *testing.T) {
	for name, decide := range map[string]func(*Server, *resumable){
		"spent record": func(s *Server, e *resumable) {
			s.recordEndLocked(e, CloseIdle)
			s.dropRecordLocked(e.handle, s.ended[e.handle])
		},
		"attached end": func(_ *Server, e *resumable) { e.endDecided = true },
	} {
		s := NewServer(ServerConfig{clock: &manualClock{}})
		e := &resumable{rc: NewResumableConn(), handle: "h", ended: make(chan string, 1)}
		s.mu.Lock()
		decide(s, e)
		s.expireLocked(e)
		r := s.ended[e.handle]
		s.mu.Unlock()
		if r != nil {
			t.Fatalf("%s: expiry left record %q, want none", name, r.reason)
		}
	}
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
