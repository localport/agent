//go:build linux || darwin

package session

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// cutConn writes at most limit bytes in all, then fails and closes: a stream
// cut at an exact byte, mid-frame or on a boundary.
type cutConn struct {
	net.Conn
	mu    sync.Mutex
	limit int
}

func (c *cutConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) <= c.limit {
		c.limit -= len(p)
		return c.Conn.Write(p)
	}
	n, _ := c.Conn.Write(p[:c.limit])
	c.limit = 0
	_ = c.Close()
	return n, net.ErrClosed
}

func attachAsync(c *ResumableConn, stream net.Conn, peer uint64) <-chan AttachEnd {
	out := make(chan AttachEnd, 1)
	go func() { out <- c.Attach(stream, peer) }()
	return out
}

func waitEnd(t *testing.T, ch <-chan AttachEnd) AttachEnd {
	t.Helper()
	select {
	case end := <-ch:
		return end
	case <-time.After(10 * time.Second):
		t.Fatal("Attach did not return")
		return 0
	}
}

// The frame header of a full frame with a zero ack is 1 + 3 bytes.
const fullFrame = 4 + resumeMaxFrame

func TestResumableConnSurvivesACutAnywhere(t *testing.T) {
	payload := make([]byte, 3*resumeMaxFrame+1234)
	_, _ = rand.Read(payload)
	for _, cut := range []int{1, 2, 3, 4, 5, 4096, fullFrame - 1, fullFrame, fullFrame + 1, fullFrame + 4, 2*fullFrame + 7, len(payload)} {
		a, b := NewResumableConn(), NewResumableConn()
		got := make(chan []byte, 1)
		go func() {
			data, _ := io.ReadAll(b)
			got <- data
		}()
		s1a, s1b := tcpPair(t)
		endA := attachAsync(a, &cutConn{Conn: s1a, limit: cut}, 0)
		endB := attachAsync(b, s1b, 0)
		wrote := make(chan error, 1)
		go func() {
			_, err := a.Write(payload)
			wrote <- err
		}()
		if e := waitEnd(t, endA); e != Detached {
			t.Fatalf("cut at %d: first stream ended %v on the writer, want Detached", cut, e)
		}
		if e := waitEnd(t, endB); e != Detached {
			t.Fatalf("cut at %d: first stream ended %v on the reader, want Detached", cut, e)
		}
		s2a, s2b := tcpPair(t)
		posA, posB := a.Received(), b.Received()
		endA = attachAsync(a, s2a, posB)
		endB = attachAsync(b, s2b, posA)
		if err := <-wrote; err != nil {
			t.Fatalf("cut at %d: write: %v", cut, err)
		}
		_ = a.Close()
		select {
		case data := <-got:
			if !bytes.Equal(data, payload) {
				t.Fatalf("cut at %d: the reader got %d bytes, not every byte exactly once in order", cut, len(data))
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("cut at %d: the reader saw no end; writer stream ended %v, reader stream %v (received %d of %d)",
				cut, waitEnd(t, endA), waitEnd(t, endB), b.Received(), len(payload))
		}
		if e := waitEnd(t, endA); e != Closed {
			t.Fatalf("cut at %d: closing side ended %v, want Closed", cut, e)
		}
		if e := waitEnd(t, endB); e != Closed {
			t.Fatalf("cut at %d: peer ended %v after the closeTag, want Closed", cut, e)
		}
	}
}

func TestWriteBlocksWhileTheSendBufferIsFull(t *testing.T) {
	a, b := NewResumableConn(), NewResumableConn()
	if n, err := a.Write(make([]byte, resumeSendBuffer)); err != nil || n != resumeSendBuffer {
		t.Fatalf("detached write of a full buffer = %d, %v", n, err)
	}
	extra := make(chan error, 1)
	go func() {
		_, err := a.Write([]byte{1})
		extra <- err
	}()
	select {
	case err := <-extra:
		t.Fatalf("a write past the full send buffer returned (%v) instead of blocking", err)
	case <-time.After(100 * time.Millisecond):
	}
	go func() { _, _ = io.Copy(io.Discard, b) }()
	sa, sb := tcpPair(t)
	attachAsync(a, sa, 0)
	attachAsync(b, sb, 0)
	select {
	case err := <-extra:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the blocked write did not return once acks freed space")
	}
}

func TestResumeFromOutsideTheBufferEndsTheConn(t *testing.T) {
	a := NewResumableConn()
	if _, err := a.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	sa, sb := tcpPair(t)
	if e := a.Attach(sa, 11); e != Ended || !errors.Is(a.Ended(), ErrResumeLost) {
		t.Fatalf("resume past the buffer = %v, %v; want Ended, ErrResumeLost", e, a.Ended())
	}
	tag, err := binary.ReadUvarint(bufio.NewReader(sb))
	if err != nil || tag != closeTag {
		t.Fatalf("the peer read %x, %v; want the closeTag", tag, err)
	}
	if _, err := a.Write([]byte("x")); !errors.Is(err, ErrResumeLost) {
		t.Fatalf("write after a lost resume = %v", err)
	}
}

// manualClock fires the detach timer on demand; other timers never fire.
type manualClock struct {
	mu     sync.Mutex
	detach []chan time.Time
	// armed is each recorded detach timer's duration, in order.
	armed []time.Duration
	// offset moves Now ahead of the wall clock (advance).
	offset time.Duration
}

// lastArmed is the duration of the last detach timer armed.
func (c *manualClock) lastArmed() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.armed) == 0 {
		return 0
	}
	return c.armed[len(c.armed)-1]
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

// advance moves Now ahead by d; no timer fires.
func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	c.offset += d
	c.mu.Unlock()
}

// NewTimer is every other timer, which never fires.
func (c *manualClock) NewTimer(time.Duration) (<-chan time.Time, func() bool) {
	return make(chan time.Time, 1), func() bool { return true }
}

// NewDetachTimer records a detach timer.
func (c *manualClock) NewDetachTimer(d time.Duration) (<-chan time.Time, func() bool) {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	c.detach = append(c.detach, ch)
	c.armed = append(c.armed, d)
	c.mu.Unlock()
	return ch, func() bool { return true }
}

func (c *manualClock) fireDetach() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ch := range c.detach {
		select {
		case ch <- time.Now():
		default:
		}
	}
}

// resumeConn is a client connection whose stream a test can cut and resume.
type resumeConn struct {
	f      *sshFixture
	key    ed25519.PrivateKey
	cr     *ClientResumable
	client *ssh.Client
	stream net.Conn
	ended  <-chan AttachEnd
	// resumeCert is the certificate of the last resume.
	resumeCert []byte
}

// connectResumable runs a first connect with serial 42 (resume option "2a").
func (f *sshFixture) connectResumable(t *testing.T) *resumeConn {
	t.Helper()
	return f.connectResumableAs(t, f.defaults())
}

// connectResumableAs is connectResumable with the certificate options o.
func (f *sshFixture) connectResumableAs(t *testing.T, o certOpts) *resumeConn {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	o.key = key
	signer, _ := f.mint(t, o)
	rc := &resumeConn{f: f, key: key}
	rc.stream = f.serveStream(t, 42)
	cr, err := Hello(rc.stream, signer, f.hostKey)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	rc.cr = cr
	rc.ended = attachAsync(cr.Conn, rc.stream, 0)
	c, chans, reqs, err := ssh.NewClientConn(cr.Conn, "gw-01", &ssh.ClientConfig{
		User: o.login, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(f.hostKey),
	})
	if err != nil {
		t.Fatalf("ssh over the resumable conn: %v", err)
	}
	rc.client = ssh.NewClient(c, chans, reqs)
	t.Cleanup(func() {
		_ = rc.client.Close()
		select {
		case <-cr.Conn.Done():
		case <-time.After(5 * time.Second):
		}
	})
	return rc
}

// streamID is the session id the fixture's notice gives the stream of serial.
func streamID(serial uint64) [16]byte { return [16]byte{0x01, 0x9b, byte(serial)} }

// serveStream serves one stream with the notice serial and returns its
// client side.
func (f *sshFixture) serveStream(t *testing.T, serial uint64) net.Conn {
	t.Helper()
	srvSide, cliSide := tcpPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer srvSide.Close()
		f.srv.Serve(srvSide, streamID(serial), serial, f.clientAddr)
	}()
	t.Cleanup(func() {
		_ = cliSide.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return")
		}
	})
	_ = cliSide.SetDeadline(time.Now().Add(5 * time.Second))
	return cliSide
}

// cut drops the stream as a network loss would and waits for the client to
// see it.
func (rc *resumeConn) cut(t *testing.T) {
	t.Helper()
	_ = rc.stream.Close()
	if e := waitEnd(t, rc.ended); e != Detached {
		t.Fatalf("a cut stream ended %v, want Detached", e)
	}
}

// resume mints a resume certificate with o's edits and resumes on a new
// stream with notice serial 77.
func (rc *resumeConn) resume(t *testing.T, edit func(*certOpts)) error {
	t.Helper()
	o := rc.f.defaults()
	o.key, o.serial, o.resumes = rc.key, 77, "2a"
	if edit != nil {
		edit(&o)
	}
	signer, cert := rc.f.mint(t, o)
	rc.resumeCert = cert.Marshal()
	stream := rc.f.serveStream(t, 77)
	pos, err := rc.cr.Resume(stream, signer)
	if err != nil {
		// The client reads the refusal before the server's endAttempt ran:
		// wait for it, so the next resume never meets this attempt's claim.
		// A busy answer means another claim is held on purpose.
		if resumeCode(err) != CloseResumeBusy {
			noClaim(t, rc.f.srv)
		}
		return err
	}
	_ = stream.SetDeadline(time.Time{})
	rc.stream = stream
	// The client's close of a resumed stream sends no FIN, so a test can
	// leave the agent's end half open (TestResumeTakesOverAHalfOpenResumedStream).
	rc.ended = attachAsync(rc.cr.Conn, noFIN{stream}, pos)
	return nil
}

// alive reports whether the SSH connection answers a global request.
func (rc *resumeConn) alive() bool {
	done := make(chan error, 1)
	go func() {
		_, _, err := rc.client.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(5 * time.Second):
		return false
	}
}

func resumeCode(err error) string {
	var re *ResumeError
	if errors.As(err, &re) {
		return re.Code
	}
	return ""
}

func TestResumeContinuesTheConnection(t *testing.T) {
	clock := &manualClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	rc := f.connectResumable(t)
	if !rc.alive() {
		t.Fatal("the first connect does not answer")
	}
	rc.cut(t)
	if f.srv.LiveSessions() != 1 {
		t.Fatalf("a detached connection holds %d slots, want 1", f.srv.LiveSessions())
	}
	if err := rc.resume(t, nil); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !rc.alive() {
		t.Fatal("the resumed connection does not answer")
	}
	// A second cut and resume of the same connection.
	rc.cut(t)
	if err := rc.resume(t, nil); err != nil || !rc.alive() {
		t.Fatalf("second resume: %v", err)
	}
}

// A resume's client address replaces the first connect's for the requests
// made after it.
func TestResumeReplacesTheClientAddr(t *testing.T) {
	f := newSSHFixture(t, nil)
	f.clientAddr = "203.0.113.9:40022"
	o := f.defaults()
	o.kind = "ssh"
	rc := f.connectResumableAs(t, o)
	run := func(want string) {
		t.Helper()
		sess, err := rc.client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		_ = sess.Run("ls")
		if got := f.launcher.lastRequest(t).ClientAddr; got != want {
			t.Fatalf("launcher request ClientAddr %q, want %q", got, want)
		}
	}
	run("203.0.113.9:40022")
	rc.cut(t)
	f.clientAddr = "198.51.100.4:51000"
	if err := rc.resume(t, func(o *certOpts) { o.kind = "ssh" }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	run("198.51.100.4:51000")
}

func TestResumeRefusals(t *testing.T) {
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name string
		edit func(*certOpts)
	}{
		{"another subject", func(o *certOpts) { o.subject = "user:bob" }},
		{"another original serial", func(o *certOpts) { o.resumes = "2b" }},
		{"a fresh certificate", func(o *certOpts) { o.resumes = "" }},
		{"another kind", func(o *certOpts) { o.kind = "files" }},
		{"another login", func(o *certOpts) { o.login = "ops" }},
		// The device holds no recording key: a first connect would refuse it.
		{"a recording key not held", func(o *certOpts) {
			o.rec = &certRec{Policy: RecPolicyStrict, PubSHA256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
		}},
		{"another key", func(o *certOpts) { o.key = otherKey }},
		{"another notice serial", func(o *certOpts) { o.serial = 78 }},
		{"expired", func(o *certOpts) { o.before = time.Now().Add(-time.Minute) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Both logins are enabled, so only the resume check refuses ops.
			f := newSSHFixture(t, func(c *ServerConfig) {
				c.Capabilities = []string{"terminal", "files"}
				c.Logins = []string{testLogin, "ops"}
			})
			rc := f.connectResumable(t)
			rc.cut(t)
			key := rc.cr.key
			if tc.name == "another key" {
				// The client refuses this itself; bypass it to reach the agent.
				pub, _ := ssh.NewPublicKey(otherKey.Public())
				rc.cr.key = pub.Marshal()
			}
			if err := rc.resume(t, tc.edit); resumeCode(err) != CloseResumeRefused {
				t.Fatalf("resume = %v, want %s", err, CloseResumeRefused)
			}
			rc.cr.key = key
			// The refusal leaves the connection detached and resumable.
			if err := rc.resume(t, nil); err != nil || !rc.alive() {
				t.Fatalf("a good resume after the refusal: %v", err)
			}
		})
	}
}

func TestThreeFailedProofsEndTheConnection(t *testing.T) {
	f := newSSHFixture(t, nil)
	rc := f.connectResumable(t)
	rc.cut(t)
	token := rc.cr.token
	rc.cr.token = bytes.Repeat([]byte{7}, len(token))
	for i := range maxProofFailures {
		if err := rc.resume(t, nil); resumeCode(err) != CloseResumeRefused {
			t.Fatalf("proof %d with the wrong token = %v, want %s", i+1, err, CloseResumeRefused)
		}
	}
	rc.cr.token = token
	if err := rc.resume(t, nil); resumeCode(err) != CloseResumeLost {
		t.Fatalf("resume after %d failed proofs = %v, want %s (connection ended)", maxProofFailures, err, CloseResumeLost)
	}
}

func TestResumeWhileAnotherResumeRunsIsBusy(t *testing.T) {
	f := newSSHFixture(t, nil)
	rc := f.connectResumable(t)
	rc.cut(t)
	f.srv.mu.Lock()
	for _, e := range f.srv.conns {
		e.resuming = true
	}
	f.srv.mu.Unlock()
	if err := rc.resume(t, nil); resumeCode(err) != CloseResumeBusy {
		t.Fatalf("resume during another = %v, want %s", err, CloseResumeBusy)
	}
}

func TestDetachTimeoutEndsTheConnection(t *testing.T) {
	clock := &manualClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	rc := f.connectResumable(t)
	rc.cut(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		clock.fireDetach()
		if f.srv.LiveSessions() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the detach timeout did not end the connection")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := rc.resume(t, nil); resumeCode(err) != CloseResumeLost {
		t.Fatalf("resume after the detach timeout = %v, want %s", err, CloseResumeLost)
	}
}

func TestDeliberateCloseEndsWithoutDetach(t *testing.T) {
	f := newSSHFixture(t, nil)
	rc := f.connectResumable(t)
	_ = rc.client.Close()
	if e := waitEnd(t, rc.ended); e != Closed {
		t.Fatalf("a client close ended %v, want Closed", e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.srv.LiveSessions() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("a deliberate close left the connection holding its slot")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestResumeCertificateRefusedOnAFirstConnect(t *testing.T) {
	f := newSSHFixture(t, nil)
	o := f.defaults()
	o.resumes = "2a"
	signer, _ := f.mint(t, o)
	stream := f.serveStream(t, o.serial)
	if _, err := Hello(stream, signer, f.hostKey); resumeCode(err) != CloseResumeRefused {
		t.Fatalf("hello with a resume certificate = %v, want %s", err, CloseResumeRefused)
	}
}

// Userauth must present the certificate key the hello bound the connection
// to; a second certificate for another key is refused.
func TestUserauthMustPresentTheHelloKey(t *testing.T) {
	f := newSSHFixture(t, nil)
	helloSigner, _ := f.mint(t, f.defaults())
	otherSigner, _ := f.mint(t, f.defaults())
	stream := f.serveStream(t, 42)
	cr, err := Hello(stream, helloSigner, f.hostKey)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Time{})
	go cr.Conn.Attach(stream, 0)
	defer cr.Conn.End(errConnEnded)
	_, _, _, err = ssh.NewClientConn(cr.Conn, "gw-01", &ssh.ClientConfig{
		User: testLogin, Auth: []ssh.AuthMethod{ssh.PublicKeys(otherSigner)}, HostKeyCallback: ssh.FixedHostKey(f.hostKey), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("userauth with another key than the hello's succeeded")
	}
}

// noFIN is a stream whose Close only fails its reads and writes: the peer sees
// no close, as when a network loss leaves the edge's stream half open.
type noFIN struct{ net.Conn }

func (n noFIN) Close() error { return n.SetDeadline(time.Now()) }

// A resume while the previous resumed stream is still attached on the agent
// (half open) detaches that stream and takes over; it is never busy.
func TestResumeTakesOverAHalfOpenResumedStream(t *testing.T) {
	f := newSSHFixture(t, nil)
	rc := f.connectResumable(t)
	rc.cut(t)
	if err := rc.resume(t, nil); err != nil {
		t.Fatalf("first resume: %v", err)
	}
	if !rc.alive() {
		t.Fatal("the resumed connection does not answer")
	}
	// The client's stream fails without a FIN: the agent's end of the
	// resumed stream stays attached, half open.
	_ = rc.stream.SetDeadline(time.Now())
	if e := waitEnd(t, rc.ended); e != Detached {
		t.Fatalf("client detach ended %v", e)
	}
	if err := rc.resume(t, nil); err != nil || !rc.alive() {
		t.Fatalf("resume over a half-open resumed stream = %v, want it to take over", err)
	}
}

// A resume in progress holds the detach timer (it cannot fire); the resume's
// end, failed here, arms it again, and its fire ends the connection.
func TestARunningResumeHoldsTheDetachTimer(t *testing.T) {
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
			t.Fatal("the lost stream armed no detach timer")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got, status := f.srv.beginResume(&handler{}, e.handle); got != e || status != statusOK {
		t.Fatalf("beginResume = %v, %d", got, status)
	}
	clock.fireDetach()
	time.Sleep(50 * time.Millisecond)
	if f.srv.LiveSessions() != 1 {
		t.Fatal("the detach timer fired while a resume held the connection")
	}
	f.srv.endAttempt(e, true)
	clock.fireDetach()
	for f.srv.LiveSessions() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the failed resume left the expired connection running")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := rc.resume(t, nil); resumeCode(err) != CloseResumeLost {
		t.Fatalf("resume after the expiry = %v, want %s", err, CloseResumeLost)
	}
}

// onlyConn returns the server's one resumable connection.
func onlyConn(t *testing.T, s *Server) *resumable {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conns) != 1 {
		t.Fatalf("%d connections, want 1", len(s.conns))
	}
	for _, e := range s.conns {
		return e
	}
	return nil
}

// A taken-over resume's end does not clear the claim of the resume that took
// its stream: a third resume meanwhile is still busy.
func TestATakenOverResumeLeavesTheNextResumesClaim(t *testing.T) {
	f := newSSHFixture(t, nil)
	rc := f.connectResumable(t)
	rc.cut(t)
	// Resume A on its own stream, so the test knows when its Serve returns.
	o := f.defaults()
	o.key, o.serial, o.resumes = rc.key, 77, "2a"
	signer, _ := f.mint(t, o)
	srvSide, cliSide := tcpPair(t)
	served := make(chan struct{})
	go func() {
		defer close(served)
		defer srvSide.Close()
		f.srv.Serve(srvSide, [16]byte{0x01, 0x9c}, 77, "")
	}()
	t.Cleanup(func() { _ = cliSide.Close() })
	pos, err := rc.cr.Resume(cliSide, signer)
	if err != nil {
		t.Fatalf("resume A: %v", err)
	}
	rc.stream, rc.ended = cliSide, attachAsync(rc.cr.Conn, noFIN{cliSide}, pos)
	if !rc.alive() {
		t.Fatal("resume A does not answer")
	}
	e := onlyConn(t, f.srv)
	// Resume B has claimed the handle and detaches A's stream.
	f.srv.mu.Lock()
	e.resuming = true
	f.srv.mu.Unlock()
	e.rc.Detach()
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("resume A's Serve did not return")
	}
	f.srv.mu.Lock()
	claimed := e.resuming
	e.resuming = false
	f.srv.mu.Unlock()
	if !claimed {
		t.Fatal("resume A's end cleared resume B's claim: a third resume would not be busy")
	}
}

// Through serveResume: a verified resume keeps its claim until its stream is
// installed, so a second resume up to and at the install is busy; then a
// lost stream re-arms the detach timer and it ends the connection.
func TestAResumeKeepsItsClaimUntilItsStreamIsInstalled(t *testing.T) {
	clock := &manualClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	rc := f.connectResumable(t)
	rc.cut(t)
	var second atomic.Uint32
	second.Store(99)
	hook := func(e *resumable) {
		_, status := f.srv.beginResume(&handler{}, e.handle)
		second.Store(status)
	}
	afterResumeInstall.Store(&hook)
	t.Cleanup(func() { afterResumeInstall.Store(nil) })
	if err := rc.resume(t, nil); err != nil || !rc.alive() {
		t.Fatalf("resume: %v", err)
	}
	if got := second.Load(); got != statusBusy {
		t.Fatalf("a second resume at the install = %d, want busy (%d)", got, statusBusy)
	}
	afterResumeInstall.Store(nil)
	rc.cut(t)
	deadline := time.Now().Add(5 * time.Second)
	for f.srv.LiveSessions() != 0 {
		clock.fireDetach()
		if time.Now().After(deadline) {
			t.Fatal("the resumed connection's lost stream armed no detach timer")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Install takes an attached stream over: the old stream's run returns
// Detached and the new one carries the bytes.
func TestInstallTakesOverAnAttachedStream(t *testing.T) {
	a, b := NewResumableConn(), NewResumableConn()
	s1a, s1b := tcpPair(t)
	endA1 := attachAsync(a, s1a, 0)
	// b leaves its first stream without a FIN, so a's stays attached and only
	// a's next Install can take it over.
	endB1 := attachAsync(b, noFIN{s1b}, 0)
	if _, err := a.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(b, buf); err != nil || string(buf) != "one" {
		t.Fatalf("first stream read %q, %v", buf, err)
	}
	s2a, s2b := tcpPair(t)
	b.Detach()
	if e := waitEnd(t, endB1); e != Detached {
		t.Fatalf("b's first stream ended %v", e)
	}
	endB2 := attachAsync(b, s2b, a.Received())
	// a's first stream is still attached: Install takes it over.
	endA2 := attachAsync(a, s2a, b.Received())
	if e := waitEnd(t, endA1); e != Detached {
		t.Fatalf("a's taken-over stream ended %v, want Detached", e)
	}
	if _, err := a.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(b, buf); err != nil || string(buf) != "two" {
		t.Fatalf("second stream read %q, %v", buf, err)
	}
	_ = a.Close()
	waitEnd(t, endA2)
	waitEnd(t, endB2)
}

// expire drops the conn, so a write blocked on a full send buffer of a
// detached connection returns and run's end is not stuck behind it.
func TestExpireUnblocksABlockedWrite(t *testing.T) {
	e := &resumable{rc: NewResumableConn(), ended: make(chan string, 1)}
	if _, err := e.rc.Write(make([]byte, resumeSendBuffer)); err != nil {
		t.Fatal(err)
	}
	wrote := make(chan error, 1)
	go func() {
		_, err := e.rc.Write([]byte("stderr: the session ended"))
		wrote <- err
	}()
	select {
	case err := <-wrote:
		t.Fatalf("the write did not block on a full buffer: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	e.expire()
	select {
	case err := <-wrote:
		if err == nil {
			t.Fatal("the blocked write succeeded after expire")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expire left the write blocked")
	}
	if reason := <-e.ended; reason != CloseDetachTimeout {
		t.Fatalf("queued end %q, want %s", reason, CloseDetachTimeout)
	}
}

// A resume naming a position outside the agent's send buffer ends the
// connection resume_lost only once its proof verifies: the same message
// with a bad proof (a relay replaying an old resume) leaves it resumable.
func TestALostPositionEndsTheConnectionOnlyAfterTheProof(t *testing.T) {
	f := newSSHFixture(t, nil)
	rc := f.connectResumable(t)
	if !rc.alive() {
		t.Fatal("the connection does not answer")
	}
	rc.cut(t)
	// Claim fewer received bytes than the client acked: the agent trimmed them.
	rc.cr.Conn.mu.Lock()
	real := rc.cr.Conn.received
	rc.cr.Conn.received = 0
	rc.cr.Conn.mu.Unlock()
	if real == 0 {
		t.Fatal("no bytes were received to lose")
	}
	token := rc.cr.token
	rc.cr.token = bytes.Repeat([]byte{9}, len(token))
	if err := rc.resume(t, nil); resumeCode(err) != CloseResumeRefused {
		t.Fatalf("lost position with a bad proof = %v, want %s", err, CloseResumeRefused)
	}
	rc.cr.token = token
	rc.cr.Conn.mu.Lock()
	rc.cr.Conn.received = real
	rc.cr.Conn.mu.Unlock()
	if err := rc.resume(t, nil); err != nil || !rc.alive() {
		t.Fatalf("the connection did not survive a replayed lost position: %v", err)
	}
	rc.cut(t)
	rc.cr.Conn.mu.Lock()
	rc.cr.Conn.received = 0
	rc.cr.Conn.mu.Unlock()
	if err := rc.resume(t, nil); resumeCode(err) != CloseResumeLost {
		t.Fatalf("lost position with a good proof = %v, want %s", err, CloseResumeLost)
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.srv.LiveSessions() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("a lost position with a good proof left the connection running")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// onlyDeadline returns the connection's detach deadline once it is set.
func onlyDeadline(t *testing.T, s *Server, e *resumable) time.Time {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		d := e.deadline
		s.mu.Unlock()
		if !d.IsZero() {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatal("the lost stream set no detach deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The detach deadline is absolute: a refused resume (the handle is not
// secret) does not move it, and a resume that reaches the install clears it.
func TestARefusedResumeDoesNotMoveTheDetachDeadline(t *testing.T) {
	clock := &manualClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	rc := f.connectResumable(t)
	rc.cut(t)
	e := onlyConn(t, f.srv)
	first := onlyDeadline(t, f.srv, e)
	clock.advance(time.Minute)
	if err := rc.resume(t, func(o *certOpts) { o.subject = "user:bob" }); resumeCode(err) != CloseResumeRefused {
		t.Fatalf("refused resume = %v", err)
	}
	settled(t, f.srv, e)
	if got := onlyDeadline(t, f.srv, e); !got.Equal(first) {
		t.Fatalf("a refused resume moved the deadline by %v", got.Sub(first))
	}
	// The timer re-armed at the attempt's end runs for the time left, a
	// minute short of a full window.
	if armed := clock.lastArmed(); armed > detachTimeout-time.Minute+time.Second {
		t.Fatalf("the timer re-armed after a refused resume runs %v, want at most the %v left", armed, detachTimeout-time.Minute)
	}
	if err := rc.resume(t, nil); err != nil || !rc.alive() {
		t.Fatalf("resume: %v", err)
	}
	f.srv.mu.Lock()
	cleared := e.deadline.IsZero()
	f.srv.mu.Unlock()
	if !cleared {
		t.Fatal("an installed resume left the detach deadline set")
	}
}

// A deadline that passes while a resume attempt runs is not cut into the
// attempt; the attempt's failure ends the connection at once.
func TestADeadlinePassedDuringAnAttemptEndsTheConnectionAfterIt(t *testing.T) {
	clock := &manualClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	rc := f.connectResumable(t)
	rc.cut(t)
	e := onlyConn(t, f.srv)
	onlyDeadline(t, f.srv, e)
	if _, status := f.srv.beginResume(&handler{}, e.handle); status != statusOK {
		t.Fatalf("beginResume = %d", status)
	}
	clock.advance(detachTimeout + time.Second)
	clock.fireDetach()
	time.Sleep(50 * time.Millisecond)
	if f.srv.LiveSessions() != 1 {
		t.Fatal("the deadline expired the connection while an attempt ran")
	}
	// A second resume during the attempt is busy.
	if _, status := f.srv.beginResume(&handler{}, e.handle); status != statusBusy {
		t.Fatalf("a second resume during the attempt = %d, want busy", status)
	}
	f.srv.endAttempt(e, true)
	deadline := time.Now().Add(5 * time.Second)
	for f.srv.LiveSessions() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the failed attempt left a connection past its deadline running")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// settled waits until the server's end of every resume attempt on e ran:
// no stream handler holds e and no claim is left.
func settled(t *testing.T, s *Server, e *resumable) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		done := e.running == 0 && !e.resuming
		s.mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the resume attempt's end never ran on the server")
		}
		time.Sleep(time.Millisecond)
	}
}

// noClaim waits until no connection on s holds a resume claim: every
// attempt's end ran on the server.
func noClaim(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		held := false
		for _, e := range s.conns {
			held = held || e.resuming
		}
		s.mu.Unlock()
		if !held {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a refused resume's claim was never released on the server")
		}
		time.Sleep(time.Millisecond)
	}
}

// A resume after the deadline passed, before the detach timer fired, is
// lost: the claim checks the deadline itself.
func TestAResumeAfterThePassedDeadlineIsLost(t *testing.T) {
	clock := &manualClock{}
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = clock })
	rc := f.connectResumable(t)
	rc.cut(t)
	e := onlyConn(t, f.srv)
	onlyDeadline(t, f.srv, e)
	clock.advance(detachTimeout + time.Second)
	// A certificate valid at the agent's advanced clock: without the claim's
	// deadline check this resume would be installed.
	now := clock.Now()
	valid := func(o *certOpts) { o.after, o.before = now.Add(-30*time.Second), now.Add(time.Minute) }
	if err := rc.resume(t, valid); resumeCode(err) != CloseResumeLost {
		t.Fatalf("resume past the deadline = %v, want %s", err, CloseResumeLost)
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.srv.LiveSessions() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the connection past its deadline kept running")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
