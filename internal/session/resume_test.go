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
}

func (c *manualClock) Now() time.Time { return time.Now() }

func (c *manualClock) NewTimer(d time.Duration) (<-chan time.Time, func() bool) {
	ch := make(chan time.Time, 1)
	if d == detachTimeout {
		c.mu.Lock()
		c.detach = append(c.detach, ch)
		c.mu.Unlock()
	}
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
}

// connectResumable runs a first connect with serial 42 (resume option "2a").
func (f *sshFixture) connectResumable(t *testing.T) *resumeConn {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	o := f.defaults()
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
		User: testLogin, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(f.hostKey),
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

// serveStream serves one stream with the notice serial and returns its
// client side.
func (f *sshFixture) serveStream(t *testing.T, serial uint64) net.Conn {
	t.Helper()
	srvSide, cliSide := tcpPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer srvSide.Close()
		f.srv.Serve(srvSide, [16]byte{0x01, 0x9b}, serial)
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
	signer, _ := rc.f.mint(t, o)
	stream := rc.f.serveStream(t, 77)
	pos, err := rc.cr.Resume(stream, signer)
	if err != nil {
		return err
	}
	_ = stream.SetDeadline(time.Time{})
	rc.stream = stream
	rc.ended = attachAsync(rc.cr.Conn, stream, pos)
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
		{"another key", func(o *certOpts) { o.key = otherKey }},
		{"another notice serial", func(o *certOpts) { o.serial = 78 }},
		{"expired", func(o *certOpts) { o.before = time.Now().Add(-time.Minute) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSSHFixture(t, func(c *ServerConfig) { c.Capabilities = []string{"terminal", "files"} })
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
