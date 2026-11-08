//go:build linux || darwin

package session

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// otherKeySigner presents its certificate but signs with another key: a
// prelude signature that does not verify with the certificate's key.
type otherKeySigner struct {
	ssh.Signer
	other ssh.Signer
}

func (s otherKeySigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return s.other.Sign(r, data)
}

// closeResume runs a close resume on a new stream with notice serial 77, the
// certificate edited by edit and the signer replaced by wrap when set.
func (rc *resumeConn) closeResume(t *testing.T, edit func(*certOpts), wrap func(ssh.Signer) ssh.Signer) error {
	t.Helper()
	o := rc.f.defaults()
	o.key, o.serial, o.resumes = rc.key, 77, "2a"
	if edit != nil {
		edit(&o)
	}
	signer, _ := rc.f.mint(t, o)
	if wrap != nil {
		signer = wrap(signer)
	}
	_, err := rc.cr.resume(rc.f.serveStream(t, 77), signer, true)
	noClaim(t, rc.f.srv)
	return err
}

// waitNoSessions waits until the server holds no session slot.
func waitNoSessions(t *testing.T, s *Server, why string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.LiveSessions() != 0 {
		if time.Now().After(deadline) {
			t.Fatal(why)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The manual clock never fires the detach timer, so an end proves the close
// resume ended the connection.
func TestACloseResumeEndsTheConnection(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = &manualClock{} })
	rc := f.connectResumable(t)
	if !rc.alive() {
		t.Fatal("the first connect does not answer")
	}
	ends := make(chan string, 1)
	hook := func(reason string) { ends <- reason }
	onConnEnd.Store(&hook)
	t.Cleanup(func() { onConnEnd.Store(nil) })
	rc.cut(t)
	f.srv.mu.Lock()
	var e *resumable
	for _, c := range f.srv.conns {
		e = c
	}
	f.srv.mu.Unlock()
	if err := rc.closeResume(t, nil, nil); err != nil {
		t.Fatalf("close resume: %v", err)
	}
	waitNoSessions(t, f.srv, "a close resume left the connection running")
	// A received closeTag's end: the client's close, no reason (detach
	// timeout, refusal, loss).
	select {
	case reason := <-ends:
		if reason != "" {
			t.Fatalf("the close resume ended the connection with %q, want a client close", reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the connection's end was not decided")
	}
	e.rc.mu.Lock()
	remoteClosed := e.rc.remoteClosed
	e.rc.mu.Unlock()
	if !remoteClosed {
		t.Fatal("the connection does not record the peer's close")
	}
	if err := rc.resume(t, nil); resumeCode(err) != CloseResumeLost {
		t.Fatalf("a resume after the close resume = %v, want %s", err, CloseResumeLost)
	}
}

// A conn its peer closed (a close resume or a received closeTag) takes no
// later stream, so the resume token is spent.
func TestARemoteClosedConnRefusesAStream(t *testing.T) {
	c := NewResumableConn()
	c.CloseRemote()
	a, b := net.Pipe()
	defer b.Close()
	if run, end := c.Install(a, 0); run != nil || end != Ended {
		t.Fatalf("Install on a remote-closed conn = run %v, %v; want nil, Ended", run != nil, end)
	}
}

func TestARefusedCloseResumeLeavesTheConnectionDetached(t *testing.T) {
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromKey(otherKey)
	for _, tc := range []struct {
		name  string
		edit  func(*certOpts)
		wrap  func(ssh.Signer) ssh.Signer
		token bool
	}{
		{name: "a bad proof", token: true},
		{name: "another subject", edit: func(o *certOpts) { o.subject = "user:bob" }},
		{name: "a bad signature", wrap: func(s ssh.Signer) ssh.Signer { return otherKeySigner{Signer: s, other: other} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSSHFixture(t, func(c *ServerConfig) { c.clock = &manualClock{} })
			rc := f.connectResumable(t)
			rc.cut(t)
			token := rc.cr.token
			if tc.token {
				rc.cr.token = bytes.Repeat([]byte{7}, len(token))
			}
			if err := rc.closeResume(t, tc.edit, tc.wrap); resumeCode(err) != CloseResumeRefused {
				t.Fatalf("close resume = %v, want %s", err, CloseResumeRefused)
			}
			rc.cr.token = token
			if f.srv.LiveSessions() != 1 {
				t.Fatalf("a refused close resume left %d slots, want the detached connection's 1", f.srv.LiveSessions())
			}
			if err := rc.resume(t, nil); err != nil || !rc.alive() {
				t.Fatalf("a good resume after the refused close resume: %v", err)
			}
		})
	}
}

func TestACloseResumeFromALostPositionEnds(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) { c.clock = &manualClock{} })
	rc := f.connectResumable(t)
	if !rc.alive() {
		t.Fatal("the connection does not answer")
	}
	rc.cut(t)
	rc.cr.Conn.mu.Lock()
	rc.cr.Conn.received = 0
	rc.cr.Conn.mu.Unlock()
	if err := rc.closeResume(t, nil, nil); err != nil {
		t.Fatalf("close resume from a lost position: %v", err)
	}
	waitNoSessions(t, f.srv, "a close resume from a lost position left the connection running")
}
