//go:build linux || darwin

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// closedWithin reports whether reading c ends within d: the peer closed it.
func closedWithin(c io.Reader, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, c)
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// A resume runs the connection under the resume certificate: a forwarding
// direction it no longer allows ends that direction's forwarded connections
// and listeners, and new forwards of it are refused.
func TestAResumeNarrowsForwarding(t *testing.T) {
	f := forwardFixture(t, nil)
	tcp := echoServer(t, "tcp", "127.0.0.1:0")
	rc := f.connectResumableAs(t, f.forwardOpts(true, true))
	// The forward helpers end with the connection, before serveForwards
	// waits for them.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = f.srv.Shutdown(ctx)
	})
	local, err := rc.client.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pingPong(t, local)
	ln, err := rc.client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	loopback := net.JoinHostPort("127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	c, err := net.Dial("tcp", loopback)
	if err != nil {
		t.Fatalf("the remote listener does not accept: %v", err)
	}
	pingPong(t, c)
	_ = c.Close()

	rc.cut(t)
	// The grant lost both forwarding directions: the resume certificate
	// carries neither extension.
	if err := rc.resume(t, func(o *certOpts) { o.kind = "ssh" }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !closedWithin(local, 5*time.Second) {
		t.Fatal("a local forward the resume disallows stays open")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", loopback)
		if err != nil {
			break
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("a remote listener the resume disallows still accepts")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var oce *ssh.OpenChannelError
	if _, err := rc.client.Dial("tcp", tcp.Addr().String()); !errors.As(err, &oce) || oce.Reason != ssh.Prohibited {
		t.Fatalf("a local forward after the resume: %v, want prohibited", err)
	}
	if _, err := rc.client.Listen("tcp", "127.0.0.1:0"); err == nil {
		t.Fatal("a remote forward after the resume was allowed")
	}
	if !rc.alive() {
		t.Fatal("the resumed connection does not answer")
	}
}

// A resume narrows only the direction it disallows, and a later resume that
// allows it again widens the connection's forwarding.
func TestAResumeNarrowsOneDirectionAndWidensAgain(t *testing.T) {
	f := forwardFixture(t, nil)
	tcp := echoServer(t, "tcp", "127.0.0.1:0")
	rc := f.connectResumableAs(t, f.forwardOpts(true, true))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = f.srv.Shutdown(ctx)
	})
	ln, err := rc.client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	loopback := net.JoinHostPort("127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))

	rc.cut(t)
	if err := rc.resume(t, func(o *certOpts) { o.kind, o.fwdRemote = "ssh", true }); err != nil {
		t.Fatalf("resume without forward_local: %v", err)
	}
	c, err := net.Dial("tcp", loopback)
	if err != nil {
		t.Fatalf("the remote listener the resume still allows was closed: %v", err)
	}
	pingPong(t, c)
	_ = c.Close()
	var oce *ssh.OpenChannelError
	if _, err := rc.client.Dial("tcp", tcp.Addr().String()); !errors.As(err, &oce) || oce.Reason != ssh.Prohibited {
		t.Fatalf("a local forward without forward_local: %v, want prohibited", err)
	}

	rc.cut(t)
	if err := rc.resume(t, func(o *certOpts) { o.kind, o.fwdLocal, o.fwdRemote = "ssh", true, true }); err != nil {
		t.Fatalf("resume with forward_local again: %v", err)
	}
	local, err := rc.client.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatalf("a local forward after a widening resume: %v", err)
	}
	pingPong(t, local)
	_ = local.Close()
}

// A resume that disallows remote forwarding while a tcpip-forward is between
// its bind and its registration refuses that listener.
func TestAResumeDuringAListenRefusesTheListener(t *testing.T) {
	f := forwardFixture(t, nil)
	client := f.connect(t, f.forwardOpts(false, true))
	var bound uint32
	hook := func(fw *forwarder, l *remoteListener) {
		bound = l.port
		fw.c.readmit(&connAdmission{admission: &admission{Kind: "ssh"}, sessionID: fw.c.adm.Load().sessionID})
	}
	beforeListenerRegistration.Store(&hook)
	t.Cleanup(func() { beforeListenerRegistration.Store(nil) })
	if _, err := client.Listen("tcp", "127.0.0.1:0"); err == nil {
		t.Fatal("a listener bound across a resume that disallows remote forwarding was registered")
	}
	// The refused listener's port is released, not left bound unregistered.
	loopback := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(bound)))
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", loopback)
		if err != nil {
			break
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("the refused listener still accepts")
		}
		time.Sleep(10 * time.Millisecond)
	}
	beforeListenerRegistration.Store(nil)
	if _, err := client.Listen("tcp", "127.0.0.1:0"); err == nil {
		t.Fatal("a remote forward after the narrowing was allowed")
	}
}

// A channel opened after a resume opens its recording under the resume
// stream's session id with the resume certificate, the pair the edge
// attests for that stream.
func TestAChannelAfterAResumeRecordsUnderTheResumeStream(t *testing.T) {
	client := &captureClient{opens: make(chan capturedOpen, 2)}
	f, keySum, _ := recordingFixture(t, client)
	rec := &certRec{Policy: RecPolicyStrict, PubSHA256: keySum}
	o := f.defaults()
	o.kind, o.rec = "ssh", rec
	rc := f.connectResumableAs(t, o)
	rc.cut(t)
	if err := rc.resume(t, func(o *certOpts) { o.kind, o.rec = "ssh", rec }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	s, err := rc.client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var exitErr *ssh.ExitError
	if err := s.Run("ls -l /tmp"); !errors.As(err, &exitErr) || exitErr.ExitStatus() != 3 {
		t.Fatalf("run on a channel opened after the resume: %v", err)
	}
	session := uuidText(streamID(77))
	select {
	case got := <-client.opens:
		if got.sessionID != session || !bytes.Equal(got.cert, rc.resumeCert) {
			t.Fatalf("open session %s, want the resume stream's %s and the resume certificate", got.sessionID, session)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the channel opened no recording")
	}
}
