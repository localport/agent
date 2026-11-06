//go:build linux || darwin

package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
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

// A resume whose certificate narrows the files option ends the SFTP channels
// started with more access; a channel started afterwards gets the narrowed
// access, and a resume that keeps it leaves that channel running. An ssh
// connection, which outlives its channels (a files connection ends with its
// last channel).
func TestAResumeNarrowingFilesEndsSFTPChannels(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) { c.Capabilities = []string{"terminal", "files"} })
	o := f.defaults()
	o.kind = "ssh"
	rc := f.connectResumableAs(t, o)
	openSFTP := func() io.Reader {
		t.Helper()
		sess, err := rc.client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		out, err := sess.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := sess.RequestSubsystem("sftp"); err != nil {
			t.Fatalf("sftp: %v", err)
		}
		return out
	}
	full := openSFTP()
	rc.cut(t)
	downloadOnly := func(o *certOpts) { o.kind, o.files = "ssh", new("download") }
	if err := rc.resume(t, downloadOnly); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !closedWithin(full, 5*time.Second) {
		t.Fatal("an SFTP channel started with upload stays open after a resume without it")
	}
	narrow := openSFTP()
	if req := f.launcher.lastRequest(t); !req.FilesDownload || req.FilesUpload {
		t.Fatalf("a channel after the narrowing resume: %+v", req)
	}
	rc.cut(t)
	if err := rc.resume(t, downloadOnly); err != nil {
		t.Fatalf("second resume: %v", err)
	}
	if closedWithin(narrow, 300*time.Millisecond) {
		t.Fatal("a resume with the same access ended an SFTP channel")
	}
}

// The recording of an SFTP channel a narrowing resume ends states why it
// ended.
func TestAResumeNarrowingFilesMarksTheEndedChannelsRecording(t *testing.T) {
	client := &captureClient{opens: make(chan capturedOpen, 1)}
	f, keySum, _ := recordingFixture(t, client)
	rec := &certRec{Policy: RecPolicyBestEffort, PubSHA256: keySum}
	o := f.defaults()
	o.kind, o.rec = "ssh", rec
	rc := f.connectResumableAs(t, o)
	sess, err := rc.client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("sftp: %v", err)
	}
	rc.cut(t)
	if err := rc.resume(t, func(o *certOpts) { o.kind, o.rec, o.files = "ssh", rec, new("download") }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !closedWithin(out, 5*time.Second) {
		t.Fatal("an SFTP channel started with upload stays open after a resume without it")
	}
	open := <-client.opens
	if text := client.plaintext(t, open.id); !strings.Contains(text, `"`+CloseFilesNarrowed+`"`) {
		t.Fatalf("the ended channel's recording does not state %s:\n%s", CloseFilesNarrowed, text)
	}
}

// A resume that narrows the files option while the launcher starts an SFTP
// server finds no file server to end yet (readmit skips a channel not handed
// off), so the hand-off itself refuses the channel and closes the server
// started with the old access.
func TestAResumeNarrowingFilesDuringLauncherStartRefusesTheChannel(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) { c.Capabilities = []string{"terminal", "files"} })
	f.launcher.hold, f.launcher.starting = make(chan struct{}), make(chan struct{}, 1)
	f.launcher.helperDone = make(chan struct{}, 1)
	o := f.defaults()
	o.kind = "ssh"
	rc := f.connectResumableAs(t, o)
	sess, err := rc.client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	subsystem := make(chan error, 1)
	go func() { subsystem <- sess.RequestSubsystem("sftp") }()
	select {
	case <-f.launcher.starting:
	case <-time.After(5 * time.Second):
		t.Fatal("the launcher was not asked")
	}
	if req := f.launcher.lastRequest(t); !req.FilesDownload || !req.FilesUpload {
		t.Fatalf("the server starts with %+v, want both directions", req)
	}
	rc.cut(t)
	if err := rc.resume(t, func(o *certOpts) { o.kind, o.files = "ssh", new("download") }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	close(f.launcher.hold)
	select {
	case err := <-subsystem:
		if err == nil {
			t.Fatal("an SFTP server started with upload was handed off after a resume without it")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the sftp request got no answer")
	}
	select {
	case <-f.launcher.helperDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the file server started with the old access was never ended")
	}
}
