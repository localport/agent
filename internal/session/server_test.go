//go:build linux || darwin

package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/recording"
)

const testLogin = "pi"

// fakeLauncher runs an in-process helper on each session channel: a terminal
// echoes its input and exits 7 on "bye"; exec "cat" echoes stdin until eof
// and exits 0; any other command writes it to stdout, "warn" to stderr and
// exits 3.
type fakeLauncher struct {
	mu       sync.Mutex
	requests []launcher.Request
	resizes  chan [2]uint16
	refuse   error
	// messages are the PAM messages every started session carries.
	messages []string
	// hold, when set, makes Start wait for it to close after announcing the
	// request on starting; helperDone receives when a helper's channel ends.
	hold       chan struct{}
	starting   chan struct{}
	helperDone chan struct{}
	// badEvent, when set, is the event frame payload an sftp helper sends
	// in place of a valid file event.
	badEvent []byte
	// forward, when set, serves a forward request's channel (the real
	// forward server, in-process).
	forward func(conn net.Conn)
}

func newFakeLauncher() *fakeLauncher { return &fakeLauncher{resizes: make(chan [2]uint16, 8)} }

func (l *fakeLauncher) Probe(context.Context) (launcher.Probe, error) { return launcher.Probe{}, nil }

func (l *fakeLauncher) Start(_ context.Context, req launcher.Request, channel *os.File) (*launcher.Session, error) {
	l.mu.Lock()
	l.requests = append(l.requests, req)
	refuse, hold := l.refuse, l.hold
	l.mu.Unlock()
	if refuse != nil {
		return nil, refuse
	}
	conn, err := net.FileConn(channel)
	if err != nil {
		return nil, err
	}
	if hold != nil {
		l.starting <- struct{}{}
		<-hold
	}
	if req.Kind == launcher.KindForward && l.forward != nil {
		go l.forward(conn)
		return &launcher.Session{Messages: l.messages}, nil
	}
	go func() {
		l.helper(conn, req)
		if l.helperDone != nil {
			l.helperDone <- struct{}{}
		}
	}()
	return &launcher.Session{Messages: l.messages}, nil
}

func (l *fakeLauncher) lastRequest(t *testing.T) launcher.Request {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.requests) == 0 {
		t.Fatal("no launcher request")
	}
	return l.requests[len(l.requests)-1]
}

func (l *fakeLauncher) helper(conn net.Conn, req launcher.Request) {
	defer conn.Close()
	exit := func(code int32) { _ = launcher.WriteFrame(conn, launcher.Frame{Type: launcher.FrameExit, Code: code}) }
	if req.Command == "killed" {
		exit(-9)
		return
	}
	if req.Command == "hold" {
		// Ignores every frame, eof included, until the agent closes the
		// channel.
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	event := func() {
		ev, _ := launcher.FileEvent{Op: launcher.OpList, Path: "/", Result: launcher.ResultOK}.Marshal()
		if l.badEvent != nil {
			ev = l.badEvent
		}
		_ = launcher.WriteFrame(conn, launcher.Frame{Type: launcher.FrameEvent, Data: ev})
	}
	if req.Command == "flood" {
		// Output until the channel ends, more than any client window.
		chunk := make([]byte, 32<<10)
		for launcher.WriteFrame(conn, launcher.Frame{Type: launcher.FrameData, Data: chunk}) == nil {
		}
		return
	}
	if req.Kind == launcher.KindSFTP || req.Command == "event" {
		// A file event, then the sftp bytes echo until eof; an exec helper
		// that sends one breaks the channel protocol.
		event()
	}
	if req.Kind == launcher.KindExec && req.Command != "cat" && req.Command != "" && req.Command != "event" {
		_ = launcher.WriteFrame(conn, launcher.Frame{Type: launcher.FrameData, Data: []byte(req.Command)})
		_ = launcher.WriteFrame(conn, launcher.Frame{Type: launcher.FrameStderr, Data: []byte("warn")})
		exit(3)
		return
	}
	fr := launcher.NewFrameReader(conn)
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f.Type {
		case launcher.FrameData:
			if bytes.Contains(f.Data, []byte("bye")) {
				exit(7)
				return
			}
			_ = launcher.WriteFrame(conn, launcher.Frame{Type: launcher.FrameData, Data: bytes.Clone(f.Data)})
		case launcher.FrameResize:
			l.resizes <- [2]uint16{f.Cols, f.Rows}
		case launcher.FrameEOF:
			exit(0)
			return
		}
	}
}

// sshFixture is a session server for device gw-01 with one CA key.
type sshFixture struct {
	srv      *Server
	cfg      *ServerConfig
	launcher *fakeLauncher
	ca       ed25519.PrivateKey
	device   Device
	hostKey  ssh.PublicKey
	events   chan string
	// clientAddr is the notice's client address dial serves streams with.
	clientAddr string
	// clientConn, when set, wraps the client side of each stream dial makes.
	clientConn func(net.Conn) net.Conn
}

func newSSHFixture(t *testing.T, edit func(*ServerConfig)) *sshFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gw-01"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	tlsCert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	caPub, ca, _ := ed25519.GenerateKey(rand.Reader)
	f := &sshFixture{launcher: newFakeLauncher(), ca: ca, events: make(chan string, 64),
		device: Device{Prefix: "gw-01", SPKISHA256: SPKIHash(leaf.RawSubjectPublicKeyInfo)}}
	f.hostKey, _ = ssh.NewPublicKey(&key.PublicKey)
	cfg := ServerConfig{
		Prefix:       "gw-01",
		Certificate:  func() (*tls.Certificate, bool) { return tlsCert, true },
		CAKeys:       func() []ed25519.PublicKey { return []ed25519.PublicKey{caPub} },
		Capabilities: []string{"terminal"},
		Logins:       []string{testLogin},
		Device:       "client.device",
		Identifier:   "client.device",
		Launcher:     f.launcher,
		OnEvent: func(s string) {
			select {
			case f.events <- s:
			default:
			}
		},
	}
	if edit != nil {
		edit(&cfg)
	}
	f.cfg = &cfg
	f.srv = NewServer(cfg)
	// A connection outlives its Serve call; every one ends before the test's
	// directories and fakes go away (registered after edit's TempDir).
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := f.srv.Shutdown(ctx); err != nil {
			t.Errorf("connections still running at the end of the test: %v", err)
		}
	})
	return f
}

// certOpts edits a minted certificate before it is signed.
type certOpts struct {
	serial  uint64
	kind    string
	login   string
	prefix  string
	spki    string
	after   time.Time
	before  time.Time
	extraCO bool
	rec     *certRec
	signer  ed25519.PrivateKey
	// fwdLocal and fwdRemote add the forwarding extensions.
	fwdLocal, fwdRemote bool
	// subject replaces user:ana; resumes adds the resume option.
	subject string
	resumes string
	// key signs instead of a fresh client key.
	key ed25519.PrivateKey
	// files replaces the files option of a files or ssh certificate (default
	// "download,upload") and adds it to any other kind; noFiles leaves the
	// option out.
	files   *string
	noFiles bool
	// clipboard replaces the clipboard option of a vnc or rdp certificate
	// (default "copy,paste") and adds it to any other kind; noClipboard
	// leaves the option out.
	clipboard   *string
	noClipboard bool
}

func (f *sshFixture) defaults() certOpts {
	return certOpts{serial: 42, kind: "terminal", login: testLogin, prefix: f.device.Prefix, spki: f.device.SPKISHA256,
		after: time.Now().Add(-30 * time.Second), before: time.Now().Add(time.Minute), signer: f.ca}
}

// mint signs a certificate for a fresh client key and returns its signer.
func (f *sshFixture) mint(t *testing.T, o certOpts) (ssh.Signer, *ssh.Certificate) {
	t.Helper()
	clientKey := o.key
	if clientKey == nil {
		_, clientKey, _ = ed25519.GenerateKey(rand.Reader)
	}
	client, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	subject := o.subject
	if subject == "" {
		subject = "user:ana"
	}
	dev, _ := json.Marshal(map[string]string{"tunnel": "abc123", "prefix": o.prefix, "spki_sha256": o.spki})
	cert := &ssh.Certificate{
		Key: client.PublicKey(), Serial: o.serial, CertType: ssh.UserCert, KeyId: "mint-1",
		ValidPrincipals: []string{o.login}, ValidAfter: uint64(o.after.Unix()), ValidBefore: uint64(o.before.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{optionDevice: string(dev)},
			Extensions:      map[string]string{extKind: o.kind, extSubject: `{"subject":"` + subject + `"}`, "permit-pty": ""},
		},
	}
	if o.resumes != "" {
		cert.CriticalOptions[optionResume] = o.resumes
	}
	if o.extraCO {
		cert.CriticalOptions["force-command"] = "/bin/true"
	}
	if carriesFiles(o.kind) && !o.noFiles || o.files != nil {
		cert.CriticalOptions[optionFiles] = "download,upload"
		if o.files != nil {
			cert.CriticalOptions[optionFiles] = *o.files
		}
	}
	if carriesClipboard(o.kind) && !o.noClipboard || o.clipboard != nil {
		cert.CriticalOptions[optionClipboard] = "copy,paste"
		if o.clipboard != nil {
			cert.CriticalOptions[optionClipboard] = *o.clipboard
		}
	}
	if o.fwdLocal {
		cert.Extensions[extForwardLocal] = ""
	}
	if o.fwdRemote {
		cert.Extensions[extForwardRemote] = ""
	}
	if o.rec != nil {
		raw, _ := json.Marshal(o.rec)
		cert.Extensions[extRec] = string(raw)
	}
	caSigner, err := ssh.NewSignerFromKey(o.signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, client)
	if err != nil {
		t.Fatal(err)
	}
	return certSigner, cert
}

// dial serves one stream with the notice serial and connects an x/crypto
// client that trusts exactly the device's host key.
func (f *sshFixture) dial(t *testing.T, serial uint64, signer ssh.Signer, edit func(*ssh.ClientConfig)) (*ssh.Client, error) {
	t.Helper()
	srvSide, cliSide := tcpPair(t)
	if f.clientConn != nil {
		cliSide = f.clientConn(cliSide)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer srvSide.Close()
		f.srv.Serve(srvSide, [16]byte{0x01, 0x9a}, serial, f.clientAddr)
	}()
	t.Cleanup(func() {
		_ = cliSide.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return")
		}
	})
	cfg := &ssh.ClientConfig{
		User:            signer.PublicKey().(*ssh.Certificate).ValidPrincipals[0],
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(f.hostKey),
		Timeout:         5 * time.Second,
	}
	if edit != nil {
		edit(cfg)
	}
	_ = cliSide.SetDeadline(time.Now().Add(5 * time.Second))
	cr, err := Hello(cliSide, signer, f.hostKey)
	if err != nil {
		return nil, err
	}
	_ = cliSide.SetDeadline(time.Time{})
	go cr.Conn.Attach(cliSide, 0)
	c, chans, reqs, err := ssh.NewClientConn(cr.Conn, "gw-01", cfg)
	if err != nil {
		cr.Conn.End(err)
		return nil, err
	}
	client := ssh.NewClient(c, chans, reqs)
	// A deliberate close: the closeTag leaves before the stream is cut, so
	// the agent ends the connection instead of detaching it.
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-cr.Conn.Done():
		case <-time.After(5 * time.Second):
			t.Error("the client's close did not flush")
		}
	})
	return client, nil
}

// tcpPair is a connected loopback pair. SSH needs a buffered transport: both
// ends write their version line before reading, which net.Pipe deadlocks.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	return server, client
}

func (f *sshFixture) connect(t *testing.T, o certOpts) *ssh.Client {
	t.Helper()
	signer, _ := f.mint(t, o)
	client, err := f.dial(t, o.serial, signer, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return client
}

func readFor(t *testing.T, r io.Reader, want string) {
	t.Helper()
	got := make([]byte, len(want))
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(r, got); done <- err }()
	select {
	case err := <-done:
		if err != nil || string(got) != want {
			t.Fatalf("read %q, %v; want %q", got, err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no %q within 5 s", want)
	}
}

// A terminal session: pty-req and shell start the launcher's terminal with
// the requested size; bytes pass both ways; window-change resizes; the
// helper's exit becomes exit-status, and the terminal connection ends with
// its channel.
func TestTerminalOverSSH(t *testing.T) {
	f := newSSHFixture(t, nil)
	client := f.connect(t, f.defaults())
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm-256color", 40, 100, nil); err != nil {
		t.Fatalf("pty-req: %v", err)
	}
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	req := f.launcher.lastRequest(t)
	if req.Kind != launcher.KindTerminal || req.Login != testLogin || req.Cols != 100 || req.Rows != 40 ||
		req.Term != "xterm-256color" || req.Device != "client.device" || req.Command != "" {
		t.Fatalf("launcher request %+v", req)
	}
	_, _ = in.Write([]byte("hello"))
	readFor(t, out, "hello")
	if err := sess.WindowChange(50, 120); err != nil {
		t.Fatalf("window-change: %v", err)
	}
	select {
	case got := <-f.launcher.resizes:
		if got != [2]uint16{120, 50} {
			t.Fatalf("resize %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no resize frame")
	}
	_, _ = in.Write([]byte("bye"))
	var exitErr *ssh.ExitError
	if err := sess.Wait(); !errors.As(err, &exitErr) || exitErr.ExitStatus() != 7 {
		t.Fatalf("wait = %v, want exit status 7", err)
	}
	waitClosed(t, client)
}

// A connection that ends while the launcher starts a channel's session ends
// that session once Start returns: its helper channel is closed, so the helper
// ends, and Serve returns (the dial cleanup requires it).
func TestConnectionEndDuringLauncherStart(t *testing.T) {
	f := newSSHFixture(t, nil)
	f.launcher.hold, f.launcher.starting = make(chan struct{}), make(chan struct{}, 1)
	f.launcher.helperDone = make(chan struct{}, 1)
	o := f.defaults()
	o.kind = "ssh"
	client := f.connect(t, o)
	sess, _ := client.NewSession()
	go func() { _ = sess.Start("hold") }()
	select {
	case <-f.launcher.starting:
	case <-time.After(5 * time.Second):
		t.Fatal("the launcher was not asked")
	}
	ended := make(chan struct{}, 1)
	signal := func() {
		select {
		case ended <- struct{}{}:
		default:
		}
	}
	afterChannelEnd.Store(&signal)
	t.Cleanup(func() { afterChannelEnd.Store(nil) })
	_ = client.Close()
	select {
	case <-ended: // the server ended the channel while Start is held
	case <-time.After(5 * time.Second):
		t.Fatal("the channel did not end after the client closed")
	}
	close(f.launcher.hold)
	select {
	case <-f.launcher.helperDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the session started after the connection ended was never ended")
	}
}

// The certificate's principal must be the SSH user: a certificate for pi
// presented as ops (also an enabled login) fails userauth.
func TestUserauthRequiresThePrincipalAsUser(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) { c.Logins = []string{testLogin, "ops"} })
	signer, _ := f.mint(t, f.defaults())
	if _, err := f.dial(t, 42, signer, func(c *ssh.ClientConfig) { c.User = "ops" }); err == nil {
		t.Fatal("a certificate passed userauth for a user it does not name")
	}
	if _, err := f.dial(t, 42, signer, nil); err != nil {
		t.Fatalf("the principal itself was refused: %v", err)
	}
}

func waitClosed(t *testing.T, client *ssh.Client) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection did not end")
	}
}

// exec on an ssh connection runs the command through the launcher without a
// PTY: stdout and stderr stay apart and the exit status arrives; stdin's end
// reaches the helper as eof.
func TestExecOverSSH(t *testing.T) {
	f := newSSHFixture(t, nil)
	o := f.defaults()
	o.kind = "ssh"
	client := f.connect(t, o)

	sess, _ := client.NewSession()
	var stdout, stderr bytes.Buffer
	sess.Stdout, sess.Stderr = &stdout, &stderr
	err := sess.Run("ls -l /tmp")
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 3 || stdout.String() != "ls -l /tmp" || stderr.String() != "warn" {
		t.Fatalf("run = %v, stdout %q, stderr %q", err, stdout.String(), stderr.String())
	}
	if req := f.launcher.lastRequest(t); req.Kind != launcher.KindExec || req.Command != "ls -l /tmp" || req.Cols != 0 || req.Term != "" {
		t.Fatalf("launcher request %+v", req)
	}

	sess, _ = client.NewSession()
	sess.Stdin = strings.NewReader("piped input")
	got, err := sess.Output("cat")
	if err != nil || string(got) != "piped input" {
		t.Fatalf("cat = %q, %v", got, err)
	}
}

// Every certificate the local config or the notice does not admit fails
// userauth.
func TestUserauthRefusals(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) {
		c.Capabilities, c.Desktop = []string{"terminal", "files", "desktop"}, []string{"vnc"}
	})
	_, otherCA, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name   string
		edit   func(*certOpts)
		serial uint64 // the notice's serial; 0 is the certificate's
	}{
		{"serial differs from the notice", nil, 43},
		{"another device prefix", func(o *certOpts) { o.prefix = "gw-02" }, 0},
		{"another device key", func(o *certOpts) { o.spki = "AAAA" }, 0},
		{"signed by a key outside the set", func(o *certOpts) { o.signer = otherCA }, 0},
		{"expired", func(o *certOpts) { o.after, o.before = time.Now().Add(-5*time.Minute), time.Now().Add(-time.Minute) }, 0},
		{"not yet valid", func(o *certOpts) { o.after, o.before = time.Now().Add(time.Minute), time.Now().Add(2*time.Minute) }, 0},
		{"unknown critical option", func(o *certOpts) { o.extraCO = true }, 0},
		{"login not enabled", func(o *certOpts) { o.login = "root" }, 0},
		{"kind not enabled", func(o *certOpts) { o.kind = "rdp" }, 0},
		{"desktop certificate with a device login", func(o *certOpts) { o.kind = "vnc" }, 0},
		{"recording key not held", func(o *certOpts) { o.rec = &certRec{Policy: RecPolicyStrict, PubSHA256: "AAAA"} }, 0},
		{"files certificate without its files option", func(o *certOpts) { o.kind, o.noFiles = "files", true }, 0},
		{"files option malformed", func(o *certOpts) { o.kind, o.files = "files", new("upload,download") }, 0},
		{"terminal certificate with a files option", func(o *certOpts) { o.files = new("download") }, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := f.defaults()
			if tc.edit != nil {
				tc.edit(&o)
			}
			signer, _ := f.mint(t, o)
			serial := o.serial
			if tc.serial != 0 {
				serial = tc.serial
			}
			if _, err := f.dial(t, serial, signer, nil); err == nil {
				t.Fatal("userauth passed")
			}
		})
	}
	t.Run("plain key", func(t *testing.T) {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		plain, _ := ssh.NewSignerFromKey(k)
		cert, _ := f.mint(t, f.defaults())
		// The user comes from the certificate; the key offered is plain.
		_, err := f.dial(t, 42, cert, func(c *ssh.ClientConfig) { c.Auth = []ssh.AuthMethod{ssh.PublicKeys(plain)} })
		if err == nil {
			t.Fatal("a plain key passed userauth")
		}
	})
}

// Userauth proves the key the prelude admitted; the admission (login, kind,
// options) comes from the admitted certificate, never from the one userauth
// presents. A client whose file holds an earlier certificate over the same key
// (ssh-proxy retried with a new one) logs in; another key or user does not.
func TestUserauthIsBoundToTheAdmittedKeyAndCertificate(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) { c.Capabilities = []string{"terminal", "files"} })
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	admitted := f.defaults()
	admitted.key = key
	admittedSigner, _ := f.mint(t, admitted)

	earlier := admitted
	earlier.serial = admitted.serial + 1
	earlier.kind = "ssh"
	earlier.after, earlier.before = time.Now().Add(-10*time.Minute), time.Now().Add(-time.Minute)
	earlierSigner, _ := f.mint(t, earlier)
	plainSigner, _ := ssh.NewSignerFromKey(key)

	for name, auth := range map[string]ssh.Signer{"an earlier certificate": earlierSigner, "the plain key": plainSigner} {
		client, err := f.dial(t, admitted.serial, admittedSigner, func(c *ssh.ClientConfig) {
			c.Auth = []ssh.AuthMethod{ssh.PublicKeys(auth)}
		})
		if err != nil {
			t.Fatalf("userauth with %s over the admitted key = %v", name, err)
		}
		// The admitted certificate is a terminal one: exec, which the earlier
		// ssh certificate would allow, stays refused.
		sess, _ := client.NewSession()
		var exitErr *ssh.ExitError
		if err := sess.Run("id"); err == nil || errors.As(err, &exitErr) {
			t.Fatalf("%s: exec = %v, want the terminal admission's refusal", name, err)
		}
	}

	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	other := admitted
	other.key = otherKey
	otherSigner, _ := f.mint(t, other)
	if _, err := f.dial(t, admitted.serial, admittedSigner, func(c *ssh.ClientConfig) {
		c.Auth = []ssh.AuthMethod{ssh.PublicKeys(otherSigner)}
	}); err == nil {
		t.Fatal("a certificate over another key passed userauth")
	}
}

// A certificate of a CA key the agent does not hold yet passes after one key
// refresh that brings it.
func TestUserauthRefreshesForAnUnknownCA(t *testing.T) {
	newPub, newCA, _ := ed25519.GenerateKey(rand.Reader)
	var refreshed atomic.Int32
	var keys atomic.Pointer[[]ed25519.PublicKey]
	f := newSSHFixture(t, func(c *ServerConfig) {
		old := c.CAKeys()
		keys.Store(&old)
		c.CAKeys = func() []ed25519.PublicKey { return *keys.Load() }
		c.RefreshKeys = func(context.Context) error {
			refreshed.Add(1)
			both := append(*keys.Load(), newPub)
			keys.Store(&both)
			return nil
		}
	})
	o := f.defaults()
	o.signer = newCA
	f.connect(t, o)
	if refreshed.Load() != 1 {
		t.Fatalf("refreshed %d times, want 1", refreshed.Load())
	}
}

// Channel policy: a terminal connection serves one session channel with a
// PTY shell; exec, a second channel, subsystems, forwarding and X11 are
// refused. An ssh connection serves at most maxChannels channels at once.
func TestChannelPolicy(t *testing.T) {
	f := newSSHFixture(t, nil)
	client := f.connect(t, f.defaults())
	sess, _ := client.NewSession()
	var exitErr *ssh.ExitError
	if err := sess.Run("id"); err == nil || errors.As(err, &exitErr) {
		t.Fatalf("exec on a terminal connection: %v, want the request refused", err)
	}
	if n := len(f.launcher.requests); n != 0 {
		t.Fatalf("exec on a terminal connection reached the launcher (%d requests)", n)
	}
	if _, err := client.NewSession(); err == nil {
		t.Fatal("a second channel opened on a terminal connection")
	}

	o := f.defaults()
	o.kind = "ssh"
	client = f.connect(t, o)
	if _, err := client.Dial("tcp", "127.0.0.1:22"); err == nil {
		t.Fatal("direct-tcpip opened")
	}
	if ok, _, _ := client.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		Addr string
		Port uint32
	}{"0.0.0.0", 8080})); ok {
		t.Fatal("tcpip-forward accepted")
	}
	sess, _ = client.NewSession()
	for _, req := range []string{"auth-agent-req@openssh.com", "x11-req"} {
		if ok, _ := sess.SendRequest(req, true, nil); ok {
			t.Fatalf("%s accepted", req)
		}
	}
	if err := sess.RequestSubsystem("netconf"); err == nil {
		t.Fatal("a subsystem other than sftp started")
	}
	if err := sess.Setenv("PATH", "/evil"); err == nil {
		t.Fatal("env PATH accepted")
	}
	held := []*ssh.Session{sess}
	for len(held) < maxChannels {
		s, err := client.NewSession()
		if err != nil {
			t.Fatalf("channel %d: %v", len(held)+1, err)
		}
		held = append(held, s)
	}
	if _, err := client.NewSession(); err == nil {
		t.Fatalf("channel %d opened", maxChannels+1)
	}
}

// The sftp subsystem: an ssh connection serves it beside shells, a files
// connection serves it only (no pty, shell or exec), a terminal connection
// never; each becomes one launcher request of kind sftp without a terminal.
func TestFilesChannelPolicy(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) { c.Capabilities = []string{"terminal", "files"} })
	o := f.defaults()
	o.kind = "files"
	client := f.connect(t, o)
	sess, _ := client.NewSession()
	if ok, _ := sess.SendRequest("pty-req", true, ssh.Marshal(ptyRequest{Term: "xterm", Cols: 80, Rows: 24})); ok {
		t.Fatal("pty-req accepted on a files connection")
	}
	if err := sess.Shell(); err == nil {
		t.Fatal("a shell started on a files connection")
	}
	sess, _ = client.NewSession()
	if err := sess.Start("id"); err == nil {
		t.Fatal("an exec started on a files connection")
	}
	sess, _ = client.NewSession()
	if err := sess.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("sftp on a files connection: %v", err)
	}
	if req := f.launcher.lastRequest(t); req.Kind != launcher.KindSFTP || req.Cols != 0 || req.Term != "" || req.Command != "" ||
		!req.FilesDownload || !req.FilesUpload {
		t.Fatalf("launcher request %+v", req)
	}
	if n := len(f.launcher.requests); n != 1 {
		t.Fatalf("launcher requests %d, want only the sftp one", n)
	}

	o.kind = "ssh"
	sess, _ = f.connect(t, o).NewSession()
	if err := sess.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("sftp on an ssh connection: %v", err)
	}
	if req := f.launcher.lastRequest(t); req.Kind != launcher.KindSFTP {
		t.Fatalf("launcher request %+v", req)
	}

	// The certificate's files option is the access the file server gets.
	o.kind, o.files = "ssh", new("download")
	sess, _ = f.connect(t, o).NewSession()
	if err := sess.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("sftp with download only: %v", err)
	}
	if req := f.launcher.lastRequest(t); !req.FilesDownload || req.FilesUpload {
		t.Fatalf("download-only launcher request %+v", req)
	}
	o.files = nil

	o.kind = "terminal"
	sess, _ = f.connect(t, o).NewSession()
	if err := sess.RequestSubsystem("sftp"); err == nil {
		t.Fatal("sftp on a terminal connection")
	}
}

// A malformed event from an sftp helper, or one naming an exec, ends the
// channel with helper_failed: the agent validates what it records.
func TestBadFileEventEndsTheSFTPChannel(t *testing.T) {
	for name, payload := range map[string][]byte{
		"malformed":      []byte(`{"op":`),
		"unknown field":  []byte(`{"op":"list","path":"/","result":"ok","extra":1}`),
		"exec from sftp": []byte(`{"op":"exec","command":"id"}`),
	} {
		t.Run(name, func(t *testing.T) {
			f := newSSHFixture(t, func(c *ServerConfig) { c.Capabilities = []string{"terminal", "files"} })
			f.launcher.badEvent = payload
			o := f.defaults()
			o.kind = "ssh"
			sess, err := f.connect(t, o).NewSession()
			if err != nil {
				t.Fatal(err)
			}
			stderr, _ := sess.StderrPipe()
			// An open stdin, so the helper never exits on eof before the event.
			if _, err := sess.StdinPipe(); err != nil {
				t.Fatal(err)
			}
			if err := sess.RequestSubsystem("sftp"); err != nil {
				t.Fatal(err)
			}
			readFor(t, stderr, "\r\nlocalport: session ended: "+CloseHelperFailed)
		})
	}
}

// A file event from an sftp helper is taken and the channel keeps relaying;
// one from an exec helper ends the channel with helper_failed.
func TestFileEventsOnlyFromTheFileServer(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) { c.Capabilities = []string{"terminal", "files"} })
	o := f.defaults()
	o.kind = "ssh"
	client := f.connect(t, o)

	sess, _ := client.NewSession()
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	if err := sess.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(stdout, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("the sftp channel stopped relaying after an event: %q, %v", buf, err)
	}

	sess, _ = client.NewSession()
	stderr, _ := sess.StderrPipe()
	// An open stdin, so the helper never exits on eof before the event.
	if _, err := sess.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := sess.Start("event"); err != nil {
		t.Fatal(err)
	}
	readFor(t, stderr, "\r\nlocalport: session ended: "+CloseHelperFailed+"\r\n")
}

// A password login answers one keyboard-interactive prompt after its
// certificate, and every channel's launcher request carries the answer;
// keyboard-interactive without the certificate step never prompts; a login
// that is not a password login is never prompted.
func TestPasswordLogins(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) { c.PasswordLogins = []string{testLogin} })
	o := f.defaults()
	o.kind = "ssh"
	signer, _ := f.mint(t, o)
	prompts := 0
	answer := func(_, _ string, questions []string, echos []bool) ([]string, error) {
		prompts++
		if len(questions) != 1 || questions[0] != passwordPrompt || echos[0] {
			t.Errorf("prompt %q echo %v", questions, echos)
		}
		return []string{"s3cret"}, nil
	}
	client, err := f.dial(t, o.serial, signer, func(c *ssh.ClientConfig) {
		c.Auth = append(c.Auth, ssh.KeyboardInteractive(answer))
	})
	if err != nil || prompts != 1 {
		t.Fatalf("certificate then password: %v, %d prompts", err, prompts)
	}
	sess, _ := client.NewSession()
	if err := sess.Run("ls -l /tmp"); err == nil {
		t.Fatal("run: want exit status 3")
	}
	if req := f.launcher.lastRequest(t); !req.HasPassword || string(req.Password) != "s3cret" {
		t.Fatalf("launcher request password %v %q", req.HasPassword, req.Password)
	}

	// Keyboard-interactive alone: the server offers it only after a verified
	// certificate, so the prompt never runs.
	prompts = 0
	if _, err := f.dial(t, o.serial, signer, func(c *ssh.ClientConfig) {
		c.Auth = []ssh.AuthMethod{ssh.KeyboardInteractive(answer)}
	}); err == nil || prompts != 0 {
		t.Fatalf("keyboard-interactive without a certificate: %v, %d prompts", err, prompts)
	}

	// The certificate alone does not finish a password login.
	if _, err := f.dial(t, o.serial, signer, nil); err == nil {
		t.Fatal("a password login authenticated without its password")
	}

	g := newSSHFixture(t, nil)
	og := g.defaults()
	og.kind = "ssh"
	signer, _ = g.mint(t, og)
	prompts = 0
	if _, err := g.dial(t, og.serial, signer, func(c *ssh.ClientConfig) {
		c.Auth = append(c.Auth, ssh.KeyboardInteractive(answer))
	}); err != nil || prompts != 0 {
		t.Fatalf("a login without a password: %v, %d prompts", err, prompts)
	}
}

// env requests: LANG and LC_* before the shell or exec reach the launcher
// request; any other name, a control character, an oversized value, a 17th
// variable and an env after the exec are refused.
func TestEnvRequests(t *testing.T) {
	f := newSSHFixture(t, nil)
	o := f.defaults()
	o.kind = "ssh"
	client := f.connect(t, o)
	sess, _ := client.NewSession()
	for name, value := range map[string]string{"LANG": "en_GB.UTF-8", "LC_TIME": "de_DE.UTF-8"} {
		if err := sess.Setenv(name, value); err != nil {
			t.Fatalf("env %s refused: %v", name, err)
		}
	}
	for _, kv := range [][2]string{{"PATH", "/evil"}, {"LD_PRELOAD", "x.so"}, {"LC_ALL", "a\nb"}, {"LANGUAGE", "en"},
		{"LC_CTYPE", strings.Repeat("a", launcher.MaxEnvValue+1)}, {"lc_all", "C"}} {
		if err := sess.Setenv(kv[0], kv[1]); err == nil {
			t.Fatalf("env %s=%q accepted", kv[0], kv[1])
		}
	}
	if err := sess.Run("ls -l /tmp"); err == nil {
		t.Fatal("run: want exit status 3")
	}
	req := f.launcher.lastRequest(t)
	if len(req.Env) != 2 || req.Env["LANG"] != "en_GB.UTF-8" || req.Env["LC_TIME"] != "de_DE.UTF-8" {
		t.Fatalf("launcher env %v", req.Env)
	}
	if ok, _ := sess.SendRequest("env", true, ssh.Marshal(struct{ Name, Value string }{"LANG", "C"})); ok {
		t.Fatal("env after the exec accepted")
	}

	many, _ := client.NewSession()
	for i := range launcher.MaxEnvVars {
		if err := many.Setenv(fmt.Sprintf("LC_V%c", 'A'+i), "C"); err != nil {
			t.Fatalf("env %d refused: %v", i+1, err)
		}
	}
	if err := many.Setenv("LC_OVER", "C"); err == nil {
		t.Fatalf("env %d accepted", launcher.MaxEnvVars+1)
	}
}

// Only the key exchanges, ciphers and MACs of the server discipline pass.
func TestAlgorithms(t *testing.T) {
	f := newSSHFixture(t, nil)
	for _, tc := range []struct {
		name string
		edit func(*ssh.ClientConfig)
		ok   bool
	}{
		{"mlkem768x25519 only", func(c *ssh.ClientConfig) { c.KeyExchanges = []string{ssh.KeyExchangeMLKEM768X25519} }, true},
		{"curve25519 only", func(c *ssh.ClientConfig) { c.KeyExchanges = []string{ssh.KeyExchangeCurve25519} }, true},
		{"group14 only", func(c *ssh.ClientConfig) { c.KeyExchanges = []string{ssh.KeyExchangeDH14SHA256} }, false},
		{"aes-ctr only", func(c *ssh.ClientConfig) { c.Ciphers = []string{ssh.CipherAES128CTR} }, false},
		{"non-etm mac with ctr", func(c *ssh.ClientConfig) {
			c.Ciphers, c.MACs = []string{ssh.CipherAES128CTR}, []string{ssh.HMACSHA256}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer, _ := f.mint(t, f.defaults())
			_, err := f.dial(t, 42, signer, tc.edit)
			if (err == nil) != tc.ok {
				t.Fatalf("dial err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// Shutdown ends a live connection, telling the client why on stderr, and
// waits for it.
func TestShutdownEndsConnections(t *testing.T) {
	f := newSSHFixture(t, nil)
	client := f.connect(t, f.defaults())
	sess, _ := client.NewSession()
	_ = sess.RequestPty("xterm", 24, 80, nil)
	stderr, _ := sess.StderrPipe()
	// An open stdin: a nil one sends eof, and the shell exiting on it would
	// end the channel before Shutdown does, without the notice.
	if _, err := sess.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	if n := f.srv.LiveSessions(); n != 1 {
		t.Fatalf("live sessions %d", n)
	}
	errc := make(chan error, 1)
	go func() { errc <- f.srv.Shutdown(context.Background()) }()
	readFor(t, stderr, "\r\nlocalport: session ended: shutdown\r\n")
	if err := <-errc; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	waitClosed(t, client)
	if n := f.srv.LiveSessions(); n != 0 {
		t.Fatalf("live sessions %d after shutdown", n)
	}
}

// A launcher refusal fails the shell request and names the reason on stderr.
func TestLauncherRefusalFailsTheRequest(t *testing.T) {
	f := newSSHFixture(t, nil)
	f.launcher.refuse = launcher.Refusal(launcher.CodeAccountRefused)
	client := f.connect(t, f.defaults())
	sess, _ := client.NewSession()
	_ = sess.RequestPty("xterm", 24, 80, nil)
	stderr, _ := sess.StderrPipe()
	if err := sess.Shell(); err == nil {
		t.Fatal("the shell started")
	}
	readFor(t, stderr, "localport: "+CodeLoginNotAllowed+"\r\n")
}

// PAM's messages reach the client's stderr ahead of the session's output, and
// ahead of the refusal when the setup refused.
func TestPAMMessagesReachTheClient(t *testing.T) {
	t.Run("started", func(t *testing.T) {
		f := newSSHFixture(t, nil)
		f.launcher.messages = []string{"Your password expires in 3 days.", "two\nlines"}
		o := f.defaults()
		o.kind = "ssh"
		client := f.connect(t, o)
		sess, _ := client.NewSession()
		var stderr bytes.Buffer
		sess.Stderr = &stderr
		_ = sess.Run("ls")
		if want := "Your password expires in 3 days.\r\ntwo\r\nlines\r\nwarn"; stderr.String() != want {
			t.Fatalf("stderr %q, want %q", stderr.String(), want)
		}
	})
	t.Run("refused", func(t *testing.T) {
		f := newSSHFixture(t, nil)
		f.launcher.refuse = &launcher.RefusalError{Code: launcher.CodeAccountRefused, Messages: []string{"Your account has expired."}}
		client := f.connect(t, f.defaults())
		sess, _ := client.NewSession()
		_ = sess.RequestPty("xterm", 24, 80, nil)
		stderr, _ := sess.StderrPipe()
		if err := sess.Shell(); err == nil {
			t.Fatal("the shell started")
		}
		readFor(t, stderr, "Your account has expired.\r\nlocalport: "+CodeLoginNotAllowed+"\r\n")
	})
}

// The notice's client address reaches every launcher request of the
// connection.
func TestClientAddrReachesTheLauncherRequest(t *testing.T) {
	f := newSSHFixture(t, nil)
	f.clientAddr = "203.0.113.9:40022"
	o := f.defaults()
	o.kind = "ssh"
	client := f.connect(t, o)
	sess, _ := client.NewSession()
	_ = sess.Run("ls")
	if req := f.launcher.lastRequest(t); req.ClientAddr != f.clientAddr {
		t.Fatalf("launcher request ClientAddr %q, want %q", req.ClientAddr, f.clientAddr)
	}
}

// A client that stops reading fills its channel window, so the end reason
// write blocks; Shutdown still ends the connection within the write bound.
func TestShutdownIsBoundedByAClientThatStopsReading(t *testing.T) {
	old := endWriteTimeout
	endWriteTimeout = 200 * time.Millisecond
	t.Cleanup(func() { endWriteTimeout = old })
	f := newSSHFixture(t, nil)
	o := f.defaults()
	o.kind = "ssh"
	client := f.connect(t, o)
	sess, _ := client.NewSession()
	// Never read: the window closes once the helper's output fills it.
	_, _ = sess.StdoutPipe()
	if err := sess.Start("flood"); err != nil {
		t.Fatal(err)
	}
	// The 2 MiB window fills in milliseconds; without the write bound,
	// Shutdown blocks past this wait.
	time.Sleep(500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if err := f.srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v after %v, want it bounded by the end write", err, time.Since(start))
	}
}

// waitEvent reads events until want arrives.
func waitEvent(t *testing.T, events <-chan string, want string) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case got := <-events:
			if got == want {
				return
			}
		case <-timeout:
			t.Fatalf("no event %q", want)
		}
	}
}

// forgedSigner presents cert but signs with another key, as a client that
// holds a certificate and not its key would.
type forgedSigner struct {
	cert  *ssh.Certificate
	other ssh.Signer
}

func (s forgedSigner) PublicKey() ssh.PublicKey { return s.cert }
func (s forgedSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return s.other.Sign(r, data)
}

// A hello whose signature does not verify is refused before its certificate
// is checked: a certificate from an unknown CA key triggers no CA refresh.
func TestBadHelloSignatureCausesNoCARefresh(t *testing.T) {
	var refreshes atomic.Int32
	f := newSSHFixture(t, func(c *ServerConfig) {
		c.RefreshKeys = func(context.Context) error { refreshes.Add(1); return nil }
	})
	_, unknownCA, _ := ed25519.GenerateKey(rand.Reader)
	o := f.defaults()
	o.signer = unknownCA
	_, cert := f.mint(t, o)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromKey(otherKey)
	if _, err := f.dial(t, 42, forgedSigner{cert: cert, other: other}, nil); err == nil {
		t.Fatal("a forged hello connected")
	}
	if n := refreshes.Load(); n != 0 {
		t.Fatalf("a forged hello caused %d CA refreshes", n)
	}
}

// A resume whose signature does not verify is refused before it claims the
// connection or checks its certificate.
func TestBadResumeSignatureCausesNoClaimOrCARefresh(t *testing.T) {
	var refreshes, claims atomic.Int32
	f := newSSHFixture(t, func(c *ServerConfig) {
		c.RefreshKeys = func(context.Context) error { refreshes.Add(1); return nil }
	})
	rc := f.connectResumable(t)
	rc.cut(t)
	hook := func() { claims.Add(1) }
	afterAttemptClaimCleared.Store(&hook)
	t.Cleanup(func() { afterAttemptClaimCleared.Store(nil) })

	_, unknownCA, _ := ed25519.GenerateKey(rand.Reader)
	o := f.defaults()
	o.key, o.serial, o.resumes, o.signer = rc.key, 77, "2a", unknownCA
	_, cert := f.mint(t, o)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	other, _ := ssh.NewSignerFromKey(otherKey)
	if _, err := rc.cr.Resume(f.serveStream(t, 77), forgedSigner{cert: cert, other: other}); resumeCode(err) != CloseResumeRefused {
		t.Fatalf("forged resume = %v, want %s", err, CloseResumeRefused)
	}
	afterAttemptClaimCleared.Store(nil)
	if n, c := refreshes.Load(), claims.Load(); n != 0 || c != 0 {
		t.Fatalf("a forged resume caused %d CA refreshes and %d claims", n, c)
	}
	if err := rc.resume(t, nil); err != nil || !rc.alive() {
		t.Fatalf("a good resume after the forged one: %v", err)
	}
	if n := handshakeCount(f.srv); n != 0 {
		t.Fatalf("handshake count %d after a resume, want 0", n)
	}
}

// A first connect's stream is attached before addConn publishes the
// connection, so a resume of its handle never finds it without a stream and
// is never taken over by the first stream's late install.
func TestFirstStreamIsAttachedWhenTheConnIsPublished(t *testing.T) {
	f := newSSHFixture(t, nil)
	attached := make(chan bool, 1)
	hook := func(e *resumable) {
		e.rc.mu.Lock()
		attached <- e.rc.att != nil
		e.rc.mu.Unlock()
	}
	afterConnPublished.Store(&hook)
	t.Cleanup(func() { afterConnPublished.Store(nil) })
	_ = f.connect(t, f.defaults())
	if !<-attached {
		t.Fatal("the connection was published without its first stream")
	}
}

// handshakeCount is the server's count of streams before their handshake
// decision.
func handshakeCount(s *Server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handshakes
}

// waitHandshakes waits until the count is n.
func waitHandshakes(t *testing.T, s *Server, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for handshakeCount(s) != n {
		if time.Now().After(deadline) {
			t.Fatalf("handshake count %d, want %d", handshakeCount(s), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// At most maxHandshakes streams wait for their handshake decision; the next
// one is closed unread. Every end path releases the count, and a live
// session holds none.
func TestHandshakeCap(t *testing.T) {
	f := newSSHFixture(t, nil)
	var silent []net.Conn
	for range maxHandshakes {
		silent = append(silent, f.serveStream(t, 42))
	}
	waitHandshakes(t, f.srv, maxHandshakes)

	extra := f.serveStream(t, 42)
	_ = extra.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := extra.Read(make([]byte, 1)); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the stream over the cap read %d bytes, %v; want closed", n, err)
	}
	if n := handshakeCount(f.srv); n != maxHandshakes {
		t.Fatalf("handshake count %d after a refused stream, want %d", n, maxHandshakes)
	}
	// Serve reports the refusal, so the mux skips the flush.
	srvSide, _ := tcpPair(t)
	if !f.srv.Serve(srvSide, [16]byte{0x01}, 42, "") {
		t.Fatal("Serve over the cap did not report the stream refused unread")
	}
	_ = srvSide.Close()

	// Prelude errors release the count.
	for _, c := range silent {
		_ = c.Close()
	}
	waitHandshakes(t, f.srv, 0)

	// A refusal releases it.
	o := f.defaults()
	o.login = "nobody"
	signer, _ := f.mint(t, o)
	if _, err := f.dial(t, 42, signer, nil); err == nil {
		t.Fatal("a refused login connected")
	}
	waitHandshakes(t, f.srv, 0)

	// A live session holds none.
	client := f.connect(t, f.defaults())
	if n := handshakeCount(f.srv); n != 0 || f.srv.LiveSessions() != 1 {
		t.Fatalf("a live session: handshake count %d, live %d", n, f.srv.LiveSessions())
	}
	_ = client
}

// A stream that sends no prelude within handshakeTimeout releases its count.
func TestHandshakeTimeoutReleasesTheCount(t *testing.T) {
	old := handshakeTimeout
	handshakeTimeout = time.Second
	t.Cleanup(func() { handshakeTimeout = old })
	f := newSSHFixture(t, nil)
	_ = f.serveStream(t, 42)
	waitHandshakes(t, f.srv, 1)
	waitHandshakes(t, f.srv, 0)
}

// capturedOpen is one open a captureClient saw.
type capturedOpen struct {
	id, sessionID string
	cert          []byte
	channels      int32
}

// captureClient records each open and answers it, and accepts every segment,
// keeping each recording's wrapped DEK and segments for decryption with priv
// (set by recordingFixture).
type captureClient struct {
	block bool
	opens chan capturedOpen
	priv  hpke.PrivateKey
	// failedOpens, when set, receives each failed open.
	failedOpens chan recording.FailedOpen

	mu       sync.Mutex
	wrapped  map[string][]byte
	segments map[string][]recording.Segment
}

func (c *captureClient) keep(id string, seg recording.Segment) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.segments == nil {
		c.segments = map[string][]recording.Segment{}
	}
	// A retried or spooled segment arrives again under its index.
	if slices.ContainsFunc(c.segments[id], func(s recording.Segment) bool { return s.Index == seg.Index }) {
		return
	}
	seg.Object = bytes.Clone(seg.Object)
	c.segments[id] = append(c.segments[id], seg)
	slices.SortFunc(c.segments[id], func(a, b recording.Segment) int { return int(a.Index) - int(b.Index) })
}

// plaintext decrypts recording id once its final segment arrived, waiting
// up to 5 s for it.
func (c *captureClient) plaintext(t *testing.T, id string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		segs := slices.Clone(c.segments[id])
		wrapped := c.wrapped[id]
		c.mu.Unlock()
		if n := len(segs); n > 0 && segs[n-1].Final {
			return decryptRecordingID(t, c.priv, id, wrapped, segs)
		}
		if time.Now().After(deadline) {
			t.Fatalf("recording %s has no final segment", id)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *captureClient) OpenFailed(_ context.Context, f recording.FailedOpen) (recording.Result, error) {
	if c.failedOpens != nil {
		c.failedOpens <- f
	}
	return recording.Result{Status: "incomplete"}, nil
}

func (c *captureClient) Open(ctx context.Context, id, sessionID string, wrappedDEK, _, cert []byte, channels int32) (recording.Result, error) {
	c.mu.Lock()
	if c.wrapped == nil {
		c.wrapped = map[string][]byte{}
	}
	c.wrapped[id] = bytes.Clone(wrappedDEK)
	c.mu.Unlock()
	select {
	case c.opens <- capturedOpen{id: id, sessionID: sessionID, cert: bytes.Clone(cert), channels: channels}:
	case <-ctx.Done():
		return recording.Result{}, ctx.Err()
	}
	if c.block {
		<-ctx.Done()
		return recording.Result{}, ctx.Err()
	}
	return recording.Result{Status: "recording"}, nil
}

func (c *captureClient) Complete(context.Context, string, []byte, recording.Completion) (recording.Result, error) {
	return recording.Result{Status: "complete"}, nil
}

func (c *captureClient) PutSegment(_ context.Context, id string, seg recording.Segment) (recording.Result, error) {
	c.keep(id, seg)
	return recording.Result{Status: "recording", Segments: seg.Index + 1}, nil
}

func (c *captureClient) PutSpooledSegment(_ context.Context, id string, load func() (recording.Segment, error)) (recording.Result, error) {
	seg, err := load()
	if err != nil {
		return recording.Result{}, err
	}
	c.keep(id, seg)
	return recording.Result{Status: "recording", Segments: seg.Index + 1}, nil
}

// recordingFixture is an ssh fixture with an uploader on a temporary spool
// and a held team recording key.
func recordingFixture(t *testing.T, client *captureClient) (*sshFixture, string, string) {
	t.Helper()
	root := t.TempDir()
	spoolDir := filepath.Join(root, "recordings")
	spool, _, err := recording.OpenSpool(root, spoolDir, false)
	if err != nil {
		t.Fatal(err)
	}
	up := recording.NewUploader(recording.UploaderConfig{
		Spool:      spool,
		Client:     func(string) (recording.Client, error) { return client, nil },
		Configured: func(string) bool { return true },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); up.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	priv, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client.priv = priv
	pub := priv.PublicKey().Bytes()
	sum := sha256.Sum256(pub)
	f := newSSHFixture(t, func(c *ServerConfig) {
		c.RecordingKey = func() ([]byte, [sha256.Size]byte, bool) { return pub, sum, true }
		c.Uploader = up
	})
	return f, base64.RawURLEncoding.EncodeToString(sum[:]), spoolDir
}

// On a recorded connection, Strict or Best effort, every session channel
// opens its own recording with the admitting certificate before its helper
// starts: a fresh recording id per channel, the notice's session id as the
// connection. Opening the session channel alone opens nothing.
func TestRecordingOpensOnePerChannel(t *testing.T) {
	for _, policy := range []string{RecPolicyStrict, RecPolicyBestEffort} {
		t.Run(policy, func(t *testing.T) {
			client := &captureClient{opens: make(chan capturedOpen, 2)}
			f, keySum, spoolDir := recordingFixture(t, client)
			o := f.defaults()
			o.kind = "ssh"
			o.rec = &certRec{Policy: policy, PubSHA256: keySum}
			signer, cert := f.mint(t, o)
			c, err := f.dial(t, 42, signer, nil)
			if err != nil {
				t.Fatal(err)
			}
			first, err := c.NewSession()
			if err != nil {
				t.Fatalf("first channel: %v", err)
			}
			select {
			case got := <-client.opens:
				t.Fatalf("a channel with no shell or exec opened a recording: %+v", got)
			case <-time.After(100 * time.Millisecond):
			}
			second, err := c.NewSession()
			if err != nil {
				t.Fatalf("a second channel on a recorded connection: %v", err)
			}
			for _, s := range []*ssh.Session{first, second} {
				var stderr bytes.Buffer
				s.Stderr = &stderr
				var exitErr *ssh.ExitError
				if err := s.Run("ls -l /tmp"); !errors.As(err, &exitErr) || exitErr.ExitStatus() != 3 {
					t.Fatalf("run on a recorded channel: %v", err)
				}
				if !strings.HasPrefix(stderr.String(), recordedNotice) {
					t.Fatalf("stderr %q does not open with the recording notice", stderr.String())
				}
			}
			session := uuidText([16]byte{0x01, 0x9a})
			ids := map[string]bool{}
			for range 2 {
				select {
				case got := <-client.opens:
					if !bytes.Equal(got.cert, cert.Marshal()) || got.sessionID != session || got.id == session {
						t.Fatalf("open %+v, want the admitting certificate, session %s and its own id", got, session)
					}
					ids[got.id] = true
				case <-time.After(5 * time.Second):
					t.Fatal("a channel opened no recording")
				}
			}
			if len(ids) != 2 {
				t.Fatalf("recording ids %v, want one per channel", ids)
			}
			if len(f.launcher.requests) != 2 {
				t.Fatalf("launcher requests %d, want 2", len(f.launcher.requests))
			}
			if entries, _ := os.ReadDir(spoolDir); len(entries) > 2 {
				t.Fatalf("spool entries %v, want at most one per channel", entries)
			}
		})
	}
}

// A recorded sftp channel records its file events only: the protocol bytes
// it relays, file contents included, never become output events.
func TestSFTPRecordingHoldsFileEventsOnly(t *testing.T) {
	client := &captureClient{opens: make(chan capturedOpen, 1)}
	f, keySum, _ := recordingFixture(t, client)
	o := f.defaults()
	o.kind = "ssh"
	o.rec = &certRec{Policy: RecPolicyBestEffort, PubSHA256: keySum}
	sess, err := f.connect(t, o).NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	if err := sess.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	_, _ = stdin.Write([]byte("file contents"))
	readFor(t, stdout, "file contents")
	_, _ = stdin.Write([]byte("bye"))
	// The helper exits; the channel closes, which ends the stdout stream.
	if _, err := io.Copy(io.Discard, stdout); err != nil {
		t.Fatalf("sftp channel end: %v", err)
	}
	open := <-client.opens
	text := client.plaintext(t, open.id)
	if strings.Contains(text, "file contents") || strings.Contains(text, `"o"`) {
		t.Fatalf("the sftp recording holds output events:\n%s", text)
	}
	if !strings.Contains(text, `"f"`) {
		t.Fatalf("the sftp recording holds no file event:\n%s", text)
	}
}

// A Best effort open that fails leaves the channel running unrecorded, with
// no spool entry.
func TestBestEffortRecordingOpenFailureRunsUnrecorded(t *testing.T) {
	saved := strictOpenTimeout
	strictOpenTimeout = 200 * time.Millisecond
	t.Cleanup(func() { strictOpenTimeout = saved })
	client := &captureClient{block: true, opens: make(chan capturedOpen, 1)}
	f, keySum, spoolDir := recordingFixture(t, client)
	o := f.defaults()
	o.kind = "ssh"
	o.rec = &certRec{Policy: RecPolicyBestEffort, PubSHA256: keySum}
	c := f.connect(t, o)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("channel: %v", err)
	}
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	var exitErr *ssh.ExitError
	if err := sess.Run("ls -l /tmp"); !errors.As(err, &exitErr) || exitErr.ExitStatus() != 3 {
		t.Fatalf("run after a failed Best effort open: %v", err)
	}
	if strings.Contains(stderr.String(), recordedNotice) {
		t.Fatal("an unrecorded channel shows the recording notice")
	}
	if entries, _ := os.ReadDir(spoolDir); len(entries) != 0 {
		t.Fatalf("spool holds %v", entries)
	}
}

// A Strict open that does not answer within strictOpenTimeout refuses that
// channel before its helper starts and leaves no spool entry; the connection
// stays and its next channel tries its own recording.
func TestStrictRecordingLateOpenRefusesTheChannel(t *testing.T) {
	saved := strictOpenTimeout
	strictOpenTimeout = 200 * time.Millisecond
	t.Cleanup(func() { strictOpenTimeout = saved })
	client := &captureClient{block: true, opens: make(chan capturedOpen, 2)}
	f, keySum, spoolDir := recordingFixture(t, client)
	o := f.defaults()
	o.kind = "ssh"
	o.rec = &certRec{Policy: RecPolicyStrict, PubSHA256: keySum}
	c := f.connect(t, o)
	for i := range 2 {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatalf("channel %d: %v", i+1, err)
		}
		stderr, _ := sess.StderrPipe()
		if err := sess.Start("ls -l /tmp"); err == nil {
			t.Fatalf("channel %d ran with its Strict recording not open", i+1)
		}
		readFor(t, stderr, "localport: "+CodeRecordingUnavailable+"\r\n")
	}
	if len(client.opens) != 2 {
		t.Fatalf("opens %d, want one per channel", len(client.opens))
	}
	if len(f.launcher.requests) != 0 {
		t.Fatal("a session started")
	}
	if entries, _ := os.ReadDir(spoolDir); len(entries) != 0 {
		t.Fatalf("spool holds %v", entries)
	}
}

func TestUUIDText(t *testing.T) {
	var id [16]byte
	binary.BigEndian.PutUint64(id[:8], 0x0192_3456_789a_7bcd)
	binary.BigEndian.PutUint64(id[8:], 0x8123_4567_89ab_cdef)
	if got := uuidText(id); got != "01923456-789a-7bcd-8123-456789abcdef" {
		t.Fatalf("uuidText = %s", got)
	}
}

// A certificate whose window is open-ended, past int64 seconds or empty is
// refused before the window is compared with the clock.
func TestCertValidityWindowMalformed(t *testing.T) {
	f := newSSHFixture(t, nil)
	cas := f.cfg.CAKeys()
	caSigner, err := ssh.NewSignerFromKey(f.ca)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	nowU := uint64(now.Unix())
	for name, tc := range map[string]struct {
		after, before uint64
		ok            bool
	}{
		"valid":           {nowU - 30, nowU + 60, true},
		"infinity":        {nowU - 30, ssh.CertTimeInfinity, false},
		"past 1<<62":      {nowU - 30, 1<<62 + 1, false},
		"after == before": {nowU, nowU, false},
		"after > before":  {nowU + 1, nowU, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, cert := f.mint(t, f.defaults())
			cert.ValidAfter, cert.ValidBefore = tc.after, tc.before
			if err := cert.SignCert(rand.Reader, caSigner); err != nil {
				t.Fatal(err)
			}
			_, err := verifyCert(cert, testLogin, cas, f.device, 42, now)
			if tc.ok {
				if err != nil {
					t.Fatalf("verifyCert = %v", err)
				}
				return
			}
			if !errors.Is(err, errCertRefused) || !strings.Contains(err.Error(), "validity window malformed") {
				t.Fatalf("verifyCert = %v, want the malformed window refusal", err)
			}
		})
	}
}
