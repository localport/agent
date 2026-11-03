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
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
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
	// hold, when set, makes Start wait for it to close after announcing the
	// request on starting; helperDone receives when a helper's channel ends.
	hold       chan struct{}
	starting   chan struct{}
	helperDone chan struct{}
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
	go func() {
		l.helper(conn, req)
		if l.helperDone != nil {
			l.helperDone <- struct{}{}
		}
	}()
	return &launcher.Session{}, nil
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
	if req.Command == "hold" {
		// Ignores every frame, eof included, until the agent closes the channel.
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	if req.Kind == launcher.KindExec && req.Command != "cat" && req.Command != "" {
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
}

func (f *sshFixture) defaults() certOpts {
	return certOpts{serial: 42, kind: "terminal", login: testLogin, prefix: f.device.Prefix, spki: f.device.SPKISHA256,
		after: time.Now().Add(-30 * time.Second), before: time.Now().Add(time.Minute), signer: f.ca}
}

// mint signs a certificate for a fresh client key and returns its signer.
func (f *sshFixture) mint(t *testing.T, o certOpts) (ssh.Signer, *ssh.Certificate) {
	t.Helper()
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	client, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := json.Marshal(map[string]string{"tunnel": "abc123", "prefix": o.prefix, "spki_sha256": o.spki})
	cert := &ssh.Certificate{
		Key: client.PublicKey(), Serial: o.serial, CertType: ssh.UserCert, KeyId: "mint-1",
		ValidPrincipals: []string{o.login}, ValidAfter: uint64(o.after.Unix()), ValidBefore: uint64(o.before.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{optionDevice: string(dev)},
			Extensions:      map[string]string{extKind: o.kind, extSubject: `{"subject":"user:ana"}`, "permit-pty": ""},
		},
	}
	if o.extraCO {
		cert.CriticalOptions["force-command"] = "/bin/true"
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
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer srvSide.Close()
		f.srv.Serve(srvSide, [16]byte{0x01, 0x9a}, serial)
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
	c, chans, reqs, err := ssh.NewClientConn(cliSide, "gw-01", cfg)
	if err != nil {
		return nil, err
	}
	client := ssh.NewClient(c, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })
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
	f := newSSHFixture(t, func(c *ServerConfig) { c.Capabilities = []string{"terminal", "files"} })
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
		{"kind not served", func(o *certOpts) { o.kind = "files" }, 0},
		{"recording key not held", func(o *certOpts) { o.rec = &certRec{Policy: RecPolicyStrict, PubSHA256: "AAAA"} }, 0},
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
	if err := sess.RequestSubsystem("sftp"); err == nil {
		t.Fatal("the sftp subsystem started")
	}
	if err := sess.Setenv("PATH", "/evil"); err == nil {
		t.Fatal("env accepted")
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

// captureClient records each open and answers it.
type captureClient struct {
	block bool
	opens chan []byte
}

func (c *captureClient) Open(ctx context.Context, _ string, _, _, cert []byte) (recording.Result, error) {
	c.opens <- bytes.Clone(cert)
	if c.block {
		<-ctx.Done()
		return recording.Result{}, ctx.Err()
	}
	return recording.Result{Status: "recording"}, nil
}

func (c *captureClient) Complete(context.Context, string, []byte, recording.Completion) (recording.Result, error) {
	return recording.Result{Status: "complete"}, nil
}

func (c *captureClient) PutSegment(context.Context, string, recording.Segment) (recording.Result, error) {
	return recording.Result{}, errors.New("unexpected segment")
}

func (c *captureClient) PutSpooledSegment(context.Context, string, recording.Segment) (recording.Result, error) {
	return recording.Result{}, errors.New("unexpected segment")
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
	priv, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	sum := sha256.Sum256(pub)
	f := newSSHFixture(t, func(c *ServerConfig) {
		c.RecordingKey = func() ([]byte, [sha256.Size]byte, bool) { return pub, sum, true }
		c.Uploader = up
	})
	return f, base64.RawURLEncoding.EncodeToString(sum[:]), spoolDir
}

// A recorded connection, Strict or Best effort, opens its recording with the
// admitting certificate before any channel (the open must come while the
// certificate is valid); the recording id is the notice's session id. It
// serves one channel only, so nothing on it runs unrecorded.
func TestRecordingOpensWithTheCertificateBeforeChannels(t *testing.T) {
	for _, policy := range []string{RecPolicyStrict, RecPolicyBestEffort} {
		t.Run(policy, func(t *testing.T) {
			client := &captureClient{opens: make(chan []byte, 1)}
			f, keySum, spoolDir := recordingFixture(t, client)
			o := f.defaults()
			o.kind = "ssh"
			o.rec = &certRec{Policy: policy, PubSHA256: keySum}
			signer, cert := f.mint(t, o)
			c, err := f.dial(t, 42, signer, nil)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-client.opens:
				if !bytes.Equal(got, cert.Marshal()) {
					t.Fatal("the open did not carry the admitting certificate")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no open")
			}
			if _, err := c.NewSession(); err != nil {
				t.Fatalf("session after the open: %v", err)
			}
			if _, err := c.NewSession(); err == nil {
				t.Fatal("a second channel opened on a recorded connection")
			}
			entries, _ := os.ReadDir(spoolDir)
			if len(entries) != 1 || entries[0].Name() != uuidText([16]byte{0x01, 0x9a}) {
				t.Fatalf("spool entries %v, want the session id", entries)
			}
		})
	}
}

// A Best effort open that fails leaves the connection running unrecorded,
// with no spool entry.
func TestBestEffortRecordingOpenFailureRunsUnrecorded(t *testing.T) {
	saved := strictOpenTimeout
	strictOpenTimeout = 200 * time.Millisecond
	t.Cleanup(func() { strictOpenTimeout = saved })
	client := &captureClient{block: true, opens: make(chan []byte, 1)}
	f, keySum, spoolDir := recordingFixture(t, client)
	o := f.defaults()
	o.rec = &certRec{Policy: RecPolicyBestEffort, PubSHA256: keySum}
	c := f.connect(t, o)
	if _, err := c.NewSession(); err != nil {
		t.Fatalf("session after a failed Best effort open: %v", err)
	}
	if entries, _ := os.ReadDir(spoolDir); len(entries) != 0 {
		t.Fatalf("spool holds %v", entries)
	}
}

// A Strict open that does not answer within strictOpenTimeout closes the
// connection before any channel, and leaves no spool entry.
func TestStrictRecordingLateOpenClosesTheConnection(t *testing.T) {
	saved := strictOpenTimeout
	strictOpenTimeout = 200 * time.Millisecond
	t.Cleanup(func() { strictOpenTimeout = saved })
	client := &captureClient{block: true, opens: make(chan []byte, 1)}
	f, keySum, spoolDir := recordingFixture(t, client)
	o := f.defaults()
	o.rec = &certRec{Policy: RecPolicyStrict, PubSHA256: keySum}
	signer, _ := f.mint(t, o)
	c, err := f.dial(t, 42, signer, nil)
	if err == nil {
		if _, err := c.NewSession(); err == nil {
			t.Fatal("a channel opened on a connection whose Strict recording did not open")
		}
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
