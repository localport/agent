//go:build unix

package session

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/recording"
	"github.com/localport/agent/internal/sessionhelper"
)

// forwardFixture is an ssh fixture whose device enables forwarding and whose
// launcher runs the real forward server in-process for a forward request.
func forwardFixture(t *testing.T, edit func(*ServerConfig)) *sshFixture {
	t.Helper()
	f := newSSHFixture(t, func(c *ServerConfig) {
		c.Capabilities = []string{"terminal", "forwarding"}
		if edit != nil {
			edit(c)
		}
	})
	serveForwards(t, f.launcher)
	return f
}

func serveForwards(t *testing.T, l *fakeLauncher) {
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	l.forward = func(conn net.Conn) {
		wg.Go(func() {
			defer conn.Close()
			_ = sessionhelper.ServeForwardSocket(conn.(*net.UnixConn), t.Logf)
		})
	}
}

func (f *sshFixture) forwardOpts(local, remote bool) certOpts {
	o := f.defaults()
	o.kind, o.fwdLocal, o.fwdRemote = "ssh", local, remote
	return o
}

func echoServer(t *testing.T, network, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln
}

func pingPong(t *testing.T, c io.ReadWriter) {
	t.Helper()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	readFor(t, c, "ping")
}

func forwardRequests(l *fakeLauncher) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.requests {
		if r.Kind == launcher.KindForward {
			n++
		}
	}
	return n
}

func socketDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "lpfw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// Local forwards (ssh -L, -W, a unix socket) run through one helper per
// connection, started at the first forward.
func TestLocalForward(t *testing.T) {
	f := forwardFixture(t, nil)
	f.clientAddr = "[2001:db8::7]:5022"
	f.launcher.messages = []string{"pam\x1b[2J"}
	tcp := echoServer(t, "tcp", "127.0.0.1:0")
	sock := filepath.Join(socketDir(t), "e.sock")
	echoServer(t, "unix", sock)
	client := f.connect(t, f.forwardOpts(true, false))
	for range 2 {
		c, err := client.Dial("tcp", tcp.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		pingPong(t, c)
		_ = c.Close()
	}
	c, err := client.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	pingPong(t, c)
	_ = c.Close()
	if n := forwardRequests(f.launcher); n != 1 {
		t.Fatalf("forward helpers started: %d, want 1", n)
	}
	r := f.launcher.lastRequest(t)
	if r.Login != testLogin || r.Device != "client.device" || r.Cols != 0 || len(r.Env) != 0 || r.ClientAddr != f.clientAddr {
		t.Fatalf("forward request %+v", r)
	}
	// A forward has no stderr: PAM's messages go to the log, escaped.
	waitEvent(t, f.events, `session: PAM message for "`+testLogin+`": "pam\x1b[2J"`)
	// A refused target answers the channel open with connection failed.
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := closed.Addr().String()
	_ = closed.Close()
	_, err = client.Dial("tcp", addr)
	var oce *ssh.OpenChannelError
	if !errors.As(err, &oce) || oce.Reason != ssh.ConnectionFailed || oce.Message != "connection_refused" {
		t.Fatalf("dial a closed port: %v", err)
	}
}

// Forwarding needs the device capability, the certificate extension for the
// direction, and an ssh connection; each refusal reaches no helper.
func TestForwardRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		capabilities  []string
		kind          string
		local, remote bool
	}{
		"no device capability": {[]string{"terminal"}, "ssh", true, true},
		"no extension":         {[]string{"terminal", "forwarding"}, "ssh", false, false},
		"terminal connection":  {[]string{"terminal", "forwarding"}, "terminal", true, true},
		"local only":           {[]string{"terminal", "forwarding"}, "ssh", true, false},
		"remote only":          {[]string{"terminal", "forwarding"}, "ssh", false, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := forwardFixture(t, func(c *ServerConfig) { c.Capabilities = tc.capabilities })
			tcp := echoServer(t, "tcp", "127.0.0.1:0")
			o := f.forwardOpts(tc.local, tc.remote)
			o.kind = tc.kind
			client := f.connect(t, o)
			wantLocal := name == "local only"
			wantRemote := name == "remote only"
			c, err := client.Dial("tcp", tcp.Addr().String())
			var oce *ssh.OpenChannelError
			switch {
			case wantLocal && err != nil:
				t.Fatalf("an allowed local forward: %v", err)
			case wantLocal:
				_ = c.Close()
			case !errors.As(err, &oce) || oce.Reason != ssh.Prohibited:
				t.Fatalf("a refused local forward: %v, want prohibited", err)
			}
			ok, _, err := client.SendRequest(reqTCPIPForward, true, ssh.Marshal(struct {
				Addr string
				Port uint32
			}{"127.0.0.1", 0}))
			if err != nil || ok != wantRemote {
				t.Fatalf("tcpip-forward: %v, %v; want %v", ok, err, wantRemote)
			}
			if !wantLocal && !wantRemote && forwardRequests(f.launcher) != 0 {
				t.Fatal("a refused forward reached the launcher")
			}
		})
	}
}

// Where unix socket forwards are not served (Windows), a direct-streamlocal
// channel is refused prohibited and a streamlocal-forward request false,
// before reaching the helper; TCP forwards still work.
func TestStreamLocalRefusedWhereUnsupported(t *testing.T) {
	old := unixForwardSupported
	unixForwardSupported = false
	t.Cleanup(func() { unixForwardSupported = old })
	f := forwardFixture(t, nil)
	client := f.connect(t, f.forwardOpts(true, true))
	path := filepath.Join(t.TempDir(), "s")
	_, err := client.Dial("unix", path)
	var oce *ssh.OpenChannelError
	if !errors.As(err, &oce) || oce.Reason != ssh.Prohibited {
		t.Fatalf("direct-streamlocal: %v, want prohibited", err)
	}
	ok, _, err := client.SendRequest(reqStreamLocalForward, true, ssh.Marshal(struct{ Path string }{path}))
	if err != nil || ok {
		t.Fatalf("streamlocal-forward: %v, %v; want false", ok, err)
	}
	if n := forwardRequests(f.launcher); n != 0 {
		t.Fatalf("a refused unix forward reached the launcher %d times", n)
	}
	tcp := echoServer(t, "tcp", "127.0.0.1:0")
	c, err := client.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatalf("a TCP forward where unix is unsupported: %v", err)
	}
	_ = c.Close()
}

// Remote forwards bind on loopback as the login; the bound port of a port 0
// request comes back; cancel closes the listener; a unix socket listener is
// served too.
func TestRemoteForward(t *testing.T) {
	f := forwardFixture(t, nil)
	client := f.connect(t, f.forwardOpts(false, true))
	ln, err := client.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if port == 0 {
		t.Fatal("no bound port")
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
	assertLoopbackOnly(t, port)
	loopback := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	c, err := net.Dial("tcp", loopback)
	if err != nil {
		t.Fatalf("the remote listener is not on loopback: %v", err)
	}
	pingPong(t, c)
	_ = c.Close()
	if err := ln.Close(); err != nil {
		t.Fatalf("cancel-tcpip-forward: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.Dial("tcp", loopback)
		if err != nil {
			break
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("the listener accepts after its cancel")
		}
		time.Sleep(10 * time.Millisecond)
	}

	path := filepath.Join(socketDir(t), "r.sock")
	uln, err := client.ListenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := uln.Accept()
		if err == nil {
			_, _ = io.Copy(c, c)
			_ = c.Close()
		}
	}()
	uc, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	pingPong(t, uc)
	_ = uc.Close()
}

// The 33rd forward channel of a connection and its 9th listener are
// refused; a third connection finds the device's 64 slots taken.
func TestForwardLimits(t *testing.T) {
	f := forwardFixture(t, nil)
	tcp := echoServer(t, "tcp", "127.0.0.1:0")
	hold := func(client *ssh.Client, n int) []net.Conn {
		var held []net.Conn
		for i := range n {
			c, err := client.Dial("tcp", tcp.Addr().String())
			if err != nil {
				t.Fatalf("forward %d: %v", i+1, err)
			}
			held = append(held, c)
		}
		return held
	}
	first := f.connect(t, f.forwardOpts(true, true))
	held := hold(first, maxForwardChannels)
	_, err := first.Dial("tcp", tcp.Addr().String())
	var oce *ssh.OpenChannelError
	if !errors.As(err, &oce) || oce.Reason != ssh.ResourceShortage {
		t.Fatalf("forward %d: %v, want resource shortage", maxForwardChannels+1, err)
	}
	for i := range maxRemoteListeners + 1 {
		_, err := first.Listen("tcp", "127.0.0.1:0")
		if i < maxRemoteListeners && err != nil {
			t.Fatalf("listener %d: %v", i+1, err)
		}
		if i == maxRemoteListeners && err == nil {
			t.Fatalf("listener %d accepted", i+1)
		}
	}
	o := f.forwardOpts(true, false)
	o.serial = 43
	second := f.connect(t, o)
	held = append(held, hold(second, maxDeviceForwards-maxForwardChannels)...)
	o.serial = 44
	third := f.connect(t, o)
	if _, err := third.Dial("tcp", tcp.Addr().String()); !errors.As(err, &oce) || oce.Reason != ssh.ResourceShortage {
		t.Fatalf("forward %d of the device: %v, want resource shortage", maxDeviceForwards+1, err)
	}
	// A closed forward frees its slot.
	_ = held[0].Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := third.Dial("tcp", tcp.Addr().String())
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no slot after a close: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Forward traffic keeps the connection active for the idle timer: every
// relayed write goes through activityWriter.
func TestForwardTrafficIsActivity(t *testing.T) {
	c := &conn{s: NewServer(ServerConfig{})}
	if _, err := (activityWriter{io.Discard, c}).Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if c.lastActivity.Load() == 0 {
		t.Fatal("a forwarded write did not count as activity")
	}
}

// stalledHandoff blocks every segment handoff until release is closed and
// counts the terminal handoff calls (End or Abort) that returned.
type stalledHandoff struct {
	recordingHandoff
	release <-chan struct{}
	ended   *atomic.Int32
}

func (h stalledHandoff) Segment(seg recording.Segment) error {
	<-h.release
	return h.recordingHandoff.Segment(seg)
}

func (h stalledHandoff) End(done recording.Completion) error {
	defer h.ended.Add(1)
	return h.recordingHandoff.End(done)
}

func (h stalledHandoff) Abort() error {
	defer h.ended.Add(1)
	return h.recordingHandoff.Abort()
}

// pausedReads is a client conn whose reads block once pause is set, as a
// client whose network stopped; release unblocks them.
type pausedReads struct {
	net.Conn
	pause   *atomic.Bool
	release <-chan struct{}
}

func (c pausedReads) Read(p []byte) (int, error) {
	if c.pause.Load() {
		<-c.release
	}
	return c.Conn.Read(p)
}

// The worst case of a connection's end on Shutdown: a client whose network
// stopped (the end writes and then the close flush run out) with a channel
// recording and a forwards recording whose handoffs never return. The bounds
// run in turn, so Shutdown takes their sum and no more; the session mux's
// sessionShutdownTimeout is set from the same sum at production values.
func TestShutdownWorstCaseIsTheSumOfTheEndBounds(t *testing.T) {
	oldWrite, oldRec, oldFlush := endWriteTimeout, recorderEndTimeout, closeFlushTimeout
	endWriteTimeout, recorderEndTimeout, closeFlushTimeout = 100*time.Millisecond, 200*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { endWriteTimeout, recorderEndTimeout, closeFlushTimeout = oldWrite, oldRec, oldFlush })
	sum := endWriteTimeout + 2*recorderEndTimeout + closeFlushTimeout

	client := &captureClient{opens: make(chan capturedOpen, 3)}
	f, keySum, _ := recordingFixture(t, client)
	f.cfg.Capabilities = []string{"terminal", "forwarding"}
	f.srv = NewServer(*f.cfg)
	serveForwards(t, f.launcher)
	release := make(chan struct{})
	var stalled, ended atomic.Int32
	wrap := func(h recordingHandoff) recordingHandoff {
		stalled.Add(1)
		return stalledHandoff{h, release, &ended}
	}
	wrapRecordingHandoff.Store(&wrap)
	var paused atomic.Bool
	f.clientConn = func(c net.Conn) net.Conn { return pausedReads{c, &paused, release} }
	t.Cleanup(func() { wrapRecordingHandoff.Store(nil) })
	// Deferred, so it runs before every cleanup (the client closes, the
	// fixture's Shutdown and uploader stop): the stalled recorders and
	// client reads continue. Shutdown abandoned the recorders, so the test
	// waits for their terminal handoffs before the cleanups remove the spool.
	defer func() {
		close(release)
		deadline := time.Now().Add(5 * time.Second)
		for ended.Load() < stalled.Load() {
			if time.Now().After(deadline) {
				t.Errorf("%d of %d stalled recordings made no terminal handoff within 5s", stalled.Load()-ended.Load(), stalled.Load())
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	tcp := echoServer(t, "tcp", "127.0.0.1:0")
	o := f.forwardOpts(true, false)
	o.rec = &certRec{Policy: RecPolicyBestEffort, PubSHA256: keySum}
	c := f.connect(t, o)
	fc, err := c.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pingPong(t, fc)
	// A quiet channel: its recording hands off only its final segment, which
	// stalls. A flooding one fills every buffer once the client stops reading.
	for _, cmd := range []string{"hold", "flood"} {
		sess, _ := c.NewSession()
		_, _ = sess.StdoutPipe()
		if err := sess.Start(cmd); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		select {
		case <-client.opens:
		case <-time.After(5 * time.Second):
			t.Fatal("the channel and forwards recordings did not all open")
		}
	}
	paused.Store(true)
	time.Sleep(500 * time.Millisecond) // the flood fills the socket and send buffers

	ctx, cancel := context.WithTimeout(context.Background(), sum+2*time.Second)
	defer cancel()
	start := time.Now()
	if err := f.srv.ShutdownConfigChanged(ctx); err != nil {
		t.Fatalf("Shutdown = %v after %v, want it within the sum of the end bounds (%v)", err, time.Since(start), sum)
	}
	// Each bound ran out in turn: the stalls are real and sequential.
	if took := time.Since(start); took < sum {
		t.Fatalf("Shutdown took %v, under the %v sum: a bound did not run out", took, sum)
	}
}

// A recorded connection's forwards go to one forwards recording: an open and
// a close with the bytes each way, never the bytes themselves.
func TestForwardRecordingEvents(t *testing.T) {
	client := &captureClient{opens: make(chan capturedOpen, 2)}
	f, keySum, _ := recordingFixture(t, client)
	f.cfg.Capabilities = []string{"terminal", "forwarding"}
	f.srv = NewServer(*f.cfg)
	serveForwards(t, f.launcher)
	tcp := echoServer(t, "tcp", "127.0.0.1:0")
	o := f.forwardOpts(true, false)
	o.rec = &certRec{Policy: RecPolicyStrict, PubSHA256: keySum}
	c := f.connect(t, o)
	fc, err := c.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pingPong(t, fc)
	_ = fc.Close()
	var open capturedOpen
	select {
	case open = <-client.opens:
	case <-time.After(5 * time.Second):
		t.Fatal("no forwards recording opened")
	}
	time.Sleep(50 * time.Millisecond)
	_ = c.Close()
	text := client.plaintext(t, open.id)
	addr := tcp.Addr().String()
	for _, want := range []string{
		`"p","{\"op\":\"open\",\"dir\":\"local\",\"kind\":\"tcp\",\"addr\":\"` + addr + `\",\"result\":\"ok\"}"`,
		`\"op\":\"close\",\"dir\":\"local\",\"kind\":\"tcp\",\"addr\":\"` + addr + `\",\"in\":4,\"out\":4}"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("recording %q lacks %s", text, want)
		}
	}
	if strings.Contains(text, "ping") {
		t.Fatal("forwarded bytes were recorded")
	}
}

// A Strict forwards recording that fails ends the connection with
// recording_failed.
func TestStrictForwardRecordingFailureEndsTheConnection(t *testing.T) {
	h := &fakeHandoff{}
	rec, _ := newTestRecorder(t, RecPolicyStrict, h)
	s := NewServer(ServerConfig{})
	c := &conn{s: s, failed: make(chan string, 1), channels: map[*channel]struct{}{}}
	c.adm.Store(&connAdmission{admission: &admission{Kind: "ssh"}})
	var wg sync.WaitGroup
	c.fwd = newForwarder(c, nil, &wg)
	ours, theirs, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer theirs.Close()
	client, err := launcher.NewForwardClient(ours, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	wg.Go(func() { c.fwd.watch(client, rec) })
	rec.closeWith(recFail, "recording_failed")
	select {
	case reason := <-c.failed:
		if reason != CloseRecordingFailed {
			t.Fatalf("reason %q", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a failed Strict forwards recording did not end the connection")
	}
	_ = client.Close()
	wg.Wait()
	rec.end()
}

// A relayed connection registered after a resume disallowed its direction is
// refused, so a forward in flight across the admission swap never outlives
// it; the allowed direction still registers.
func TestTrackRefusesADirectionTheAdmissionDisallows(t *testing.T) {
	s := NewServer(ServerConfig{Capabilities: []string{"forwarding"}})
	c := &conn{s: s, failed: make(chan string, 1), channels: map[*channel]struct{}{}}
	c.adm.Store(&connAdmission{admission: &admission{Kind: "ssh", ForwardRemote: true}})
	var wg sync.WaitGroup
	c.fwd = newForwarder(c, nil, &wg)
	local, _ := tcpPair(t)
	remote, _ := tcpPair(t)
	if c.fwd.track(local.(launcher.ForwardConn), false) {
		t.Fatal("a local forward registered under an admission without forward_local")
	}
	if !c.fwd.track(remote.(launcher.ForwardConn), true) {
		t.Fatal("a remote forward the admission allows was refused")
	}
}

// assertLoopbackOnly fails when port accepts on a non-loopback address of
// this host, which a wildcard bind would; a loopback dial cannot tell them
// apart. A host with no such address logs that and checks nothing.
func assertLoopbackOnly(t *testing.T, port int) {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		ip, ok := a.(*net.IPNet)
		if !ok || ip.IP.IsLoopback() || ip.IP.To4() == nil || ip.IP.IsLinkLocalUnicast() {
			continue
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.IP.String(), strconv.Itoa(port)), time.Second)
		if err == nil {
			_ = c.Close()
			t.Fatalf("port %d accepts on %s: the listener is not loopback only", port, ip.IP)
		}
		return
	}
	t.Log("no non-loopback IPv4 address on this host: the loopback-only bind is not checked")
}
