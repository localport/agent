//go:build unix

package session

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/launcher"
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
	if r.Login != testLogin || r.Device != "client.device" || r.Cols != 0 || len(r.Env) != 0 {
		t.Fatalf("forward request %+v", r)
	}
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
	c := &conn{s: s, adm: &admission{Kind: "ssh"}, failed: make(chan string, 1), channels: map[*channel]struct{}{}}
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
