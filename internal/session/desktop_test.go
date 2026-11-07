//go:build linux || darwin

package session

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/identity"
)

// vncTarget is a target VNC server: it runs handshake on each connection,
// then echoes it, and hands the test the server side of every accepted conn;
// closed receives once a conn reads its client's close.
type vncTarget struct {
	ln       net.Listener
	accepted chan net.Conn
	closed   chan struct{}
}

// vncAuthHandshake is a 3.8 server offering VNC authentication only; the
// test client chooses it and the echo starts (no authentication runs).
func vncAuthHandshake(c net.Conn) error {
	if _, err := io.WriteString(c, "RFB 003.008\n"); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, make([]byte, 12)); err != nil {
		return err
	}
	if _, err := c.Write([]byte{1, 2}); err != nil {
		return err
	}
	_, err := io.ReadFull(c, make([]byte, 1))
	return err
}

func newVNCTarget(t *testing.T) *vncTarget {
	t.Helper()
	return newScriptedTarget(t, vncAuthHandshake)
}

func newScriptedTarget(t *testing.T, handshake func(net.Conn) error) *vncTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	v := &vncTarget{ln: ln, accepted: make(chan net.Conn, 4), closed: make(chan struct{}, 4)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			v.accepted <- c
			go func() {
				if handshake(c) == nil {
					_, _ = io.Copy(c, c)
				} else {
					// Wait for the peer's close, as a server would.
					_, _ = io.Copy(io.Discard, c)
				}
				_ = c.Close()
				v.closed <- struct{}{}
			}()
		}
	}()
	return v
}

// memKeys is an in-memory desktop key store.
type memKeys struct {
	mu   sync.Mutex
	pins map[string][32]byte
	err  error
}

func (m *memKeys) Lookup(kind, target string) ([32]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return [32]byte{}, false, m.err
	}
	k, ok := m.pins[kind+" "+target]
	return k, ok, nil
}

func (m *memKeys) Pin(_ context.Context, kind, target string, key [32]byte) (identity.PinResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return 0, m.err
	}
	if m.pins == nil {
		m.pins = map[string][32]byte{}
	}
	if k, ok := m.pins[kind+" "+target]; ok {
		if k == key {
			return identity.PinMatch, nil
		}
		return identity.PinChanged, nil
	}
	m.pins[kind+" "+target] = key
	return identity.PinNew, nil
}

func (v *vncTarget) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-v.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the target connection was not closed")
	}
}

func (v *vncTarget) serverSide(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-v.accepted:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("the target saw no connection")
		return nil
	}
}

// desktopFixture serves a device with the desktop capability and its vnc
// target at addr.
func desktopFixture(t *testing.T, addr string, edit func(*ServerConfig)) *sshFixture {
	t.Helper()
	return newSSHFixture(t, func(c *ServerConfig) {
		c.Capabilities, c.Desktop, c.VNCTarget = []string{"desktop"}, []string{"vnc"}, addr
		c.DesktopKeys = &memKeys{}
		if edit != nil {
			edit(c)
		}
	})
}

func (f *sshFixture) vncOpts() certOpts {
	o := f.defaults()
	o.kind, o.login = "vnc", desktopPrincipal
	return o
}

// openVNC opens the desktop channel naming host:port, keeping its requests,
// and runs the client half of vncAuthHandshake, so the channel then echoes.
func openVNC(client *ssh.Client, host string, port uint32) (ssh.Channel, <-chan *ssh.Request, error) {
	ch, reqs, err := openDesktopChannel(client, host, port)
	if err != nil {
		return nil, nil, err
	}
	if err := clientHandshake(ch, "RFB 003.008\n", 2); err != nil {
		return nil, nil, err
	}
	return ch, reqs, nil
}

func openDesktopChannel(client *ssh.Client, host string, port uint32) (ssh.Channel, <-chan *ssh.Request, error) {
	return client.OpenChannel(chanDirectTCPIP, ssh.Marshal(struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}{host, port, "127.0.0.1", 0}))
}

// clientHandshake reads the server version and a 3.7+ type list, sends
// version and chooses choice.
func clientHandshake(ch ssh.Channel, version string, choice byte) error {
	if _, err := io.ReadFull(ch, make([]byte, 12)); err != nil {
		return err
	}
	if _, err := io.WriteString(ch, version); err != nil {
		return err
	}
	n := make([]byte, 1)
	if _, err := io.ReadFull(ch, n); err != nil {
		return err
	}
	if _, err := io.ReadFull(ch, make([]byte, n[0])); err != nil {
		return err
	}
	_, err := ch.Write([]byte{choice})
	return err
}

// waitEndRequest returns the reason of the channel's end@localport.io
// request, which must arrive before the channel closes.
func waitEndRequest(t *testing.T, reqs <-chan *ssh.Request) string {
	t.Helper()
	select {
	case r, ok := <-reqs:
		if !ok {
			t.Fatal("the channel closed without an end request")
		}
		var p struct{ Reason string }
		if r.Type != reqDesktopEnd || r.WantReply || ssh.Unmarshal(r.Payload, &p) != nil {
			t.Fatalf("request %q want-reply %v payload %q", r.Type, r.WantReply, r.Payload)
		}
		return p.Reason
	case <-time.After(5 * time.Second):
		t.Fatal("no end request")
		return ""
	}
}

// The desktop channel reaches the configured target whatever address it
// names; the named address sees no connection.
func TestDesktopDialsOnlyTheTarget(t *testing.T) {
	target := newVNCTarget(t)
	decoy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer decoy.Close()
	var decoyHits atomic.Int32
	go func() {
		for {
			c, err := decoy.Accept()
			if err != nil {
				return
			}
			decoyHits.Add(1)
			_ = c.Close()
		}
	}()
	f := desktopFixture(t, target.ln.Addr().String(), nil)
	client := f.connect(t, f.vncOpts())
	port := uint32(decoy.Addr().(*net.TCPAddr).Port)
	ch, _, err := openVNC(client, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pingPong(t, ch)
	target.serverSide(t)
	if n := decoyHits.Load(); n != 0 {
		t.Fatalf("the requested address saw %d connections", n)
	}
	// The client's close of the channel closes the target and ends the
	// connection.
	_ = ch.Close()
	target.waitClosed(t)
	waitClosed(t, client)
}

// A desktop certificate needs the desktop login, no recording, and its kind
// configured; rdp is not served yet.
func TestDesktopAdmission(t *testing.T) {
	target := newVNCTarget(t)
	for _, tc := range []struct {
		name    string
		desktop []string
		edit    func(*certOpts)
		ok      bool
	}{
		{"vnc", []string{"vnc"}, nil, true},
		{"recorded", []string{"vnc"}, func(o *certOpts) { o.rec = &certRec{Policy: RecPolicyStrict, PubSHA256: "AAAA"} }, false},
		{"no vnc target", []string{"rdp"}, nil, false},
		{"rdp", []string{"rdp", "vnc"}, func(o *certOpts) { o.kind = "rdp" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.Desktop = tc.desktop })
			o := f.vncOpts()
			if tc.edit != nil {
				tc.edit(&o)
			}
			signer, _ := f.mint(t, o)
			if _, err := f.dial(t, o.serial, signer, nil); (err == nil) != tc.ok {
				t.Fatalf("userauth: %v, want ok %v", err, tc.ok)
			}
		})
	}
}

// A desktop connection serves one direct-tcpip channel and nothing else.
func TestDesktopChannelRules(t *testing.T) {
	target := newVNCTarget(t)
	f := desktopFixture(t, target.ln.Addr().String(), nil)
	client := f.connect(t, f.vncOpts())
	if _, err := client.NewSession(); err == nil {
		t.Fatal("a session channel opened")
	}
	var oce *ssh.OpenChannelError
	if _, err := client.Dial("unix", filepath.Join(t.TempDir(), "s")); !errors.As(err, &oce) || oce.Reason != ssh.Prohibited {
		t.Fatalf("direct-streamlocal: %v, want prohibited", err)
	}
	ok, _, err := client.SendRequest(reqTCPIPForward, true, ssh.Marshal(struct {
		Addr string
		Port uint32
	}{"127.0.0.1", 0}))
	if err != nil || ok {
		t.Fatalf("tcpip-forward: %v, %v; want refused", ok, err)
	}
	ch, _, err := openVNC(client, "localport-desktop", 1)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pingPong(t, ch)
	if _, _, err := openVNC(client, "localport-desktop", 1); !errors.As(err, &oce) || oce.Reason != ssh.ResourceShortage {
		t.Fatalf("a second channel: %v, want resource shortage", err)
	}
	if ok, err := ch.SendRequest("env", true, nil); err != nil || ok {
		t.Fatalf("a channel request: %v", err)
	}
	pingPong(t, ch)
}

// A refused target dial rejects the channel with its code and ends the
// connection; a malformed open is refused invalid.
func TestDesktopDialRefusals(t *testing.T) {
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := closed.Addr().String()
	_ = closed.Close()
	f := desktopFixture(t, addr, nil)
	client := f.connect(t, f.vncOpts())
	_, _, err := openVNC(client, "localport-desktop", 1)
	var oce *ssh.OpenChannelError
	if !errors.As(err, &oce) || oce.Reason != ssh.ConnectionFailed || oce.Message != "connection_refused" {
		t.Fatalf("open: %v, want connection_refused", err)
	}
	waitClosed(t, client)

	o := f.vncOpts()
	o.serial = 43
	client = f.connect(t, o)
	if _, _, err := openVNC(client, "", 1); !errors.As(err, &oce) || oce.Message != "invalid" {
		t.Fatalf("an empty host: %v, want invalid", err)
	}
	waitClosed(t, client)
}

// idleClock is manualClock that also fires the idle timer on demand.
type idleClock struct {
	manualClock
	idle []chan time.Time
}

func (c *idleClock) NewTimer(d time.Duration) (<-chan time.Time, func() bool) {
	if d <= detachTimeout {
		return c.manualClock.NewTimer(d)
	}
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	c.idle = append(c.idle, ch)
	c.mu.Unlock()
	return ch, func() bool { return true }
}

func (c *idleClock) fireIdle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ch := range c.idle {
		select {
		case ch <- time.Now():
		default:
		}
	}
}

// On a desktop connection only client channel data is activity: target
// output and global requests do not hold off the idle end, which the client
// is told by end@localport.io.
func TestDesktopIdle(t *testing.T) {
	t.Run("target output only", func(t *testing.T) {
		clock := &idleClock{}
		target := newVNCTarget(t)
		f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.clock = clock })
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openVNC(client, "localport-desktop", 1)
		if err != nil {
			t.Fatal(err)
		}
		server := target.serverSide(t)
		// The round trip settles the handshake's client bytes, which are
		// activity, before the clock moves.
		pingPong(t, ch)
		clock.advance(idleTimeout + time.Minute)
		if _, err := server.Write([]byte("frame")); err != nil {
			t.Fatal(err)
		}
		readFor(t, ch, "frame")
		if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			t.Fatal(err)
		}
		clock.fireIdle()
		if reason := waitEndRequest(t, reqs); reason != CloseIdle {
			t.Fatalf("end reason %q, want %q", reason, CloseIdle)
		}
		target.waitClosed(t)
		waitClosed(t, client)
	})
	t.Run("client data", func(t *testing.T) {
		clock := &idleClock{}
		target := newVNCTarget(t)
		f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.clock = clock })
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openVNC(client, "localport-desktop", 1)
		if err != nil {
			t.Fatal(err)
		}
		clock.advance(idleTimeout - time.Minute)
		pingPong(t, ch)
		clock.advance(2 * time.Minute)
		clock.fireIdle()
		pingPong(t, ch)
		select {
		case r := <-reqs:
			t.Fatalf("request %v on an active connection", r)
		default:
		}
	})
}

// Every end the agent decides closes the target and tells the client its
// reason first; Shutdown returns once the connection's goroutines ended.
func TestDesktopEndClosesTheTarget(t *testing.T) {
	for _, tc := range []struct {
		reason string
		end    func(*Server, context.Context) error
	}{
		{CloseShutdown, (*Server).Shutdown},
		{CloseConfigChanged, (*Server).ShutdownConfigChanged},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			target := newVNCTarget(t)
			f := desktopFixture(t, target.ln.Addr().String(), nil)
			client := f.connect(t, f.vncOpts())
			ch, reqs, err := openVNC(client, "localport-desktop", 1)
			if err != nil {
				t.Fatal(err)
			}
			pingPong(t, ch)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tc.end(f.srv, ctx); err != nil {
				t.Fatalf("end: %v", err)
			}
			if reason := waitEndRequest(t, reqs); reason != tc.reason {
				t.Fatalf("end reason %q, want %q", reason, tc.reason)
			}
			target.waitClosed(t)
		})
	}
}

// An end during the target dial cancels it, refuses the channel and lets the
// connection's run return.
func TestDesktopEndDuringTheDial(t *testing.T) {
	dialing := make(chan struct{})
	f := desktopFixture(t, "127.0.0.1:5900", func(c *ServerConfig) {
		c.dialDesktop = func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(dialing)
			<-ctx.Done()
			return nil, ctx.Err()
		}
	})
	client := f.connect(t, f.vncOpts())
	opened := make(chan error, 1)
	go func() {
		_, _, err := openVNC(client, "localport-desktop", 1)
		opened <- err
	}()
	<-dialing
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown during a dial: %v", err)
	}
	select {
	case err := <-opened:
		// The refusal races the connection's close, so only the failure is certain.
		if err == nil {
			t.Fatal("the channel opened after the end")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the channel open was never answered")
	}
}

// A dial that connects after the connection ended closes what it connected
// and never opens the channel.
func TestDesktopDialFinishingAfterTheEnd(t *testing.T) {
	target := newVNCTarget(t)
	dialing := make(chan struct{})
	f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) {
		c.dialDesktop = func(ctx context.Context, network, addr string) (net.Conn, error) {
			close(dialing)
			<-ctx.Done()
			// A dial that completes although its context was cancelled.
			return net.Dial(network, addr)
		}
	})
	client := f.connect(t, f.vncOpts())
	opened := make(chan error, 1)
	go func() {
		_, _, err := openVNC(client, "localport-desktop", 1)
		opened <- err
	}()
	<-dialing
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.srv.ShutdownConfigChanged(ctx); err != nil {
		t.Fatalf("end during a dial: %v", err)
	}
	if err := <-opened; err == nil {
		t.Fatal("the channel opened after the end")
	}
	target.serverSide(t)
	target.waitClosed(t)
}

// The target's close ends the channel and the connection without an end
// request: the channel already stopped. A client's EOF ends the target.
func TestDesktopEndsWithItsChannel(t *testing.T) {
	t.Run("target closes", func(t *testing.T) {
		target := newVNCTarget(t)
		f := desktopFixture(t, target.ln.Addr().String(), nil)
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openVNC(client, "localport-desktop", 1)
		if err != nil {
			t.Fatal(err)
		}
		pingPong(t, ch)
		_ = target.serverSide(t).Close()
		select {
		case r, ok := <-reqs:
			if ok {
				t.Fatalf("request %q after the target closed", r.Type)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the channel did not close")
		}
		waitClosed(t, client)
	})
	t.Run("target closes during the check", func(t *testing.T) {
		target := newScriptedTarget(t, func(c net.Conn) error {
			_, _ = io.WriteString(c, "RFB 003.008\n")
			_ = c.Close()
			return errors.New("closed mid-handshake")
		})
		f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.DesktopKeys = &memKeys{} })
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openDesktopChannel(client, "localport-desktop", 1)
		if err != nil {
			t.Fatal(err)
		}
		readFor(t, ch, "RFB 003.008\n")
		_, _ = io.WriteString(ch, "RFB 003.008\n")
		select {
		case r, ok := <-reqs:
			if ok {
				t.Fatalf("request %q after the target closed", r.Type)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the channel did not close")
		}
		waitClosed(t, client)
	})
	t.Run("client EOF", func(t *testing.T) {
		target := newVNCTarget(t)
		f := desktopFixture(t, target.ln.Addr().String(), nil)
		client := f.connect(t, f.vncOpts())
		ch, _, err := openVNC(client, "localport-desktop", 1)
		if err != nil {
			t.Fatal(err)
		}
		pingPong(t, ch)
		_ = ch.CloseWrite()
		target.waitClosed(t)
		waitClosed(t, client)
	})
}

// A desktop connection resumes with its relay; a detach timeout closes the
// target.
func TestDesktopResume(t *testing.T) {
	clock := &manualClock{}
	target := newVNCTarget(t)
	f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.clock = clock })
	rc := f.connectResumableAs(t, f.vncOpts())
	ch, _, err := openVNC(rc.client, "localport-desktop", 1)
	if err != nil {
		t.Fatal(err)
	}
	pingPong(t, ch)
	rc.cut(t)
	if err := rc.resume(t, func(o *certOpts) { o.kind, o.login = "vnc", desktopPrincipal }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	pingPong(t, ch)
	rc.cut(t)
	// The agent arms its detach timer after it sees the cut, which may be
	// after the client did: fire until the connection ends.
	deadline := time.Now().Add(5 * time.Second)
	for f.srv.LiveSessions() != 0 {
		clock.fireDetach()
		if time.Now().After(deadline) {
			t.Fatal("the detach timeout did not end the connection")
		}
		time.Sleep(10 * time.Millisecond)
	}
	target.waitClosed(t)
}
