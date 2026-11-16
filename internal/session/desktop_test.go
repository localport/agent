//go:build linux || darwin

package session

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
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

// rfbServerInit is a ServerInit of 800x600, 32-bit true colour, named "x".
func rfbServerInit() []byte {
	b := []byte{3, 32, 2, 88, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}
	return append(binary.BigEndian.AppendUint32(b, 1), 'x')
}

// finishNoneHandshake is the server side after security None under 3.8: the
// result, ClientInit and ServerInit, then bellOnKeyEvent.
func finishNoneHandshake(c net.Conn) error {
	if _, err := c.Write(make([]byte, 4)); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		return err
	}
	if _, err := c.Write(rfbServerInit()); err != nil {
		return err
	}
	return bellOnKeyEvent(c)
}

// bellOnKeyEvent answers each 8-byte KeyEvent with a Bell until the client
// leaves, and returns the read's error.
func bellOnKeyEvent(c net.Conn) error {
	for {
		if _, err := io.ReadFull(c, make([]byte, 8)); err != nil {
			return err
		}
		if _, err := c.Write([]byte{rfbServerBell}); err != nil {
			return err
		}
	}
}

// vncNoneHandshake is a 3.8 server offering security None; the client
// chooses it, and after ServerInit the server answers key events.
func vncNoneHandshake(c net.Conn) error {
	if _, err := io.WriteString(c, "RFB 003.008\n"); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, make([]byte, 12)); err != nil {
		return err
	}
	if _, err := c.Write([]byte{1, rfbSecNone}); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		return err
	}
	return finishNoneHandshake(c)
}

func newVNCTarget(t *testing.T) *vncTarget {
	t.Helper()
	return newScriptedTarget(t, vncNoneHandshake)
}

// desktopPing sends a KeyEvent through the filter and waits for the Bell.
func desktopPing(t *testing.T, ch io.ReadWriter) {
	t.Helper()
	if _, err := ch.Write([]byte{rfbClientKeyEvent, 1, 0, 0, 0, 0, 0, 'p'}); err != nil {
		t.Fatal(err)
	}
	readFor(t, ch, string([]byte{rfbServerBell}))
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

// openVNC opens the vnc desktop channel, keeping its requests, and runs the
// client half of vncNoneHandshake through ServerInit.
func openVNC(client *ssh.Client) (ssh.Channel, <-chan *ssh.Request, error) {
	ch, reqs, err := openDesktopChannel(client, chanVNC)
	if err != nil {
		return nil, nil, err
	}
	if err := clientHandshake(ch, "RFB 003.008\n", rfbSecNone); err != nil {
		return nil, nil, err
	}
	if err := finishClientHandshake(ch); err != nil {
		return nil, nil, err
	}
	return ch, reqs, nil
}

// finishClientHandshake is the client side of finishNoneHandshake up to its
// key events.
func finishClientHandshake(ch ssh.Channel) error {
	if _, err := io.ReadFull(ch, make([]byte, 4)); err != nil {
		return err
	}
	if _, err := ch.Write([]byte{1}); err != nil {
		return err
	}
	_, err := io.ReadFull(ch, make([]byte, len(rfbServerInit())))
	return err
}

// openDesktopChannel opens a desktop channel of chanType with the empty
// payload the agent requires.
func openDesktopChannel(client *ssh.Client, chanType string) (ssh.Channel, <-chan *ssh.Request, error) {
	return client.OpenChannel(chanType, nil)
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

// The vnc channel reaches the configured vnc target; the client's close of
// the channel closes the target and ends the connection.
func TestDesktopReachesTheTarget(t *testing.T) {
	target := newVNCTarget(t)
	f := desktopFixture(t, target.ln.Addr().String(), nil)
	client := f.connect(t, f.vncOpts())
	ch, _, err := openVNC(client)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	desktopPing(t, ch)
	target.serverSide(t)
	_ = ch.Close()
	target.waitClosed(t)
	waitClosed(t, client)
}

// A desktop certificate needs the desktop login, no recording, and its kind
// configured.
func TestDesktopAdmission(t *testing.T) {
	target := newVNCTarget(t)
	rdp := func(o *certOpts) { o.kind = "rdp" }
	for _, tc := range []struct {
		name    string
		desktop []string
		edit    func(*certOpts)
		ok      bool
	}{
		{"vnc", []string{"vnc"}, nil, true},
		{"recorded", []string{"vnc"}, func(o *certOpts) { o.rec = &certRec{Policy: RecPolicyStrict, PubSHA256: "AAAA"} }, false},
		{"no vnc target", []string{"rdp"}, nil, false},
		{"rdp", []string{"rdp", "vnc"}, rdp, true},
		{"rdp recorded", []string{"rdp"}, func(o *certOpts) { rdp(o); o.rec = &certRec{Policy: RecPolicyStrict, PubSHA256: "AAAA"} }, false},
		{"rdp other login", []string{"rdp"}, func(o *certOpts) { rdp(o); o.login = "root" }, false},
		{"no rdp target", []string{"vnc"}, rdp, false},
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

// A desktop connection serves one channel of its kind's type, with an empty
// payload, and nothing else. A refused open before the channel ends the
// connection; one after it leaves the channel serving.
func TestDesktopChannelRules(t *testing.T) {
	target := newVNCTarget(t)
	f := desktopFixture(t, target.ln.Addr().String(), nil)
	var oce *ssh.OpenChannelError
	for name, open := range map[string]func(client *ssh.Client) error{
		"session": func(client *ssh.Client) error { _, _, err := client.OpenChannel("session", nil); return err },
		"direct-streamlocal": func(client *ssh.Client) error {
			_, err := client.Dial("unix", filepath.Join(t.TempDir(), "s"))
			return err
		},
		"rdp type": func(client *ssh.Client) error { _, _, err := openDesktopChannel(client, chanRDP); return err },
		"direct-tcpip": func(client *ssh.Client) error {
			_, _, err := client.OpenChannel(chanDirectTCPIP, ssh.Marshal(struct {
				Host     string
				Port     uint32
				OrigHost string
				OrigPort uint32
			}{"localport-desktop", 1, "127.0.0.1", 0}))
			return err
		},
		"payload": func(client *ssh.Client) error { _, _, err := client.OpenChannel(chanVNC, []byte{0}); return err },
	} {
		client := f.connect(t, f.vncOpts())
		if err := open(client); !errors.As(err, &oce) || oce.Reason != ssh.Prohibited {
			t.Fatalf("%s: %v, want prohibited", name, err)
		}
		waitClosed(t, client)
	}
	client := f.connect(t, f.vncOpts())
	ok, _, err := client.SendRequest(reqTCPIPForward, true, ssh.Marshal(struct {
		Addr string
		Port uint32
	}{"127.0.0.1", 0}))
	if err != nil || ok {
		t.Fatalf("tcpip-forward: %v, %v; want refused", ok, err)
	}
	ch, _, err := openVNC(client)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	desktopPing(t, ch)
	if _, _, err := openVNC(client); !errors.As(err, &oce) || oce.Reason != ssh.ResourceShortage {
		t.Fatalf("a second channel: %v, want resource shortage", err)
	}
	if _, _, err := openDesktopChannel(client, chanRDP); !errors.As(err, &oce) || oce.Reason != ssh.Prohibited {
		t.Fatalf("a wrong type after the channel: %v, want prohibited", err)
	}
	if ok, err := ch.SendRequest("env", true, nil); err != nil || ok {
		t.Fatalf("a channel request: %v", err)
	}
	desktopPing(t, ch)
}

// A refused target dial rejects the channel with its code and ends the
// connection.
func TestDesktopDialRefusals(t *testing.T) {
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := closed.Addr().String()
	_ = closed.Close()
	f := desktopFixture(t, addr, nil)
	client := f.connect(t, f.vncOpts())
	_, _, err := openVNC(client)
	var oce *ssh.OpenChannelError
	if !errors.As(err, &oce) || oce.Reason != ssh.ConnectionFailed || oce.Message != "connection_refused" {
		t.Fatalf("open: %v, want connection_refused", err)
	}
	waitClosed(t, client)
}

// A terminal connection rejects both desktop channel types as it rejects any
// unknown type.
func TestTerminalRejectsDesktopChannels(t *testing.T) {
	f := newSSHFixture(t, nil)
	client := f.connect(t, f.defaults())
	for _, typ := range []string{chanVNC, chanRDP} {
		var oce *ssh.OpenChannelError
		if _, _, err := openDesktopChannel(client, typ); !errors.As(err, &oce) || oce.Reason != ssh.Prohibited {
			t.Fatalf("%s: %v, want prohibited", typ, err)
		}
	}
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
		ch, reqs, err := openVNC(client)
		if err != nil {
			t.Fatal(err)
		}
		server := target.serverSide(t)
		// The round trip settles the handshake's client bytes, which are
		// activity, before the clock moves.
		desktopPing(t, ch)
		clock.advance(idleTimeout + time.Minute)
		if _, err := server.Write([]byte{rfbServerBell}); err != nil {
			t.Fatal(err)
		}
		readFor(t, ch, string([]byte{rfbServerBell}))
		if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			t.Fatal(err)
		}
		clock.fireIdle()
		if reason := waitEndRequest(t, reqs); reason != CloseIdle {
			t.Fatalf("end reason %q, want %q", reason, CloseIdle)
		}
		target.waitClosed(t)
		// The idle end closed the target under the relay; the end logged is
		// the connection's, not the target error the relay saw after it.
		waitEvent(t, f.events, desktopEndLine("vnc", target.ln.Addr().String(), CloseIdle))
		waitClosed(t, client)
	})
	t.Run("client data", func(t *testing.T) {
		clock := &idleClock{}
		target := newVNCTarget(t)
		f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.clock = clock })
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openVNC(client)
		if err != nil {
			t.Fatal(err)
		}
		clock.advance(idleTimeout - time.Minute)
		desktopPing(t, ch)
		clock.advance(2 * time.Minute)
		clock.fireIdle()
		desktopPing(t, ch)
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
			ch, reqs, err := openVNC(client)
			if err != nil {
				t.Fatal(err)
			}
			desktopPing(t, ch)
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
		_, _, err := openVNC(client)
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
		// The refusal races the connection's close, so only the failure is
		// certain.
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
		_, _, err := openVNC(client)
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

// desktopEndLine is the log line of a desktop connection's end.
func desktopEndLine(kind, addr, end string) string {
	return "session: " + kind + " desktop connection to " + addr + " ended: " + end
}

// failingWrites is a target connection whose writes fail once fail is set,
// as a write to a target that reset does.
type failingWrites struct {
	net.Conn
	fail *atomic.Bool
}

func (c failingWrites) Write(b []byte) (int, error) {
	if c.fail.Load() {
		return 0, syscall.ECONNRESET
	}
	return c.Conn.Write(b)
}

// The target's close or I/O error, before or during the relay, ends
// desktop_target_closed, told to the client, for both kinds; the end is
// logged once. A client's EOF ends the target, with nothing told.
func TestDesktopEndsWithItsChannel(t *testing.T) {
	t.Run("target closes", func(t *testing.T) {
		target := newVNCTarget(t)
		addr := target.ln.Addr().String()
		f := desktopFixture(t, addr, nil)
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openVNC(client)
		if err != nil {
			t.Fatal(err)
		}
		desktopPing(t, ch)
		_ = target.serverSide(t).Close()
		if reason := waitEndRequest(t, reqs); reason != CloseDesktopTargetClosed {
			t.Fatalf("end reason %q, want %q", reason, CloseDesktopTargetClosed)
		}
		waitEvent(t, f.events, desktopEndLine("vnc", addr, CloseDesktopTargetClosed))
		waitClosed(t, client)
	})
	t.Run("target write fails", func(t *testing.T) {
		target := newVNCTarget(t)
		var fail atomic.Bool
		f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) {
			c.dialDesktop = func(ctx context.Context, network, addr string) (net.Conn, error) {
				nc, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return failingWrites{Conn: nc, fail: &fail}, nil
			}
		})
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openVNC(client)
		if err != nil {
			t.Fatal(err)
		}
		desktopPing(t, ch)
		fail.Store(true)
		if _, err := ch.Write([]byte{rfbClientKeyEvent, 1, 0, 0, 0, 0, 0, 'p'}); err != nil {
			t.Fatal(err)
		}
		if reason := waitEndRequest(t, reqs); reason != CloseDesktopTargetClosed {
			t.Fatalf("end reason %q, want %q", reason, CloseDesktopTargetClosed)
		}
		waitClosed(t, client)
	})
	t.Run("rdp target closes", func(t *testing.T) {
		cert := testCert(t, "desktop.test")
		target := newRDPTarget(t, cert, x224Confirm(rdpProtocolHybrid), func(c net.Conn) error {
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if _, err := io.ReadFull(tc, make([]byte, len(tsNego))); err != nil {
				return err
			}
			if _, err := tc.Write(tsNego); err != nil {
				return err
			}
			_ = tc.Close()
			return errors.New("closed mid-relay")
		})
		addr := target.ln.Addr().String()
		f := rdpFixture(t, addr, nil)
		client := f.connect(t, f.rdpOpts())
		ch, reqs := openRDP(t, client, marshalRequest(t, validRequest()))
		rdpKeyRequest(t, reqs, true)
		r := bufio.NewReader(ch)
		readResponse(t, r)
		if _, err := ch.Write(tsNego); err != nil {
			t.Fatal(err)
		}
		readFor(t, r, string(tsNego))
		if reason := waitEndRequest(t, reqs); reason != CloseDesktopTargetClosed {
			t.Fatalf("end reason %q, want %q", reason, CloseDesktopTargetClosed)
		}
		waitEvent(t, f.events, desktopEndLine("rdp", addr, CloseDesktopTargetClosed))
		waitClosed(t, client)
	})
	t.Run("rdp target write fails", func(t *testing.T) {
		target := newRDPTarget(t, testCert(t, "desktop.test"), x224Confirm(rdpProtocolHybrid), nil)
		var fail atomic.Bool
		f := rdpFixture(t, target.ln.Addr().String(), func(c *ServerConfig) {
			c.dialDesktop = func(ctx context.Context, network, addr string) (net.Conn, error) {
				nc, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				return failingWrites{Conn: nc, fail: &fail}, nil
			}
		})
		client := f.connect(t, f.rdpOpts())
		ch, reqs := openRDP(t, client, marshalRequest(t, validRequest()))
		rdpKeyRequest(t, reqs, true)
		r := bufio.NewReader(ch)
		readResponse(t, r)
		if _, err := ch.Write(tsNego); err != nil {
			t.Fatal(err)
		}
		readFor(t, r, string(tsNego))
		fail.Store(true)
		if _, err := ch.Write(tsNego); err != nil {
			t.Fatal(err)
		}
		if reason := waitEndRequest(t, reqs); reason != CloseDesktopTargetClosed {
			t.Fatalf("end reason %q, want %q", reason, CloseDesktopTargetClosed)
		}
		waitClosed(t, client)
	})
	t.Run("rdp idle during the relay", func(t *testing.T) {
		clock := &idleClock{}
		target := newRDPTarget(t, testCert(t, "desktop.test"), x224Confirm(rdpProtocolHybrid), nil)
		addr := target.ln.Addr().String()
		f := rdpFixture(t, addr, func(c *ServerConfig) { c.clock = clock })
		client := f.connect(t, f.rdpOpts())
		ch, reqs := openRDP(t, client, marshalRequest(t, validRequest()))
		rdpKeyRequest(t, reqs, true)
		r := bufio.NewReader(ch)
		readResponse(t, r)
		// The round trip settles the client's bytes, which are activity,
		// before the clock moves.
		if _, err := ch.Write(tsNego); err != nil {
			t.Fatal(err)
		}
		readFor(t, r, string(tsNego))
		clock.advance(idleTimeout + time.Minute)
		clock.fireIdle()
		if reason := waitEndRequest(t, reqs); reason != CloseIdle {
			t.Fatalf("end reason %q, want %q", reason, CloseIdle)
		}
		target.waitClosed(t)
		waitEvent(t, f.events, desktopEndLine("rdp", addr, CloseIdle))
		waitClosed(t, client)
	})
	t.Run("dial fails after another end was decided", func(t *testing.T) {
		release := make(chan struct{})
		f := desktopFixture(t, "127.0.0.1:5900", func(c *ServerConfig) {
			c.dialDesktop = func(context.Context, string, string) (net.Conn, error) {
				<-release
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
			}
		})
		client := f.connect(t, f.vncOpts())
		opened := make(chan error, 1)
		go func() {
			_, _, err := openDesktopChannel(client, chanVNC)
			opened <- err
		}()
		// Shutdown is decided first; the dial then fails and records its
		// code before the end line is written.
		var once sync.Once
		hook := func(reason string) {
			if reason != CloseShutdown {
				return
			}
			once.Do(func() {
				close(release)
				<-opened
			})
		}
		onConnEnd.Store(&hook)
		t.Cleanup(func() { onConnEnd.Store(nil) })
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := f.srv.Shutdown(ctx); err != nil {
			t.Fatalf("shutdown: %v", err)
		}
		waitEvent(t, f.events, desktopEndLine("vnc", "127.0.0.1:5900", CloseShutdown))
	})
	t.Run("rdp client closes", func(t *testing.T) {
		target := newRDPTarget(t, testCert(t, "desktop.test"), x224Confirm(rdpProtocolHybrid), nil)
		addr := target.ln.Addr().String()
		f := rdpFixture(t, addr, nil)
		client := f.connect(t, f.rdpOpts())
		ch, reqs := openRDP(t, client, marshalRequest(t, validRequest()))
		rdpKeyRequest(t, reqs, true)
		r := bufio.NewReader(ch)
		readResponse(t, r)
		if _, err := ch.Write(tsNego); err != nil {
			t.Fatal(err)
		}
		readFor(t, r, string(tsNego))
		_ = ch.CloseWrite()
		noRequestsThenClose(t, reqs)
		target.waitClosed(t)
		waitEvent(t, f.events, desktopEndLine("rdp", addr, CloseExited))
		waitClosed(t, client)
	})
	t.Run("dial refused", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		f := desktopFixture(t, addr, nil)
		client := f.connect(t, f.vncOpts())
		if _, _, err := openDesktopChannel(client, chanVNC); err == nil {
			t.Fatal("the channel opened to a closed port")
		}
		waitEvent(t, f.events, desktopEndLine("vnc", addr, CloseExited+" (connection_refused)"))
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
		ch, reqs, err := openDesktopChannel(client, chanVNC)
		if err != nil {
			t.Fatal(err)
		}
		readFor(t, ch, "RFB 003.008\n")
		_, _ = io.WriteString(ch, "RFB 003.008\n")
		if reason := waitEndRequest(t, reqs); reason != CloseDesktopTargetClosed {
			t.Fatalf("end reason %q, want %q", reason, CloseDesktopTargetClosed)
		}
		waitClosed(t, client)
	})
	t.Run("client EOF", func(t *testing.T) {
		target := newVNCTarget(t)
		addr := target.ln.Addr().String()
		f := desktopFixture(t, addr, nil)
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openVNC(client)
		if err != nil {
			t.Fatal(err)
		}
		desktopPing(t, ch)
		_ = ch.CloseWrite()
		noRequestsThenClose(t, reqs)
		target.waitClosed(t)
		waitEvent(t, f.events, desktopEndLine("vnc", addr, CloseExited))
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
	ch, _, err := openVNC(rc.client)
	if err != nil {
		t.Fatal(err)
	}
	desktopPing(t, ch)
	rc.cut(t)
	if err := rc.resume(t, func(o *certOpts) { o.kind, o.login = "vnc", desktopPrincipal }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	desktopPing(t, ch)
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
