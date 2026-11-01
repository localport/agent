//go:build linux || darwin

package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/launcher"
)

// fakeLauncher answers the probe with probeErr and each Start with startErr,
// or hands the helper's end of the channel to helpers.
type fakeLauncher struct {
	probeErr error
	startErr error
	requests chan launcher.Request
	helpers  chan *os.File
}

func newFakeLauncher() *fakeLauncher {
	return &fakeLauncher{requests: make(chan launcher.Request, 4), helpers: make(chan *os.File, 4)}
}

func (l *fakeLauncher) Probe(context.Context) (launcher.Probe, error) {
	return launcher.Probe{PAM: true}, l.probeErr
}

func (l *fakeLauncher) Start(_ context.Context, req launcher.Request, channel *os.File) (*launcher.Session, error) {
	l.requests <- req
	if l.startErr != nil {
		return nil, l.startErr
	}
	// The caller closes its copy after Start, as with the real launcher.
	fd, err := unix.Dup(int(channel.Fd()))
	if err != nil {
		return nil, err
	}
	l.helpers <- os.NewFile(uintptr(fd), "helper-end")
	return &launcher.Session{ID: "s1"}, nil
}

const relayDevice = "01kpq7x2abcd34/device/tun12345.gw-01"

func relayServer(t *testing.T, l *fakeLauncher) *testServer {
	t.Helper()
	return newTestServer(t, func(c *ServerConfig) { c.Launcher, c.Device = l, relayDevice })
}

func (l *fakeLauncher) helper(t *testing.T) (*os.File, *launcher.FrameReader) {
	t.Helper()
	select {
	case h := <-l.helpers:
		t.Cleanup(func() { h.Close() })
		_ = h.SetDeadline(time.Now().Add(5 * time.Second))
		return h, launcher.NewFrameReader(h)
	case <-time.After(5 * time.Second):
		t.Fatal("no session started")
	}
	return nil, nil
}

const relayStart = `{"cols":80,"rows":24,"term":"xterm"}`

func TestRelayCarriesInputOutputResizeAndExit(t *testing.T) {
	l := newFakeLauncher()
	ts := relayServer(t, l)
	c := ts.openStart(t, ts.ticket(t, nil), []byte(relayStart))
	h, fr := l.helper(t)
	req := <-l.requests
	if req.Device != relayDevice || req.Kind != launcher.KindTerminal || req.Cols != 80 || req.Rows != 24 || req.Term != "xterm" || req.Login == "" {
		t.Fatalf("request %+v", req)
	}

	if err := c.ch.WriteMessage(TypeData, []byte("ls\r")); err != nil {
		t.Fatal(err)
	}
	if f, err := fr.ReadFrame(); err != nil || f.Type != launcher.FrameData || string(f.Data) != "ls\r" {
		t.Fatalf("input frame %+v, %v", f, err)
	}
	if err := c.ch.WriteMessage(TypeResize, []byte(`{"cols":100,"rows":30}`)); err != nil {
		t.Fatal(err)
	}
	if f, err := fr.ReadFrame(); err != nil || f.Type != launcher.FrameResize || f.Cols != 100 || f.Rows != 30 {
		t.Fatalf("resize frame %+v, %v", f, err)
	}

	if err := launcher.WriteFrame(h, launcher.Frame{Type: launcher.FrameData, Data: []byte("out")}); err != nil {
		t.Fatal(err)
	}
	c.expectData(t, "out")
	if err := launcher.WriteFrame(h, launcher.Frame{Type: launcher.FrameExit, Code: 3}); err != nil {
		t.Fatal(err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := c.ch.ReadMessage()
	if err != nil || m.Type != TypeExit || string(m.Body) != `{"code":3}` {
		t.Fatalf("got %v %s, %v; want exit 3", m.Type, m.Body, err)
	}
	c.expectClose(t, CloseExited)
}

// A helper that dies leaves the channel without an exit frame.
func TestRelayEndsWithHelperFailedOnAChannelWithoutExit(t *testing.T) {
	l := newFakeLauncher()
	ts := relayServer(t, l)
	c := ts.openStart(t, ts.ticket(t, nil), []byte(relayStart))
	h, _ := l.helper(t)
	h.Close()
	c.expectClose(t, CloseHelperFailed)
}

// The client's close ends the agent's end of the channel, which is the
// helper's signal to run the session's end path.
func TestRelayClientCloseHangsUpTheHelper(t *testing.T) {
	l := newFakeLauncher()
	ts := relayServer(t, l)
	c := ts.openStart(t, ts.ticket(t, nil), []byte(relayStart))
	_, fr := l.helper(t)
	if err := c.ch.WriteClose(""); err != nil {
		t.Fatal(err)
	}
	if f, err := fr.ReadFrame(); err == nil {
		t.Fatalf("helper read %+v after the client's close, want the channel's end", f)
	}
}

func TestRelayMapsLauncherRefusals(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{launcher.Refusal(launcher.CodeAccountRefused), CodeLoginNotAllowed},
		{launcher.Refusal(launcher.CodeAccountUnavailable), CodeLoginNotAllowed},
		{launcher.Refusal(launcher.CodeLoginNotEnabled), CodeLoginNotAllowed},
		{launcher.Refusal(launcher.CodeKindNotEnabled), CodeKindDisabled},
		{launcher.Refusal(launcher.CodeBusy), CodeAgentBusy},
		{launcher.Refusal(launcher.CodePAMFailed), CodeKindUnavailable},
		{fmt.Errorf("%w: dial", launcher.ErrUnavailable), CloseLauncherUnavailable},
	} {
		t.Run(tc.reason+"/"+tc.err.Error(), func(t *testing.T) {
			l := newFakeLauncher()
			l.startErr = tc.err
			ts := relayServer(t, l)
			c := ts.openStart(t, ts.ticket(t, nil), []byte(relayStart))
			c.expectClose(t, tc.reason)
		})
	}
}

// A launcher that does not answer its probe refuses the ticket before the
// spend.
func TestRelayRefusesUnspentWithoutALauncher(t *testing.T) {
	l := newFakeLauncher()
	l.probeErr = errors.New("connection refused")
	ts := relayServer(t, l)
	raw := ts.ticket(t, nil)
	if got := ts.refusal(t, raw); got != CodeKindUnavailable {
		t.Fatalf("refused %q, want kind_unavailable", got)
	}
	if ts.spent(ts.f.payload().JTI) {
		t.Fatal("the ticket was spent")
	}
}
