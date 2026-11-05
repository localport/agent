//go:build windows

package sessionhelper

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/launcher"
)

// unixForwardSupported: Windows serves TCP forwards only.
const unixForwardSupported = false

// forwardServerCommand is the forward server's command line: this binary in
// ForwardServerMode, run as the login on pipes like any piped command.
func forwardServerCommand() (app, cmdLine string, err error) {
	if app, err = os.Executable(); err != nil {
		return "", "", err
	}
	return app, syscall.EscapeArg(app) + " " + ForwardServerMode, nil
}

// RunForwardServer is `localport-session forward-server`: it serves the
// forward messages on standard input and output, which the helper relays to
// the agent's session pipe, until standard input ends.
func RunForwardServer(log func(string, ...any)) error {
	p := &pipeForwardPeer{in: os.Stdin, out: os.Stdout}
	p.mux = launcher.NewForwardMux(p.write)
	return ServeForwards(p, log)
}

// pipeForwardPeer carries each forward as a launcher.ForwardStream: no
// handle crosses to the agent, which runs as another account, and each
// stream's buffers are bounded by its credit window.
type pipeForwardPeer struct {
	in  io.Reader
	out io.Writer
	mux *launcher.ForwardMux

	wmu sync.Mutex
	buf []byte
}

func (p *pipeForwardPeer) Read(b []byte) (int, error) { return p.in.Read(b) }

func (p *pipeForwardPeer) write(m launcher.FwdMsg) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	b, err := launcher.AppendForwardMsg(p.buf[:0], m)
	if err != nil {
		return err
	}
	p.buf = b
	_, err = p.out.Write(b)
	return err
}

// send opens the stream before the answer goes out, so the agent's first
// data finds it, then pumps it to conn.
func (p *pipeForwardPeer) send(m launcher.FwdMsg, conn net.Conn) error {
	if conn == nil {
		return p.write(m)
	}
	s, err := p.mux.Open(m.ID)
	if err != nil {
		_ = conn.Close()
		return err
	}
	if err := p.write(m); err != nil {
		_ = s.Close()
		_ = conn.Close()
		return err
	}
	go pumpForward(s, conn)
	return nil
}

func (p *pipeForwardPeer) deliver(m launcher.FwdMsg) error { return p.mux.Deliver(m) }
func (p *pipeForwardPeer) conns() int                      { return p.mux.Len() }
func (p *pipeForwardPeer) closeAll()                       { p.mux.CloseAll() }

// pumpForward relays one stream and its socket until both directions ended
// or either side failed, then closes both.
func pumpForward(s *launcher.ForwardStream, conn net.Conn) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(conn, s); err != nil {
			_ = conn.Close()
			_ = s.Close()
			return
		}
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	if _, err := io.Copy(s, conn); err != nil {
		_ = s.Close()
		_ = conn.Close()
	} else {
		_ = s.CloseWrite()
	}
	<-done
	_ = s.Close()
	_ = conn.Close()
}

func errConnRefused(err error) bool { return errors.Is(err, windows.WSAECONNREFUSED) }
func errAddrInUse(err error) bool   { return errors.Is(err, windows.WSAEADDRINUSE) }
func errPermission(err error) bool {
	return errors.Is(err, windows.WSAEACCES) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
