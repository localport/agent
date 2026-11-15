package access

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"

	"github.com/localport/agent/internal/errcode"
)

// Forward is one local listener mapped to one port on the device.
type Forward struct {
	// Socket reports that LocalAddr is a Unix socket path.
	Socket bool
	// LocalAddr is the local host:port. An empty port lets the OS assign one,
	// printed once bound.
	LocalAddr string
	// RemotePort is the device port each accepted connection is forwarded to.
	RemotePort uint16
}

// Proxy serves a set of forwards over one session.
type Proxy struct {
	Session  *Session
	Forwards []Forward

	// OnListen reports the bound address of each forward, including
	// OS-assigned ports.
	OnListen func(f Forward, addr string)
	OnConn   func(local string, port uint16)
	OnError  func(err error)
}

// Run binds every forward and serves until ctx ends.
func (p *Proxy) Run(ctx context.Context) error {
	var (
		wg        sync.WaitGroup
		listeners []net.Listener
	)
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()

	for _, f := range p.Forwards {
		ln, err := f.listen()
		if err != nil {
			return errcode.New(errcode.ForwardListenFailed).With(err, f.LocalAddr)
		}
		listeners = append(listeners, ln)
		if p.OnListen != nil {
			p.OnListen(f, ln.Addr().String())
		}

		wg.Add(1)
		go func(ln net.Listener, f Forward) {
			defer wg.Done()
			p.serve(ctx, ln, f, &wg)
		}(ln, f)
	}

	<-ctx.Done()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	wg.Wait()
	return nil
}

func (f Forward) listen() (net.Listener, error) {
	if f.Socket {
		return listenSocket(f.LocalAddr)
	}
	return net.Listen("tcp", f.LocalAddr)
}

// serve accepts on one listener. Connections are tracked so Run returns only
// after all forwards finish.
func (p *Proxy) serve(ctx context.Context, ln net.Listener, f Forward, wg *sync.WaitGroup) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if p.OnError != nil {
				p.OnError(errcode.New(errcode.ForwardListenFailed).With(err, "accept"))
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.handle(ctx, conn, f)
		}()
	}
}

func (p *Proxy) handle(ctx context.Context, local net.Conn, f Forward) {
	defer local.Close()

	stream, err := p.Session.Open(ctx, f.RemotePort)
	if err != nil {
		if p.OnError != nil {
			p.OnError(err)
		}
		return
	}
	defer stream.Close()

	// On cancel, close both sides to unblock pending reads.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = local.Close()
			_ = stream.Close()
		case <-done:
		}
	}()

	if p.OnConn != nil {
		p.OnConn(local.RemoteAddr().String(), f.RemotePort)
	}

	// Report only the remote direction's error. Under TLS 1.3 the server
	// rejects the client certificate after Finished, so the alert arrives on
	// the first read and dial succeeds.
	var wg sync.WaitGroup
	var remoteErr error
	wg.Go(func() { remoteErr = halfCopy(local, stream) })
	wg.Go(func() { _ = halfCopy(stream, local) })
	wg.Wait()

	if remoteErr != nil && p.OnError != nil {
		p.OnError(streamError(p.Session.Device, remoteErr))
	}
}

// ServeStdio forwards in and out to a device port, for `ssh -o
// ProxyCommand`. It returns once the device-to-out direction ends (EOF, reset
// or alert), as `ssh -W` ends with its channel, and closes the stream. The
// copy from in is not waited for: the caller owns in and ends a read still
// blocked on it, as process exit does for stdin.
func (p *Proxy) ServeStdio(ctx context.Context, in io.Reader, out io.Writer, port uint16) error {
	stream, err := p.Session.Open(ctx, port)
	if err != nil {
		return err
	}
	defer stream.Close()

	go func() {
		_, _ = io.Copy(stream, in)
		// Half-close only when the stream supports it, as in halfCopy.
		if cw, ok := stream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	if _, err := io.Copy(out, stream); !isNormalClose(err) {
		return streamError(p.Session.Device, err)
	}
	return nil
}

// halfCopy copies until EOF and reports anything that was not an ordinary
// close.
func halfCopy(dst, src net.Conn) error {
	_, err := io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	if isNormalClose(err) {
		return nil
	}
	return err
}

// isNormalClose reports whether err is an ordinary end of stream. Keep in sync
// with tunnel.ignoreClosed.
func isNormalClose(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// Some platforms report a peer disconnect mid-copy as a reset.
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// RFC 8446 alert codes the edge sends to refuse a client certificate.
const (
	alertBadCertificate      tls.AlertError = 42
	alertRevokedCertificate  tls.AlertError = 44
	alertExpiredCertificate  tls.AlertError = 45
	alertUnknownCertificate  tls.AlertError = 46
	alertUnknownCA           tls.AlertError = 48
	alertAccessDenied        tls.AlertError = 49
	alertCertificateRequired tls.AlertError = 116
)

var refusalAlerts = []tls.AlertError{
	alertBadCertificate, alertRevokedCertificate, alertExpiredCertificate, alertUnknownCertificate,
	alertUnknownCA, alertAccessDenied, alertCertificateRequired,
}

// receivedAlert returns the refusal alert the peer sent, if err carries one.
// crypto/tls reports a received alert as a *net.OpError with Op "remote
// error" around its unexported alert type, whose Error text is the same table
// as tls.AlertError's; only the codes in refusalAlerts are recognised. An
// outer *net.OpError, such as the "readfrom" of a copy into a TCP socket, is
// passed through to the one it wraps.
func receivedAlert(err error) (tls.AlertError, bool) {
	var op *net.OpError
	for errors.As(err, &op) {
		if op.Op != "remote error" {
			err = op.Err
			continue
		}
		if op.Err == nil {
			return 0, false
		}
		got := op.Err.Error()
		for _, code := range refusalAlerts {
			if got == code.Error() {
				return code, true
			}
		}
		return 0, false
	}
	return 0, false
}

// refusalError maps a refusal alert to an actionable error.
func refusalError(device string, code tls.AlertError, err error) error {
	var msg string
	switch code {
	case alertRevokedCertificate:
		msg = device + " reports this certificate as revoked: it cannot be renewed, so obtain a new one with `localport setup <TOKEN>` or `localport login`"
	case alertAccessDenied:
		msg = device + " denied this identity: its access to the device was withdrawn or narrowed, check the grants in the dashboard"
	case alertExpiredCertificate:
		msg = device + " rejected the certificate as expired: an expired credential cannot be renewed, so run `localport login` again for a sign-in, or `localport setup` with a new setup token for a machine credential"
	default:
		msg = device + " refused this certificate: check that the identity has access to the device, and run `localport identity list`"
	}
	return errcode.New(errcode.DeviceRefused).With(err, msg)
}

// streamError maps a failure after the handshake, such as a refusal alert, to
// an actionable error.
func streamError(device string, err error) error {
	if code, ok := receivedAlert(err); ok {
		return refusalError(device, code, err)
	}
	return errcode.New(errcode.DeviceUnreachable).With(err, "the connection to "+device+" ended")
}

// dialError reports an unreachable device.
func dialError(device string, err error) error {
	return errcode.New(errcode.DeviceUnreachable).With(err, device+": device offline or unknown address")
}

// handshakeError maps a failed handshake: a refusal alert, a peer that does
// not speak TLS, or an unreachable device.
func handshakeError(device string, err error) error {
	if code, ok := receivedAlert(err); ok {
		return refusalError(device, code, err)
	}
	// Conn is set only when the first record from the peer was not TLS.
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) && rhe.Conn != nil {
		return errcode.New(errcode.DeviceUnreachable).With(err, device+" is not answering with TLS on this port")
	}
	return errcode.New(errcode.DeviceUnreachable).With(err, device+": device offline or unknown address")
}
