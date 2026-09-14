package access

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
)

// Forward is one local listener mapped to one port on the device.
type Forward struct {
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
	var listeners []net.Listener
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()

	for _, f := range p.Forwards {
		ln, err := net.Listen("tcp", f.LocalAddr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", f.LocalAddr, err)
		}
		listeners = append(listeners, ln)
		if p.OnListen != nil {
			p.OnListen(f, ln.Addr().String())
		}
		go p.serve(ctx, ln, f)
	}

	<-ctx.Done()
	return nil
}

// serve accepts on one listener until it is closed.
func (p *Proxy) serve(ctx context.Context, ln net.Listener, f Forward) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if p.OnError != nil {
				p.OnError(fmt.Errorf("accept: %w", err))
			}
			continue
		}
		go p.handle(ctx, conn, f)
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

// ServeStdio forwards stdin and stdout to a device port, for
// `ssh -o ProxyCommand`.
func (p *Proxy) ServeStdio(ctx context.Context, in io.Reader, out io.Writer, port uint16) error {
	stream, err := p.Session.Open(ctx, port)
	if err != nil {
		return err
	}
	defer stream.Close()

	var wg sync.WaitGroup
	var remoteErr error
	wg.Go(func() {
		_, err := io.Copy(out, stream)
		if !isNormalClose(err) {
			remoteErr = err
		}
	})
	wg.Go(func() {
		_, _ = io.Copy(stream, in)
		// Half-close only when the stream supports it, as in halfCopy.
		if cw, ok := stream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	})
	wg.Wait()

	if remoteErr != nil {
		return streamError(p.Session.Device, remoteErr)
	}
	return nil
}

// halfCopy copies until EOF and reports anything that was not an ordinary close.
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

// streamError maps a mid-stream TLS alert to an actionable error.
//
// Matching is by message text. A post-handshake alert arrives as a net.OpError
// wrapping the unexported crypto/tls alert type, and tls.AlertError exists only
// during the handshake. The strings come from crypto/tls alertText.
func streamError(device string, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "tls: bad certificate"),
		strings.Contains(msg, "tls: unknown certificate"),
		strings.Contains(msg, "tls: certificate required"),
		strings.Contains(msg, "tls: unknown certificate authority"):
		return fmt.Errorf("%s refused this certificate: check that the identity has access to the device, and run `localport identity list`: %w", device, err)
	case strings.Contains(msg, "tls: certificate expired"),
		strings.Contains(msg, "tls: expired certificate"):
		return fmt.Errorf("%s rejected the certificate as expired: run `localport login` again, or `localport identity renew`: %w", device, err)
	default:
		return fmt.Errorf("connection to %s ended: %w", device, err)
	}
}

// dialError reports an unreachable device.
func dialError(device string, err error) error {
	return fmt.Errorf("cannot reach %s: device offline or unknown address: %w", device, err)
}

// handshakeError reports a refusal during the handshake.
func handshakeError(device string, err error) error {
	msg := err.Error()
	if strings.Contains(msg, "first record does not look like a TLS handshake") {
		return fmt.Errorf("%s is not answering with TLS on this port: %w", device, err)
	}
	return fmt.Errorf("cannot reach %s: device offline or unknown address: %w", device, err)
}
