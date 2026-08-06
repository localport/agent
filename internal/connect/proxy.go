package connect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
)

// Proxy accepts local TCP connections and forwards each one to a locked tunnel
// over mTLS. Every accepted connection gets its own TLS connection to Remote.
type Proxy struct {
	Remote    string
	LocalAddr string
	TLSConfig *tls.Config

	OnConn  func(local, remote string)
	OnError func(err error)
}

func (p *Proxy) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.LocalAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", p.LocalAddr, err)
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if p.OnError != nil {
				p.OnError(fmt.Errorf("accept: %w", err))
			}
			continue
		}
		go p.handle(conn)
	}
}

func (p *Proxy) handle(local net.Conn) {
	defer local.Close()

	remote, err := tls.Dial("tcp", p.Remote, p.TLSConfig)
	if err != nil {
		if p.OnError != nil {
			p.OnError(friendlyDialError(p.Remote, err))
		}
		return
	}
	defer remote.Close()

	if p.OnConn != nil {
		p.OnConn(local.RemoteAddr().String(), p.Remote)
	}

	// Only the remote direction's error is reported: under TLS 1.3 the client
	// certificate goes after the server's Finished, so a rejection arrives on the
	// first read rather than at Dial. The local side ending is not a failure.
	//
	// wg.Done is deferred by these closures, not by halfCopy, so the write to
	// remoteErr happens before Wait returns.
	var wg sync.WaitGroup
	var remoteErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		remoteErr = halfCopy(local, remote)
	}()
	go func() {
		defer wg.Done()
		_ = halfCopy(remote, local)
	}()
	wg.Wait()

	if remoteErr != nil && p.OnError != nil {
		p.OnError(friendlyStreamError(p.Remote, remoteErr))
	}
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

// isNormalClose reports whether err is an ordinary end of stream.
func isNormalClose(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// A peer going away mid-copy is a normal disconnect on some platforms.
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// friendlyStreamError turns a mid-stream failure into something actionable.
// The TLS alert says only that the certificate was not accepted, so the message
// names what the holder can check.
func friendlyStreamError(remote string, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "tls: bad certificate"),
		strings.Contains(msg, "tls: unknown certificate"),
		strings.Contains(msg, "tls: certificate required"),
		strings.Contains(msg, "tls: unknown certificate authority"):
		return fmt.Errorf(
			"%s refused the certificate presented for this connection.\n"+
				"  Check in the dashboard that this identity has been given access to the device you are reaching,\n"+
				"  and that its certificate is still valid and has not been revoked: %w", remote, err)
	case strings.Contains(msg, "tls: certificate expired"),
		strings.Contains(msg, "tls: expired certificate"):
		return fmt.Errorf("%s rejected the certificate as expired: %w", remote, err)
	default:
		return fmt.Errorf("connection to %s ended: %w", remote, err)
	}
}

// friendlyDialError translates common TLS handshake failures into actionable
// messages, keeping the original as the cause.
func friendlyDialError(remote string, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "first record does not look like a TLS handshake"):
		return fmt.Errorf("dial %s: remote is not speaking TLS on this port; verify the endpoint is mTLS-enabled: %w", remote, err)
	case strings.Contains(msg, "remote error: tls: unrecognized name"):
		return fmt.Errorf("dial %s: remote rejected SNI; try --server-name: %w", remote, err)
	default:
		return fmt.Errorf("dial %s: %w", remote, err)
	}
}
