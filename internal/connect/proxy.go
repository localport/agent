package connect

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
)

// Proxy accepts local TCP connections and forwards each one through an
// mTLS tunnel to the remote edge endpoint. Each accepted local conn gets
// its own TLS connection to Remote.
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
			p.OnError(fmt.Errorf("dial %s: %w", p.Remote, err))
		}
		return
	}
	defer remote.Close()

	if p.OnConn != nil {
		p.OnConn(local.RemoteAddr().String(), p.Remote)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go halfCopy(&wg, remote, local)
	go halfCopy(&wg, local, remote)
	wg.Wait()
}

func halfCopy(wg *sync.WaitGroup, dst, src net.Conn) {
	defer wg.Done()
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
