package access

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// connectTimeout bounds one dial and TLS handshake, so an unreachable device
// cannot hold the session lock indefinitely. Tests override it.
var connectTimeout = 20 * time.Second

const (
	// h2ReadIdleTimeout is the idle time before the transport sends a ping.
	// h2PingTimeout is the time a ping may go unanswered before the
	// connection is closed.
	h2ReadIdleTimeout = 30 * time.Second
	h2PingTimeout     = 15 * time.Second
)

// Session carries all forwards to a device over one HTTP/2 connection to the
// edge, with one CONNECT stream per accepted local connection. A dropped
// connection is dialed again by the next forward.
type Session struct {
	// Device is the device host. It is the TLS server name and the CONNECT
	// authority.
	Device string
	// Addr is the host:port to dial.
	Addr string
	// TLSConfig carries the client certificate and the server name.
	TLSConfig *tls.Config

	mu        sync.Mutex
	transport *http2.Transport
	conn      *http2.ClientConn
	// tlsConn is the connection under conn. It keeps the first read error,
	// which http2 replaces with a generic one.
	tlsConn *readErrConn
}

// Open returns a byte stream to one port on the device.
func (s *Session) Open(ctx context.Context, port uint16) (net.Conn, error) {
	conn, err := s.clientConn(ctx)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	authority := net.JoinHostPort(s.Device, strconv.Itoa(int(port)))
	req := (&http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: authority},
		Host:          authority,
		Header:        make(http.Header),
		Body:          pr,
		ContentLength: -1,
	}).WithContext(ctx)

	resp, err := conn.RoundTrip(req)
	if err != nil {
		_ = pw.Close()
		// Under TLS 1.3 a refused client certificate arrives here, on the
		// first read after the handshake.
		if cause := s.drop(conn); cause != nil {
			err = cause
		}
		return nil, streamError(s.Device, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = pw.Close()
		_ = resp.Body.Close()
		return nil, statusError(port, resp.StatusCode)
	}
	return &streamConn{w: pw, r: resp.Body, local: s.Addr, remote: authority}, nil
}

// Close ends the connection to the edge.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

// clientConn returns the live connection, dialing one when there is none.
func (s *Session) clientConn(ctx context.Context) (*http2.ClientConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil && s.conn.State().Closed {
		s.conn = nil
	}
	if s.conn != nil {
		return s.conn, nil
	}

	if s.transport == nil {
		// Pings detect a connection lost to a network switch before the next
		// forward uses it.
		s.transport = &http2.Transport{
			ReadIdleTimeout: h2ReadIdleTimeout,
			PingTimeout:     h2PingTimeout,
		}
	}
	if s.TLSConfig == nil {
		return nil, errors.New("no certificate to present")
	}
	cfg := s.TLSConfig.Clone()
	// The edge refuses a CONNECT whose authority differs from the SNI.
	cfg.ServerName = s.Device
	cfg.NextProtos = []string{"h2"}

	// ctx lives as long as the process. The dial holds s.mu, so it needs its
	// own bound.
	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(dialCtx, "tcp", s.Addr)
	if err != nil {
		return nil, dialError(s.Device, err)
	}
	tlsConn := tls.Client(raw, cfg)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = raw.Close()
		return nil, handshakeError(s.Device, err)
	}
	tracked := &readErrConn{Conn: tlsConn}
	conn, err := s.transport.NewClientConn(tracked)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	s.conn = conn
	s.tlsConn = tracked
	return conn, nil
}

// drop discards a failed connection so the next forward dials a new one. It
// returns the connection's first read error, if any.
func (s *Session) drop(conn *http2.ClientConn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != conn {
		return nil
	}
	s.conn = nil
	return s.tlsConn.err()
}

// readErrConn records the first read error of the TLS connection, such as the
// alert for a refused client certificate.
type readErrConn struct {
	*tls.Conn
	mu      sync.Mutex
	readErr error
}

func (c *readErrConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.mu.Lock()
		if c.readErr == nil {
			c.readErr = err
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *readErrConn) err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readErr
}

// streamConn is a net.Conn view of one CONNECT stream.
type streamConn struct {
	w      *io.PipeWriter
	r      io.ReadCloser
	local  string
	remote string
	once   sync.Once
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *streamConn) Close() error {
	c.once.Do(func() {
		_ = c.w.Close()
		_ = c.r.Close()
	})
	return nil
}

// CloseWrite ends the request body so a service waiting for EOF can reply.
func (c *streamConn) CloseWrite() error { return c.w.Close() }

func (c *streamConn) LocalAddr() net.Addr  { return streamAddr(c.local) }
func (c *streamConn) RemoteAddr() net.Addr { return streamAddr(c.remote) }

// Deadlines are no-ops. The HTTP/2 layer manages stream lifetime.
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

type streamAddr string

func (a streamAddr) Network() string { return "tcp" }
func (a streamAddr) String() string  { return string(a) }

// statusError maps an edge refusal status to an actionable error.
func statusError(port uint16, status int) error {
	switch status {
	case http.StatusForbidden:
		return fmt.Errorf("not allowed: check this identity's access to the device, and that port %d is open on it", port)
	case http.StatusMisdirectedRequest:
		return errors.New("address does not match the device")
	case http.StatusMethodNotAllowed:
		return errors.New("not a fleet device address")
	case http.StatusBadGateway:
		return fmt.Errorf("nothing is listening on port %d on the device", port)
	case http.StatusServiceUnavailable:
		return errors.New("device is busy, retry")
	default:
		return fmt.Errorf("edge refused the connection: %d", status)
	}
}
