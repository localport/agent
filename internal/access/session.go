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
		s.drop(conn)
		return nil, err
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
		s.transport = &http2.Transport{}
	}
	if s.TLSConfig == nil {
		return nil, errors.New("no certificate to present")
	}
	cfg := s.TLSConfig.Clone()
	// The edge refuses a CONNECT whose authority differs from the SNI.
	cfg.ServerName = s.Device
	cfg.NextProtos = []string{"h2"}

	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", s.Addr)
	if err != nil {
		return nil, dialError(s.Device, err)
	}
	tlsConn := tls.Client(raw, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, handshakeError(s.Device, err)
	}
	conn, err := s.transport.NewClientConn(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	s.conn = conn
	return conn, nil
}

// drop discards a failed connection so the next forward dials a new one.
func (s *Session) drop(conn *http2.ClientConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == conn {
		s.conn = nil
	}
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
