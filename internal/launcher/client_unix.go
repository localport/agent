//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// Client reaches the launcher at Path.
type Client struct {
	Path string
}

// DefaultClient is the launcher at SocketPath.
func DefaultClient() Client { return Client{Path: SocketPath} }

func (c Client) dial(ctx context.Context) (*net.UnixConn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	uc := conn.(*net.UnixConn)
	if deadline, ok := ctx.Deadline(); ok {
		_ = uc.SetDeadline(deadline)
	}
	return uc, nil
}

// Probe asks the launcher what it offers sessions on this host.
func (c Client) Probe(ctx context.Context) (Probe, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return Probe{}, err
	}
	defer conn.Close()
	if err := sendMessage(conn, Request{V: Version, Kind: KindProbe}, nil); err != nil {
		return Probe{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	resp, err := readResponse(conn)
	if err != nil {
		return Probe{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	switch {
	case resp.Probe != nil:
		return *resp.Probe, nil
	case resp.Refused != nil:
		return Probe{}, clientRefusal(resp.Refused.Code, nil, "")
	}
	return Probe{}, errors.New("launcher: unexpected response to probe")
}

// Start sends a session request with channel attached and waits for the
// launcher's started or refused answer. channel is the helper's end of the
// session channel; the caller closes its copy after Start returns. A refusal
// is a *RefusalError.
func (c Client) Start(ctx context.Context, req Request, channel *os.File) (*Session, error) {
	req.V = Version
	if err := req.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, StartTimeout)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := sendMessage(conn, req, channel); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	resp, err := readResponse(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	switch {
	case resp.Started != nil:
		_ = conn.SetDeadline(time.Time{})
		return &Session{conn: conn, ID: resp.Started.SessionID, Messages: resp.Messages, FullDiskAccess: resp.FullDiskAccess}, nil
	case resp.Refused != nil:
		conn.Close()
		return nil, clientRefusal(resp.Refused.Code, resp.Messages, resp.FullDiskAccess)
	}
	conn.Close()
	return nil, errors.New("launcher: unexpected response to a session request")
}
