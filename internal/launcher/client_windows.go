//go:build windows

package launcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// Client reaches the launcher at Path, a pipe that must be owned by SYSTEM.
type Client struct {
	Path string
}

// DefaultClient is the launcher at PipePath.
func DefaultClient() Client { return Client{Path: PipePath} }

func (c Client) dial(ctx context.Context) (*os.File, error) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	conn, err := dialPipe(ctx, c.Path, system)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

// Probe asks the launcher what it offers sessions on this host.
func (c Client) Probe(ctx context.Context) (Probe, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return Probe{}, err
	}
	defer conn.Close()
	if err := writeMessage(conn, Request{V: Version, Kind: KindProbe}); err != nil {
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
		return Probe{}, Refusal(resp.Refused.Code)
	}
	return Probe{}, errors.New("launcher: unexpected response to probe")
}

// Start sends a session request naming the session channel pipe (req.Pipe,
// from NewSessionChannel) and waits for the launcher's started or refused
// answer. channel must be nil: Windows passes the channel by name. A refusal
// is a *RefusalError. req.Password is zeroed once sent.
func (c Client) Start(ctx context.Context, req Request, channel *os.File) (*Session, error) {
	defer clear(req.Password)
	if channel != nil {
		return nil, errors.New("launcher: Windows passes the session channel by pipe name")
	}
	req.V = Version
	req.HasPassword = len(req.Password) > 0
	if req.Kind != KindProbe && req.Pipe == "" {
		return nil, Refusal(CodeBadRequest)
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, StartTimeout)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	err = writeMessage(conn, req)
	if err == nil && req.HasPassword {
		err = writeSecret(conn, req.Password)
	}
	if err != nil {
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
		return &Session{conn: conn, ID: resp.Started.SessionID}, nil
	case resp.Refused != nil:
		conn.Close()
		return nil, Refusal(resp.Refused.Code)
	}
	conn.Close()
	return nil, errors.New("launcher: unexpected response to a session request")
}
