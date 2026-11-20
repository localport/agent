//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/localport/agent/internal/security"
)

// OpenStatus opens the device service's status publication: a KindStatus
// request the launcher accepts with Publishing. The caller writes frames
// with WriteStatusFrame and closes the connection to withdraw its document.
// A second publisher is refused with CodeBusy.
func (c Client) OpenStatus(ctx context.Context) (io.ReadWriteCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, StartTimeout)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := sendMessage(conn, Request{V: Version, Kind: KindStatus}, nil); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	resp, err := readResponse(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	switch {
	case resp.Publishing:
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	case resp.Refused != nil:
		conn.Close()
		return nil, clientRefusal(resp.Refused.Code, nil, "")
	}
	conn.Close()
	return nil, errors.New("launcher: unexpected response to a status request")
}

const statusReadTimeout = 3 * time.Second

// ErrStatusUntrusted refuses a status endpoint that is not the launcher's: a
// link or anything other than a socket, a socket not owned by root and the
// agent group or open to others, or a directory root does not own or its
// group or others may write.
var ErrStatusUntrusted = errors.New("the status endpoint is not the launcher's")

// ErrStatusDenied is the status endpoint refusing this account: only root,
// the agent account and members of the agent group may read it.
var ErrStatusDenied = errors.New("this account may not read the device status")

// statusSocket is StatusSocketPath; tests point it at their own socket.
var statusSocket = StatusSocketPath

// statusTrustedIDs are the owner uid and group gid the endpoint must have;
// tests replace it.
var statusTrustedIDs = func() (uid, gid uint32, err error) {
	gid, err = agentGroup()
	return 0, gid, err
}

func agentGroup() (uint32, error) {
	gid, err := security.AgentGroupID()
	if err != nil {
		return 0, err
	}
	return uint32(gid), nil
}

// ReadStatus reads the status document from the launcher's status endpoint
// after checking that root owns it: at most MaxStatusFrame bytes within
// statusReadTimeout. Empty means the device service publishes none: it is
// not running, or the launcher refused this account. ErrUnavailable means
// the endpoint does not exist or does not answer, ErrStatusDenied that this
// account may not reach it.
func ReadStatus(ctx context.Context) ([]byte, error) {
	if err := checkStatusSocket(statusSocket); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, statusReadTimeout)
	defer cancel()
	conn, err := (Client{Path: statusSocket}).dial(ctx)
	if errors.Is(err, fs.ErrPermission) {
		return nil, ErrStatusDenied
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	raw, err := io.ReadAll(io.LimitReader(conn, MaxStatusFrame+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if len(raw) > MaxStatusFrame {
		return nil, fmt.Errorf("%w: over %d bytes", ErrStatusFrame, MaxStatusFrame)
	}
	return raw, nil
}

// checkStatusSocket refuses unless path is a socket (no link) owned by the
// trusted uid with the agent group and mode 0660 or narrower, in a directory
// the trusted uid owns that neither group nor others can write.
func checkStatusSocket(path string) error {
	uid, gid, err := statusTrustedIDs()
	if errors.Is(err, security.ErrAgentGroupMissing) {
		// No agent group: the service was never installed here.
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	case errors.Is(err, fs.ErrPermission):
		return ErrStatusDenied
	case err != nil:
		return err
	}
	st := fi.Sys().(*syscall.Stat_t)
	if fi.Mode().Type() != fs.ModeSocket || st.Uid != uid || st.Gid != gid || fi.Mode().Perm()&^0o660 != 0 {
		return fmt.Errorf("%w: %s", ErrStatusUntrusted, path)
	}
	err = checkTrustedDir(filepath.Dir(path), uid, ErrStatusUntrusted)
	if errors.Is(err, fs.ErrPermission) {
		return ErrStatusDenied
	}
	return err
}

// checkTrustedDir refuses, with untrusted, unless dir is a directory (no
// link) owned by uid that neither group nor others can write.
func checkTrustedDir(dir string, uid uint32, untrusted error) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || st.Uid != uid || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s", untrusted, dir)
	}
	return nil
}
