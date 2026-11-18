package status

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// Publisher retry bounds after a failure to reach the launcher.
const (
	publishRetryMin = time.Second
	publishRetryMax = time.Minute
	// publishWriteTimeout bounds one frame write, so a stalled launcher only
	// delays the next document, never the board's writers.
	publishWriteTimeout = 5 * time.Second
)

// Opener opens a publishing connection to the launcher
// (launcher.Client.OpenStatus). The launcher never writes on it, so a read
// returns only when the launcher closes it.
type Opener func(context.Context) (io.ReadWriteCloser, error)

// Publish sends b's latest document to the launcher over one connection
// opened with open, and each newer one as the board changes, until ctx ends;
// it closes the connection before it returns. Changes made while a write is
// in flight coalesce into the newest document. A failure to reach the
// launcher is retried with jittered backoff from 1 s to 1 min and logged once
// per outage, since a run without the device service has no launcher at all;
// it never affects the devices.
func Publish(ctx context.Context, b *Board, open Opener, logf func(format string, args ...any)) {
	backoff := publishRetryMin
	unreachable := false
	for ctx.Err() == nil {
		conn, err := open(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if !unreachable {
				logf("status: cannot reach the session launcher, so status shows the config only; retrying in the background: %v", err)
				unreachable = true
			}
			if !sleep(ctx, backoff/2+rand.N(backoff/2+1)) {
				return
			}
			backoff = min(2*backoff, publishRetryMax)
			continue
		}
		if unreachable {
			logf("status: publishing to the session launcher")
			unreachable = false
		}
		backoff = publishRetryMin
		err = publishOn(ctx, b, conn)
		_ = conn.Close()
		if err != nil && ctx.Err() == nil {
			// One short jittered pause, so a launcher that accepts and then
			// closes at once is not redialled in a tight loop.
			wait := publishRetryMin/2 + rand.N(publishRetryMin/2+1)
			logf("status: the session launcher connection ended, reconnecting in %s: %v", wait.Round(time.Millisecond), err)
			if !sleep(ctx, wait) {
				return
			}
		}
	}
}

// errLauncherClosed is a publishing connection the launcher closed, as a
// restarted launcher does; Publish reconnects so the new one gets the
// document without waiting for a board change.
var errLauncherClosed = errors.New("the session launcher closed the status connection")

// publishOn writes the latest document, then each newer one, until ctx ends,
// a write fails or the launcher closes the connection.
func publishOn(ctx context.Context, b *Board, conn io.ReadWriteCloser) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		var one [1]byte
		_, _ = conn.Read(one[:])
	}()
	deadline, _ := conn.(interface{ SetWriteDeadline(time.Time) error })
	for {
		doc := b.Latest()
		if deadline != nil {
			_ = deadline.SetWriteDeadline(time.Now().Add(publishWriteTimeout))
		}
		// A full board fits a frame (config.MaxDevices, TestFullBoardFitsAFrame).
		if err := launcher.WriteStatusFrame(conn, doc); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-closed:
			return errLauncherClosed
		case <-b.Changed():
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ErrNoDocument means the launcher holds no document: the device service is
// not running, or this account may not read the status endpoint.
var ErrNoDocument = errors.New("no status document")

// Read reads and decodes the status document from the launcher's status
// endpoint. Errors wrap launcher.ErrUnavailable (launcher not running),
// launcher.ErrStatusUntrusted, launcher.ErrStatusDenied,
// launcher.ErrStatusFrame, ErrNoDocument or ErrInvalid.
func Read(ctx context.Context) (*Document, error) {
	raw, err := readStatus(ctx)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, ErrNoDocument
	}
	return Decode(raw)
}

// readStatus is launcher.ReadStatus; tests replace it.
var readStatus = launcher.ReadStatus
