//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package netmon

import (
	"context"
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

// routeSource reads routing messages from a PF_ROUTE socket, such as interface
// state, address and default route changes. The read blocks with no CPU cost
// until a message arrives.
type routeSource struct {
	f *os.File
}

func newSource(logger *slog.Logger) source {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		logger.Debug("route socket failed; using address poll", slog.Any("error", err))
		return nil
	}
	// Wrap the non-blocking descriptor in an os.File so the runtime poller owns
	// it. Close then interrupts a pending read, which close(2) on a raw
	// descriptor does not guarantee.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		logger.Debug("route socket nonblock failed; using address poll", slog.Any("error", err))
		return nil
	}
	return &routeSource{f: os.NewFile(uintptr(fd), "route")}
}

func (s *routeSource) watch(ctx context.Context, wake chan<- struct{}) {
	buf := make([]byte, 4096)
	for {
		// Blocks until a routing message arrives or Close interrupts it.
		n, err := s.f.Read(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		// The monitor's address diff filters out irrelevant messages.
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (s *routeSource) Close() error { return s.f.Close() }
