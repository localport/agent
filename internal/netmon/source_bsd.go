//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package netmon

import (
	"context"
	"log/slog"
	"syscall"
)

// routeSource listens on a PF_ROUTE socket. The kernel delivers every routing
// message (interface up/down, address add/delete, default-route change) to it;
// a blocking read parks the goroutine at zero CPU until one arrives. This is
// the BSD/macOS equivalent of Linux netlink and the same mechanism route(8)
// and mDNSResponder use.
type routeSource struct {
	fd int
}

func newSource(logger *slog.Logger) source {
	fd, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		logger.Debug("route socket failed; using address poll", slog.Any("error", err))
		return nil
	}
	return &routeSource{fd: fd}
}

func (s *routeSource) watch(ctx context.Context, wake chan<- struct{}) {
	buf := make([]byte, 4096)
	for {
		// Blocks until the kernel emits a routing message (or the fd is closed
		// on shutdown, which returns an error and ends the loop).
		n, err := syscall.Read(s.fd, buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		// Any routing message is a candidate change; the portable address diff
		// filters the noise, so no message parsing is needed here.
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (s *routeSource) Close() error { return syscall.Close(s.fd) }
