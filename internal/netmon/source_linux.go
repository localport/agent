//go:build linux

package netmon

import (
	"context"
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

// rtnetlink multicast groups for link state and IPv4/IPv6 address changes.
const rtnetlinkAllAddrs = unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR

// netlinkSource reads link and address changes from an AF_NETLINK route
// socket. The read blocks with no CPU cost until a message arrives.
type netlinkSource struct {
	f *os.File
}

func newSource(logger *slog.Logger) source {
	fd, err := unix.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC,
		unix.NETLINK_ROUTE,
	)
	if err != nil {
		logger.Debug("netlink socket failed; using address poll", slog.Any("error", err))
		return nil
	}
	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: rtnetlinkAllAddrs,
	}
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		logger.Debug("netlink bind failed; using address poll", slog.Any("error", err))
		return nil
	}
	// Wrap the non-blocking descriptor in an os.File so the runtime poller owns
	// it. Close then interrupts a pending read, which close(2) on a raw
	// descriptor does not guarantee.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		logger.Debug("netlink nonblock failed; using address poll", slog.Any("error", err))
		return nil
	}
	return &netlinkSource{f: os.NewFile(uintptr(fd), "netlink")}
}

func (s *netlinkSource) watch(ctx context.Context, wake chan<- struct{}) {
	buf := make([]byte, 8192)
	for {
		// Blocks until a change arrives or Close interrupts it.
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

func (s *netlinkSource) Close() error { return s.f.Close() }
