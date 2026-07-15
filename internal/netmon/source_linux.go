//go:build linux

package netmon

import (
	"context"
	"log/slog"
	"syscall"
)

// rtnetlink multicast group masks (from uapi/linux/rtnetlink.h). Stable kernel
// ABI values, defined locally because the stdlib syscall package does not
// export them (they live in golang.org/x/sys/unix, which we avoid adding for
// three constants). Subscribing to these makes the kernel multicast interface
// up/down and IPv4/IPv6 address add/delete events to our socket.
const (
	rtmgrpLink        = 0x1   // RTMGRP_LINK
	rtmgrpIPv4IfAddr  = 0x10  // RTMGRP_IPV4_IFADDR
	rtmgrpIPv6IfAddr  = 0x100 // RTMGRP_IPV6_IFADDR
	rtnetlinkAllAddrs = rtmgrpLink | rtmgrpIPv4IfAddr | rtmgrpIPv6IfAddr
)

// netlinkSource listens on an AF_NETLINK route socket. The kernel multicasts
// link and IPv4/IPv6 address changes to the subscribed groups; a blocking
// recvmsg parks the goroutine at zero CPU until one arrives. Present on every
// Linux kernel (NETLINK_ROUTE is core), so this covers servers and embedded
// edge devices alike.
type netlinkSource struct {
	fd int
}

func newSource(logger *slog.Logger) source {
	fd, err := syscall.Socket(
		syscall.AF_NETLINK,
		syscall.SOCK_RAW|syscall.SOCK_CLOEXEC,
		syscall.NETLINK_ROUTE,
	)
	if err != nil {
		logger.Debug("netlink socket failed; using address poll", slog.Any("error", err))
		return nil
	}
	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: rtnetlinkAllAddrs,
	}
	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		logger.Debug("netlink bind failed; using address poll", slog.Any("error", err))
		return nil
	}
	return &netlinkSource{fd: fd}
}

func (s *netlinkSource) watch(ctx context.Context, wake chan<- struct{}) {
	buf := make([]byte, 8192)
	for {
		// Blocks until the kernel multicasts a link/address change (or the fd
		// is closed on shutdown, which returns an error and ends the loop).
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
		// Any route message is a candidate change; the portable address diff
		// decides whether it is real, so no parsing is needed here.
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (s *netlinkSource) Close() error { return syscall.Close(s.fd) }
