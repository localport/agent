//go:build cgo && linux

package sessionhelper

import "golang.org/x/sys/unix"

// closeRangeCloexec marks every descriptor from first up close-on-exec in
// one call (Linux 5.11 and later).
func closeRangeCloexec(first uint) error {
	return unix.CloseRange(first, ^uint(0), unix.CLOSE_RANGE_CLOEXEC)
}
