//go:build windows

package recording

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// availableBytes returns the bytes this process can still use on the volume
// holding path: GetDiskFreeSpaceEx's free bytes available to the caller,
// which honors the caller's disk quota.
func availableBytes(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return 0, fmt.Errorf("free space of %s: %w", path, err)
	}
	return avail, nil
}

// diskFull reports whether err is the volume or the caller's quota running
// out of space.
func diskFull(err error) bool {
	return errors.Is(err, windows.ERROR_DISK_FULL) || errors.Is(err, windows.ERROR_HANDLE_DISK_FULL) ||
		errors.Is(err, windows.ERROR_DISK_QUOTA_EXCEEDED)
}
