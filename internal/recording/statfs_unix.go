//go:build linux || darwin

package recording

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// availableBytes returns the bytes an unprivileged writer can still use on
// the filesystem holding path.
func availableBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// diskFull reports whether err is the filesystem or the user's quota running
// out of space.
func diskFull(err error) bool {
	return errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT)
}
