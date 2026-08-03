//go:build !windows

package security

import (
	"fmt"
	"os"
	"syscall"
)

func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, nil
}

// verifyPrivate refuses a file that group or other can reach, or one owned by
// another account. A 0600 file belonging to someone else is not ours, and
// reading a key from it would trust whoever placed it there.
func verifyPrivate(f *os.File, path string) error {
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if mode := info.Mode(); mode&os.ModeType != 0 {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s has too-open permissions %#o (want 0600 or stricter)", path, perm)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read ownership of %s", path)
	}
	if uid := os.Geteuid(); int(st.Uid) != uid {
		return fmt.Errorf("%s is owned by uid %d, not %d", path, st.Uid, uid)
	}
	return nil
}
