//go:build !windows

package security

import (
	"fmt"
	"os"
	"syscall"
)

const (
	privateDirPerm  os.FileMode = 0o700
	privateFilePerm os.FileMode = 0o600
)

func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, nil
}

func createPrivate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, privateFilePerm)
}

func mkdirPrivate(path string) error {
	if err := os.MkdirAll(path, privateDirPerm); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	// MkdirAll applies the umask and leaves an existing directory's mode alone,
	// so neither a laxer umask nor a directory predating this code is trusted.
	if err := os.Chmod(path, privateDirPerm); err != nil {
		return fmt.Errorf("secure %s: %w", path, err)
	}
	return nil
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

// isRedirect reports whether a directory entry points somewhere other than where
// it appears to. On Unix that is a symlink and nothing else.
func isRedirect(info os.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}
