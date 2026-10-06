//go:build !windows

package security

import (
	"errors"
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

func createPrivate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, privateFilePerm)
}

// inspectPrivateDir opens path with O_DIRECTORY, plus O_NOFOLLOW unless follow,
// and checks the owner uid on the descriptor. With secure it creates a missing
// directory and fchmods it to 0700, without secure it changes nothing.
func inspectPrivateDir(path string, follow, secure bool) error {
	if secure {
		if err := os.Mkdir(path, privateDirPerm); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create %s: %w", path, err)
		}
	}
	flags := os.O_RDONLY | syscall.O_DIRECTORY
	if !follow {
		flags |= syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		// symlink or non-directory. The errno differs by OS (ELOOP, EMLINK on
		// FreeBSD, EFTYPE on NetBSD, ENOTDIR).
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.EMLINK) || errors.Is(err, refusedLinkErrno) {
			return fmt.Errorf("%w: %s is not a directory of its own; credential paths must not be redirected", ErrUntrustedPath, path)
		}
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUntrustedPath, path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read ownership of %s", path)
	}
	if uid := os.Geteuid(); int(st.Uid) != uid {
		return fmt.Errorf("%w: %s is owned by uid %d, not %d", ErrUntrustedPath, path, st.Uid, uid)
	}
	if !secure {
		return nil
	}
	// fchmod so the mode lands on the inode just checked. Mkdir is subject to
	// the umask and leaves an existing directory's mode alone.
	if err := f.Chmod(privateDirPerm); err != nil {
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
