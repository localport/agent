package service

import (
	"os"

	"golang.org/x/sys/unix"
)

// openBundleFile opens a bundle file for root to copy: no symlink in any path
// component; O_NONBLOCK so a FIFO cannot block the open.
func openBundleFile(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, &os.PathError{Op: "openat2", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
