package service

import (
	"os"

	"golang.org/x/sys/unix"
)

// openBundleFile opens a bundle file for root to copy: no symlink in any path
// component; O_NONBLOCK so a FIFO cannot block the open.
func openBundleFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
}
