//go:build linux || darwin

package sessionhelper

import (
	"os"
	"path"

	"golang.org/x/sys/unix"
)

// renameAtParents opens the parents of from and to through root, so the
// rename stays confined, and runs rename on the two directory descriptors
// and the base names.
func renameAtParents(root *os.Root, from, to string, rename func(fromDir int, fromName string, toDir int, toName string) error) error {
	// O_DIRECTORY and O_NONBLOCK: a FIFO named as a parent answers at once.
	const parentFlags = os.O_RDONLY | unix.O_DIRECTORY | unix.O_NONBLOCK
	fromDir, err := root.OpenFile(path.Dir(from), parentFlags, 0)
	if err != nil {
		return err
	}
	defer fromDir.Close()
	toDir, err := root.OpenFile(path.Dir(to), parentFlags, 0)
	if err != nil {
		return err
	}
	defer toDir.Close()
	return rename(int(fromDir.Fd()), path.Base(from), int(toDir.Fd()), path.Base(to))
}
