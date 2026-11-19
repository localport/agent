package sessionhelper

import (
	"errors"
	"io/fs"

	"golang.org/x/sys/unix"
)

// osRenameNoReplace renames the OS path from to to, atomically refusing an
// existing target (renamex_np RENAME_EXCL); a file system without the flag
// takes the check-then-rename path.
func osRenameNoReplace(from, to string) error {
	err := unix.RenamexNp(from, to, unix.RENAME_EXCL)
	switch {
	case errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.EINVAL):
		return checkThenRename(osRenamer{}, from, to)
	case errors.Is(err, unix.EEXIST):
		return &fs.PathError{Op: "rename", Path: to, Err: fs.ErrExist}
	case err != nil:
		return &fs.PathError{Op: "rename", Path: to, Err: err}
	}
	return nil
}
