package sessionhelper

import (
	"errors"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames from to to inside root, atomically refusing an
// existing target (renameatx_np RENAME_EXCL). The parents are opened through
// root, so the rename stays confined; a file system without the flag takes
// the check-then-rename path.
func renameNoReplace(root *os.Root, from, to string) error {
	return renameAtParents(root, from, to, func(fromDir int, fromName string, toDir int, toName string) error {
		err := unix.RenameatxNp(fromDir, fromName, toDir, toName, unix.RENAME_EXCL)
		return renameExclResult(err, root, from, to)
	})
}

// osRenameNoReplace renames the OS path from to to, atomically refusing an
// existing target (renamex_np RENAME_EXCL); a file system without the flag
// takes the check-then-rename path.
func osRenameNoReplace(from, to string) error {
	return renameExclResult(unix.RenamexNp(from, to, unix.RENAME_EXCL), osRenamer{}, from, to)
}

// renameExclResult maps a RENAME_EXCL result; a volume without the flag
// takes the check-then-rename path through r.
func renameExclResult(err error, r renamer, from, to string) error {
	switch {
	case errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.EINVAL):
		return checkThenRename(r, from, to)
	case errors.Is(err, unix.EEXIST):
		return &fs.PathError{Op: "rename", Path: to, Err: fs.ErrExist}
	case err != nil:
		return &fs.PathError{Op: "rename", Path: to, Err: err}
	}
	return nil
}
