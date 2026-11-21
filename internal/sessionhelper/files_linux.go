package sessionhelper

import (
	"errors"
	"io/fs"
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

// statVFS reports dir's file system.
func statVFS(dir string) (*sftp.StatVFS, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return nil, err
	}
	return &sftp.StatVFS{
		Bsize: uint64(st.Bsize), Frsize: uint64(st.Frsize), Blocks: st.Blocks, Bfree: st.Bfree, Bavail: st.Bavail,
		Files: st.Files, Ffree: st.Ffree, Favail: st.Ffree, Namemax: uint64(st.Namelen),
	}, nil
}

// renameNoReplace renames from to to inside root, atomically refusing an
// existing target. Parents open through root, keeping the rename confined;
// without RENAME_NOREPLACE it falls back to check-then-rename.
func renameNoReplace(root *os.Root, from, to string) error {
	return renameAtParents(root, from, to, func(fromDir int, fromName string, toDir int, toName string) error {
		err := unix.Renameat2(fromDir, fromName, toDir, toName, unix.RENAME_NOREPLACE)
		return renameat2Result(err, root, from, to)
	})
}

// osRenameNoReplace renames OS path from to to, atomically refusing an existing target.
func osRenameNoReplace(from, to string) error {
	err := unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
	return renameat2Result(err, osRenamer{}, from, to)
}

// renameat2Result maps a RENAME_NOREPLACE result; a file system without the
// flag takes the check-then-rename path through r.
func renameat2Result(err error, r renamer, from, to string) error {
	switch {
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL):
		return checkThenRename(r, from, to)
	case errors.Is(err, unix.EEXIST):
		return &fs.PathError{Op: "rename", Path: to, Err: fs.ErrExist}
	case err != nil:
		return &fs.PathError{Op: "rename", Path: to, Err: err}
	}
	return nil
}
