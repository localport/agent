package sessionhelper

import (
	"errors"
	"io/fs"
	"os"
	"path"

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
// existing target. The parents are opened through root, so the rename stays
// confined; a file system without RENAME_NOREPLACE takes the check-then-rename
// path.
func renameNoReplace(root *os.Root, from, to string) error {
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
	err = unix.Renameat2(int(fromDir.Fd()), path.Base(from), int(toDir.Fd()), path.Base(to), unix.RENAME_NOREPLACE)
	switch {
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL):
		return checkThenRename(root, from, to)
	case errors.Is(err, unix.EEXIST):
		return &fs.PathError{Op: "rename", Path: to, Err: fs.ErrExist}
	case err != nil:
		return &fs.PathError{Op: "rename", Path: to, Err: err}
	}
	return nil
}
