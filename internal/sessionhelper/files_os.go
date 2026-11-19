package sessionhelper

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pkg/sftp"
)

// osFS serves the real file system as the login, as OpenSSH's sftp-server
// does: the OS permissions of the login are the only boundary, and symlinks,
// absolute ones included, resolve as the OS resolves them. The platform hooks
// map client paths: the identity on Unix, the drive grammar on Windows
// (files_os_windows.go).
type osFS struct{}

// native maps name for a read (write false) or a change to the file system.
func (osFS) native(name string, write bool) (string, error) { return osPath(name, write) }

func writes(flag int) bool { return flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 }

func (f osFS) OpenFile(name string, flag int, perm fs.FileMode) (*os.File, error) {
	p, err := f.native(name, writes(flag))
	if err != nil {
		return nil, err
	}
	return os.OpenFile(p, flag, perm)
}

func (f osFS) Stat(name string) (fs.FileInfo, error) {
	if osVirtualRoot(name) {
		return virtualDirInfo("/"), nil
	}
	p, err := f.native(name, false)
	if err != nil {
		return nil, err
	}
	return os.Stat(p)
}

func (f osFS) Lstat(name string) (fs.FileInfo, error) {
	if osVirtualRoot(name) {
		return virtualDirInfo("/"), nil
	}
	p, err := f.native(name, false)
	if err != nil {
		return nil, err
	}
	return os.Lstat(p)
}

// Readlink returns the link's target in client form.
func (f osFS) Readlink(name string) (string, error) {
	p, err := f.native(name, false)
	if err != nil {
		return "", err
	}
	target, err := os.Readlink(p)
	if err != nil {
		return "", err
	}
	return osClientTarget(name, target)
}

func (f osFS) Mkdir(name string, perm fs.FileMode) error {
	p, err := f.native(name, true)
	if err != nil {
		return err
	}
	return os.Mkdir(p, perm)
}

func (f osFS) Symlink(target, name string) error {
	p, err := f.native(name, true)
	if err != nil {
		return err
	}
	t, err := osLinkTarget(target)
	if err != nil {
		return err
	}
	return os.Symlink(t, p)
}

// pair maps the two names of a link or rename. The OS refuses a cross-volume
// pair (EXDEV): os.Rename, MoveFileEx without MOVEFILE_COPY_ALLOWED and
// CreateHardLink never copy.
func (f osFS) pair(oldname, newname string) (string, string, error) {
	from, err := f.native(oldname, true)
	if err != nil {
		return "", "", err
	}
	to, err := f.native(newname, true)
	if err != nil {
		return "", "", err
	}
	return from, to, nil
}

func (f osFS) Link(oldname, newname string) error {
	from, to, err := f.pair(oldname, newname)
	if err != nil {
		return err
	}
	return os.Link(from, to)
}

func (f osFS) Rename(oldname, newname string) error {
	from, to, err := f.pair(oldname, newname)
	if err != nil {
		return err
	}
	return os.Rename(from, to)
}

func (f osFS) RenameNoReplace(oldname, newname string) error {
	from, to, err := f.pair(oldname, newname)
	if err != nil {
		return err
	}
	return osRenameNoReplace(from, to)
}

func (f osFS) Remove(name string) error {
	p, err := f.native(name, true)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

func (f osFS) Chmod(name string, mode fs.FileMode) error {
	p, err := f.native(name, true)
	if err != nil {
		return err
	}
	return os.Chmod(p, mode)
}

func (f osFS) Chown(name string, uid, gid int) error {
	p, err := f.native(name, true)
	if err != nil {
		return err
	}
	return os.Chown(p, uid, gid)
}

func (f osFS) Chtimes(name string, atime, mtime time.Time) error {
	p, err := f.native(name, true)
	if err != nil {
		return err
	}
	return os.Chtimes(p, atime, mtime)
}

// StatVFS answers for the file system holding name (on Windows the volume its
// data is on).
func (f osFS) StatVFS(name string) (*sftp.StatVFS, error) {
	if osVirtualRoot(name) {
		return nil, &fs.PathError{Op: "statvfs", Path: name, Err: syscall.EINVAL}
	}
	p, err := f.native(name, false)
	if err != nil {
		return nil, err
	}
	return statVFS(p)
}

func (osFS) virtualDir(name string) ([]fs.FileInfo, bool, error) {
	if !osVirtualRoot(name) {
		return nil, false, nil
	}
	entries, err := osVirtualEntries()
	return entries, true, err
}

// filesHome is the home argument of FilesServerMode, checked by the spawning
// helper so a bad home refuses the session before it starts: empty with a
// files_root, else home, which must be a directory.
func filesHome(root, home string) (string, error) {
	if root != "" {
		return "", nil
	}
	fi, err := os.Stat(home)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", &fs.PathError{Op: "home", Path: home, Err: syscall.ENOTDIR}
	}
	return home, nil
}

// startDir is the client form of the login's home with its symlinks
// resolved, where relative paths start. A missing home or one that is not a
// directory is refused.
func startDir(home string) (string, error) {
	if home == "" {
		return "", &fs.PathError{Op: "home", Path: home, Err: syscall.ENOENT}
	}
	dir, err := filepath.EvalSymlinks(home)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", &fs.PathError{Op: "home", Path: dir, Err: syscall.ENOTDIR}
	}
	return osClientPath(dir)
}

// virtualDirInfo is a synthesized read-only directory: the Windows top and
// its drive entries.
type virtualDirInfo string

func (n virtualDirInfo) Name() string     { return string(n) }
func (virtualDirInfo) Size() int64        { return 0 }
func (virtualDirInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o555 }
func (virtualDirInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (virtualDirInfo) IsDir() bool        { return true }
func (virtualDirInfo) Sys() any           { return nil }
