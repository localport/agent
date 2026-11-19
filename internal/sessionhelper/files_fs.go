package sessionhelper

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

// filesFS is the file system one files session serves. Every name is a clean
// absolute client path ("/" is the top); each backing maps it to the OS.
type filesFS interface {
	OpenFile(name string, flag int, perm fs.FileMode) (*os.File, error)
	Stat(name string) (fs.FileInfo, error)
	Lstat(name string) (fs.FileInfo, error)
	Readlink(name string) (string, error)
	Mkdir(name string, perm fs.FileMode) error
	// Symlink creates name pointing at target, the client's link text.
	Symlink(target, name string) error
	Link(oldname, newname string) error
	// Rename replaces an existing target; RenameNoReplace refuses one.
	Rename(oldname, newname string) error
	RenameNoReplace(oldname, newname string) error
	Remove(name string) error
	Chmod(name string, mode fs.FileMode) error
	Chown(name string, uid, gid int) error
	Chtimes(name string, atime, mtime time.Time) error
	StatVFS(name string) (*sftp.StatVFS, error)
	// virtualDir lists a directory the backing synthesizes (the Windows
	// drive list); ok is false for every name the OS lists.
	virtualDir(name string) (entries []fs.FileInfo, ok bool, err error)
}

// rel is the root-relative name of a client path for an os.Root: "." names
// the root itself.
func rel(p string) string {
	p = strings.TrimPrefix(path.Clean("/"+p), "/")
	if p == "" {
		return "."
	}
	return p
}

// rootFS confines every name to files_root through an os.Root, so neither
// "..", an absolute name nor a symlink leaves it.
type rootFS struct{ root *os.Root }

func (r rootFS) OpenFile(name string, flag int, perm fs.FileMode) (*os.File, error) {
	return r.root.OpenFile(rel(name), flag, perm)
}
func (r rootFS) Stat(name string) (fs.FileInfo, error)  { return r.root.Stat(rel(name)) }
func (r rootFS) Lstat(name string) (fs.FileInfo, error) { return r.root.Lstat(rel(name)) }
func (r rootFS) Readlink(name string) (string, error)   { return r.root.Readlink(rel(name)) }
func (r rootFS) Mkdir(name string, perm fs.FileMode) error {
	return r.root.Mkdir(rel(name), perm)
}
func (r rootFS) Symlink(target, name string) error { return r.root.Symlink(target, rel(name)) }
func (r rootFS) Link(oldname, newname string) error {
	return r.root.Link(rel(oldname), rel(newname))
}
func (r rootFS) Rename(oldname, newname string) error {
	return r.root.Rename(rel(oldname), rel(newname))
}
func (r rootFS) RenameNoReplace(oldname, newname string) error {
	return renameNoReplace(r.root, rel(oldname), rel(newname))
}
func (r rootFS) Remove(name string) error                  { return r.root.Remove(rel(name)) }
func (r rootFS) Chmod(name string, mode fs.FileMode) error { return r.root.Chmod(rel(name), mode) }
func (r rootFS) Chown(name string, uid, gid int) error     { return r.root.Chown(rel(name), uid, gid) }
func (r rootFS) Chtimes(name string, atime, mtime time.Time) error {
	return r.root.Chtimes(rel(name), atime, mtime)
}

// StatVFS answers for files_root's file system whatever the name.
func (r rootFS) StatVFS(string) (*sftp.StatVFS, error) { return statVFS(r.root.Name()) }

func (rootFS) virtualDir(string) ([]fs.FileInfo, bool, error) { return nil, false, nil }

// renamer is the part of an os.Root or a filesFS checkThenRename uses.
type renamer interface {
	Lstat(name string) (fs.FileInfo, error)
	Rename(oldname, newname string) error
}

// checkThenRename renames after checking that the target does not exist; a
// racing create can be replaced.
func checkThenRename(r renamer, from, to string) error {
	if _, err := r.Lstat(to); err == nil {
		return &fs.PathError{Op: "rename", Path: to, Err: fs.ErrExist}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return r.Rename(from, to)
}
