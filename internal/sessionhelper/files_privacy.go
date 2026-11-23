package sessionhelper

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

// FilesServerMode privacy argument values.
const (
	filesPrivacyOn  = "privacy"
	filesPrivacyOff = "full"
)

// ParsePrivacyArg parses privacyArg output; any other value is refused.
func ParsePrivacyArg(v string) (on, ok bool) {
	switch v {
	case filesPrivacyOn:
		return true, true
	case filesPrivacyOff:
		return false, true
	}
	return false, false
}

// privacyFolders are the login's home folders macOS privacy protection (TCC)
// gates for a process without Full Disk Access: Desktop, Documents, Downloads,
// and Library, which holds iCloud Drive, Mail, Messages, Safari and other
// apps' data. Volumes covers removable and network volumes.
var privacyFolders = []string{"Desktop", "Documents", "Downloads", "Library"}

// privacyBundleSuffix names a Photos library, gated wherever it is.
const privacyBundleSuffix = ".photoslibrary"

// maxLinkHops bounds symlink expansion in a privacy walk, as the OS does with
// ELOOP; a deeper chain is left to the operation, which fails the same way.
const maxLinkHops = 40

// privacyGuard identifies the directories a files session without Full Disk
// Access never looks into, so macOS never shows a privacy prompt on the
// device's screen for it.
type privacyGuard struct{ dirs []fs.FileInfo }

// newPrivacyGuard reads the protected directories of the login's home and
// /Volumes. Each read is an lstat in a directory macOS does not gate; a
// folder that does not exist is skipped.
func newPrivacyGuard(home string) privacyGuard {
	var g privacyGuard
	names := []string{"/Volumes"}
	for _, f := range privacyFolders {
		names = append(names, filepath.Join(home, f))
	}
	for _, n := range names {
		if fi, err := os.Lstat(n); err == nil && fi.IsDir() {
			g.dirs = append(g.dirs, fi)
		}
	}
	return g
}

func (g privacyGuard) protected(fi fs.FileInfo) bool {
	if !fi.IsDir() {
		return false
	}
	// APFS is case-insensitive by default.
	if n := fi.Name(); len(n) >= len(privacyBundleSuffix) && strings.EqualFold(n[len(n)-len(privacyBundleSuffix):], privacyBundleSuffix) {
		return true
	}
	for _, d := range g.dirs {
		if os.SameFile(d, fi) {
			return true
		}
	}
	return false
}

// walk resolves name from dir one component at a time with lstat and
// readlink, and refuses with fs.ErrPermission before any lookup inside a
// protected directory. A final protected directory is refused only when use
// is set (the operation opens or changes it); reading its own metadata is a
// lookup in its parent, which macOS does not gate. A final symlink is
// followed only when follow is set. dir is "." for an os.Root, whose
// absolute symlinks fail in the operation itself, or "/" for the real file
// system, where they restart at "/". A component that cannot be read ends
// the walk without a refusal: the operation reports that error.
func (g privacyGuard) walk(lstat func(string) (fs.FileInfo, error), readlink func(string) (string, error), dir, name string, follow, use bool) error {
	todo := strings.Split(name, "/")
	for hops := 0; len(todo) > 0; {
		c := todo[0]
		todo = todo[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			dir = path.Dir(dir)
			continue
		}
		next := path.Join(dir, c)
		fi, err := lstat(next)
		if err != nil {
			return nil
		}
		if fi.Mode()&fs.ModeSymlink != 0 && (len(todo) > 0 || follow) {
			if hops++; hops > maxLinkHops {
				return nil
			}
			target, err := readlink(next)
			if err != nil {
				return nil
			}
			if path.IsAbs(target) {
				if !path.IsAbs(dir) {
					return nil
				}
				dir = "/"
			}
			todo = append(strings.Split(target, "/"), todo...)
			continue
		}
		if (len(todo) > 0 || use) && g.protected(fi) {
			return &fs.PathError{Op: "open", Path: next, Err: fs.ErrPermission}
		}
		dir = next
	}
	return nil
}

// checkRoot refuses a files_root inside or equal to a protected directory:
// opening it would look inside one.
func (g privacyGuard) checkRoot(root string) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	return g.walk(os.Lstat, os.Readlink, "/", filepath.ToSlash(abs), true, true)
}

// privacyFS is rootFS for a macOS files session without Full Disk Access:
// the guard checks every name before the os.Root looks it up. A component
// swapped for a symlink between check and operation can still reach a
// protected directory, but only the login can swap its own files.
type privacyFS struct {
	rootFS
	guard privacyGuard
}

// check walks name; follow and use are walk's.
func (p privacyFS) check(name string, follow, use bool) error {
	return p.guard.walk(p.root.Lstat, p.root.Readlink, ".", rel(name), follow, use)
}

// change checks names an operation creates, removes or renames, without
// following their final symlinks.
func (p privacyFS) change(names ...string) error {
	for _, n := range names {
		if err := p.check(n, false, true); err != nil {
			return err
		}
	}
	return nil
}

func (p privacyFS) OpenFile(name string, flag int, perm fs.FileMode) (*os.File, error) {
	if err := p.check(name, true, true); err != nil {
		return nil, err
	}
	return p.rootFS.OpenFile(name, flag, perm)
}

func (p privacyFS) Stat(name string) (fs.FileInfo, error) {
	if err := p.check(name, true, false); err != nil {
		return nil, err
	}
	return p.rootFS.Stat(name)
}

func (p privacyFS) Lstat(name string) (fs.FileInfo, error) {
	if err := p.check(name, false, false); err != nil {
		return nil, err
	}
	return p.rootFS.Lstat(name)
}

func (p privacyFS) Readlink(name string) (string, error) {
	if err := p.check(name, false, false); err != nil {
		return "", err
	}
	return p.rootFS.Readlink(name)
}

func (p privacyFS) Mkdir(name string, perm fs.FileMode) error {
	if err := p.change(name); err != nil {
		return err
	}
	return p.rootFS.Mkdir(name, perm)
}

func (p privacyFS) Symlink(target, name string) error {
	if err := p.change(name); err != nil {
		return err
	}
	return p.rootFS.Symlink(target, name)
}

func (p privacyFS) Link(oldname, newname string) error {
	if err := p.change(oldname, newname); err != nil {
		return err
	}
	return p.rootFS.Link(oldname, newname)
}

func (p privacyFS) Rename(oldname, newname string) error {
	if err := p.change(oldname, newname); err != nil {
		return err
	}
	return p.rootFS.Rename(oldname, newname)
}

func (p privacyFS) RenameNoReplace(oldname, newname string) error {
	if err := p.change(oldname, newname); err != nil {
		return err
	}
	return p.rootFS.RenameNoReplace(oldname, newname)
}

func (p privacyFS) Remove(name string) error {
	if err := p.change(name); err != nil {
		return err
	}
	return p.rootFS.Remove(name)
}

func (p privacyFS) Chmod(name string, mode fs.FileMode) error {
	if err := p.check(name, true, true); err != nil {
		return err
	}
	return p.rootFS.Chmod(name, mode)
}

func (p privacyFS) Chown(name string, uid, gid int) error {
	if err := p.check(name, true, true); err != nil {
		return err
	}
	return p.rootFS.Chown(name, uid, gid)
}

func (p privacyFS) Chtimes(name string, atime, mtime time.Time) error {
	if err := p.check(name, true, true); err != nil {
		return err
	}
	return p.rootFS.Chtimes(name, atime, mtime)
}

// StatVFS answers for the root's file system, as rootFS does.
func (p privacyFS) StatVFS(name string) (*sftp.StatVFS, error) { return p.rootFS.StatVFS(name) }
