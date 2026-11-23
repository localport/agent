package sessionhelper

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
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

// privacyFolders are the home folders macOS privacy protection (TCC) gates
// for a process without Full Disk Access; Library holds iCloud Drive, Mail,
// Messages and Safari data.
var privacyFolders = []string{"Desktop", "Documents", "Downloads", "Library"}

// privacyBundleSuffix names a Photos library, gated wherever it is.
const privacyBundleSuffix = ".photoslibrary"

// maxLinkHops caps the symlinks one walk follows, like the kernel's ELOOP
// limit. A longer chain is left for the operation to fail.
const maxLinkHops = 40

// privacyGuard holds the directories a files session without Full Disk
// Access never looks into, so macOS shows no privacy prompt.
type privacyGuard struct {
	users fs.FileInfo   // <top>/Users; nil when missing
	dirs  []fs.FileInfo // /Volumes, /Network, the login's home folders
}

var errHomeNotAbsolute = errors.New("home is not an absolute path")

// privacyTop is the system root the session guards; tests replace it.
var privacyTop = "/"

func systemPrivacyGuard(home string) (privacyGuard, error) { return newPrivacyGuard(privacyTop, home) }

// newPrivacyGuard guards top/Volumes, top/Network, the four folders of each
// home in top/Users and of home. A relative home returns errHomeNotAbsolute.
// A home inside a protected directory returns fs.ErrPermission and a guard
// without its folders; nothing inside home is looked up.
func newPrivacyGuard(top, home string) (privacyGuard, error) {
	var g privacyGuard
	if !filepath.IsAbs(home) {
		return g, fmt.Errorf("%w: %q", errHomeNotAbsolute, home)
	}
	if fi, err := os.Lstat(filepath.Join(top, "Users")); err == nil && fi.IsDir() {
		g.users = fi
	}
	g.addDirs(filepath.Join(top, "Volumes"), filepath.Join(top, "Network"))
	if _, err := g.checkRoot(home); err != nil {
		return g, err
	}
	for _, f := range privacyFolders {
		g.addDirs(filepath.Join(home, f))
	}
	return g, nil
}

// addDirs guards each name that is a directory.
func (g *privacyGuard) addDirs(names ...string) {
	for _, n := range names {
		if fi, err := os.Lstat(n); err == nil && fi.IsDir() {
			g.dirs = append(g.dirs, fi)
		}
	}
}

// protected reports whether directory fi, reached through parents, is gated.
// Case-insensitive names match APFS defaults.
func (g privacyGuard) protected(fi fs.FileInfo, parents []fs.FileInfo) bool {
	if !fi.IsDir() {
		return false
	}
	n := fi.Name()
	if len(n) >= len(privacyBundleSuffix) && strings.EqualFold(n[len(n)-len(privacyBundleSuffix):], privacyBundleSuffix) {
		return true
	}
	if g.users != nil && len(parents) >= 2 && os.SameFile(parents[len(parents)-2], g.users) &&
		slices.ContainsFunc(privacyFolders, func(f string) bool { return strings.EqualFold(f, n) }) {
		return true
	}
	for _, d := range g.dirs {
		if os.SameFile(d, fi) {
			return true
		}
	}
	return false
}

// walk resolves name from dir one component at a time and returns
// fs.ErrPermission before any lookup inside a protected directory. A final
// protected directory is refused only with use (open or change); its metadata
// lives in the parent. dir is "." for an os.Root (an absolute symlink fails)
// or "/" (it restarts at "/"). base lists the directories from "/" down to
// dir; walk returns it extended with the directories it entered and never
// modifies it. If a component cannot be read, walk stops without refusing and
// the operation reports the error.
func (g privacyGuard) walk(lstat func(string) (fs.FileInfo, error), readlink func(string) (string, error), dir string, base []fs.FileInfo, name string, follow, use bool) ([]fs.FileInfo, error) {
	parents := slices.Clip(base)
	todo := strings.Split(name, "/")
	for hops := 0; len(todo) > 0; {
		c := todo[0]
		todo = todo[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			dir = path.Dir(dir)
			if len(parents) > len(base) {
				parents = parents[:len(parents)-1]
			}
			continue
		}
		next := path.Join(dir, c)
		fi, err := lstat(next)
		if err != nil {
			return parents, nil
		}
		if fi.Mode()&fs.ModeSymlink != 0 && (len(todo) > 0 || follow) {
			if hops++; hops > maxLinkHops {
				return parents, nil
			}
			target, err := readlink(next)
			if err != nil {
				return parents, nil
			}
			if path.IsAbs(target) {
				if !path.IsAbs(dir) {
					return parents, nil
				}
				dir, parents = "/", parents[:1]
			}
			todo = append(strings.Split(target, "/"), todo...)
			continue
		}
		if (len(todo) > 0 || use) && g.protected(fi, parents) {
			return parents, &fs.PathError{Op: "open", Path: next, Err: fs.ErrPermission}
		}
		dir, parents = next, append(parents, fi)
	}
	return parents, nil
}

// rootBase is walk's base for "/".
var rootBase = []fs.FileInfo{nil}

// checkRoot refuses a files_root inside or equal to a protected directory and
// returns its directories, privacyFS's base. root is not cleaned first, so
// ".." after a symlink starts from the link's target, as in open(2).
func (g privacyGuard) checkRoot(root string) ([]fs.FileInfo, error) {
	abs := root
	if !filepath.IsAbs(root) {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		abs = wd + string(filepath.Separator) + root
	}
	return g.walk(os.Lstat, os.Readlink, "/", rootBase, filepath.ToSlash(abs), true, true)
}

// privacyFS is rootFS for a macOS files session without Full Disk Access; the
// guard checks every name before the os.Root looks it up. A symlink created
// between the check and the operation can still reach a protected directory,
// but only in a folder the login can write.
type privacyFS struct {
	rootFS
	guard privacyGuard
	base  []fs.FileInfo // the root's directories from checkRoot
}

// check walks name; follow and use are walk's.
func (p privacyFS) check(name string, follow, use bool) error {
	_, err := p.guard.walk(p.root.Lstat, p.root.Readlink, ".", p.base, rel(name), follow, use)
	return err
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
