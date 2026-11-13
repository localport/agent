//go:build !windows

package security

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

// CheckPackageManagerBinary is CheckServiceBinary's Windows companion; no
// package manager root is refused here, as the ownership rule already refuses
// a user-owned Homebrew prefix.
func CheckPackageManagerBinary(string) error { return nil }

// CheckServiceBinary refuses path, the resolved executable the device service
// runs, unless the file and every directory above it are owned by root and
// writable by nobody else: no other-write bit, and a group-write bit only for
// gid 0 or, on Linux, the group named staff, which Debian documents as
// root-equivalent through /usr/local. macOS admin group write is refused.
// path must have no symlinks left (filepath.EvalSymlinks).
func CheckServiceBinary(path string) error {
	if !filepath.IsAbs(path) {
		return ErrUnsafeExecutable.With(nil, fmt.Sprintf("%s is not an absolute path", path))
	}
	path = filepath.Clean(path)
	for p := path; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", p, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("inspect %s: the file system reports no owner", p)
		}
		if err := checkRootOnly(binaryEntry{path: p, mode: fi.Mode(), uid: uint32(st.Uid), gid: uint32(st.Gid), leaf: p == path}, runtime.GOOS, groupName); err != nil {
			return err
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

// binaryEntry is the service binary or one of its ancestor directories.
type binaryEntry struct {
	path     string
	mode     fs.FileMode
	uid, gid uint32
	leaf     bool
}

// checkRootOnly is CheckServiceBinary's rule for one entry. groupName
// resolves a gid for the Linux staff exception.
func checkRootOnly(e binaryEntry, goos string, groupName func(gid uint32) (string, error)) error {
	switch {
	case e.leaf && !e.mode.IsRegular():
		return ErrUnsafeExecutable.With(nil, fmt.Sprintf("%s is not a regular file", e.path))
	case !e.leaf && !e.mode.IsDir():
		return ErrUnsafeExecutable.With(nil, fmt.Sprintf("%s is not a directory; resolve symlinks first", e.path))
	case e.uid != 0:
		return ErrUnsafeExecutable.With(nil, fmt.Sprintf("%s is owned by uid %d, not root", e.path, e.uid))
	case e.mode&0o002 != 0:
		return ErrUnsafeExecutable.With(nil, fmt.Sprintf("every user can write to %s", e.path))
	case e.mode&0o020 == 0 || e.gid == 0:
		return nil
	}
	name, err := groupName(e.gid)
	if err != nil {
		return ErrUnsafeExecutable.With(err, fmt.Sprintf("%s is writable by group %d, whose name cannot be read", e.path, e.gid))
	}
	if goos == "linux" && name == "staff" {
		return nil
	}
	return ErrUnsafeExecutable.With(nil, fmt.Sprintf("group %s can write to %s", name, e.path))
}

func groupName(gid uint32) (string, error) {
	g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		return "", err
	}
	return g.Name, nil
}
