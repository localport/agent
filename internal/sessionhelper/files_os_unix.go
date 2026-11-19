//go:build unix

package sessionhelper

import (
	"io/fs"
	"os"
)

// On Unix a client path is the OS path: "/" is the real root.

func osPath(name string, _ bool) (string, error)      { return name, nil }
func osClientPath(dir string) (string, error)         { return dir, nil }
func osClientName(p string) string                    { return p }
func osVirtualRoot(string) bool                       { return false }
func osVirtualEntries() ([]fs.FileInfo, error)        { return nil, nil }
func osLinkTarget(target string) (string, error)      { return target, nil }
func osClientTarget(_, target string) (string, error) { return target, nil }

// osRenamer is checkThenRename over OS paths.
type osRenamer struct{}

func (osRenamer) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(name) }
func (osRenamer) Rename(oldname, newname string) error   { return os.Rename(oldname, newname) }
