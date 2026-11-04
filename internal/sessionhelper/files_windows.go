//go:build windows

package sessionhelper

import (
	"io/fs"
	"os"
	"syscall"

	"github.com/pkg/sftp"
	"golang.org/x/sys/windows"
)

// openNonblock has no Windows counterpart; opens do not block on a pipe name
// inside a root, which os.Root resolves as a file path.
const openNonblock = 0

// checkOpened refuses a handle that is not a disk file (a pipe, a console, a
// device), as Win32-OpenSSH's fileio does.
func checkOpened(f *os.File) error {
	t, err := windows.GetFileType(windows.Handle(f.Fd()))
	if err != nil {
		return err
	}
	if t != windows.FILE_TYPE_DISK {
		return &fs.PathError{Op: "open", Path: f.Name(), Err: syscall.EACCES}
	}
	return nil
}

// statVFS reports dir's volume in 4 KiB blocks; Windows has no inode counts.
func statVFS(dir string) (*sftp.StatVFS, error) {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return nil, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(name, &avail, &total, &free); err != nil {
		return nil, err
	}
	const block = 4096
	return &sftp.StatVFS{
		Bsize: block, Frsize: block, Blocks: total / block, Bfree: free / block, Bavail: avail / block, Namemax: 255,
	}, nil
}
