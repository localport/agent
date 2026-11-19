//go:build windows

package sessionhelper

import (
	"io/fs"
	"os"
	"syscall"
	"unsafe"

	"github.com/pkg/sftp"
	"golang.org/x/sys/windows"
)

// openNonblock has no Windows counterpart; opens do not block on a pipe or
// device name: inside a root os.Root resolves it as a file path, and without
// one winPath refuses UNC and device paths and DOS device names.
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

var procNtQueryVolumeInformationFile = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryVolumeInformationFile")

// fileFsFullSizeInformation is FILE_FS_FULL_SIZE_INFORMATION, information
// class 7 (FileFsFullSizeInformation).
type fileFsFullSizeInformation struct {
	TotalAllocationUnits           int64
	CallerAvailableAllocationUnits int64
	ActualAvailableAllocationUnits int64
	SectorsPerAllocationUnit       uint32
	BytesPerSector                 uint32
}

const fileFsFullSizeInformationClass = 7

// statVFS reports the volume holding name's data, as statvfs(2) does: name
// is opened as the login, following symlinks, junctions and mounted folders.
// Bavail is the login's quota. Windows has no inode counts.
func statVFS(name string) (*sftp.StatVFS, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, &fs.PathError{Op: "statvfs", Path: name, Err: err}
	}
	// FILE_FLAG_BACKUP_SEMANTICS opens a directory; without
	// FILE_FLAG_OPEN_REPARSE_POINT the open follows reparse points.
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "statvfs", Path: name, Err: err}
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var iosb windows.IO_STATUS_BLOCK
	var info fileFsFullSizeInformation
	status, _, _ := procNtQueryVolumeInformationFile.Call(uintptr(h), uintptr(unsafe.Pointer(&iosb)),
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), fileFsFullSizeInformationClass)
	if st := windows.NTStatus(status); st != windows.STATUS_SUCCESS {
		return nil, &fs.PathError{Op: "statvfs", Path: name, Err: st.Errno()}
	}
	unit := uint64(info.SectorsPerAllocationUnit) * uint64(info.BytesPerSector)
	return &sftp.StatVFS{
		Bsize: unit, Frsize: unit, Blocks: uint64(info.TotalAllocationUnits),
		Bfree: uint64(info.ActualAvailableAllocationUnits), Bavail: uint64(info.CallerAvailableAllocationUnits),
		Namemax: 255,
	}, nil
}
