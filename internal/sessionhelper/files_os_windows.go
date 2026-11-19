package sessionhelper

import (
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows hooks of osFS: the grammar of files_winpath.go over the drives
// Win32-OpenSSH lists (GetLogicalDriveStringsW minus unknown, no-root-dir
// and RAM disks).

// driveServed reports whether the logical drive letter (upper case) is one
// the virtual top lists.
func driveServed(mask uint32, letter byte) bool {
	if mask&(1<<(letter-'A')) == 0 {
		return false
	}
	root, err := windows.UTF16PtrFromString(string(letter) + `:\`)
	if err != nil {
		return false
	}
	switch windows.GetDriveType(root) {
	case windows.DRIVE_UNKNOWN, windows.DRIVE_NO_ROOT_DIR, windows.DRIVE_RAMDISK:
		return false
	}
	return true
}

func driveListed(letter byte) bool {
	mask, err := windows.GetLogicalDrives()
	return err == nil && driveServed(mask, letter)
}

var procRtlIsDosDeviceNameU = windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlIsDosDeviceName_U")

// deviceNamed reports whether seg names a DOS device: a reserved name alone
// always, with an extension ("nul.txt") only where this kernel still treats
// it as the device (before Windows 11), as RtlIsDosDeviceName_U answers.
func deviceNamed(seg string) bool {
	reserved, exact := reservedDeviceBase(seg)
	if !reserved || exact {
		return reserved
	}
	p, err := windows.UTF16PtrFromString(seg)
	if err != nil {
		return true
	}
	r, _, _ := procRtlIsDosDeviceNameU.Call(uintptr(unsafe.Pointer(p)))
	return r != 0
}

var hostWinOS = winOS{listed: driveListed, device: deviceNamed}

func osPath(name string, write bool) (string, error) { return winPath(name, write, hostWinOS) }
func osClientPath(dir string) (string, error)        { return winClientPath(dir) }
func osClientName(p string) string                   { return winClientName(p) }
func osVirtualRoot(name string) bool                 { return name == "/" }
func osLinkTarget(target string) (string, error)     { return winLinkTarget(target, hostWinOS) }
func osClientTarget(link, target string) (string, error) {
	return winClientTarget(link, target)
}

// osVirtualEntries lists the served drives as "c:", "d:" and so on.
func osVirtualEntries() ([]fs.FileInfo, error) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: "/", Err: err}
	}
	var out []fs.FileInfo
	for letter := byte('A'); letter <= 'Z'; letter++ {
		if driveServed(mask, letter) {
			out = append(out, virtualDirInfo(string(letter-'A'+'a')+":"))
		}
	}
	return out, nil
}

// osRenameNoReplace renames the OS path from to to; MoveFileEx without
// MOVEFILE_REPLACE_EXISTING refuses an existing target atomically.
func osRenameNoReplace(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	if err := windows.MoveFileEx(f, t, 0); err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}
