//go:build windows

package security

import "golang.org/x/sys/windows"

// syncDir flushes the directory through a handle opened for writing with
// FILE_FLAG_BACKUP_SEMANTICS; os.Open opens it read-only, which
// FlushFileBuffers refuses.
func syncDir(dir string) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return
	}
	_ = windows.FlushFileBuffers(h)
	_ = windows.CloseHandle(h)
}
