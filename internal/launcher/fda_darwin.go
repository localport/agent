package launcher

import (
	"errors"
	"io/fs"
	"os"
)

// tccDatabase is readable only by a process holding Full Disk Access.
const tccDatabase = "/Library/Application Support/com.apple.TCC/TCC.db"

// ReadFullDiskAccess reports whether this process holds Full Disk Access, by
// opening a file TCC protects for every process without it. Without the
// grant, tccd logs one denial per call; the launcher reads it once per
// session request and the revocation checks once per interval.
func ReadFullDiskAccess() string {
	f, err := os.Open(tccDatabase)
	switch {
	case err == nil:
		_ = f.Close()
		return FullDiskAccessGranted
	case errors.Is(err, fs.ErrPermission):
		return FullDiskAccessDenied
	}
	return FullDiskAccessUnknown
}
