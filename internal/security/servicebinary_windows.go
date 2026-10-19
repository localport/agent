//go:build windows

package security

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Rights that let a trustee replace the entry at a path (winnt.h): DELETE,
// WRITE_DAC, WRITE_OWNER, GENERIC_ALL and GENERIC_WRITE, and on a directory
// FILE_DELETE_CHILD. Adding entries (FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY) is
// not one: it cannot replace the binary, and C:\ grants it to every user.
const binaryReplaceRights windows.ACCESS_MASK = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000

// binaryDataRights are FILE_WRITE_DATA and FILE_APPEND_DATA, which change the
// binary itself.
const binaryDataRights windows.ACCESS_MASK = 0x2 | 0x4

// CheckServiceBinary refuses path, the resolved executable the device service
// runs, unless the file and every directory above it are owned by SYSTEM,
// Administrators or TrustedInstaller and no other trustee holds a right that
// replaces an entry, or on the file itself one that writes its data.
// Inherit-only ACEs are ignored. The invoking user and the service's own
// account are never trusted here, unlike the private file checks.
func CheckServiceBinary(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %s is not an absolute path", ErrUnsafeExecutable, path)
	}
	trusted, err := binaryTrustees()
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	for p := path; ; p = filepath.Dir(p) {
		rights := binaryReplaceRights
		if p == path {
			rights |= binaryDataRights
		}
		if err := checkBinaryEntry(p, p == path, rights, trusted); err != nil {
			return err
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

func binaryTrustees() ([]*windows.SID, error) {
	var trusted []*windows.SID
	for _, wk := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(wk)
		if err != nil {
			return nil, fmt.Errorf("resolve well-known SID: %w", err)
		}
		trusted = append(trusted, sid)
	}
	installer, err := windows.StringToSid(ServiceSID("TrustedInstaller"))
	if err != nil {
		return nil, fmt.Errorf("resolve the TrustedInstaller SID: %w", err)
	}
	return append(trusted, installer), nil
}

// checkBinaryEntry opens path itself, never a reparse point's target, and
// checks its owner and DACL against trusted.
func checkBinaryEntry(path string, leaf bool, rights windows.ACCESS_MASK, trusted []*windows.SID) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	h, err := windows.CreateFile(p,
		windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return fmt.Errorf("%w: %s is a reparse point; resolve it first", ErrUnsafeExecutable, path)
	case leaf && isDir:
		return fmt.Errorf("%w: %s is a directory", ErrUnsafeExecutable, path)
	case !leaf && !isDir:
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafeExecutable, path)
	}

	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read security descriptor of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read owner of %s: %w", path, err)
	}
	if !sidIn(owner, trusted) {
		return fmt.Errorf("%w: %s is owned by %s, not by SYSTEM, Administrators or TrustedInstaller", ErrUnsafeExecutable, path, owner)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL of %s: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("%w: %s has no DACL, which grants full access to everyone", ErrUnsafeExecutable, path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d of %s: %w", i, path, err)
		}
		if ace.Header.AceFlags&inheritOnlyACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, systemAuditACEType, systemAlarmACEType:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if ace.Mask&rights != 0 && !sidIn(sid, trusted) {
				return fmt.Errorf("%w: %s lets %s replace or change it; only SYSTEM, Administrators and TrustedInstaller may", ErrUnsafeExecutable, path, sid)
			}
		default:
			return fmt.Errorf("%w: %s carries an access-control entry of type %d this check cannot evaluate", ErrUnsafeExecutable, path, ace.Header.AceType)
		}
	}
	return nil
}
