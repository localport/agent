//go:build windows

package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Rights that let a trustee replace the entry at a path (winnt.h): DELETE,
// WRITE_DAC, WRITE_OWNER, GENERIC_ALL and GENERIC_WRITE, and on a directory
// FILE_DELETE_CHILD.
const binaryReplaceRights windows.ACCESS_MASK = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000

// binaryDataRights are FILE_WRITE_DATA and FILE_APPEND_DATA, which change the
// binary itself.
const binaryDataRights windows.ACCESS_MASK = 0x2 | 0x4

// binaryDirAddRights are FILE_ADD_FILE and FILE_ADD_SUBDIRECTORY (the same
// bits as binaryDataRights, read on a directory). On the binary's own
// directory they let a trustee plant a DLL the loader finds first or an
// <exe>.local redirection directory, so they count there. Above it they do
// not: C:\ grants both to every user, and they replace nothing there.
const binaryDirAddRights windows.ACCESS_MASK = 0x2 | 0x4

// CheckPackageManagerBinary refuses path, the resolved executable the device
// service would run, when winget (portable package) or Scoop installed it,
// with ErrPackageManagerExecutable naming the manager. Scoop's roots are its
// SCOOP and SCOOP_GLOBAL settings and their defaults, %USERPROFILE%\scoop and
// %ProgramData%\scoop.
func CheckPackageManagerBinary(path string) error {
	roots := []string{os.Getenv("SCOOP"), os.Getenv("SCOOP_GLOBAL")}
	if home := os.Getenv("USERPROFILE"); home != "" {
		roots = append(roots, filepath.Join(home, "scoop"))
	}
	if data := os.Getenv("ProgramData"); data != "" {
		roots = append(roots, filepath.Join(data, "scoop"))
	}
	if manager := packageManagerOf(path, roots); manager != "" {
		return fmt.Errorf("%w: %s installed %s", ErrPackageManagerExecutable, manager, path)
	}
	return nil
}

// CheckServiceBinary refuses path, the resolved executable the device service
// runs, unless the file and every directory above it are owned by SYSTEM,
// Administrators or TrustedInstaller and no other trustee holds a right that
// replaces an entry, on the file itself one that writes its data, or on its
// directory one that adds an entry.
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
		switch p {
		case path:
			rights |= binaryDataRights
		case filepath.Dir(path):
			rights |= binaryDirAddRights
		}
		if err := checkBinaryEntry(p, p == path, rights, trusted); err != nil {
			return err
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

// CheckServiceDir is CheckServiceBinary for the directory a service binary
// will be installed in: dir with the add rights and every directory above it
// with the replace rights, so a binary placed there passes the binary rule.
func CheckServiceDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: %s is not an absolute path", ErrUnsafeExecutable, dir)
	}
	trusted, err := binaryTrustees()
	if err != nil {
		return err
	}
	dir = filepath.Clean(dir)
	for p := dir; ; p = filepath.Dir(p) {
		rights := binaryReplaceRights
		if p == dir {
			rights |= binaryDirAddRights
		}
		if err := checkBinaryEntry(p, false, rights, trusted); err != nil {
			return err
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

// installDirSDDL is a new install directory's descriptor, as Program Files
// grants: owner Administrators, SYSTEM and Administrators full, Users read
// and execute, all inherited.
const installDirSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

// EnsureInstallDir creates dir with installDirSDDL when it is missing; an
// existing directory is left as it is for CheckServiceDir to judge. Its
// parent must exist.
func EnsureInstallDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(installDirSDDL)
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return nil
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
