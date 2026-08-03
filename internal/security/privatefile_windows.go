//go:build windows

package security

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows mode bits are synthesised by the Go runtime from the read-only
// attribute, so they report nothing about who may read a file. Access is
// carried by the DACL, which is what is checked here.
//
// The owner, LocalSystem and Administrators are the permitted trustees.
// Administrators stay because they may take ownership of any object regardless,
// so excluding them would deny nothing while breaking every service
// deployment. This is the set Win32 OpenSSH enforces on its own key files.

// openNoFollow opens path without traversing a junction or symlink.
func openNoFollow(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return os.NewFile(uintptr(h), path), nil
}

func verifyPrivate(f *os.File, path string) error {
	h := windows.Handle(f.Fd())

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is a reparse point; credential paths must not be redirected", path)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return fmt.Errorf("%s is a directory, not a regular file", path)
	}
	// The Unix side refuses anything that is not a regular file; this is the
	// Windows half of that rule. A named pipe or a device supplied as `--pem`
	// (`\\.\pipe\...`) opens and reads perfectly well, and carries no DACL of its
	// own to check, so a path that is not a file on disk is refused on shape
	// rather than trusted because the access check happened to pass.
	if ft, err := windows.GetFileType(h); err == nil && ft != windows.FILE_TYPE_DISK {
		return fmt.Errorf("%s is not a regular file", path)
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
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL of %s: %w", path, err)
	}
	// A NULL DACL grants everyone full control.
	if dacl == nil {
		return fmt.Errorf("%s has no DACL, which grants full access to everyone", path)
	}

	// The owner must be us, SYSTEM or Administrators. This is the Windows half of
	// the Unix `st.Uid != euid` check: reading a key from a file somebody else
	// owns is trusting whoever placed it there, which is the thing this file
	// exists to prevent.
	if err := assertOwnerIsTrusted(owner, path); err != nil {
		return err
	}

	allowed, err := allowedTrustees()
	if err != nil {
		return err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d of %s: %w", i, path, err)
		}
		// DENY takes nothing away that matters here, and the audit/alarm types
		// grant nothing. Every other type CAN grant access and is refused rather
		// than skipped, so an unrecognised object-allow ACE cannot read as
		// "no findings".
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, systemAuditACEType, systemAlarmACEType:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !sidIn(sid, allowed) {
				return fmt.Errorf("%s grants access to %s; only its owner, SYSTEM and Administrators may reach a private key",
					path, sid)
			}
		default:
			return fmt.Errorf("%s carries an access-control entry of type %d this check cannot evaluate; refusing rather than assuming it grants nothing",
				path, ace.Header.AceType)
		}
	}
	return nil
}

// x/sys/windows exports only the ALLOWED and DENIED types. These two are from
// winnt.h and are named here so the switch above can pass over them explicitly
// rather than through a default that would also swallow the granting types.
const (
	systemAuditACEType = 2
	systemAlarmACEType = 3
)

// assertOwnerIsTrusted refuses a file owned by another account.
//
// Administrators and SYSTEM are accepted because a service credential is
// legitimately installed by one of them, and because an administrator can take
// ownership of any object regardless, so excluding them would deny nothing and
// would break every service deployment.
func assertOwnerIsTrusted(owner *windows.SID, path string) error {
	trusted, err := allowedTrustees()
	if err != nil {
		return err
	}
	if !sidIn(owner, trusted) {
		return fmt.Errorf("%s is owned by %s, not by this account, SYSTEM or Administrators", path, owner)
	}
	return nil
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read process token: %w", err)
	}
	return user.User.Sid, nil
}

// allowedTrustees is who may own or reach a private key: this account, SYSTEM,
// and Administrators. The set is derived from who WE are, and the file's owner
// is then tested against it.
func allowedTrustees() ([]*windows.SID, error) {
	user, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	allowed := []*windows.SID{user}
	for _, wk := range []windows.WELL_KNOWN_SID_TYPE{
		windows.WinLocalSystemSid,
		windows.WinBuiltinAdministratorsSid,
	} {
		sid, err := windows.CreateWellKnownSid(wk)
		if err != nil {
			return nil, fmt.Errorf("resolve well-known SID: %w", err)
		}
		allowed = append(allowed, sid)
	}
	return allowed, nil
}

func sidIn(sid *windows.SID, set []*windows.SID) bool {
	for _, s := range set {
		if s != nil && sid.Equals(s) {
			return true
		}
	}
	return false
}
