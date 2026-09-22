//go:build windows

package security

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the Go runtime derives mode bits from the read-only attribute, so
// they do not describe access. Access is controlled by the DACL, which is set
// at creation. Setting it afterwards would leave the key with inherited access
// for a moment, which matters under the user-writable %PROGRAMDATA%.
//
// Permitted trustees are the owner, LocalSystem and Administrators, the same
// set Win32 OpenSSH enforces. Administrators can take ownership of any object.

// openNoFollow opens path without traversing a junction or symlink.
func openNoFollow(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	// FILE_SHARE_DELETE lets WritePrivateFileAtomic rename over this path
	// while it is open. Without it the rename fails with "Access is denied".
	// Replacing the file still requires the rights the DACL grants.
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return os.NewFile(uintptr(h), path), nil
}

func createPrivate(path string) (*os.File, error) {
	sa, err := privateSecurityAttributes()
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_WRITE,
		0,
		sa,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func mkdirPrivate(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", path, err)
	}
	if info, err := os.Stat(abs); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", abs)
		}
		return setPrivateDACL(abs)
	}
	if parent := filepath.Dir(abs); parent != abs {
		if _, err := os.Stat(parent); os.IsNotExist(err) {
			if err := mkdirPrivate(parent); err != nil {
				return err
			}
		}
	}

	sa, err := privateSecurityAttributes()
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(p, sa); err != nil {
		return fmt.Errorf("create %s: %w", abs, err)
	}
	return nil
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
	// Refuse anything that is not a regular disk file, as on Unix. A named
	// pipe or device such as `\\.\pipe\...` opens and reads but has no DACL to
	// check.
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

	// The owner must be this account, SYSTEM or Administrators, matching the
	// Unix `st.Uid != euid` check.
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
		// Deny, audit and alarm ACEs grant nothing. Any other type may grant
		// access and is refused, including unrecognized ones.
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

// setPrivateDACL applies the protected DACL to an existing directory through
// an open handle, so the path cannot be swapped between check and use.
// FILE_FLAG_OPEN_REPARSE_POINT opens a junction itself, so a planted junction
// cannot redirect the DACL to another directory.
func setPrivateDACL(path string) error {
	sd, err := privateSecurityDescriptor()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL for %s: %w", path, err)
	}

	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("secure %s: %w", path, err)
	}
	h, err := windows.CreateFile(p,
		windows.WRITE_DAC|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer windows.CloseHandle(h)

	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("secure %s: %w", path, err)
	}
	return nil
}

func privateSecurityAttributes() (*windows.SecurityAttributes, error) {
	sd, err := privateSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

// privateSecurityDescriptor builds a protected DACL granting full access to the
// current user, LocalSystem and Administrators, and to nobody else. `P` marks
// it protected, so nothing is inherited from the parent directory.
func privateSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	sddl := fmt.Sprintf("D:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", user)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build security descriptor: %w", err)
	}
	return sd, nil
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read process token: %w", err)
	}
	return user.User.Sid, nil
}

// allowedTrustees returns the SIDs that may own or access a private key, this
// account, SYSTEM and Administrators.
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

// isRedirect reports whether a directory entry is a reparse point such as a
// symlink or junction.
//
// It tests FILE_ATTRIBUTE_REPARSE_POINT because Go sets os.ModeSymlink only
// for IO_REPARSE_TAG_SYMLINK and reports a junction as ModeIrregular. Creating
// a junction needs only write access to the parent directory.
func isRedirect(info os.FileInfo) bool {
	if d, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
	}
	// Without attribute data, treat the entry as a redirect.
	return true
}
