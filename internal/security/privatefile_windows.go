//go:build windows

package security

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the Go runtime derives mode bits from the read-only attribute, so
// they do not describe access. Access is controlled by the DACL, which is set
// at creation. Setting it afterwards would leave the key with inherited access
// for a moment, which matters under the user-writable %PROGRAMDATA%.
//
// Permitted trustees are the owner, LocalSystem and Administrators, the set
// Win32 OpenSSH enforces, plus the device service SID under the device
// identity directory (allowedTrustees). Administrators can take ownership of any object.

// openNoFollow opens path without traversing a junction or symlink.
func openNoFollow(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
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
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

func createPrivate(path string) (*os.File, error) {
	sa, err := privateSecurityAttributes(path, false)
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

// inspectPrivateDir opens path with FILE_FLAG_BACKUP_SEMANTICS, plus
// FILE_FLAG_OPEN_REPARSE_POINT unless follow, and checks on the handle that it
// is a directory, not a reparse point, owned by a trustee allowedTrustees
// returns for path. With secure it creates a missing directory and sets the
// protected DACL on the same handle. Without secure it changes nothing and
// refuses a DACL that lets another trustee write to the directory.
func inspectPrivateDir(path string, follow, secure bool) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return &fs.PathError{Op: "inspect", Path: path, Err: err}
	}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	if secure {
		sa, err := privateSecurityAttributes(path, true)
		if err != nil {
			return err
		}
		if err := windows.CreateDirectory(p, sa); err != nil && err != windows.ERROR_ALREADY_EXISTS {
			return &fs.PathError{Op: "create", Path: path, Err: err}
		}
		access |= windows.WRITE_DAC
	}

	// FILE_FLAG_OPEN_REPARSE_POINT opens a junction itself, so SetSecurityInfo
	// can never reach its target.
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS)
	if !follow {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	h, err := windows.CreateFile(p,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0)
	if err != nil {
		return &fs.PathError{Op: "open", Path: path, Err: err}
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return &fs.PathError{Op: "inspect", Path: path, Err: err}
	}
	if !follow && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("%s is a reparse point; credential paths must not be redirected", path))
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("%s is not a directory", path))
	}

	current, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return &fs.PathError{Op: "read security descriptor of", Path: path, Err: err}
	}
	owner, _, err := current.Owner()
	if err != nil {
		return &fs.PathError{Op: "read owner of", Path: path, Err: err}
	}
	if err := assertOwnerIsTrusted(owner, path); err != nil {
		return err
	}
	if !secure {
		dacl, _, err := current.DACL()
		if err != nil {
			return &fs.PathError{Op: "read DACL of", Path: path, Err: err}
		}
		return assertNoForeignWriter(dacl, path)
	}

	sd, err := privateSecurityDescriptor(path, true)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return &fs.PathError{Op: "read DACL for", Path: path, Err: err}
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return &fs.PathError{Op: "secure", Path: path, Err: err}
	}
	return nil
}

// openLockNoFollow opens or creates path with FILE_FLAG_OPEN_REPARSE_POINT and
// refuses a reparse point or directory from the handle attributes, so there is
// no window between check and use.
func openLockNoFollow(path string) (*os.File, error) {
	sa, err := privateSecurityAttributes(path, false)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		sa,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0)
	if err != nil {
		// without FILE_FLAG_BACKUP_SEMANTICS a directory or junction fails
		// with ERROR_ACCESS_DENIED. The open already failed, Lstat only
		// names the cause.
		if fi, lErr := os.Lstat(path); lErr == nil && (fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0) {
			return nil, ErrUntrustedPath.With(nil, fmt.Sprintf("%s is not a regular file of its own", path))
		}
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return nil, &fs.PathError{Op: "inspect", Path: path, Err: err}
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = windows.CloseHandle(h)
		return nil, ErrUntrustedPath.With(nil, fmt.Sprintf("%s is not a regular file of its own", path))
	}
	return os.NewFile(uintptr(h), path), nil
}

func verifyPrivate(f *os.File, path string) error {
	h := windows.Handle(f.Fd())

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return &fs.PathError{Op: "inspect", Path: path, Err: err}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("%s is a reparse point; credential paths must not be redirected", path))
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("%s is a directory, not a regular file", path))
	}
	// Refuse anything that is not a regular disk file, as on Unix. A named
	// pipe or device such as `\\.\pipe\...` opens and reads but has no DACL to
	// check.
	ft, err := windows.GetFileType(h)
	if err != nil {
		return ErrUntrustedPath.With(err, fmt.Sprintf("cannot read the file type of %s", path))
	}
	if ft != windows.FILE_TYPE_DISK {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("%s is not a regular file", path))
	}

	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return &fs.PathError{Op: "read security descriptor of", Path: path, Err: err}
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return &fs.PathError{Op: "read owner of", Path: path, Err: err}
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return &fs.PathError{Op: "read DACL of", Path: path, Err: err}
	}
	// A NULL DACL grants everyone full control.
	if dacl == nil {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("%s has no DACL, which grants full access to everyone", path))
	}

	// The owner must be a trustee allowedTrustees returns for path, matching
	// the Unix `st.Uid != euid` check.
	if err := assertOwnerIsTrusted(owner, path); err != nil {
		return err
	}

	allowed, err := allowedTrustees(path)
	if err != nil {
		return err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return &fs.PathError{Op: fmt.Sprintf("read ACE %d of", i), Path: path, Err: err}
		}
		// Deny, audit and alarm ACEs grant nothing. Any other type may grant
		// access and is refused, including unrecognized ones.
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, systemAuditACEType, systemAlarmACEType:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !sidIn(sid, allowed) {
				return ErrUntrustedPath.With(nil, fmt.Sprintf("%s grants access to %s; only this account, SYSTEM, Administrators and, under the device identity directory, NT SERVICE\\localport-device may reach a private key",
					path, sid))

			}
		default:
			return ErrUntrustedPath.With(nil, fmt.Sprintf("%s carries an access-control entry of type %d this check cannot evaluate; refusing rather than assuming it grants nothing",
				path, ace.Header.AceType))

		}
	}
	return nil
}

// directoryWriteRights are the access rights that let a trustee add, replace
// or delete entries in a directory, or change who may. Values from winnt.h:
// FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_WRITE_EA, FILE_DELETE_CHILD,
// FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL and
// GENERIC_WRITE.
const directoryWriteRights windows.ACCESS_MASK = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 |
	0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000

// inheritOnlyACE marks an ACE that applies to children only (winnt.h).
const inheritOnlyACE = 0x08

// assertNoForeignWriter is the Windows form of the Unix group/other-write
// check on a directory: no allow ACE may grant write rights on the directory
// itself to anyone but the trustees allowedTrustees returns.
func assertNoForeignWriter(dacl *windows.ACL, path string) error {
	if dacl == nil {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("%s has no DACL, which grants full access to everyone", path))
	}
	allowed, err := allowedTrustees(path)
	if err != nil {
		return err
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return &fs.PathError{Op: fmt.Sprintf("read ACE %d of", i), Path: path, Err: err}
		}
		// An inherit-only ACE applies to children, not to this directory.
		if ace.Header.AceFlags&inheritOnlyACE != 0 {
			continue
		}
		// As in verifyPrivate: deny, audit and alarm ACEs grant nothing, and
		// any other type than a plain allow is refused unevaluated.
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, systemAuditACEType, systemAlarmACEType:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if ace.Mask&directoryWriteRights != 0 && !sidIn(sid, allowed) {
				return ErrUntrustedPath.With(nil, fmt.Sprintf("%s lets %s write to it; only this account, SYSTEM, Administrators and, under the device identity directory, NT SERVICE\\localport-device may", path, sid))
			}
		default:
			return ErrUntrustedPath.With(nil, fmt.Sprintf("%s carries an access-control entry of type %d this check cannot evaluate; refusing rather than assuming it grants nothing",
				path, ace.Header.AceType))

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
	trusted, err := allowedTrustees(path)
	if err != nil {
		return err
	}
	if !sidIn(owner, trusted) {
		return ErrUntrustedPath.With(errForeignOwner, fmt.Sprintf("%s is owned by %s, not by this account, SYSTEM, Administrators or, under the device identity directory, NT SERVICE\\localport-device", path, owner))
	}
	return nil
}

func privateSecurityAttributes(path string, dir bool) (*windows.SecurityAttributes, error) {
	sd, err := privateSecurityDescriptor(path, dir)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

// privateSecurityDescriptor builds a protected DACL granting full access to
// the current user, LocalSystem and Administrators, and to nobody else. `P`
// marks it protected, so nothing is inherited from the parent directory.
//
// A directory's entries are inherited by its files and subdirectories (OICI).
// Setting the DACL propagates to existing children that are not protected,
// and without inheritable entries that would leave each of them an empty
// DACL, reachable by nobody.
//
// For a path under the device identity directory, a privileged process grants
// the device service's virtual account instead of its own user, so the
// elevated Administrator that runs connect and the service that runs the
// renewer can each read and replace what the other wrote. An elevated process
// also names Administrators as the owner there, which the service accepts;
// the service cannot assign an owner but itself.
func privateSecurityDescriptor(path string, dir bool) (*windows.SECURITY_DESCRIPTOR, error) {
	t, err := currentTrust()
	if err != nil {
		return nil, err
	}
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	grantee, owner := t.user, ""
	if t.servesIdentityDir(path) {
		grantee = t.service
		if t.elevated {
			owner = "O:BA"
		}
	}
	sddl := fmt.Sprintf("%[1]sD:P(A;%[2]s;FA;;;%[3]s)(A;%[2]s;FA;;;SY)(A;%[2]s;FA;;;BA)", owner, inherit, grantee)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build security descriptor: %w", err)
	}
	return sd, nil
}

// processTrust is what decides which trustees this process accepts.
type processTrust struct {
	user     *windows.SID
	service  *windows.SID
	elevated bool
}

// privileged reports a process that uses the machine-wide root: an elevated
// Administrator or the device service's virtual account.
func (t processTrust) privileged() bool { return t.elevated || t.user.Equals(t.service) }

// servesIdentityDir reports whether the service's virtual account is
// trusted for path: only a privileged process, and only under the device
// identity directory, so the service SID never widens a check elsewhere. The
// rest of the device directory holds system files (systemfile_windows.go).
func (t processTrust) servesIdentityDir(path string) bool {
	return t.privileged() && underIdentityDir(path, os.Getenv("ProgramData"))
}

// underIdentityDir reports whether path is
// %ProgramData%\localport-device\identity or below it, compared
// case-insensitively as NTFS does.
func underIdentityDir(path, programData string) bool {
	programData = strings.TrimSpace(programData)
	if programData == "" || !filepath.IsAbs(path) {
		return false
	}
	root := filepath.Join(programData, DeviceDirName, "identity")
	p := filepath.Clean(path)
	if len(p) < len(root) || !strings.EqualFold(p[:len(root)], root) {
		return false
	}
	return len(p) == len(root) || p[len(root)] == filepath.Separator
}

func currentTrust() (processTrust, error) {
	user, err := currentUserSID()
	if err != nil {
		return processTrust{}, err
	}
	service, err := windows.StringToSid(ServiceSID(WindowsServiceName))
	if err != nil {
		return processTrust{}, fmt.Errorf("resolve the device service SID: %w", err)
	}
	return processTrust{user: user, service: service, elevated: windows.GetCurrentProcessToken().IsElevated()}, nil
}

func currentUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read process token: %w", err)
	}
	return user.User.Sid, nil
}

// allowedTrustees returns the SIDs that may own or access the private file
// or directory at path: this account, SYSTEM and Administrators, and for a
// privileged process under the device identity directory also the device
// service's virtual account NT SERVICE\localport-device.
func allowedTrustees(path string) ([]*windows.SID, error) {
	t, err := currentTrust()
	if err != nil {
		return nil, err
	}
	allowed := []*windows.SID{t.user}
	if t.servesIdentityDir(path) {
		allowed = append(allowed, t.service)
	}
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
