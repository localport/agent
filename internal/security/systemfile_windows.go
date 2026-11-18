//go:build windows

package security

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the system files are the device config directory and the files
// in it that SYSTEM and Administrators write and the device service's virtual
// account NT SERVICE\localport-device only reads or locks: every one is
// owned by Administrators (or SYSTEM) under a protected DACL. The service
// reads the directory and agent.yaml, reads and writes run.lock, and cannot
// reach agent.yaml.lock; it owns only identity\ (privatefile_windows.go).
// Every check runs on a handle opened without following a reparse point.

const (
	// SystemRunLockPerm selects the run.lock DACL: the service reads and
	// writes it, so it can lock it and record its PID.
	SystemRunLockPerm os.FileMode = 0o660
	// SystemConfigLockPerm selects the agent.yaml.lock DACL: SYSTEM and
	// Administrators only.
	SystemConfigLockPerm os.FileMode = 0o600
)

// AgentGroupID is 0: Windows has no agent group; the DACLs name the device
// service's SID.
func AgentGroupID() (int, error) { return 0, nil }

// IsSystemWriter reports whether this process writes the system files: an
// elevated Administrator or SYSTEM. The euid argument is unused.
func IsSystemWriter(int) bool { return windows.GetCurrentProcessToken().IsElevated() }

// Access the service SID may hold on each kind of system object, as the
// specific rights SDDL FR, FX and FW expand to (winnt.h FILE_GENERIC_*).
const (
	fileGenericRead    windows.ACCESS_MASK = 0x120089
	fileGenericExecute windows.ACCESS_MASK = 0x1200a0
	fileGenericWrite   windows.ACCESS_MASK = 0x120116

	serviceDirAccess  = fileGenericRead | fileGenericExecute
	serviceFileAccess = fileGenericRead
	serviceLockAccess = fileGenericRead | fileGenericWrite
)

// systemSDDL is the security descriptor of a system object: owner
// Administrators, full access for SYSTEM and Administrators, and service, an
// SDDL rights string, for the device service's SID when not empty. A
// directory's entries are inherited by its children (OICI), as in
// privateSecurityDescriptor: setting it on a directory that already holds
// unprotected children would otherwise leave each of them an empty DACL.
func systemSDDL(service string, dir bool) string {
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	sddl := fmt.Sprintf("O:BAD:P(A;%[1]s;FA;;;SY)(A;%[1]s;FA;;;BA)", inherit)
	if service == "" {
		return sddl
	}
	return sddl + fmt.Sprintf("(A;%s;%s;;;%s)", inherit, service, ServiceSID(WindowsServiceName))
}

func systemSecurityAttributes(service string, dir bool) (*windows.SecurityAttributes, *windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.SecurityDescriptorFromString(systemSDDL(service, dir))
	if err != nil {
		return nil, nil, fmt.Errorf("build security descriptor: %w", err)
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, sd, nil
}

// lockRights returns the service's SDDL rights and checked mask for a lock
// file of perm.
func lockRights(perm os.FileMode) (string, windows.ACCESS_MASK) {
	if perm == SystemRunLockPerm {
		return "FRFW", serviceLockAccess
	}
	return "", 0
}

// serviceCrashAccess is modify (read, write, execute, delete; SDDL 0x1301bf):
// the device service creates, rotates and removes its own crash files.
const serviceCrashAccess = fileGenericRead | fileGenericWrite | fileGenericExecute | windows.DELETE

// crashSDDL is a crash directory's descriptor: owner Administrators, SYSTEM
// and Administrators full, and with deviceService the device service modify,
// every entry inherited by files and subdirectories.
func crashSDDL(deviceService bool) string {
	sddl := "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if deviceService {
		sddl += fmt.Sprintf("(A;OICI;%#x;;;%s)", uint32(serviceCrashAccess), ServiceSID(WindowsServiceName))
	}
	return sddl
}

// EnsureCrashDir creates the crash directory dir and its parents when missing
// and sets its owner and protected DACL (crashSDDL): the device service's
// directory with deviceService, the session launcher's without, which the
// device service cannot reach at all. An elevated Administrator only. A
// directory owned by anyone but SYSTEM or Administrators is refused.
func EnsureCrashDir(dir string, deviceService bool) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(crashSDDL(deviceService))
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return &fs.PathError{Op: "create", Path: dir, Err: err}
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return &fs.PathError{Op: "create", Path: dir, Err: err}
	}
	h, err := openSystemHandle(dir, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES, windows.OPEN_EXISTING, nil, true)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := checkSystemOwner(h, dir); err != nil {
		return err
	}
	return applySystemDescriptor(h, dir, sd)
}

// CheckCrashDir refuses the crash directory dir unless it is a directory, not
// a reparse point, owned by SYSTEM or Administrators, and its DACL grants the
// device service at most modify (deviceService) or nothing, and nobody else
// anything. Files inside are not owner-checked: the device service creates
// its own.
func CheckCrashDir(dir string, deviceService bool) error {
	h, err := openSystemHandle(dir, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.OPEN_EXISTING, nil, true)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	access := windows.ACCESS_MASK(0)
	if deviceService {
		access = serviceCrashAccess
	}
	return checkSystemObject(h, dir, access)
}

// CheckSystemDir refuses dir unless it is a directory, not a reparse point,
// owned by SYSTEM or Administrators, and its DACL grants the device service
// at most read and traverse and nobody else anything. It changes nothing.
func CheckSystemDir(dir string) error {
	h, err := openSystemHandle(dir, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.OPEN_EXISTING, nil, true)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return checkSystemObject(h, dir, serviceDirAccess)
}

// EnsureSystemDir creates dir when missing and, through its handle, sets the
// system directory owner and DACL. An elevated Administrator only. A
// directory owned by anyone but SYSTEM or Administrators is refused, not
// taken over: its owner could have placed links in it.
func EnsureSystemDir(dir string, _ int) error {
	sa, sd, err := systemSecurityAttributes("FRFX", true)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return &fs.PathError{Op: "create", Path: dir, Err: err}
	}
	if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return &fs.PathError{Op: "create", Path: dir, Err: err}
	}
	h, err := openSystemHandle(dir, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES, windows.OPEN_EXISTING, nil, true)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := checkSystemOwner(h, dir); err != nil {
		return err
	}
	return applySystemDescriptor(h, dir, sd)
}

// ReadSystemFile reads path after checking, on the open handle, that it is a
// regular file owned by SYSTEM or Administrators whose DACL grants the
// device service read only and nobody else anything. The session launcher
// relies on it: a config the service could write is refused.
func ReadSystemFile(path string) ([]byte, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := windows.Handle(f.Fd())
	if err := checkRegularFile(h, path); err != nil {
		return nil, err
	}
	if err := checkSystemObject(h, path, serviceFileAccess); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// WriteSystemFileAtomic writes data to a new file beside path, created with
// the system file DACL, flushes it and renames it over path.
func WriteSystemFileAtomic(path string, data []byte, _ int) error {
	sa, _, err := systemSecurityAttributes("FR", false)
	if err != nil {
		return err
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+hex.EncodeToString(suffix[:])+".tmp")
	h, err := openSystemHandle(tmp, windows.GENERIC_WRITE|windows.DELETE, windows.CREATE_NEW, sa, false)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), tmp)
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	// The *os.File and os.Rename errors carry their paths.
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		committed = true
		return err
	}
	committed = true
	SyncDir(filepath.Dir(path))
	return nil
}

// AdoptSystemFile sets the system file owner and DACL on an existing path,
// through its handle, so an agent.yaml written while the service could
// write it becomes read-only to the service. One owned by anyone but SYSTEM
// or Administrators is refused: its owner could have written it.
func AdoptSystemFile(path string) error {
	_, sd, err := systemSecurityAttributes("FR", false)
	if err != nil {
		return err
	}
	h, err := openSystemHandle(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES, windows.OPEN_EXISTING, nil, false)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := checkRegularFile(h, path); err != nil {
		return err
	}
	if err := checkSystemOwner(h, path); err != nil {
		return err
	}
	return applySystemDescriptor(h, path, sd)
}

// OpenSystemLock opens or creates the lock file path and sets its owner and
// DACL for perm (SystemRunLockPerm or SystemConfigLockPerm) through the
// handle. A lock holds no trusted content, so one left by an earlier layout
// is taken over. While the handle is open the file cannot be deleted
// (lockFileShare).
func OpenSystemLock(path string, _ int, perm os.FileMode) (*os.File, error) {
	rights, _ := lockRights(perm)
	sa, sd, err := systemSecurityAttributes(rights, false)
	if err != nil {
		return nil, err
	}
	h, err := openSystemHandleShared(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_DAC|windows.WRITE_OWNER, lockFileShare, windows.OPEN_ALWAYS, sa, false)
	if err != nil {
		return nil, err
	}
	if err := checkRegularFile(h, path); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	if err := applySystemDescriptor(h, path, sd); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// OpenSystemRunLock opens the existing run.lock for the device service and
// refuses one whose owner or DACL is not the one OpenSystemLock sets. While
// the handle is open the file cannot be deleted (lockFileShare).
func OpenSystemRunLock(path string) (*os.File, error) {
	h, err := openSystemHandleShared(path, windows.GENERIC_READ|windows.GENERIC_WRITE, lockFileShare, windows.OPEN_EXISTING, nil, false)
	if err != nil {
		return nil, err
	}
	if err := checkRegularFile(h, path); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	if err := checkSystemObject(h, path, serviceLockAccess); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// openSystemHandle opens path with access and disposition, never following
// a reparse point; dir adds FILE_FLAG_BACKUP_SEMANTICS and requires a
// directory, otherwise a directory is refused.
func openSystemHandle(path string, access uint32, disposition uint32, sa *windows.SecurityAttributes, dir bool) (windows.Handle, error) {
	return openSystemHandleShared(path, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, sa, dir)
}

// lockFileShare is the share mode of a lock file's handle: without
// FILE_SHARE_DELETE the file cannot be deleted or renamed while any process
// has it open, so a held lock cannot be sidestepped by deleting the file and
// locking a new one.
const lockFileShare = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE

// openSystemHandleShared is openSystemHandle with the share mode share.
func openSystemHandleShared(path string, access, share, disposition uint32, sa *windows.SecurityAttributes, dir bool) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	flags := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if dir {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	h, err := windows.CreateFile(p, access, share, sa, disposition, flags, 0)
	if err != nil {
		return 0, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return 0, &fs.PathError{Op: "inspect", Path: path, Err: err}
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDir != dir {
		_ = windows.CloseHandle(h)
		return 0, ErrUntrustedPath.With(nil, fmt.Sprintf("%s is a reparse point or not the expected type", path))
	}
	return h, nil
}

// checkRegularFile refuses a handle that is not a disk file, such as a pipe.
func checkRegularFile(h windows.Handle, path string) error {
	ft, err := windows.GetFileType(h)
	if err != nil {
		return ErrUntrustedPath.With(err, fmt.Sprintf("cannot read the file type of %s", path))
	}
	if ft != windows.FILE_TYPE_DISK {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("%s is not a regular file", path))
	}
	return nil
}

// systemTrustees are SYSTEM and Administrators, the only owners and writers
// of system objects.
func systemTrustees() ([]*windows.SID, error) {
	var out []*windows.SID
	for _, wk := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(wk)
		if err != nil {
			return nil, fmt.Errorf("resolve well-known SID: %w", err)
		}
		out = append(out, sid)
	}
	return out, nil
}

func checkSystemOwner(h windows.Handle, path string) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return &fs.PathError{Op: "read security descriptor of", Path: path, Err: err}
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return &fs.PathError{Op: "read owner of", Path: path, Err: err}
	}
	trusted, err := systemTrustees()
	if err != nil {
		return err
	}
	if !sidIn(owner, trusted) {
		return ErrUntrustedPath.With(errForeignOwner, fmt.Sprintf("%s is owned by %s, not by SYSTEM or Administrators", path, owner))
	}
	return nil
}

// checkSystemObject refuses an owner other than SYSTEM or Administrators, a
// NULL DACL, an allow entry for the device service granting more than
// serviceAccess, an allow entry for any other trustee, and any entry type it
// cannot evaluate. Inherit-only entries apply to children and are skipped.
func checkSystemObject(h windows.Handle, path string, serviceAccess windows.ACCESS_MASK) error {
	if err := checkSystemOwner(h, path); err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return &fs.PathError{Op: "read security descriptor of", Path: path, Err: err}
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return &fs.PathError{Op: "read DACL of", Path: path, Err: err}
	}
	if dacl == nil {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("%s has no DACL, which grants full access to everyone", path))
	}
	trusted, err := systemTrustees()
	if err != nil {
		return err
	}
	service, err := windows.StringToSid(ServiceSID(WindowsServiceName))
	if err != nil {
		return fmt.Errorf("resolve the device service SID: %w", err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return &fs.PathError{Op: fmt.Sprintf("read ACE %d of", i), Path: path, Err: err}
		}
		if ace.Header.AceFlags&inheritOnlyACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, systemAuditACEType, systemAlarmACEType:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			switch {
			case sidIn(sid, trusted):
			case sid.Equals(service):
				if ace.Mask&^serviceAccess != 0 {
					return ErrUntrustedPath.With(nil, fmt.Sprintf("%s grants NT SERVICE\\%s access %#x beyond %#x; only SYSTEM and Administrators may change it", path, WindowsServiceName, uint32(ace.Mask), uint32(serviceAccess)))
				}
			default:
				return ErrUntrustedPath.With(nil, fmt.Sprintf("%s grants access to %s; only SYSTEM, Administrators and NT SERVICE\\%s may reach it", path, sid, WindowsServiceName))
			}
		default:
			return ErrUntrustedPath.With(nil, fmt.Sprintf("%s carries an access-control entry of type %d this check cannot evaluate; refusing rather than assuming it grants nothing",
				path, ace.Header.AceType))

		}
	}
	return nil
}

// applySystemDescriptor sets sd's owner and protected DACL on h.
func applySystemDescriptor(h windows.Handle, path string, sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return &fs.PathError{Op: "read owner for", Path: path, Err: err}
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return &fs.PathError{Op: "read DACL for", Path: path, Err: err}
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return &fs.PathError{Op: "secure", Path: path, Err: err}
	}
	return nil
}
