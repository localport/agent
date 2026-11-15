package securitytest

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// winnt.h values x/sys/windows does not export: an ACE that applies to
// children only, and the audit and alarm ACE types, which grant nothing.
const (
	inheritOnlyACE     = 0x08
	systemAuditACEType = 2
	systemAlarmACEType = 3
)

// RequireOwnerOnly fails the test unless path's DACL grants access to
// nobody but this process's user, SYSTEM and Administrators: the Windows form
// of a Unix mode without group or other bits. An inherit-only entry, which
// does not apply to path itself, is not counted.
func RequireOwnerOnly(t testing.TB, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read the DACL of %s: %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("read the DACL of %s: %v", path, err)
	}
	if dacl == nil {
		t.Fatalf("%s has a NULL DACL, which grants everyone full access", path)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	allowed := []*windows.SID{user.User.Sid}
	for _, wk := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(wk)
		if err != nil {
			t.Fatal(err)
		}
		allowed = append(allowed, sid)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("read ACE %d of %s: %v", i, path, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, systemAuditACEType, systemAlarmACEType:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			t.Fatalf("%s carries an access-control entry of type %d this check cannot evaluate", path, ace.Header.AceType)
		}
		if ace.Header.AceFlags&inheritOnlyACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		trusted := false
		for _, a := range allowed {
			trusted = trusted || sid.Equals(a)
		}
		if !trusted {
			t.Fatalf("%s grants access to %s; want this account, SYSTEM and Administrators only", path, sid)
		}
	}
}
