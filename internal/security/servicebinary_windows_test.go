//go:build windows

package security

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// A binary under the user's temp directory is owned by the user and refused.
func TestCheckServiceBinaryRefusesAUserBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "localport.exe")
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckServiceBinary(path); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("CheckServiceBinary(%s) = %v, want ErrUnsafeExecutable", path, err)
	}
}

// Adding a file (a planted DLL) or a subdirectory (an <exe>.local
// redirection) in the binary's own directory lets its holder change what the
// service loads, so either right for another trustee refuses the binary.
func TestCheckServiceBinaryRefusesAddRightsOnItsDirectory(t *testing.T) {
	requireElevated(t)
	dir, err := os.MkdirTemp(os.Getenv("ProgramData"), "localport-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	const owned = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	setDACL(t, dir, owned)
	path := filepath.Join(dir, "localport.exe")
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	setDACL(t, path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err := CheckServiceBinary(path); err != nil {
		t.Fatalf("CheckServiceBinary on an admin-only directory = %v", err)
	}
	for name, right := range map[string]string{"FILE_ADD_FILE": "0x2", "FILE_ADD_SUBDIRECTORY": "0x4"} {
		setDACL(t, dir, owned+"(A;;"+right+";;;BU)")
		if err := CheckServiceBinary(path); !errors.Is(err, ErrUnsafeExecutable) {
			t.Errorf("%s for Users on the directory: CheckServiceBinary = %v, want ErrUnsafeExecutable", name, err)
		}
	}
}

// The service SID is trusted under identity\ only: agent.yaml, run.lock and
// the device directory itself are system files it cannot write.
func TestUnderIdentityDir(t *testing.T) {
	const pd = `C:\ProgramData`
	for path, want := range map[string]bool{
		`C:\ProgramData\localport-device\identity`:                  true,
		`C:\PROGRAMDATA\Localport-Device\Identity\x\key.pem`:        true,
		`C:\ProgramData\localport-device\identity\recordings\a.seg`: true,
		`C:\ProgramData\localport-device`:                           false,
		`C:\ProgramData\localport-device\agent.yaml`:                false,
		`C:\ProgramData\localport-device\run.lock`:                  false,
		`C:\ProgramData\localport-device\identity-evil\key.pem`:     false,
		`C:\ProgramData\localport-device-evil\identity\key.pem`:     false,
		`C:\ProgramData\localport\identity`:                         false,
		`C:\Users\me\.localport\identity`:                           false,
		`localport-device\identity\key.pem`:                         false,
	} {
		if got := underIdentityDir(path, pd); got != want {
			t.Errorf("underIdentityDir(%s) = %v, want %v", path, got, want)
		}
	}
	if underIdentityDir(`C:\ProgramData\localport-device\identity`, "") {
		t.Error("an unset %ProgramData% must trust nothing")
	}
}
