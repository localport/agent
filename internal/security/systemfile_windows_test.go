//go:build windows

package security

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// requireElevated skips unless the test runs as an elevated Administrator,
// the only account that writes system files.
func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated Administrator")
	}
}

// setDACL replaces path's DACL with sddl's.
func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// agent.yaml is read-only to the device service. A config the service could
// write is refused, so the launcher never acts on one a compromised agent
// rewrote.
func TestSystemFileRefusesAServiceWriter(t *testing.T) {
	requireElevated(t)
	dir := filepath.Join(t.TempDir(), "localport-device")
	if err := EnsureSystemDir(dir, 0); err != nil {
		t.Fatal(err)
	}
	if err := CheckSystemDir(dir); err != nil {
		t.Fatalf("CheckSystemDir after EnsureSystemDir: %v", err)
	}
	path := filepath.Join(dir, "agent.yaml")
	if err := WriteSystemFileAtomic(path, []byte("version: 2\n"), 0); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadSystemFile(path); err != nil || string(got) != "version: 2\n" {
		t.Fatalf("ReadSystemFile = %q, %v", got, err)
	}
	svc := ServiceSID(WindowsServiceName)
	setDACL(t, path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFW;;;"+svc+")")
	if _, err := ReadSystemFile(path); !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("ReadSystemFile with the service granted write = %v, want ErrUntrustedPath", err)
	}
	// AdoptSystemFile restores the read-only grant.
	if err := AdoptSystemFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSystemFile(path); err != nil {
		t.Fatalf("ReadSystemFile after AdoptSystemFile: %v", err)
	}
	// Any other trustee, even read-only, is refused.
	setDACL(t, path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
	if _, err := ReadSystemFile(path); !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("ReadSystemFile readable by Users = %v, want ErrUntrustedPath", err)
	}
}

// run.lock lets the service read and write it, not change its DACL.
func TestSystemRunLockRefusesAServiceDACLWriter(t *testing.T) {
	requireElevated(t)
	dir := filepath.Join(t.TempDir(), "localport-device")
	if err := EnsureSystemDir(dir, 0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "run.lock")
	f, err := OpenSystemLock(path, 0, SystemRunLockPerm)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if f, err := OpenSystemRunLock(path); err != nil {
		t.Fatalf("OpenSystemRunLock: %v", err)
	} else {
		f.Close()
	}
	setDACL(t, path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+ServiceSID(WindowsServiceName)+")")
	if _, err := OpenSystemRunLock(path); !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("OpenSystemRunLock with full service access = %v, want ErrUntrustedPath", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
