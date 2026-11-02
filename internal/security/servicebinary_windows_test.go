//go:build windows

package security

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
