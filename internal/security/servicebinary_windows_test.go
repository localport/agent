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

func TestUnderDeviceDir(t *testing.T) {
	const pd = `C:\ProgramData`
	for path, want := range map[string]bool{
		`C:\ProgramData\localport-device`:                    true,
		`C:\PROGRAMDATA\Localport-Device\identity\x\key.pem`: true,
		`C:\ProgramData\localport-device-evil\agent.yaml`:    false,
		`C:\ProgramData\localport\agent.yaml`:                false,
		`C:\Users\me\.localport\identity`:                    false,
		`localport-device\agent.yaml`:                        false,
	} {
		if got := underDeviceDir(path, pd); got != want {
			t.Errorf("underDeviceDir(%s) = %v, want %v", path, got, want)
		}
	}
	if underDeviceDir(`C:\ProgramData\localport-device`, "") {
		t.Error("an unset %ProgramData% must trust nothing")
	}
}
