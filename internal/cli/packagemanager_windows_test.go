package cli

import (
	"errors"
	"testing"

	"github.com/localport/agent/internal/security"
)

// connect and service install take their service binary from
// serviceExecutable, which refuses one under each package-manager root.
func TestServiceExecutableRefusesAPackageManagerInstall(t *testing.T) {
	t.Setenv("USERPROFILE", `C:\Users\ana`)
	t.Setenv("ProgramData", `C:\ProgramData`)
	t.Setenv("SCOOP", `D:\tools\scoop`)
	t.Setenv("SCOOP_GLOBAL", "")
	saved := runningExecutable
	t.Cleanup(func() { runningExecutable = saved })
	for _, exe := range []string{
		`C:\Program Files\WinGet\Packages\Localport.Localport_Microsoft.Winget.Source_8wekyb3d8bbwe\localport.exe`,
		`C:\Users\ana\AppData\Local\Microsoft\WinGet\Packages\Localport.Localport_Microsoft.Winget.Source_8wekyb3d8bbwe\localport.exe`,
		`C:\Users\ana\scoop\apps\localport\current\localport.exe`,
		`C:\ProgramData\scoop\apps\localport\current\localport.exe`,
		`D:\tools\scoop\apps\localport\1.4.0\localport.exe`,
	} {
		runningExecutable = func() (string, error) { return exe, nil }
		if _, err := serviceExecutable(); !errors.Is(err, security.ErrPackageManagerExecutable) {
			t.Errorf("serviceExecutable for %s = %v, want ErrPackageManagerExecutable", exe, err)
		}
	}
}
