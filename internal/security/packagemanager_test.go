package security

import "testing"

// A binary a package manager installed and updates is never the device
// service's binary: winget portable packages (machine and user scope) and
// Scoop apps (default and custom roots) are named, other paths are not.
func TestPackageManagerOf(t *testing.T) {
	scoopRoots := []string{`C:\Users\ana\scoop`, `C:\ProgramData\scoop`, `D:\tools\sc`}
	for path, want := range map[string]string{
		`C:\Program Files\WinGet\Packages\Localport.Localport_Microsoft.Winget.Source_8wekyb3d8bbwe\localport.exe`:         "winget",
		`C:\Users\ana\AppData\Local\Microsoft\WinGet\Packages\Localport.Localport_Microsoft.Winget.Source_x\localport.exe`: "winget",
		`c:\program files\winget\packages\x\localport.exe`:                                                                 "winget",
		`C:\Users\ana\scoop\apps\localport\1.4.0\localport.exe`:                                                            "Scoop",
		`C:\ProgramData\scoop\apps\localport\current\localport.exe`:                                                        "Scoop",
		`D:\tools\sc\apps\localport\1.4.0\localport.exe`:                                                                   "Scoop",
		`C:\Program Files\Localport\localport.exe`:                                                                         "",
		`C:\Users\ana\scoop\localport.exe`:                                                                                 "",
		`C:\Program Files\WinGetX\Packages\localport.exe`:                                                                  "",
		`D:\tools\scoopish\apps\localport.exe`:                                                                             "",
	} {
		if got := packageManagerOf(path, scoopRoots); got != want {
			t.Errorf("packageManagerOf(%s) = %q, want %q", path, got, want)
		}
	}
}
