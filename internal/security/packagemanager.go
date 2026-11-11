package security

import (
	"strings"

	"github.com/localport/agent/internal/errcode"
)

// ErrPackageManagerExecutable refuses a device service binary that a package
// manager (winget portable, Scoop) installed: the package manager replaces and
// removes it on its own schedule, without stopping or re-registering the
// service.
var ErrPackageManagerExecutable = errcode.New(errcode.PackageManagerExecutable)

// packageManagerOf names the package manager whose install root holds path,
// a Windows path, or returns "". winget portable packages live under a
// ...\WinGet\Packages\ directory (machine scope under Program Files, user
// scope under %LOCALAPPDATA%\Microsoft); Scoop apps under <root>\apps\ for
// each of scoopRoots. Matching ignores case, as Windows paths do.
func packageManagerOf(path string, scoopRoots []string) string {
	p := windowsFold(path)
	if strings.Contains(p, `\winget\packages\`) {
		return "winget"
	}
	for _, root := range scoopRoots {
		if root != "" && strings.HasPrefix(p, strings.TrimRight(windowsFold(root), `\`)+`\apps\`) {
			return "Scoop"
		}
	}
	return ""
}

// windowsFold is path as Windows compares it: case folded, / as \.
func windowsFold(path string) string {
	return strings.ReplaceAll(strings.ToLower(path), "/", `\`)
}
