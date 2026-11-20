//go:build cgo && (linux || darwin)

package sessionhelper

import "github.com/localport/agent/internal/launcher"

// ShellExecMode is the argv[1] of the mode that replaces itself with a
// session's shell as its own responsible process (ShellExec, macOS).
const ShellExecMode = "shell-exec"

// spawnMode is how a session's process starts.
type spawnMode int

const (
	// spawnPlain starts the process as the helper's child; Localport.app is
	// responsible for what it touches.
	spawnPlain spawnMode = iota
	// spawnShellExec starts the shell through ShellExecMode, its own responsible process.
	spawnShellExec
	// spawnRefuse refuses the session: Localport.app would be responsible
	// and TCC would prompt the console user.
	spawnRefuse
)

// shellSpawn decides how a session of kind starts from the launcher's Full
// Disk Access reading (empty off macOS) and whether this macOS can disclaim
// responsibility. A terminal or exec shell starts plainly with the grant or
// off macOS, through shell-exec without it, and is refused when shell-exec is
// unavailable. The file and forward servers start plainly; the launcher
// refuses files without the grant.
func shellSpawn(kind, fullDiskAccess string, disclaim bool) spawnMode {
	if (kind != launcher.KindTerminal && kind != launcher.KindExec) || fullDiskAccess == "" || fullDiskAccess == launcher.FullDiskAccessGranted {
		return spawnPlain
	}
	if disclaim {
		return spawnShellExec
	}
	return spawnRefuse
}
