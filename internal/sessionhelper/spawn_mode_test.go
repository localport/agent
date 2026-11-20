//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"testing"

	"github.com/localport/agent/internal/launcher"
)

// A terminal or exec shell starts plainly with the grant or without a
// reading, through shell-exec without the grant, and is refused when this
// macOS cannot disclaim; the file and forward servers always start plainly.
func TestShellSpawnDecision(t *testing.T) {
	const (
		granted = launcher.FullDiskAccessGranted
		denied  = launcher.FullDiskAccessDenied
		unknown = launcher.FullDiskAccessUnknown
	)
	for _, tc := range []struct {
		kind, reading string
		disclaim      bool
		want          spawnMode
	}{
		{launcher.KindTerminal, granted, true, spawnPlain},
		{launcher.KindTerminal, granted, false, spawnPlain},
		{launcher.KindTerminal, "", false, spawnPlain},
		{launcher.KindTerminal, denied, true, spawnShellExec},
		{launcher.KindTerminal, unknown, true, spawnShellExec},
		{launcher.KindExec, denied, true, spawnShellExec},
		{launcher.KindTerminal, denied, false, spawnRefuse},
		{launcher.KindExec, unknown, false, spawnRefuse},
		{launcher.KindSFTP, granted, false, spawnPlain},
		{launcher.KindSFTP, "", false, spawnPlain},
		{launcher.KindForward, "", false, spawnPlain},
	} {
		if got := shellSpawn(tc.kind, tc.reading, tc.disclaim); got != tc.want {
			t.Errorf("%s reading %q disclaim %v: %d, want %d", tc.kind, tc.reading, tc.disclaim, got, tc.want)
		}
	}
}
