//go:build windows

package sessionhelper

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

// The shell runs a command in the Win32-OpenSSH form, and alone for a login
// shell.
func TestCommandLine(t *testing.T) {
	shell := `C:\Windows\System32\cmd.exe`
	if got := commandLine(shell, ""); got != `"C:\Windows\System32\cmd.exe"` {
		t.Errorf("login shell: %s", got)
	}
	if got := commandLine(shell, `dir "C:\Program Files"`); got != `"C:\Windows\System32\cmd.exe" /c "dir "C:\Program Files""` {
		t.Errorf("command: %s", got)
	}
}

// Client variables replace a login variable of the same name in any case and
// are appended otherwise; the block round-trips through environmentStrings.
func TestMergeEnvironment(t *testing.T) {
	block := mergeEnvironment([]string{"Path=C:\\Windows", "lang=fr_FR", "USERNAME=alice"},
		map[string]string{"LANG": "en_GB.UTF-8", "LC_TIME": "C"})
	if block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatal("the block is not double-NUL terminated")
	}
	got := environmentStrings(&block[0])
	if len(got) != 4 || got[0] != `Path=C:\Windows` || got[1] != "LANG=en_GB.UTF-8" || got[2] != "USERNAME=alice" ||
		got[3] != "LC_TIME=C" {
		t.Fatalf("environment %q", got)
	}
	// Non-ASCII values survive the UTF-16 encoding.
	block = mergeEnvironment(nil, map[string]string{"LANG": "日本語"})
	if got := environmentStrings(&block[0]); !slices.Equal(got, []string{"LANG=日本語"}) {
		t.Fatalf("environment %q", got)
	}
	if strings.ContainsRune(string(utf16.Decode(block)), 0xfffd) {
		t.Fatal("the block holds a replacement character")
	}
}
