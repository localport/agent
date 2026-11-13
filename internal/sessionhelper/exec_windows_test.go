//go:build windows

package sessionhelper

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/testroot"
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

// The console host runs headless at the session's size in cells with its
// signal pipe as a hex handle, then the shell's command line after --.
func TestConsoleHostCommandLine(t *testing.T) {
	got := consoleHostCommandLine(`C:\Windows\System32\conhost.exe`, 120, 40, windows.Handle(0x1a4), `"C:\Windows\System32\cmd.exe"`)
	want := `C:\Windows\System32\conhost.exe --headless --width 120 --height 40 --signal 0x1a4 -- "C:\Windows\System32\cmd.exe"`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// A resize is conhost's ResizeWindow signal: id 8, columns, rows, each a
// little-endian u16.
func TestResizeMessage(t *testing.T) {
	if got := resizeMessage(300, 0x0102); !bytes.Equal(got, []byte{8, 0, 0x2c, 0x01, 0x02, 0x01}) {
		t.Fatalf("message % x", got)
	}
}

// A piped command runs inside the kill-on-close job, which spawnInJob
// joins before resuming it.
func TestStartPipedRunsInTheJob(t *testing.T) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	shell, err := shellPath()
	if err != nil {
		t.Fatal(err)
	}
	env := mergeEnvironment(os.Environ(), nil, nil)
	p, err := startPiped(token, shell, commandLine(shell, "ping -n 3 127.0.0.1 >nul"), env, false)
	if err != nil {
		testroot.Require(t, "CreateProcessAsUser with this process's token: "+err.Error())
	}
	defer p.close()
	// x/sys/windows has no IsProcessInJob wrapper.
	var in int32
	r, _, err := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(uintptr(p.process), uintptr(p.job), uintptr(unsafe.Pointer(&in)))
	if r == 0 || in == 0 {
		t.Fatalf("in the job %d, %v", in, err)
	}
}

// Client variables replace a login variable of the same name in any case and
// are appended otherwise; the block round-trips through environmentStrings.
func TestMergeEnvironment(t *testing.T) {
	block := mergeEnvironment([]string{"Path=C:\\Windows", "lang=fr_FR", "USERNAME=alice"}, nil,
		map[string]string{"LANG": "en_GB.UTF-8", "LC_TIME": "C"})
	if block[len(block)-1] != 0 || block[len(block)-2] != 0 {
		t.Fatal("the block is not double-NUL terminated")
	}
	got := environmentStrings(&block[0])
	if len(got) != 4 || got[0] != `Path=C:\Windows` || got[1] != "LANG=en_GB.UTF-8" || got[2] != "USERNAME=alice" ||
		got[3] != "LC_TIME=C" {
		t.Fatalf("environment %q", got)
	}
	// The client's origin sets SSH_CLIENT and SSH_CONNECTION.
	block = mergeEnvironment([]string{"USERNAME=alice"}, launcher.OriginEnv("[2001:db8::7]:5022"), nil)
	if got := environmentStrings(&block[0]); !slices.Equal(got, []string{"USERNAME=alice",
		"SSH_CLIENT=2001:db8::7 5022 22", "SSH_CONNECTION=2001:db8::7 5022 127.0.0.1 22"}) {
		t.Fatalf("environment %q", got)
	}
	// Non-ASCII values survive the UTF-16 encoding.
	block = mergeEnvironment(nil, nil, map[string]string{"LANG": "日本語"})
	if got := environmentStrings(&block[0]); !slices.Equal(got, []string{"LANG=日本語"}) {
		t.Fatalf("environment %q", got)
	}
	if strings.ContainsRune(string(utf16.Decode(block)), 0xfffd) {
		t.Fatal("the block holds a replacement character")
	}
}
