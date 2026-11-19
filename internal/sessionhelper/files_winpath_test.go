package sessionhelper

import (
	"errors"
	"syscall"
	"testing"
)

// cAndD lists drives C and D and treats every reserved name as a device, as
// Windows before 11 does.
var cAndD = winOS{
	listed: func(letter byte) bool { return letter == 'C' || letter == 'D' },
	device: func(seg string) bool { r, _ := reservedDeviceBase(seg); return r },
}

// win11 is cAndD where a reserved name with an extension is a file.
var win11 = winOS{
	listed: cAndD.listed,
	device: func(seg string) bool { r, exact := reservedDeviceBase(seg); return r && exact },
}

func TestReservedDeviceBase(t *testing.T) {
	for seg, want := range map[string][2]bool{
		"NUL": {true, true}, "nul": {true, true}, "Com1": {true, true}, "LPT³": {true, true}, "CONIN$": {true, true},
		"nul.txt": {true, false}, "COM1 .log": {true, false}, "aux.c": {true, false}, "con:stream": {true, false},
		"COM0": {false, false}, "NULL": {false, false}, "console": {false, false}, "x": {false, false},
		// Only ASCII letters fold: a dotless i is not an I.
		"conın$": {false, false},
	} {
		if r, exact := reservedDeviceBase(seg); r != want[0] || exact != want[1] {
			t.Errorf("reservedDeviceBase(%q) = %v, %v, want %v, %v", seg, r, exact, want[0], want[1])
		}
	}
}

func TestWinPath(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write bool
		want  string
		err   error
	}{
		{name: "/c:", want: `C:\`},
		{name: "/C:", want: `C:\`},
		{name: "/c:/Users/x", want: `C:\Users\x`},
		{name: "/D:/a/../b", want: `D:\b`},
		{name: "/", err: syscall.EACCES},
		{name: "/", write: true, err: syscall.EACCES},
		{name: "/z:", err: syscall.ENOENT},
		{name: "/z:", write: true, err: syscall.EACCES},
		{name: "/z:/x", write: true, err: syscall.ENOENT},
		{name: "/Users", err: syscall.ENOENT},
		{name: "/newdir", write: true, err: syscall.EACCES},
		{name: "/Users/x", write: true, err: syscall.ENOENT},
		{name: "/c:/x/file:stream", err: syscall.EINVAL},
		{name: "/c:/x:y", err: syscall.EINVAL},
		{name: "/cc:/x", err: syscall.EINVAL},
		{name: "/1:/x", err: syscall.EINVAL},
		{name: "/??/C:/x", err: syscall.EINVAL},
		{name: "/??/Volume{0}/Windows", err: syscall.EINVAL},
		{name: "/c:/x/NUL", err: syscall.EINVAL},
		{name: "/c:/x/com1", write: true, err: syscall.EINVAL},
		{name: "/c:/x/aux.c", err: syscall.EINVAL},
		{name: "/c:/nul.txt/y", err: syscall.EINVAL},
		{name: "//server/share/x", err: syscall.EINVAL},
		{name: "//./pipe/x", err: syscall.EINVAL},
		{name: `/c:/x\..\..\Windows`, err: syscall.EINVAL},
		{name: "c:/x", err: syscall.EINVAL},
	} {
		got, err := winPath(tc.name, tc.write, cAndD)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("winPath(%q, write %v) = %q, %v, want %v", tc.name, tc.write, got, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("winPath(%q) = %q, %v, want %q", tc.name, got, err, tc.want)
		}
	}
	// Windows 11 serves a reserved name with an extension as a file.
	if got, err := winPath("/c:/x/aux.c", false, win11); err != nil || got != `C:\x\aux.c` {
		t.Errorf("winPath(/c:/x/aux.c) on Windows 11 = %q, %v", got, err)
	}
	if _, err := winPath("/c:/x/AUX", false, win11); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("winPath(/c:/x/AUX) on Windows 11 = %v, want invalid", err)
	}
}

// A Windows path maps to its client form and back.
func TestWinClientPathRoundTrips(t *testing.T) {
	for native, client := range map[string]string{
		`C:\`:          "/c:",
		`C:\Users\x`:   "/c:/Users/x",
		`d:\a b\c.txt`: "/d:/a b/c.txt",
	} {
		got, err := winClientPath(native)
		if err != nil || got != client {
			t.Errorf("winClientPath(%q) = %q, %v, want %q", native, got, err, client)
			continue
		}
		back, err := winPath(got, false, cAndD)
		if err != nil || !equalFold(back, native) {
			t.Errorf("winPath(%q) = %q, %v, want %q", got, back, err, native)
		}
	}
	for _, native := range []string{`\\server\share`, `\\?\Volume{0}\`, `C:`, `C:x`, `x`, `C:\a:b`} {
		if got, err := winClientPath(native); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("winClientPath(%q) = %q, %v, want invalid", native, got, err)
		}
	}
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if 'a' <= x && x <= 'z' {
			x -= 'a' - 'A'
		}
		if 'a' <= y && y <= 'z' {
			y -= 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func TestWinClientTarget(t *testing.T) {
	for target, want := range map[string]string{
		`C:\Windows\x`: "/c:/Windows/x",
		`\Windows\x`:   "/d:/Windows/x",
		`..\y\z`:       "../y/z",
		`y`:            "y",
	} {
		if got, err := winClientTarget("/d:/a/link", target); err != nil || got != want {
			t.Errorf("winClientTarget(%q) = %q, %v, want %q", target, got, err, want)
		}
	}
	for _, target := range []string{`\\server\share\x`, `\??\Volume{0}\x`, `\\?\C:\x`, `\\.\pipe\x`, `C:x`, `a:b`} {
		if got, err := winClientTarget("/d:/a/link", target); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("winClientTarget(%q) = %q, %v, want invalid", target, got, err)
		}
	}
}

func TestWinLinkTarget(t *testing.T) {
	for target, want := range map[string]string{
		"/c:/Windows/x": `C:\Windows\x`,
		"/C:":           `C:\`,
		"../y/z":        `..\y\z`,
		"y":             `y`,
	} {
		if got, err := winLinkTarget(target, cAndD); err != nil || got != want {
			t.Errorf("winLinkTarget(%q) = %q, %v, want %q", target, got, err, want)
		}
	}
	for _, target := range []string{`..\y`, "c:x", "/c:/a:b", "//server/share", "NUL", "../com1", "/c:/x/CON"} {
		if got, err := winLinkTarget(target, cAndD); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("winLinkTarget(%q) = %q, %v, want invalid", target, got, err)
		}
	}
}

func TestWinClientName(t *testing.T) {
	for in, want := range map[string]string{
		"/C:":      "/c:",
		"/C:/Xy":   "/c:/Xy",
		"/d:/a":    "/d:/a",
		"/":        "/",
		"/Users/x": "/Users/x",
	} {
		if got := winClientName(in); got != want {
			t.Errorf("winClientName(%q) = %q, want %q", in, got, want)
		}
	}
}
