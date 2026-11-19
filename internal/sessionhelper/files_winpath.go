package sessionhelper

import (
	"io/fs"
	"path"
	"strings"
	"syscall"
)

// The Windows client grammar, as Win32-OpenSSH serves it: "/" is a virtual,
// read-only top listing the drives, and the first segment of every other path
// is a drive, "/c:" for C:\ (any letter case, shown lower case). These
// functions are pure so every platform tests them; files_os_windows.go wires
// them to the OS through winOS.

// winOS holds the OS facts the grammar needs: listed reports whether an
// upper-case drive letter is one the top lists, device whether a path segment
// names a DOS device (NUL, COM1, CONIN$; with an extension only where the
// kernel still treats it as one).
type winOS struct {
	listed func(letter byte) bool
	device func(seg string) bool
}

// reservedDeviceBase reports whether seg's base, the text before its first
// dot or colon with trailing spaces removed, is a DOS device name, and
// whether seg is that base alone (exact), which every Windows version
// treats as the device.
func reservedDeviceBase(seg string) (reserved, exact bool) {
	base := seg
	if i := strings.IndexAny(base, ".:"); i >= 0 {
		base = base[:i]
	}
	base = strings.TrimRight(base, " ")
	// ASCII case folding only, as the kernel compares device names.
	switch asciiUpper(base) {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³":
		return true, len(base) == len(seg)
	}
	return false, false
}

func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// driveLetter is the upper-case letter of a "<letter>:" segment.
func driveLetter(seg string) (byte, bool) {
	if len(seg) != 2 || seg[1] != ':' {
		return 0, false
	}
	switch c := seg[0]; {
	case 'A' <= c && c <= 'Z':
		return c, true
	case 'a' <= c && c <= 'z':
		return c - 'a' + 'A', true
	}
	return 0, false
}

func invalidPath(op, name string) error {
	return &fs.PathError{Op: op, Path: name, Err: syscall.EINVAL}
}

// winPath maps a clean absolute client path to a Windows path: "/c:" to C:\,
// "/c:/Users/x" to C:\Users\x. UNC and device paths ("//" first, as the
// request server shows \\server and \\.\), \??\ paths ("/??"), DOS device
// names (NUL, COM1), a backslash (only symlink target text still carries one)
// and an alternate data stream (a colon past the drive) are invalid. The top
// itself, and a new entry in it (write), are refused as permission denied;
// any other name in the top that is not a listed drive does not exist.
func winPath(name string, write bool, w winOS) (string, error) {
	if !strings.HasPrefix(name, "/") || strings.HasPrefix(name, "//") || strings.Contains(name, `\`) {
		return "", invalidPath("path", name)
	}
	clean := path.Clean(name)
	if clean == "/" {
		return "", &fs.PathError{Op: "path", Path: name, Err: syscall.EACCES}
	}
	segs := strings.Split(clean[1:], "/")
	for _, s := range segs[1:] {
		if strings.Contains(s, ":") || w.device(s) {
			return "", invalidPath("path", name)
		}
	}
	letter, ok := driveLetter(segs[0])
	if !ok && (segs[0] == "??" || strings.Contains(segs[0], ":")) {
		return "", invalidPath("path", name)
	}
	if !ok || !w.listed(letter) {
		if write && len(segs) == 1 {
			return "", &fs.PathError{Op: "path", Path: name, Err: syscall.EACCES}
		}
		return "", &fs.PathError{Op: "path", Path: name, Err: syscall.ENOENT}
	}
	return string(letter) + `:\` + strings.Join(segs[1:], `\`), nil
}

// winClientPath is the client form of an absolute Windows path with a drive
// (C:\Users\x to /c:/Users/x); any other form is invalid.
func winClientPath(native string) (string, error) {
	letter, ok := byte(0), false
	if len(native) >= 3 && (native[2] == '\\' || native[2] == '/') {
		letter, ok = driveLetter(native[:2])
	}
	if !ok {
		return "", invalidPath("path", native)
	}
	rest := strings.ReplaceAll(native[2:], `\`, "/")
	if strings.Contains(rest, ":") {
		return "", invalidPath("path", native)
	}
	return path.Clean("/" + string(letter-'A'+'a') + ":" + rest), nil
}

// winClientTarget is the client form of a symlink target read from the link
// at the client path link: a drive path in /c:/ form, a rooted path on the
// link's drive, a relative path with forward slashes. UNC, \??\, device and
// volume targets and drive-relative ones (C:x) have no client form.
func winClientTarget(link, target string) (string, error) {
	if strings.HasPrefix(target, `\\`) || strings.HasPrefix(target, `\??\`) {
		return "", invalidPath("readlink", link)
	}
	if len(target) >= 2 && target[1] == ':' {
		p, err := winClientPath(target)
		if err != nil {
			return "", invalidPath("readlink", link)
		}
		return p, nil
	}
	slashed := strings.ReplaceAll(target, `\`, "/")
	if strings.Contains(slashed, ":") {
		return "", invalidPath("readlink", link)
	}
	if strings.HasPrefix(slashed, "/") {
		drive, _, _ := strings.Cut(strings.TrimPrefix(link, "/"), "/")
		if _, ok := driveLetter(drive); !ok {
			return "", invalidPath("readlink", link)
		}
		return path.Clean("/" + strings.ToLower(drive) + slashed), nil
	}
	return slashed, nil
}

// winLinkTarget is the Windows text of a symlink target the client sent: a
// /c:/ path maps to C:\, a relative one keeps its segments with backslashes.
// A backslash, a colon or a DOS device name in a relative target is invalid.
func winLinkTarget(target string, w winOS) (string, error) {
	if strings.HasPrefix(target, "/") {
		return winPath(target, false, w)
	}
	if strings.Contains(target, `\`) || strings.Contains(target, ":") {
		return "", invalidPath("symlink", target)
	}
	for seg := range strings.SplitSeq(target, "/") {
		if w.device(seg) {
			return "", invalidPath("symlink", target)
		}
	}
	return strings.ReplaceAll(target, "/", `\`), nil
}

// winClientName shows a client path's drive in lower case ("/C:/x" as
// "/c:/x"); any other path is returned as is.
func winClientName(p string) string {
	drive, rest, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	letter, ok := driveLetter(drive)
	if !ok || !strings.HasPrefix(p, "/") {
		return p
	}
	if rest == "" {
		return "/" + string(letter-'A'+'a') + ":"
	}
	return "/" + string(letter-'A'+'a') + ":/" + rest
}
