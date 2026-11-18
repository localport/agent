//go:build !windows

package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/localport/agent/internal/errcode"
)

// The Linux account shape rules. They read plain files, so they build and
// are tested on every Unix; only Linux calls them (account_linux.go).

// The account databases the shape check reads; tests point them at their own
// files. The account is local on every host the agent runs on.
var (
	passwdPath    = "/etc/passwd"
	shadowPath    = "/etc/shadow"
	groupPath     = "/etc/group"
	loginDefsPath = "/etc/login.defs"
)

// defaultSysUIDMax is SYS_UID_MAX when login.defs does not set it, as
// shadow-utils and systemd assume.
const defaultSysUIDMax = 999

// noSystemRange is sysUIDMax on a host without login.defs (OpenWrt, whose
// user_add allocates from 32768; BusyBox): no range is defined there.
const noSystemRange = 0

// linuxNologinShells are the shells that refuse a login: nologin(8) and false.
var linuxNologinShells = []string{"/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin", "/bin/false", "/usr/bin/false"}

// linuxPrivilegedGroups are the groups the account must not belong to: each grants
// root, the password hashes, raw disks, the system logs, or a container
// runtime that does.
var linuxPrivilegedGroups = []string{"root", "wheel", "sudo", "admin", "adm", "shadow", "disk", "docker", "lxd"}

// linuxAccountShape refuses an existing Linux account that could log in or reach
// more than the agent needs, as useradd --system and systemd-sysusers create
// it: a locked password (no crypt(3) result in shadow), a nologin shell, the
// localport group as primary group, a uid other than root's and, where
// login.defs defines the system range, within it (SYS_UID_MAX), a home it
// cannot write (so it holds no SSH keys of its own),
// and no membership in linuxPrivilegedGroups. It never edits the account.
func linuxAccountShape(acct Account) error {
	pw, err := accountEntry(passwdPath, 7)
	if err != nil {
		return errAccount.With(err, "read "+passwdPath)
	}
	var unsafe []string
	locked, err := passwordLocked(pw[1])
	unchecked := errors.Is(err, ErrPasswordUnchecked)
	switch {
	case unchecked:
	case err != nil:
		return errAccount.With(err, "read "+shadowPath)
	case !locked:
		unsafe = append(unsafe, "its password is not locked")
	}
	if !slices.Contains(linuxNologinShells, pw[6]) {
		unsafe = append(unsafe, "its shell "+pw[6]+" allows a login")
	}
	gr, err := accountEntry(groupPath, 3)
	switch {
	case errors.Is(err, errNoEntry), err == nil && gr[2] != strconv.Itoa(acct.GID):
		unsafe = append(unsafe, "its primary group is not "+AgentAccount)
	case err != nil:
		return errAccount.With(err, "read "+groupPath)
	}
	sysMax, err := sysUIDMax()
	if err != nil {
		return errAccount.With(err, "read "+loginDefsPath)
	}
	switch {
	case acct.UID <= 0:
		unsafe = append(unsafe, fmt.Sprintf("its uid %d is root's or invalid", acct.UID))
	case sysMax != noSystemRange && acct.UID > sysMax:
		unsafe = append(unsafe, fmt.Sprintf("its uid %d is outside the system range 1-%d", acct.UID, sysMax))
	}
	if writable, err := homeWritable(pw[5], acct.UID); err != nil {
		return errAccount.With(err, "check the home "+pw[5])
	} else if writable {
		unsafe = append(unsafe, "its home "+pw[5]+" is writable by it")
	}
	groups, err := memberGroups(acct.GID)
	if err != nil {
		return errAccount.With(err, "read "+groupPath)
	}
	for _, name := range groups {
		if slices.Contains(linuxPrivilegedGroups, name) {
			unsafe = append(unsafe, "it is a member of "+name)
		}
	}
	if len(unsafe) > 0 {
		return errcode.New(errcode.AgentAccountUnsafe).With(nil, strings.Join(unsafe, "; "))
	}
	if unchecked {
		return ErrPasswordUnchecked
	}
	return nil
}

// errNoEntry is a database without an AgentAccount line.
var errNoEntry = errors.New("no entry")

// accountEntry returns the colon-separated fields of the AgentAccount line of
// the database at path, which must have n fields.
func accountEntry(path string, n int) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for line := range strings.Lines(string(data)) {
		f := strings.Split(strings.TrimRight(line, "\r\n"), ":")
		if f[0] == AgentAccount {
			if len(f) < n {
				return nil, fmt.Errorf("the %s entry has %d fields, want %d", AgentAccount, len(f), n)
			}
			return f, nil
		}
	}
	return nil, fmt.Errorf("%w for %s", errNoEntry, AgentAccount)
}

// passwordLocked reports whether no password can unlock the account: the
// shadow hash when the passwd field is "x", else the passwd field itself, is
// not a crypt(3) result (shadow(5)): "!" or "*" first, or "x" as OpenWrt's
// user_add writes. An empty one admits a login without a password. With no
// shadow database the "x" itself is the hash (BusyBox without shadow); a
// shadow the caller may not read is ErrPasswordUnchecked.
func passwordLocked(passwdField string) (bool, error) {
	hash := passwdField
	if passwdField == "x" {
		sp, err := accountEntry(shadowPath, 2)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case errors.Is(err, fs.ErrPermission):
			return false, ErrPasswordUnchecked
		case err != nil:
			return false, err
		default:
			hash = sp[1]
		}
	}
	return !cryptResult(hash), nil
}

// cryptResult reports whether hash may be a crypt(3) result a password
// matches: empty (no password), a "$id$" hash, or 13 characters of the
// traditional DES alphabet.
func cryptResult(hash string) bool {
	if hash == "" || strings.HasPrefix(hash, "$") {
		return true
	}
	if strings.HasPrefix(hash, "!") || strings.HasPrefix(hash, "*") || len(hash) != 13 {
		return false
	}
	return strings.Trim(hash, "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") == ""
}

// sysUIDMax is SYS_UID_MAX of login.defs, defaultSysUIDMax when the file
// does not set it, or noSystemRange without the file.
func sysUIDMax() (int, error) {
	data, err := os.ReadFile(loginDefsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return noSystemRange, nil
	}
	if err != nil {
		return 0, err
	}
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "SYS_UID_MAX" {
			return strconv.Atoi(f[1])
		}
	}
	return defaultSysUIDMax, nil
}

// homeWritable reports whether home exists and the account owns it or its
// group or others may write it. A missing home (/nonexistent) is not.
func homeWritable(home string, uid int) (bool, error) {
	fi, err := os.Stat(home)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	st := fi.Sys().(*syscall.Stat_t)
	return int(st.Uid) == uid || fi.Mode().Perm()&0o022 != 0, nil
}

// memberGroups returns the groups of the group database whose member list
// names AgentAccount, and the group whose id is the primary gid.
func memberGroups(gid int) ([]string, error) {
	data, err := os.ReadFile(groupPath)
	if err != nil {
		return nil, err
	}
	var names []string
	for line := range strings.Lines(string(data)) {
		f := strings.Split(strings.TrimRight(line, "\r\n"), ":")
		if len(f) < 4 {
			continue
		}
		if f[2] == strconv.Itoa(gid) || slices.Contains(strings.Split(f[3], ","), AgentAccount) {
			names = append(names, f[0])
		}
	}
	return names, nil
}
