//go:build windows

package cli

import (
	"golang.org/x/sys/windows"
)

// localAccountSID is S-1-5-113, "Local account" (MS-DTYP 2.4.2.4), present in
// the token of every local user account.
const localAccountSID = "S-1-5-113"

// processLogin is this process's default login and, when it has none, why
// (windowsDefaultLogin). It reads the process token, never the registry.
func processLogin() (login, noDefault string) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", "this process's account cannot be read; name the accounts terminal and files sessions may use with --logins"
	}
	sid := user.User.Sid
	return windowsDefaultLogin(sid.String(), tokenHasGroup(token, localAccountSID),
		func() (string, error) {
			account, _, _, err := sid.LookupAccount("")
			return account, err
		},
		func() (string, error) {
			return userNameEx(windows.NameUserPrincipal)
		})
}

// tokenHasGroup reports whether the token's group list holds sid, whatever
// the group's attributes.
func tokenHasGroup(token windows.Token, sid string) bool {
	want, err := windows.StringToSid(sid)
	if err != nil {
		return false
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.Equals(want) {
			return true
		}
	}
	return false
}

// userNameEx returns the calling thread's account name in format
// (GetUserNameExW), growing the buffer on ERROR_MORE_DATA.
func userNameEx(format uint32) (string, error) {
	n := uint32(256)
	for {
		buf := make([]uint16, n)
		err := windows.GetUserNameEx(format, &buf[0], &n)
		if err == nil {
			return windows.UTF16ToString(buf[:n]), nil
		}
		if err != windows.ERROR_MORE_DATA || n <= uint32(len(buf)) {
			return "", err
		}
	}
}
