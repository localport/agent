//go:build windows

package sessionhelper

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestParseLogin(t *testing.T) {
	for in, want := range map[string]login{
		"alice":              {User: "alice"},
		`CORP\alice`:         {User: "alice", Domain: "CORP"},
		"alice@corp.example": {User: "alice", UPN: "alice@corp.example"},
	} {
		got, err := parseLogin(in)
		if err != nil || got != want {
			t.Errorf("parseLogin(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{`\alice`, `CORP\`, `CORP\a\b`, `CORP\a@b`, "@corp", "alice@", "a@b@c"} {
		if _, err := parseLogin(bad); err == nil {
			t.Errorf("parseLogin(%q) must fail", bad)
		}
	}
	if !(login{User: "alice"}).local() || (login{User: "alice", UPN: "alice@corp"}).local() || !(login{User: "a", Domain: "."}).local() {
		t.Error("local() misclassifies a login")
	}
}

// A password logon zeroes the password on every path, a refusal included.
// The valid password reaches LogonUserW, which refuses the unknown account
// as an account refusal; the invalid one is refused before the call.
func TestPasswordLogonZeroesThePassword(t *testing.T) {
	for _, tc := range []struct {
		pw         []byte
		reachedAPI bool
	}{{[]byte("Not-the-password-1é"), true}, {[]byte("bad-\x00"), false}} {
		pw := tc.pw
		_, err := passwordLogonToken(login{User: "localport-no-such-user"}, pw)
		if !errors.Is(err, errAccount) {
			t.Errorf("logon with %d-byte password = %v, want errAccount", len(pw), err)
		}
		// Only a call that reached LogonUserW carries its error.
		if got := errors.Is(err, windows.ERROR_LOGON_FAILURE); got != tc.reachedAPI {
			t.Errorf("logon with %d-byte password = %v; reached LogonUserW %v, want %v", len(pw), err, got, tc.reachedAPI)
		}
		for _, b := range pw {
			if b != 0 {
				t.Fatalf("password not zeroed: %q", pw)
			}
		}
	}
}
