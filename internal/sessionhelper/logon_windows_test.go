//go:build windows

package sessionhelper

import "testing"

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
func TestPasswordLogonZeroesThePassword(t *testing.T) {
	pw := []byte("not-the-password-\x00")
	_, _ = passwordLogonToken(login{User: "localport-no-such-user"}, pw)
	for _, b := range pw {
		if b != 0 {
			t.Fatalf("password not zeroed: %q", pw)
		}
	}
}
