package main

import "testing"

func TestSystemdFDsMatchesByName(t *testing.T) {
	fds, err := systemdFDs("42", "2", "status:session", 42)
	if err != nil || fds[fdNameStatus] != 3 || fds[fdNameSession] != 4 {
		t.Fatalf("systemdFDs = %v, %v; want status 3, session 4", fds, err)
	}
	if fds, err := systemdFDs("41", "2", "session:status", 42); fds != nil || err != nil {
		t.Fatalf("descriptors for another pid = %v, %v; want none", fds, err)
	}
	// Units without the status socket still serve sessions.
	if fds, err := systemdFDs("42", "1", "session", 42); err != nil || fds[fdNameSession] != 3 || len(fds) != 1 {
		t.Fatalf("session socket only = %v, %v; want session 3", fds, err)
	}
	for name, c := range map[string][2]string{
		"no session socket": {"1", "status"},
		"unknown name":      {"2", "session:other"},
		"duplicate name":    {"2", "session:session"},
		"names mismatched":  {"2", "session"},
		"bad count":         {"x", "session:status"},
	} {
		if _, err := systemdFDs("42", c[0], c[1], 42); err == nil {
			t.Errorf("%s: systemdFDs accepted LISTEN_FDS=%s LISTEN_FDNAMES=%s", name, c[0], c[1])
		}
	}
}
