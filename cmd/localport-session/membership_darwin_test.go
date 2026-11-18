//go:build cgo

package main

import (
	"os"
	"testing"
)

// The directory service lists an account in its primary group and not in
// daemon (gid 1), which holds no user accounts.
func TestGroupMemberAsksTheDirectory(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if uid == 0 {
		t.Skip("root is listed in daemon")
	}
	if ok, err := groupMember(uid, gid); err != nil || !ok {
		t.Fatalf("groupMember(%d, primary %d) = %v, %v; want true", uid, gid, ok, err)
	}
	if ok, err := groupMember(uid, 1); err != nil || ok {
		t.Fatalf("groupMember(%d, daemon) = %v, %v; want false", uid, ok, err)
	}
}
