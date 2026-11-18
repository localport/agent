//go:build cgo

package main

/*
#include <membership.h>
#include <uuid/uuid.h>
*/
import "C"

import "fmt"

// groupMember reports whether the directory service lists uid as a member of
// gid (mbr_check_membership(3)), nested groups included. The status reader
// check uses it for a peer whose credential lists 16 groups, the most an
// xucred carries, without the agent group.
func groupMember(uid, gid uint32) (bool, error) {
	var user, group C.uuid_t
	if rc := C.mbr_uid_to_uuid(C.uid_t(uid), &user[0]); rc != 0 {
		return false, fmt.Errorf("mbr_uid_to_uuid %d: error %d", uid, rc)
	}
	if rc := C.mbr_gid_to_uuid(C.gid_t(gid), &group[0]); rc != 0 {
		return false, fmt.Errorf("mbr_gid_to_uuid %d: error %d", gid, rc)
	}
	var member C.int
	if rc := C.mbr_check_membership(&user[0], &group[0], &member); rc != 0 {
		return false, fmt.Errorf("mbr_check_membership uid %d gid %d: error %d", uid, gid, rc)
	}
	return member != 0, nil
}
