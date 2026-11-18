package main

// groupMember is nil on Linux: SO_PEERGROUPS carries every supplementary
// group, so the peer credential alone decides.
var groupMember func(uid, gid uint32) (bool, error)
