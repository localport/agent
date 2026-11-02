package security

import "errors"

// System files are the root-owned device config directory and the files in it
// that root writes and the unprivileged agent account reads through group
// AgentGroup: the directory is root:localport 0750, agent.yaml root:localport
// 0640, run.lock root:localport 0660 and agent.yaml.lock root-only 0600. Every
// check runs on a descriptor opened without following a symlink, as for the
// private files. Windows has the same set guarded by DACLs instead
// (systemfile_windows.go); the gid arguments are unused there.

// AgentGroup is the group of the agent account, the only group besides root
// that reaches the system files.
const AgentGroup = "localport"

// ErrAgentGroupMissing means the agent group does not exist on this host:
// `localport service install` creates it.
var ErrAgentGroupMissing = errors.New("the " + AgentGroup + " group does not exist")

// systemOwner is the uid every system file and directory must be owned by.
var systemOwner = 0

// OverrideSystemOwner makes uid the required owner of system files until the
// returned restore runs. Only tests call it, so an unprivileged test can
// create and check system files with its own uid.
func OverrideSystemOwner(uid int) (restore func()) {
	prev := systemOwner
	systemOwner = uid
	return func() { systemOwner = prev }
}

// SystemOwner is the uid that owns the system files: root outside tests.
func SystemOwner() int { return systemOwner }
