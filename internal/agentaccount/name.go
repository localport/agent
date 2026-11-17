// Package agentaccount names the system account the device service runs as
// on Linux and macOS, and the group that shares the system config with it.
// It is a leaf package so that errcode, launcher, security and service read
// one constant. Name is this platform's account; code that writes another
// platform's service definition names Linux or MacOS.
package agentaccount

const (
	// Linux is the account and group on Linux, where the packages create the
	// same account (packaging/nfpm/sysusers.conf).
	Linux = "localport"
	// MacOS is the account and group on macOS. The leading underscore is
	// Apple's convention for daemon role accounts (_www, _mdnsresponder).
	MacOS = "_localport"
)
