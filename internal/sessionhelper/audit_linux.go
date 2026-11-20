//go:build cgo && linux

package sessionhelper

// newAuditSession does nothing on Linux: the PAM stack's pam_loginuid sets
// the login's audit user id and session (packaging/pam).
func newAuditSession(uint32, string, bool, string) error { return nil }
