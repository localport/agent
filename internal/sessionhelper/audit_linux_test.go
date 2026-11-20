//go:build cgo && linux

package sessionhelper

// auditProbeEnv names the macOS audit session probe; Linux sets the login
// uid through pam_loginuid, which the PAM root test covers.
const auditProbeEnv = "LOCALPORT_TEST_AUDIT_PROBE"

func runAuditProbe() int { return 2 }
