package identity

import (
	"testing"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/security"
)

// untrustDir grants BUILTIN\Users write on dir, which the private-directory
// check refuses, and returns the function that makes it private again.
func untrustDir(t *testing.T, dir string) (restore func()) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FA;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := security.EnsurePrivateDir(dir, dir, false); err != nil {
			t.Fatal(err)
		}
	}
}
