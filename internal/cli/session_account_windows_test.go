//go:build windows

package cli

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/security"
)

// An account other than the device service's is refused with the reason; the
// service's own account serves.
func TestSessionAccountError(t *testing.T) {
	service, err := windows.StringToSid(security.ServiceSID(security.WindowsServiceName))
	if err != nil {
		t.Fatal(err)
	}
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessionAccountError(service, service); err != nil {
		t.Fatalf("the service account = %v", err)
	}
	if err := sessionAccountError(admin, service); !errors.Is(err, errSessionsNeedDeviceService) {
		t.Fatalf("an elevated non-service run = %v, want errSessionsNeedDeviceService", err)
	}
	// The test process is not the device service.
	if err := checkSessionAccount(); !errors.Is(err, errSessionsNeedDeviceService) {
		t.Fatalf("checkSessionAccount = %v, want errSessionsNeedDeviceService", err)
	}
}
