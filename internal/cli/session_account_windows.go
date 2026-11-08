//go:build windows

package cli

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/security"
)

// errSessionsNeedDeviceService refuses terminal and files sessions in a
// process the session launcher will not serve.
var errSessionsNeedDeviceService = errors.New("terminal and files sessions run only under the installed device service, because the session launcher serves only its account")

// checkSessionAccount reports whether this process runs as the only account
// the launcher serves (launcher.Server.AgentSID).
func checkSessionAccount() error {
	service, err := windows.StringToSid(security.ServiceSID(security.WindowsServiceName))
	if err != nil {
		return fmt.Errorf("read the device service account: %w", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read the process account: %w", err)
	}
	return sessionAccountError(user.User.Sid, service)
}

func sessionAccountError(current, service *windows.SID) error {
	if current.Equals(service) {
		return nil
	}
	return fmt.Errorf("%w; this process runs as %s", errSessionsNeedDeviceService, current)
}
