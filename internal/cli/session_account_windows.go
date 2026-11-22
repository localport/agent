//go:build windows

package cli

import (
	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

// errSessionsNeedDeviceService refuses terminal and files sessions in a
// process the session launcher will not serve.
var errSessionsNeedDeviceService = errcode.New(errcode.SessionsNeedService)

// checkSessionAccount reports whether this process runs as the only account
// the launcher serves (launcher.Server.AgentSID).
func checkSessionAccount() error {
	service, err := windows.StringToSid(security.ServiceSID(security.WindowsServiceName))
	if err != nil {
		return errcode.New(errcode.Unexpected).With(err, "read the device service account")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errcode.New(errcode.CurrentUserUnknown).With(err, "")
	}
	return sessionAccountError(user.User.Sid, service)
}

func sessionAccountError(current, service *windows.SID) error {
	if current.Equals(service) {
		return nil
	}
	return errSessionsNeedDeviceService.With(nil, "this process runs as "+current.String())
}
