package cli

import (
	"os"

	"github.com/localport/agent/internal/service"
)

// notifyReload delivers each SERVICE_CONTROL_PARAMCHANGE the device service
// receives (`localport set` sends one) as SIGHUP.
func notifyReload() (<-chan os.Signal, func()) { return service.ParamChanges(), func() {} }
