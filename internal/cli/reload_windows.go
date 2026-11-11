package cli

import (
	"os"

	"github.com/localport/agent/internal/service"
)

// reloadSignals delivers each SERVICE_CONTROL_PARAMCHANGE the device service
// receives (`localport set` sends one) as SIGHUP.
func reloadSignals() (<-chan os.Signal, func()) { return service.ParamChanges(), func() {} }
