package cli

import (
	"os"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/service"
)

// reloadSignals delivers each SERVICE_CONTROL_PARAMCHANGE the device service
// receives (`localport set` sends one) as SIGHUP.
func reloadSignals() (<-chan os.Signal, func()) { return service.ParamChanges(), func() {} }

// inheritedControl and inheritedRunLock are Unix only: on Windows root never
// relays a run as the agent account (needsAgentChild).
func inheritedControl() (*launcher.ControlListener, error) { return nil, service.ErrUnsupported }

func inheritedRunLock(config.LocalConfigFile) (func() error, error) {
	return nil, service.ErrUnsupported
}
