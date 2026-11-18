package cli

import (
	"io"
	"os"

	"github.com/localport/agent/internal/service"
)

// runAsAgentAccount is never reached on Windows: there is no euid 0, so
// needsAgentChild is false.
func runAsAgentAccount([]string, io.Reader, io.Writer) error { return service.ErrUnsupported }

// runRunAsAgent, openStartingControl and runHeldAsAgent are never reached on
// Windows, as runAsAgentAccount.
func runRunAsAgent([]string, io.Reader, io.Writer) error { return service.ErrUnsupported }

type startingControl struct{}

func (*startingControl) Close() error { return nil }

func openStartingControl() (*startingControl, error) { return nil, service.ErrUnsupported }

func runHeldAsAgent([]string, io.Reader, io.Writer, *os.File, *startingControl) error {
	return service.ErrUnsupported
}
