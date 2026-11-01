package cli

import (
	"io"

	"github.com/localport/agent/internal/service"
)

// runAsAgentAccount is never reached on Windows: the system config there is
// not System, so needsAgentChild is false.
func runAsAgentAccount([]string, io.Reader, io.Writer) error { return service.ErrUnsupported }
