package cli

import (
	"io"

	"github.com/localport/agent/internal/service"
)

// runAsAgentAccount is never reached on Windows: there is no euid 0, so
// needsAgentChild is false.
func runAsAgentAccount([]string, io.Reader, io.Writer) error { return service.ErrUnsupported }
