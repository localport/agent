//go:build !windows

package cli

import (
	"fmt"

	"github.com/localport/agent/internal/errcode"
)

// runSystem refuses: the installer steps exist for the Windows installer only.
func runSystem(string, []string) error {
	return errcode.New(errcode.UnknownCommand).With(nil, fmt.Sprintf("%q", "system"))
}
