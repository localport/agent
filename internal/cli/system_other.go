//go:build !windows

package cli

import "errors"

// runSystem refuses: the installer steps exist for the Windows installer only.
func runSystem(string, []string) error {
	return errors.New(`unknown command "system"`)
}
