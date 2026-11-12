//go:build !windows

package cli

import "context"

// lockServiceDefinitions is the Windows service configuration lock; other
// platforms serialize service changes through their service managers.
func lockServiceDefinitions(context.Context) (unlock func(), err error) {
	return func() {}, nil
}
