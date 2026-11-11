//go:build !windows

package cli

import "context"

// lockServiceConfig is the Windows service configuration mutex; other
// platforms serialize service changes through their service managers.
func lockServiceConfig(context.Context) (unlock func(), abandoned bool, err error) {
	return func() {}, false, nil
}
