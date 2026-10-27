//go:build !windows

package service

import "context"

// RunUnderSCM reports false: only Windows has a service control manager.
func RunUnderSCM(func(ctx context.Context, running func()) error) (bool, error) { return false, nil }
