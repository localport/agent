//go:build !linux && !darwin

package service

import "context"

// createAccount is unsupported: Windows runs the agent under its service SID.
func createAccount(context.Context, runner) error { return ErrUnsupported }
