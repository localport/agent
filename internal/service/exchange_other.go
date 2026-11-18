//go:build !darwin && !linux

package service

import "errors"

// exchange is unsupported where launchd never runs and its tests skip.
func exchange(_, _ string) error { return errors.ErrUnsupported }
