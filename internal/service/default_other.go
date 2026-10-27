//go:build !linux && !darwin && !windows

package service

// Default returns ErrUnsupported: this platform has no supported service
// manager.
func Default() (Manager, error) { return nil, ErrUnsupported }
