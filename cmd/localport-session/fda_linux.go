//go:build cgo

package main

// sessionFullDiskAccess is nil: Full Disk Access is a macOS state, so Linux
// session requests carry no reading and are not gated by one.
var sessionFullDiskAccess func() string
