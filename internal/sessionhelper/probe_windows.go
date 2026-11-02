//go:build windows

package sessionhelper

// PAMAvailable is false: Windows sessions log on through LSA.
func PAMAvailable() bool { return false }
