//go:build !darwin

package launcher

// ReadFullDiskAccess reports unknown: Full Disk Access is a macOS state.
func ReadFullDiskAccess() string { return FullDiskAccessUnknown }
