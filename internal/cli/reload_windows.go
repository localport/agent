package cli

import "os"

// notifyReload delivers nothing: the Windows service restarts to apply a
// config change.
func notifyReload() (<-chan os.Signal, func()) { return nil, func() {} }
