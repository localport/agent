package a

import "fmt"

// Tests build such errors on purpose; test files are not checked.
var _ = fmt.Errorf("enrol: %w", ErrCoded)
