package session

import (
	"errors"
	"time"
)

const (
	// userLookupTimeout bounds every lookup run of one ticket together.
	userLookupTimeout = 2 * time.Second
	// userLookupReserve is the part of the first-frame time kept for Accept
	// and the spend's fsync.
	userLookupReserve = 3 * time.Second
)

// errNoUser is a lookup that found no account for the login. Every other
// lookup error is a failure of the directory or the tool.
var errNoUser = errors.New("no such user")
