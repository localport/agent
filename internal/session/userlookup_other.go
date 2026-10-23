//go:build !linux && !darwin

package session

import (
	"context"
	"errors"
)

// lookupUser fails: this platform has no account lookup, and kindFor serves
// no kind that needs one.
func lookupUser(context.Context, string) (*userRecord, error) {
	return nil, errors.New("no account lookup on this platform")
}
