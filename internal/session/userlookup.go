package session

import (
	"context"
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

// resolveUser resolves a ticket's login to its account before the ticket is
// spent. streamStart is the stream's start, from which the first-frame timer
// runs. A non-empty code refuses the stream: login_not_allowed when the login
// has no account or is not the agent's own user while the agent is not root,
// agent_busy when the lookup failed or no time is left for it. Every refusal
// is logged with its reason. A ticket without a login resolves to nil.
func (s *Server) resolveUser(login string, streamStart time.Time) (*userRecord, string) {
	if login == "" {
		return nil, ""
	}
	now := time.Now()
	deadline := streamStart.Add(firstFrameTimeout - userLookupReserve)
	if limit := now.Add(userLookupTimeout); limit.Before(deadline) {
		deadline = limit
	}
	if !deadline.After(now) {
		s.log("session: user lookup for %s: no time left before the first-frame deadline", login)
		return nil, CodeAgentBusy
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	user, err := s.users(ctx, login)
	if errors.Is(err, errNoUser) {
		s.log("session: user lookup for %s: no such user", login)
		return nil, CodeLoginNotAllowed
	}
	if err != nil {
		s.log("session: user lookup for %s: %v", login, err)
		return nil, CodeAgentBusy
	}
	// Without root the agent can only run as itself.
	if euid := s.euid(); euid != 0 && int64(euid) != int64(user.UID) {
		s.log("session: login %s is not the agent's own user and the agent is not root", login)
		return nil, CodeLoginNotAllowed
	}
	return user, ""
}
