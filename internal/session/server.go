package session

// userRecord is the account a kind runs as, resolved by Server.resolveUser.
// Groups starts with GID. Shell is empty when the lookup gives none (macOS
// with the agent as root).
type userRecord struct {
	Name   string
	UID    uint32
	GID    uint32
	Groups []uint32
	Home   string
	Shell  string
}
