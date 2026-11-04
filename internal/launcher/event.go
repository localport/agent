package launcher

import (
	"encoding/json"
	"errors"
	"regexp"
	"unicode/utf8"
)

// File operations a FileEvent names (the SFTP operation set Teleport audits,
// plus exec for a command line).
const (
	OpExec    = "exec"
	OpRead    = "read"
	OpWrite   = "write"
	OpMkdir   = "mkdir"
	OpRmdir   = "rmdir"
	OpRemove  = "remove"
	OpRename  = "rename"
	OpSetstat = "setstat"
	OpSymlink = "symlink"
	OpLink    = "link"
	OpList    = "list"
)

// ResultOK is the Result of an operation that succeeded.
const ResultOK = "ok"

// Bounds of a FileEvent's fields.
const (
	maxEventPath   = 4 << 10
	maxEventResult = 64
)

// FileEvent is one entry of a recording's files log, an asciicast "f"
// event: an exec command line (written by the agent) or one SFTP operation
// (sent by the helper in a FrameEvent). Path and Target are as the client
// named them, inside the session's root. Bytes is the count read or written
// through one handle, reported when it closes. Result is ResultOK or the
// SFTP status or typed code of the failure.
type FileEvent struct {
	Op      string `json:"op"`
	Path    string `json:"path,omitempty"`
	Target  string `json:"target,omitempty"`
	Command string `json:"command,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	Result  string `json:"result,omitempty"`
}

var errBadEvent = errors.New("launcher: bad file event")

var resultPattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// Validate checks an event's operation, which fields it carries and their
// bounds.
func (e FileEvent) Validate() error {
	switch {
	case !utf8.ValidString(e.Path) || !utf8.ValidString(e.Target) || !utf8.ValidString(e.Command),
		len(e.Path) > maxEventPath || len(e.Target) > maxEventPath || len(e.Command) > MaxCommand,
		e.Bytes < 0,
		e.Result != "" && !resultPattern.MatchString(e.Result):
		return errBadEvent
	}
	switch e.Op {
	case OpExec:
		if e.Path != "" || e.Target != "" || e.Bytes != 0 || e.Result != "" {
			return errBadEvent
		}
		return nil
	case OpRead, OpWrite:
		if e.Target != "" {
			return errBadEvent
		}
	case OpRename, OpSymlink, OpLink:
		if e.Target == "" || e.Bytes != 0 {
			return errBadEvent
		}
	case OpMkdir, OpRmdir, OpRemove, OpSetstat, OpList:
		if e.Target != "" || e.Bytes != 0 {
			return errBadEvent
		}
	default:
		return errBadEvent
	}
	if e.Path == "" || e.Command != "" || e.Result == "" {
		return errBadEvent
	}
	return nil
}

// ParseFileEvent decodes and validates an event frame's payload.
func ParseFileEvent(p []byte) (FileEvent, error) {
	var e FileEvent
	if err := decodeStrict(p, &e); err != nil {
		return FileEvent{}, errBadEvent
	}
	if err := e.Validate(); err != nil {
		return FileEvent{}, err
	}
	return e, nil
}

// Marshal is the event's JSON, the payload of its frame and its "f" line.
func (e FileEvent) Marshal() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}
