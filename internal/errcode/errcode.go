// Package errcode holds the agent's local error codes. Every named refusal
// the agent reports to the user carries one, printed as "message [AG###]",
// so support can name the failure without the message text. A caller that
// wraps a sentinel with detail ("%w: detail") prints the code before the
// detail, and a coded error wrapping another prints both codes. OS failures
// and flag usage errors carry no code. docs/ERRORS.md lists each code with
// what to do. Codes from the control plane or the edge (such as SE031) are
// not defined here and pass through unchanged.
package errcode

import "fmt"

// Code is a local error code: "AG" and three digits. Codes are grouped by
// package in blocks of ten.
type Code string

// Error is a coded error. Its sentinels come from New; a caller wraps one
// with fmt.Errorf("...: %w", sentinel) or sets Err to keep a cause. errors.Is
// matches any Error with the same Code.
type Error struct {
	Code Code
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error() + " [" + string(e.Code) + "]"
	}
	return e.Msg + " [" + string(e.Code) + "]"
}

func (e *Error) Unwrap() error { return e.Err }

// Is matches another Error with the same Code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// Entry is one registered code: Title names it in docs/ERRORS.md and Msg is
// the message its errors print.
type Entry struct {
	Code  Code
	Title string
	Msg   string
}

// The codes. Each has one Entry in registry.
const (
	DeviceCredential     Code = "AG002"
	TicketKeysUnreadable Code = "AG004"
	TicketKeysBusy       Code = "AG005"
	RenewalInProgress    Code = "AG006"
	NotRenewable         Code = "AG007"

	UnsafeExecutable Code = "AG011"
	UntrustedPath    Code = "AG012"

	NoTransport Code = "AG071"
)

// NewJoinCommand is the remedy for every lost or unusable device credential.
const NewJoinCommand = "create a new join command in the dashboard"

var registry = []Entry{
	{DeviceCredential, "Device credential used to reach devices", "this is a fleet device credential; it registers the device and cannot be used to reach devices"},
	{TicketKeysUnreadable, "Ticket keys unreadable", "ticket_keys.json cannot be read"},
	{TicketKeysBusy, "Ticket keys busy", "another process is writing this identity's ticket keys"},
	{RenewalInProgress, "Renewal in progress", "another process is renewing this credential"},
	{NotRenewable, "Credential does not renew", "a sign-in credential does not renew; run `localport login` again"},

	{UnsafeExecutable, "Unsafe service executable", "the localport executable cannot run as the device service"},
	{UntrustedPath, "Untrusted credential path", "untrusted credential path"},

	{NoTransport, "No transport", "no transport available: every candidate failed (check edge reachability and firewall)"},
}

// New returns the sentinel of a registered code. An unregistered code is a
// programming error and panics at package initialization.
func New(code Code) *Error {
	for _, e := range registry {
		if e.Code == code {
			return &Error{Code: code, Msg: e.Msg}
		}
	}
	panic(fmt.Sprintf("errcode: %s is not registered", code))
}
