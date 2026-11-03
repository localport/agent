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
	PendingLost          Code = "AG001"
	DeviceCredential     Code = "AG002"
	NoTicketKeys         Code = "AG003"
	TicketKeysUnreadable Code = "AG004"
	TicketKeysBusy       Code = "AG005"
	RenewalInProgress    Code = "AG006"
	NotRenewable         Code = "AG007"

	UnsafeExecutable Code = "AG011"
	UntrustedPath    Code = "AG012"

	RunLocked            Code = "AG021"
	FleetTokenRetired    Code = "AG022"
	HostCapability       Code = "AG023"
	LoginsWithoutSession Code = "AG024"
	SessionWithoutLogins Code = "AG025"
	DesktopWithoutTarget Code = "AG026"
	FilesRootMissing     Code = "AG027"
	InvalidLocalConfig   Code = "AG028"
	RunAsAgentLogins     Code = "AG029"

	NoDevice         Code = "AG031"
	NoDeviceStarts   Code = "AG032"
	ServiceInstalled Code = "AG033"
	MergeConflict    Code = "AG034"
	ExtraArgument    Code = "AG035"
	NoDefaultLogin   Code = "AG036"

	ForeignUnit     Code = "AG041"
	NotInstalled    Code = "AG042"
	Unsupported     Code = "AG043"
	MarkedForDelete Code = "AG044"

	SessionsLocked Code = "AG053"

	SpoolFull            Code = "AG061"
	DiskLow              Code = "AG062"
	RecordingUnavailable Code = "AG063"

	NoTransport Code = "AG071"
)

// NewJoinCommand is the remedy for every lost or unusable device credential.
const NewJoinCommand = "create a new join command in the dashboard"

var registry = []Entry{
	{PendingLost, "Renewed device certificate lost", "the renewed device certificate is missing from the credential store; " + NewJoinCommand},
	{DeviceCredential, "Device credential used to reach devices", "this is a fleet device credential; it registers the device and cannot be used to reach devices"},
	{NoTicketKeys, "No ticket key set", "control plane returned no ticket key set"},
	{TicketKeysUnreadable, "Ticket keys unreadable", "ticket_keys.json cannot be read"},
	{TicketKeysBusy, "Ticket keys busy", "another process is writing this identity's ticket keys"},
	{RenewalInProgress, "Renewal in progress", "another process is renewing this credential"},
	{NotRenewable, "Credential does not renew", "a sign-in credential does not renew; run `localport login` again"},

	{UnsafeExecutable, "Unsafe service executable", "the localport executable cannot run as the device service"},
	{UntrustedPath, "Untrusted credential path", "untrusted credential path"},

	{RunLocked, "Devices already running", "localport is already running the devices of this config"},
	{FleetTokenRetired, "Fleet token retired", "fleet tokens are retired: create the device in the dashboard and run the command it shows"},
	{HostCapability, "Terminal or files with a host", "terminal and files act on this machine only and cannot be enabled with a host"},
	{LoginsWithoutSession, "Logins without terminal or files", "logins apply only to a device that enables terminal or files"},
	{SessionWithoutLogins, "Terminal or files without logins", "terminal and files need at least one login"},
	{DesktopWithoutTarget, "Desktop without target", "desktop needs an rdp or vnc target"},
	{FilesRootMissing, "Files root missing", "files root is not an existing directory"},
	{InvalidLocalConfig, "Invalid local config", "invalid local config"},
	{RunAsAgentLogins, "Logins with run_as_agent", "a device that runs sessions as the agent account names no logins"},

	{NoDevice, "No enrolled device", "no enrolled device"},
	{NoDeviceStarts, "No device can start", "no enrolled device can start: every device's credential is missing or unreadable (see above)"},
	{ServiceInstalled, "Device service installed", "the device service is installed and runs the enrolled devices"},
	{MergeConflict, "Flags conflict with stored settings", "the flags conflict with this device's stored settings"},
	{ExtraArgument, "Unexpected argument", "unexpected argument"},
	{NoDefaultLogin, "No default login", "no default login"},

	{ForeignUnit, "Foreign service definition", "a service definition not written by localport is in the way"},
	{NotInstalled, "Device service not installed", "no device service is installed"},
	{Unsupported, "No supported service manager", "this system has no service manager localport can install into (systemd, launchd or the Windows service manager)"},
	{MarkedForDelete, "Windows service marked for deletion", "the device service is deleted, but Windows keeps it until every handle to it closes"},

	{SessionsLocked, "Device sessions locked", "another process serves this device's sessions"},

	{SpoolFull, "Recording spool full", "recording: spool is full"},
	{DiskLow, "Disk space low for recordings", "recording: too little free disk space for the spool"},
	{RecordingUnavailable, "Recording unavailable", "recording unavailable"},

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
