// Package errcode holds the agent's local error codes and the renderer of
// user-facing errors. Every agent-side failure the user sees carries a code,
// printed as "message: detail [AG###]", so support can name the failure
// without the message text; With adds the local detail and the cause, and a
// coded error wrapping another prints both codes. Render builds the user
// text from typed parts only; Error() is the full chain for logs and
// --verbose. Flag usage errors carry no code. docs/ERRORS.md lists each code
// with what to do. Codes from the control plane or the edge (such as SE031)
// are not defined here and pass through unchanged (Remote).
package errcode

import (
	"fmt"

	"github.com/localport/agent/internal/agentaccount"
)

// Code is a local error code: "AG" and three digits. AG001 to AG134 are
// grouped by area (ranges in docs/ERRORS.md); later codes are not.
type Code string

// Error is a coded error. New makes its sentinels; With adds the detail the
// user sees and the cause. errors.Is matches any Error with the same Code.
type Error struct {
	Code Code
	Msg  string
	// Detail is local text the user sees after Msg: a path, a value, a
	// remedy. Never text from the network, the control plane or the edge.
	Detail string
	// Err is the cause. Render shows only its typed parts (see Render).
	Err error
}

// With returns a copy of e carrying cause and detail; either may be nil or
// empty. A sentinel stays unchanged.
func (e *Error) With(cause error, detail string) *Error {
	return &Error{Code: e.Code, Msg: e.Msg, Detail: detail, Err: cause}
}

// Error is the full diagnostic text, cause included, for logs and
// --verbose: "msg: detail: cause [code]".
func (e *Error) Error() string {
	s := e.Msg
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s + " [" + string(e.Code) + "]"
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
	PendingLost           Code = "AG001"
	DeviceCredential      Code = "AG002"
	NoTicketKeys          Code = "AG003"
	TicketKeysUnreadable  Code = "AG004"
	TicketKeysBusy        Code = "AG005"
	RenewalInProgress     Code = "AG006"
	NotRenewable          Code = "AG007"
	DesktopPinsUnreadable Code = "AG008"
	DesktopPinsBusy       Code = "AG009"
	CredentialNotSaved    Code = "AG010"

	UnsafeExecutable         Code = "AG011"
	UntrustedPath            Code = "AG012"
	PackageManagerExecutable Code = "AG013"
	SessionAppInvalid        Code = "AG014"

	RunAsAgentFiles      Code = "AG020"
	RunLocked            Code = "AG021"
	SessionsNeedService  Code = "AG022"
	HostCapability       Code = "AG023"
	LoginsWithoutSession Code = "AG024"
	SessionWithoutLogins Code = "AG025"
	DesktopWithoutTarget Code = "AG026"
	FilesRootMissing     Code = "AG027"
	InvalidLocalConfig   Code = "AG028"
	RunAsAgentLogins     Code = "AG029"
	ForwardingTerminal   Code = "AG030"

	NoDevice         Code = "AG031"
	NoDeviceStarts   Code = "AG032"
	ServiceInstalled Code = "AG033"
	MergeConflict    Code = "AG034"
	ExtraArgument    Code = "AG035"
	NoDefaultLogin   Code = "AG036"
	AgentChildFailed Code = "AG037"
	AgentChildStart  Code = "AG038"
	AgentChildOnly   Code = "AG039"

	ForeignUnit     Code = "AG041"
	NotInstalled    Code = "AG042"
	Unsupported     Code = "AG043"
	MarkedForDelete Code = "AG044"
	StoreNotPurged  Code = "AG045"

	SessionsLocked  Code = "AG053"
	LoginsDisabled  Code = "AG054"
	LauncherVersion Code = "AG055"

	SpoolFull            Code = "AG061"
	DiskLow              Code = "AG062"
	RecordingUnavailable Code = "AG063"

	NoTransport       Code = "AG071"
	RegisterFailed    Code = "AG072"
	UntrustedRedirect Code = "AG073"
	TooManyRedirects  Code = "AG074"
	InboundLimit      Code = "AG075"
	DataDialFailed    Code = "AG076"
	LocalDialFailed   Code = "AG077"
	PortRefused       Code = "AG078"
	RelayFailed       Code = "AG079"

	InstallerNotElevated Code = "AG081"
	InstallDirUnsafe     Code = "AG082"
	ServicesNotStopped   Code = "AG083"
	InstallNotCommitted  Code = "AG084"
	ServicesNotRestored  Code = "AG085"
	ForeignServiceInDir  Code = "AG086"
	MachinePathNotSet    Code = "AG087"
	InstallerStepInvalid Code = "AG088"
	UninstallNotPrepared Code = "AG089"
	InstallMixed         Code = "AG090"
	ServiceConfigBusy    Code = "AG091"
	UninstallEntryNotSet Code = "AG092"
	PurgeFailed          Code = "AG093"

	NoSessionCert        Code = "AG101"
	SSHFilesBusy         Code = "AG102"
	SSHLoginRefused      Code = "AG103"
	SSHConfigPathUnsafe  Code = "AG104"
	SSHClientFiles       Code = "AG105"
	SessionCertRefused   Code = "AG106"
	SessionMintFailed    Code = "AG107"
	SessionConnectFailed Code = "AG108"
	SessionEnded         Code = "AG109"

	EnrolledNotRecorded  Code = "AG110"
	EnrolledNotInstalled Code = "AG119"
	CredentialExpired    Code = "AG111"
	ExecutableUnknown    Code = "AG112"
	CurrentUserUnknown   Code = "AG113"
	OpenSSHUnavailable   Code = "AG114"
	CredentialNotKept    Code = "AG115"
	SettingsNotApplied   Code = "AG116"
	PinResetFailed       Code = "AG117"
	DeviceAmbiguous      Code = "AG118"
	DeviceNotFound       Code = "AG120"

	ClientCertUnusable  Code = "AG121"
	AccessConfigInvalid Code = "AG122"
	ForwardListenFailed Code = "AG123"
	DeviceRefused       Code = "AG124"
	DeviceUnreachable   Code = "AG125"

	ControlPlaneUnreachable Code = "AG126"
	ControlPlaneAnswer      Code = "AG127"
	NoCredential            Code = "AG128"
	NoMatchingCredential    Code = "AG129"
	CredentialsAmbiguous    Code = "AG130"
	CredentialUnreadable    Code = "AG131"
	CredentialStoreUnusable Code = "AG132"
	CITokenUnavailable      Code = "AG133"
	SignInExpired           Code = "AG134"

	ServiceManagerFailed    Code = "AG135"
	ServiceDefinitionFailed Code = "AG136"
	AccountMissing          Code = "AG137"
	AccountNotChanged       Code = "AG138"
	SystemNeedsRoot         Code = "AG139"
	AgentGroupMissing       Code = "AG140"
	LocalConfigUnusable     Code = "AG141"
	LocalConfigBusy         Code = "AG142"
	LocalConfigNotWritten   Code = "AG143"
	TunnelConfigInvalid     Code = "AG144"
	LogFileUnusable         Code = "AG145"
	TokenFileUnreadable     Code = "AG146"
	AgentAccountUnsafe      Code = "AG147"
	UnknownCommand          Code = "AG148"
	StoreBusy               Code = "AG149"
	DeviceNotNamed          Code = "AG150"
	NoDeviceChosen          Code = "AG151"
	AgentChildOutput        Code = "AG152"
	NotJoinToken            Code = "AG153"
	DeviceLimit             Code = "AG154"
	JoinTokenWithConfig     Code = "AG155"
	JoinTokenRequired       Code = "AG156"
	NoMuxAsRoot             Code = "AG157"
	NoCredentialChosen      Code = "AG158"
	SystemRunNotPrivileged  Code = "AG159"
	ControlEndpointFailed   Code = "AG160"
	ServiceInstallBusy      Code = "AG161"
	Unexpected              Code = "AG162"
)

// NewJoinCommand is the remedy for every lost or unusable device credential.
const NewJoinCommand = "create a new join command in the dashboard"

var registry = []Entry{
	{PendingLost, "Renewed device certificate lost", "the renewed device certificate is missing from the credential store; " + NewJoinCommand},
	{DeviceCredential, "Device credential used to reach devices", "this is a fleet device credential; it registers the device and cannot be used to reach devices"},
	{NoTicketKeys, "No session key set", "the control plane returned no session CA key set"},
	{TicketKeysUnreadable, "Session keys unreadable", "ticket_keys.json cannot be read"},
	{TicketKeysBusy, "Session keys busy", "another process is writing this identity's session CA keys"},
	{RenewalInProgress, "Renewal in progress", "another process is renewing this credential"},
	{NotRenewable, "Credential does not renew", "this credential does not renew: run `localport login` again for a sign-in, or `localport setup` with a new setup token once a setup-token credential expires"},
	{DesktopPinsUnreadable, "Desktop target keys unreadable", "desktop_pins.json cannot be read"},
	{DesktopPinsBusy, "Desktop target keys busy", "another process is changing this device's desktop target keys"},
	{CredentialNotSaved, "Device credential not saved", "the issued device credential could not be saved in the credential store"},

	{UnsafeExecutable, "Unsafe service executable", "the localport executable cannot run as the device service"},
	{UntrustedPath, "Untrusted path", "a credential or system file path is a link, has the wrong owner, or is too open"},
	{PackageManagerExecutable, "Package manager executable", "a localport installed by a package manager cannot run as the device service"},
	{SessionAppInvalid, "Session app invalid", "Localport.app beside the localport executable is missing or not signed by Localport"},

	{RunAsAgentFiles, "Files with run_as_agent", "files on a device that runs sessions as the agent account needs a files root: set one with --files-root DIR"},
	{RunLocked, "Devices already running", "localport is already running the devices of this config"},
	{SessionsNeedService, "Sessions need the device service", "terminal and files sessions run only under the installed device service, because the session launcher serves only its account"},
	{HostCapability, "Terminal, files or forwarding with a host", "terminal, files and forwarding act on this machine only and cannot be enabled with a host"},
	{LoginsWithoutSession, "Logins without terminal or files", "logins apply only to a device that enables terminal or files"},
	{SessionWithoutLogins, "Terminal or files without logins", "terminal and files need at least one login"},
	{DesktopWithoutTarget, "Desktop without target", "desktop needs an rdp or vnc target"},
	{FilesRootMissing, "Files root missing", "files root is not an existing directory"},
	{InvalidLocalConfig, "Invalid local config", "invalid local config"},
	{RunAsAgentLogins, "Logins with run_as_agent", "a device that runs sessions as the agent account names no logins"},
	{ForwardingTerminal, "Forwarding without terminal", "forwarding rides an ssh connection and needs terminal enabled"},

	{NoDevice, "No enrolled device", "no enrolled device"},
	{NoDeviceStarts, "No device can start", "no enrolled device can start: each one is paused, removed, or its credential is missing or unreadable (see above)"},
	{ServiceInstalled, "Device service installed", "the device service is installed and runs the enrolled devices"},
	{MergeConflict, "Flags conflict with stored settings", "the flags conflict with this device's stored settings"},
	{ExtraArgument, "Unexpected argument", "unexpected argument"},
	{NoDefaultLogin, "No default login", "no default login"},
	{AgentChildFailed, "Agent account step failed", "the step localport runs as the agent account failed (its error is above)"},
	{AgentChildStart, "Agent account step not started", "localport could not start itself as the agent account " + agentaccount.Name},
	{AgentChildOnly, "Internal command", "this command is run only by localport itself, as the agent account"},

	{ForeignUnit, "Foreign service definition", "a service definition not written by localport is in the way"},
	{NotInstalled, "Device service not installed", "no device service is installed"},
	{Unsupported, "No supported service manager", "this system has no service manager localport can install into (systemd, OpenRC, OpenWrt procd, launchd or the Windows service manager)"},
	{MarkedForDelete, "Windows service marked for deletion", "the device service is deleted, but Windows keeps it until every handle to it closes"},
	{StoreNotPurged, "Device credentials not purged", "removing the device credentials, the recording spool or the agent's directories failed"},

	{SessionsLocked, "Device sessions locked", "another process serves this device's sessions"},
	{LoginsDisabled, "Logins disabled", "/etc/nologin exists, so only root can log in"},
	{LauncherVersion, "Session launcher from another release", "the session launcher service runs another localport release; restart it"},

	{SpoolFull, "Recording spool full", "recording: spool is full"},
	{DiskLow, "Disk space low for recordings", "recording: too little free disk space for the spool"},
	{RecordingUnavailable, "Recording unavailable", "recording unavailable"},

	{NoTransport, "No transport", "no transport available: every candidate failed (check edge reachability and firewall)"},
	{RegisterFailed, "Registration failed", "registration with the edge failed"},
	{UntrustedRedirect, "Redirect to an untrusted host", "the edge redirected to a host outside the Localport service"},
	{TooManyRedirects, "Too many redirects", "the edge redirected too many times"},
	{InboundLimit, "Too many inbound connections", "an inbound connection was refused: too many are opening at once"},
	{DataDialFailed, "Data connection failed", "a data connection to the edge failed"},
	{LocalDialFailed, "Local service unreachable", "the local service did not accept the connection"},
	{PortRefused, "Port not allowed", "the requested port is not allowed on this device"},
	{RelayFailed, "Connection broke while relaying", "the connection broke while relaying"},

	{InstallerNotElevated, "Installer step not elevated", "this installer step needs an elevated Administrator"},
	{InstallDirUnsafe, "Install directory unsafe", "the install directory can be changed by someone other than SYSTEM and Administrators"},
	{ServicesNotStopped, "Device services did not stop", "the device services did not stop; the install was undone"},
	{InstallNotCommitted, "Install not committed", "a product file was not put in place; the install was undone"},
	{ServicesNotRestored, "Device services not re-registered", "the device services were not registered for the new executables; the install was undone"},
	{ForeignServiceInDir, "Foreign service in the install directory", "a service localport did not create runs a program in the install directory"},
	{MachinePathNotSet, "Machine PATH not updated", "the machine PATH was not updated; the install was undone"},
	{InstallerStepInvalid, "Installer step invalid", "the installer named an unknown step or wrong arguments"},
	{UninstallNotPrepared, "Uninstall not prepared", "an uninstall step failed; the uninstall was undone"},
	{InstallMixed, "Install rollback failed", "the install failed and undoing it also failed"},
	{ServiceConfigBusy, "Service configuration busy", "another installer or service command is changing the device services"},
	{UninstallEntryNotSet, "Uninstall entry not written", "the Add/Remove Programs entry was not written; the install was undone"},
	{PurgeFailed, "Device state not purged", "the uninstall finished, but removing the device identities and config failed"},

	{NoSessionCert, "No session certificate", "no session certificate"},
	{SSHFilesBusy, "SSH client files busy", "another localport ssh-cert is still minting a certificate for this credential"},
	{SSHLoginRefused, "Login refused for SSH", "this login cannot be used with localport's SSH commands"},
	{SSHConfigPathUnsafe, "Path unusable in ssh_config", "a localport path holds a character ssh_config cannot carry safely"},
	{SSHClientFiles, "SSH client files unusable", "the SSH client files of this credential cannot be read or written"},
	{SessionCertRefused, "Session certificate answer refused", "the control plane's session certificate answer is not usable"},
	{SessionMintFailed, "Session certificate not issued", "the control plane did not issue a session certificate"},
	{SessionConnectFailed, "Session connection failed", "the connection to the device's session failed"},
	{SessionEnded, "Session ended", "the session ended"},

	{EnrolledNotRecorded, "Device enrolled, config not written", "the device is enrolled, but the local config was not written"},
	{CredentialExpired, "Credential expired", "the credential has expired"},
	{ExecutableUnknown, "localport path unknown", "the path of this localport executable cannot be found"},
	{CurrentUserUnknown, "Current user unknown", "the account running this command cannot be looked up"},
	{OpenSSHUnavailable, "OpenSSH client unavailable", "the OpenSSH client (ssh) cannot be run"},
	{CredentialNotKept, "Credential not saved", "the issued credential could not be saved in the credential store"},
	{SettingsNotApplied, "Settings saved but not applied", "the settings are saved, but the run serving the devices did not apply them"},
	{PinResetFailed, "Desktop key not forgotten", "the trusted desktop server key could not be forgotten"},
	{DeviceAmbiguous, "Device name ambiguous", "the name matches more than one enrolled device"},
	{DeviceNotFound, "Device not found", "the name matches no enrolled device"},
	{EnrolledNotInstalled, "Device enrolled, service not installed", "the device is enrolled and its credential saved, but its service was not installed"},

	{ClientCertUnusable, "Client certificate unusable", "the client certificate cannot be used"},
	{AccessConfigInvalid, "Invalid access config", "invalid access config"},
	{ForwardListenFailed, "Local forward not opened", "the local forward could not listen"},
	{DeviceRefused, "Device refused the connection", "the device or its edge refused the connection"},
	{DeviceUnreachable, "Device unreachable", "the device could not be reached"},

	{ControlPlaneUnreachable, "Control plane unreachable", "the control plane could not be reached"},
	{ControlPlaneAnswer, "Control plane answer unusable", "the control plane's answer is not usable"},
	{NoCredential, "No credential", "no credential on this machine; run localport login, or localport setup <TOKEN>"},
	{NoMatchingCredential, "No matching credential", "no credential on this machine matches"},
	{CredentialsAmbiguous, "Several credentials match", "several credentials match; narrow the choice with --identity"},
	{CredentialUnreadable, "Credential unreadable", "the stored credential cannot be read"},
	{CredentialStoreUnusable, "Credential store unusable", "the credential store cannot be used"},
	{CITokenUnavailable, "CI token unavailable", "the CI platform's identity token could not be obtained"},
	{SignInExpired, "Sign-in expired", "the sign-in expired before it was approved; run localport login again"},

	{ServiceManagerFailed, "Service manager failed", "the service manager could not carry out the step"},
	{ServiceDefinitionFailed, "Service definition not written", "the device service definition could not be read, written or removed"},
	{ServiceInstallBusy, "Service install busy", "another localport service install or uninstall is running"},
	{Unexpected, "Unexpected error", "localport could not finish the command"},
	{AccountMissing, "Agent account missing", "the agent account " + agentaccount.Name + " does not exist; create it with: sudo localport service install"},
	{AccountNotChanged, "Agent account not changed", "the agent account " + agentaccount.Name + " could not be created, looked up or inspected"},
	{SystemNeedsRoot, "Needs root", "only root or an elevated Administrator changes the device config directory"},
	{AgentGroupMissing, "Agent group missing", "the group " + agentaccount.Name + " does not exist; create it with: sudo localport service install"},
	{LocalConfigUnusable, "Local config unusable", "the local config cannot be located, read, secured or locked"},
	{LocalConfigBusy, "Local config busy", "another localport command is still changing the local config"},
	{LocalConfigNotWritten, "Local config not written", "the local config could not be written"},
	{TunnelConfigInvalid, "Invalid tunnel config", "the tunnel config file cannot be read or holds an invalid entry"},
	{LogFileUnusable, "Log file unusable", "the --log-file path cannot be opened as the agent's log"},
	{TokenFileUnreadable, "Token file unreadable", "the token file named by the _FILE variable cannot be read"},
	{AgentAccountUnsafe, "Agent account unsafe", "the agent account " + agentaccount.Name + " can log in or reaches other users' files; remove it, then run: sudo localport service install"},
	{UnknownCommand, "Unknown command", "no such localport command"},
	{StoreBusy, "Credential store busy", "localport service uninstall --purge is deleting the device credentials; retry when it finishes"},
	{DeviceNotNamed, "Device not named", "several devices are enrolled on this machine; name one, or give --all"},
	{NoDeviceChosen, "No device chosen", "no device was chosen"},
	{AgentChildOutput, "Agent account step output refused", "the step localport runs as the agent account returned output localport does not accept; retry, and reinstall localport if it persists"},
	{NotJoinToken, "Not a join token", "the argument is not a join token"},
	{DeviceLimit, "Device limit reached", "this machine already has the maximum number of devices"},
	{JoinTokenWithConfig, "Join token with --config", "a join token cannot be combined with --config"},
	{JoinTokenRequired, "Join token required", "join token required: create the device in the dashboard and run the command it shows"},
	{NoMuxAsRoot, "--no-mux not available as root", "--no-mux is not available to a device enrolled as root; run it as an ordinary user, or leave it out"},
	{NoCredentialChosen, "No credential chosen", "no credential was chosen"},
	{SystemRunNotPrivileged, "System run needs root", "run --system serves this machine's devices in the foreground only as root or an elevated Administrator: run sudo localport run, or on Windows localport run in an elevated shell"},
	{ControlEndpointFailed, "Control endpoint unavailable", "the foreground run could not serve its control endpoint, which up, down and set use to apply settings"},
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
