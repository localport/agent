package proto

import "fmt"

// MaxMessageSize is the upper bound on a single framed message (1 MiB).
const MaxMessageSize = 1 << 20

// MessageType is the one-byte discriminator that identifies a control message.
type MessageType byte

const (
	MsgRegister        MessageType = 1
	MsgRegisterAck     MessageType = 2
	MsgNewConnection   MessageType = 3
	MsgConnectionReady MessageType = 4
	MsgHeartbeat       MessageType = 5
	MsgHeartbeatAck    MessageType = 6
	MsgSetActive       MessageType = 7
	MsgShutdown        MessageType = 8
	MsgError           MessageType = 9
	MsgRedirect        MessageType = 10
	MsgMuxBind         MessageType = 11
	MsgMuxBindAck      MessageType = 12
	MsgPortsUpdate     MessageType = 13
	MsgPortsAck        MessageType = 14
)

var msgNames = map[MessageType]string{
	MsgRegister:        "Register",
	MsgRegisterAck:     "RegisterAck",
	MsgNewConnection:   "NewConnection",
	MsgConnectionReady: "ConnectionReady",
	MsgHeartbeat:       "Heartbeat",
	MsgHeartbeatAck:    "HeartbeatAck",
	MsgSetActive:       "SetActive",
	MsgShutdown:        "Shutdown",
	MsgError:           "Error",
	MsgRedirect:        "Redirect",
	MsgMuxBind:         "MuxBind",
	MsgMuxBindAck:      "MuxBindAck",
	MsgPortsUpdate:     "PortsUpdate",
	MsgPortsAck:        "PortsAck",
}

func (m MessageType) String() string {
	if name, ok := msgNames[m]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", m)
}

// LimitType names a resource limit reported by the edge.
type LimitType string

const (
	LimitUnspecified       LimitType = ""
	LimitBandwidth         LimitType = "bandwidth"
	LimitClientConnections LimitType = "client_connections"
	LimitNoPlan            LimitType = "no_plan"
	LimitPaymentDuePaused  LimitType = "payment_due_paused"
	LimitPlanPaused        LimitType = "plan_paused"
	LimitBlocked           LimitType = "blocked"
)

// Register kinds. A tunnel publishes a local service. A device joins a fleet.
const (
	KindTunnel = "tunnel"
	KindDevice = "device"
)

// RegisterPayload is the first message on a control connection. A tunnel
// authenticates with Token; a device sends no token and authenticates with
// the TLS client certificate of the connection.
type RegisterPayload struct {
	Token      string `json:"token,omitempty"`
	Kind       string `json:"kind,omitempty"` // tunnel or device
	Protocol   string `json:"protocol"`       // http, tcp or tls for a tunnel, empty for a device
	ClientName string `json:"client_name"`
	// AllowedPorts is a device's port ceiling, omitted when none is set.
	AllowedPorts []PortRange `json:"allowed_ports,omitempty"`
	Timestamp    int64       `json:"timestamp"`
	Nonce        string      `json:"nonce"`
	Subdomain    string      `json:"subdomain,omitempty"`

	// AgentVersion and AgentOS identify the build and platform in the audit record.
	// They are self-reported and not used for access decisions.
	AgentVersion string `json:"agent_version,omitempty"`
	AgentOS      string `json:"agent_os,omitempty"`

	// ResumeSessionID echoes the session_id from this tunnel's previous
	// RegisterAck so the edge can replace the stale session on reconnect.
	ResumeSessionID string `json:"resume_session_id,omitempty"`

	// Capabilities (terminal, files, desktop), Logins and Desktop (rdp, vnc)
	// are what a device enabled in its local config. The agent enforces them;
	// the API's session mint also refuses a kind whose capability or desktop
	// protocol is not listed.
	Capabilities []string `json:"capabilities,omitempty"`
	Logins       []string `json:"logins,omitempty"`
	Desktop      []string `json:"desktop,omitempty"`

	// SessionAuth (pam, no_pam) and FullDiskAccess (granted, denied, unknown;
	// omitted off macOS) are the session launcher's probe; RunAsAgent is the
	// device config's opt-in to run sessions as the agent account. Display
	// only: the control plane shows them and decides nothing on them.
	SessionAuth    string `json:"session_auth,omitempty"`
	RunAsAgent     bool   `json:"run_as_agent,omitempty"`
	FullDiskAccess string `json:"full_disk_access,omitempty"`
}

type RegisterAckPayload struct {
	Success    bool      `json:"success"`
	TunnelID   string    `json:"tunnel_id"`
	TunnelName string    `json:"tunnel_name"`
	Region     string    `json:"region"`
	RegionName string    `json:"region_name,omitempty"` // display name
	PublicURL  string    `json:"public_url"`
	URLs       []string  `json:"urls"`
	Subdomain  string    `json:"subdomain"`
	Port       uint16    `json:"port"`
	Mode       string    `json:"mode"`
	Protocol   string    `json:"protocol"`
	Error      string    `json:"error,omitempty"`
	ErrorCode  string    `json:"error_code,omitempty"`
	Retryable  *bool     `json:"retryable,omitempty"`
	LimitType  LimitType `json:"limit_type,omitempty"`

	// SessionID identifies this session. Send it as resume_session_id on the
	// next Register to reclaim the slot.
	SessionID string `json:"session_id,omitempty"`

	// Ports lists the device's allowed ports as set in the dashboard, with their
	// version.
	PortsVersion uint64       `json:"ports_version,omitempty"`
	Ports        []DevicePort `json:"ports,omitempty"`

	// RevokedTicketKids lists session ticket signing key ids the device must
	// stop trusting. Only a device receives it.
	RevokedTicketKids []string `json:"revoked_ticket_kids,omitempty"`
}

// PortRange is an inclusive range of ports.
type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

// DevicePort is one open port on a device.
type DevicePort struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"` // tcp | http
}

// PortsUpdatePayload replaces a device's allowed ports when Version is higher
// than the current one. The device answers with PortsAck.
type PortsUpdatePayload struct {
	Version uint64       `json:"version"`
	Ports   []DevicePort `json:"ports"`
}

// PortsAckPayload reports the port version the device serves.
type PortsAckPayload struct {
	Version uint64 `json:"version"`
}

type NewConnectionPayload struct {
	ConnectionID string `json:"connection_id"`
	RemoteAddr   string `json:"remote_addr"`

	// A device connection carries the port to dial, its protocol and the
	// consumer identity. Consumer is shown in agent output and is not sent to
	// the local service.
	TargetPort     uint16 `json:"target_port,omitempty"`
	TargetProtocol string `json:"target_protocol,omitempty"`
	Consumer       string `json:"consumer,omitempty"`
}

type ConnectionReadyPayload struct {
	ConnectionID string `json:"connection_id"`
	// Status is 0 or 200 when accepted, 403 for a port not served and 502 for
	// an unreachable target.
	Status int `json:"status,omitempty"`
}

type HeartbeatPayload struct {
	Timestamp int64 `json:"timestamp"`
}

type HeartbeatAckPayload struct {
	Timestamp int64 `json:"timestamp"`
}

type ShutdownPayload struct {
	Reason    string    `json:"reason,omitempty"`
	Code      string    `json:"code,omitempty"`
	Retryable *bool     `json:"retryable,omitempty"`
	LimitType LimitType `json:"limit_type,omitempty"`
}

type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type RedirectPayload struct {
	EdgeAddr string `json:"edge_addr"`
	EdgeID   string `json:"edge_id"`
	Reason   string `json:"reason"`
}

// MuxBindPayload binds a multiplexed data connection to a session registered on
// the control connection. It is authenticated separately and has the same replay
// protection as Register. A tunnel sends its token, a device none: its
// connection presents the client certificate its session registered with. The
// session id is always required.
type MuxBindPayload struct {
	Token     string `json:"token,omitempty"`
	SessionID string `json:"session_id"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	// Purpose is empty for the port mux and "session" for a device's session
	// mux, on which the agent is the HTTP/2 client.
	Purpose string `json:"purpose,omitempty"`
}

// MuxBindPurposeSession is the MuxBind purpose of a device's session mux.
const MuxBindPurposeSession = "session"

// MuxBindAckPayload reports whether the edge accepted the data connection. A
// refusal is not fatal; the tunnel continues on dial-back.
type MuxBindAckPayload struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Code    string `json:"code,omitempty"`
}
