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
	LimitTunnelCount       LimitType = "tunnel_count"
	LimitNoPlan            LimitType = "no_plan"
	LimitBlocked           LimitType = "blocked"
)

type RegisterPayload struct {
	Token      string `json:"token"`
	Protocol   string `json:"protocol"`
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Subdomain  string `json:"subdomain,omitempty"`

	// AgentVersion and AgentOS describe the BINARY, for the connection's audit
	// record: "which build was this, on what platform". Both are SELF-ASSERTED
	// and forensic only: nothing on the server gates on either, and an edge that
	// does not read them simply sees them absent.
	AgentVersion string `json:"agent_version,omitempty"`
	AgentOS      string `json:"agent_os,omitempty"`

	// A registering client asserts nothing that access depends on: a grant
	// names devices directly (`*`, `gw-*`, `gw-01`).

	// ResumeSessionID echoes the session_id from this tunnel's previous
	// RegisterAck so the edge can replace the stale session on reconnect.
	ResumeSessionID string `json:"resume_session_id,omitempty"`
}

type RegisterAckPayload struct {
	Success    bool      `json:"success"`
	TunnelID   string    `json:"tunnel_id"`
	TunnelName string    `json:"tunnel_name"`
	Region     string    `json:"region"`
	RegionName string    `json:"region_name,omitempty"` // display name; empty from older edges
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
	MTLS       *MTLSInfo `json:"mtls,omitempty"`

	// SessionID identifies this session; send it back as resume_session_id
	// on the next Register to reclaim the slot immediately.
	SessionID string `json:"session_id,omitempty"`
}

// MTLSInfo describes the mutual-TLS posture of a tunnel. When Enabled is true,
// consumers must present a client certificate the tunnel trusts.
//
// There is no CA fingerprint here. A tunnel trusts several certificate
// authorities at once, ours and any the customer registered, so one fingerprint
// would not name the one that matters. The field that used to be here was never
// populated by the edge either, so the agent printed an empty value. Consumers
// verify the SERVER against system roots; the CA they care about is the one in
// their own bundle.
type MTLSInfo struct {
	Enabled bool `json:"enabled"`
}

type NewConnectionPayload struct {
	ConnectionID string `json:"connection_id"`
	RemoteAddr   string `json:"remote_addr"`
}

type ConnectionReadyPayload struct {
	ConnectionID string `json:"connection_id"`
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

// MuxBindPayload binds a multiplexed data connection to a session that is
// already registered on the control connection.
//
// It carries the same replay protection as a registration because it is dialed
// and authenticated independently: the token proves which tunnel, the session id
// names which live client the streams belong to, and neither alone is accepted.
type MuxBindPayload struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	ClientID  string `json:"client_id"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
}

// MuxBindAckPayload reports whether the edge accepted the data connection. A
// refusal is not fatal; the tunnel continues on dial-back.
type MuxBindAckPayload struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Code    string `json:"code,omitempty"`
}
