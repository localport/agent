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
)

type RegisterPayload struct {
	Token      string `json:"token"`
	Protocol   string `json:"protocol"`
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Subdomain  string `json:"subdomain,omitempty"`
}

type RegisterAckPayload struct {
	Success   bool      `json:"success"`
	TunnelID  string    `json:"tunnel_id"`
	PublicURL string    `json:"public_url"`
	URLs      []string  `json:"urls"`
	Subdomain string    `json:"subdomain"`
	Port      uint16    `json:"port"`
	Mode      string    `json:"mode"`
	Protocol  string    `json:"protocol"`
	Error     string    `json:"error,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
	Retryable *bool     `json:"retryable,omitempty"`
	LimitType LimitType `json:"limit_type,omitempty"`
}

type NewConnectionPayload struct {
	ConnectionID string `json:"connection_id"`
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

type SetActivePayload struct {
	Active bool `json:"active"`
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
