package launcher

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/localport/agent/internal/config"
)

const (
	// requestTimeout bounds reading the one request after accept.
	requestTimeout = 5 * time.Second
	// helperStartTimeout bounds a helper's account lookup, logon and session
	// setup and process start (A10); the launcher kills a helper still
	// starting after it.
	helperStartTimeout = 30 * time.Second
	// maxHelpers bounds the helpers one launcher runs at once.
	maxHelpers = 64
	// replyTimeout bounds one response write, so an agent that stopped
	// reading never holds a launcher goroutine.
	replyTimeout = 5 * time.Second
	// CodeStartTimeout refuses a helper that did not start in time.
	CodeStartTimeout = "start_timeout"
)

// StartTimeout bounds a session start at the client: the launcher's own
// helper start bound plus slack for the connection.
const StartTimeout = helperStartTimeout + 5*time.Second

// HelperRequest is what the launcher sends a helper on its control channel:
// the request after the config check, with the decision the config made. The
// helper trusts it; only the launcher writes it.
type HelperRequest struct {
	Kind  string `json:"kind"`
	Login string `json:"login"`
	Cols  int    `json:"cols"`
	Rows  int    `json:"rows"`
	Term  string `json:"term"`
	// AgentAccount runs the session as the agent's own account without PAM
	// (tier 3 opt-in). Login is then the agent account's name. Unix only.
	AgentAccount bool `json:"agent_account,omitempty"`
	// Pipe is the session channel pipe the helper opens (Windows).
	Pipe string `json:"pipe,omitempty"`
	// Password selects a LogonUser logon over S4U (Windows); the helper
	// zeroes it after the logon.
	Password []byte `json:"password,omitempty"`
}

// HelperReply is the helper's one control message: started, or a refusal
// code.
type HelperReply struct {
	Started bool   `json:"started,omitempty"`
	Refused string `json:"refused,omitempty"`
}

// errHelperTimeout is a helper that did not answer within helperStartTimeout.
var errHelperTimeout = errors.New("helper did not start in time")

func startFailureCode(err error) string {
	if errors.Is(err, errHelperTimeout) {
		return CodeStartTimeout
	}
	return CodeSpawnFailed
}

// authorize checks req against the device config load reads now and returns
// what the helper is told. agentAccount is the login a run_as_agent device
// serves; empty where there is no such account (Windows), which refuses
// every run_as_agent request.
func authorize(load func() (*config.LocalConfig, error), agentAccount string, req Request) (HelperRequest, error) {
	cfg, err := load()
	if err != nil {
		return HelperRequest{}, fmt.Errorf("%w: %w", Refusal(CodeConfigUnreadable), err)
	}
	i := slices.IndexFunc(cfg.Devices, func(d config.LocalDevice) bool { return d.Identity.String() == req.Device })
	if i < 0 {
		return HelperRequest{}, Refusal(CodeDeviceUnknown)
	}
	d := cfg.Devices[i]
	if !slices.Contains(d.Enable, config.CapabilityTerminal) {
		return HelperRequest{}, Refusal(CodeKindNotEnabled)
	}
	h := HelperRequest{Kind: req.Kind, Login: req.Login, Cols: req.Cols, Rows: req.Rows, Term: req.Term, Pipe: req.Pipe, Password: req.Password}
	switch {
	case d.RunAsAgent:
		if agentAccount == "" || req.Login != agentAccount {
			return HelperRequest{}, Refusal(CodeLoginNotEnabled)
		}
		h.AgentAccount = true
	case !slices.Contains(d.Logins, req.Login):
		return HelperRequest{}, Refusal(CodeLoginNotEnabled)
	}
	return h, nil
}

// WriteHelperRequest writes the launcher's request on a helper's control
// channel.
func WriteHelperRequest(control io.Writer, req HelperRequest) error {
	return writeMessage(control, req)
}

// ReadHelperReply reads a helper's one reply: started, or a refusal.
func ReadHelperReply(control io.Reader) (HelperReply, error) {
	body, err := readBody(control)
	if err != nil {
		return HelperReply{}, err
	}
	var reply HelperReply
	if err := decodeStrict(body, &reply); err != nil || reply.Started == (reply.Refused != "") {
		return HelperReply{}, errors.New("bad helper reply")
	}
	return reply, nil
}

// ReadHelperRequest reads the launcher's request on the helper's control
// channel.
func ReadHelperRequest(control io.Reader) (HelperRequest, error) {
	body, err := readBody(control)
	if err != nil {
		return HelperRequest{}, err
	}
	var req HelperRequest
	err = decodeStrict(body, &req)
	clear(body)
	if err != nil {
		return HelperRequest{}, err
	}
	return req, nil
}

// WriteHelperReply writes the helper's one control reply.
func WriteHelperReply(control io.Writer, reply HelperReply) error {
	return writeMessage(control, reply)
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
