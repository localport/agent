package launcher

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"github.com/localport/agent/internal/config"
)

// readWithin runs read under a deadline on conn and clears the deadline
// after it. The bound covers the request only: a helper may take up to
// helperStartTimeout before the answer, and each reply bounds its own write.
func readWithin(conn interface{ SetDeadline(time.Time) error }, timeout time.Duration, read func() error) error {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	return read()
}

const (
	// requestTimeout bounds reading the one request after accept.
	requestTimeout = 5 * time.Second
	// helperStartTimeout bounds a helper's account lookup, logon and session
	// setup and process start (A10); the launcher kills a helper still
	// starting after it.
	helperStartTimeout = 30 * time.Second
	// profileStartTimeout replaces helperStartTimeout once a Windows helper
	// reports it is loading the login's profile, which can take minutes on
	// a first logon or a roaming profile.
	profileStartTimeout = 120 * time.Second
	// maxHelpers bounds the helpers one launcher runs at once.
	maxHelpers = 64
	// replyTimeout bounds one response write, so an agent that stopped
	// reading never holds a launcher goroutine.
	replyTimeout = 5 * time.Second
	// CodeStartTimeout refuses a helper that did not start in time.
	CodeStartTimeout = "start_timeout"
)

// HelperRequest is what the launcher sends a helper on its control channel:
// the request after the config check, with the decision the config made. The
// helper trusts it; only the launcher writes it.
type HelperRequest struct {
	Kind  string `json:"kind"`
	Login string `json:"login"`
	Cols  int    `json:"cols"`
	Rows  int    `json:"rows"`
	Term  string `json:"term"`
	// Command is an exec session's command line (Request.Command).
	Command string `json:"command,omitempty"`
	// Env is the client's LANG and LC_* variables (Request.Env).
	Env map[string]string `json:"env,omitempty"`
	// Root is the directory an sftp session is confined to, the device's
	// files_root; empty confines it to the login's home.
	Root string `json:"root,omitempty"`
	// FilesDownload and FilesUpload are an sftp session's access
	// (Request.FilesDownload, Request.FilesUpload).
	FilesDownload bool `json:"files_download,omitempty"`
	FilesUpload   bool `json:"files_upload,omitempty"`
	// AgentAccount runs the session as the agent's own account without PAM
	// (tier 3 opt-in). Login is then the agent account's name. Unix only.
	AgentAccount bool `json:"agent_account,omitempty"`
	// ClientAddr is the session client's `ip:port` (Request.ClientAddr),
	// empty when unknown.
	ClientAddr string `json:"client_addr,omitempty"`
	// Pipe is the session channel pipe the helper opens (Windows).
	Pipe string `json:"pipe,omitempty"`
	// HasPassword announces a password trailer after the message (Windows).
	HasPassword bool `json:"password,omitempty"`
	// Password selects a LogonUser logon over S4U (Windows). It travels as
	// a raw trailer, never in JSON; the helper zeroes it after the logon.
	Password []byte `json:"-"`
}

// HelperReply is the helper's one control message: started, or a refusal
// code, either with the PAM messages for the client (FitMessages).
type HelperReply struct {
	Started  bool     `json:"started,omitempty"`
	Refused  string   `json:"refused,omitempty"`
	Messages []string `json:"messages,omitempty"`
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
	// A file session needs files enabled, a networking helper forwarding,
	// every other session terminal.
	need := config.CapabilityTerminal
	switch req.Kind {
	case KindSFTP:
		need = config.CapabilityFiles
	case KindForward:
		need = config.CapabilityForwarding
	}
	if !slices.Contains(d.Enable, need) {
		return HelperRequest{}, Refusal(CodeKindNotEnabled)
	}
	h := HelperRequest{Kind: req.Kind, Login: req.Login, Cols: req.Cols, Rows: req.Rows, Term: req.Term, Command: req.Command,
		Env: req.Env, ClientAddr: req.ClientAddr, Pipe: req.Pipe, HasPassword: req.HasPassword, Password: req.Password}
	if req.Kind == KindSFTP {
		h.Root, h.FilesDownload, h.FilesUpload = d.FilesRoot, req.FilesDownload, req.FilesUpload
	}
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
	req.HasPassword = len(req.Password) > 0
	if err := writeMessage(control, req); err != nil {
		return err
	}
	if req.HasPassword {
		return writeSecret(control, req.Password)
	}
	return nil
}

// ProgressProfile is the one HelperProgress stage: the Windows helper is
// about to load the login's profile.
const ProgressProfile = "profile"

// HelperProgress is a message a Windows helper may send once before its
// reply.
type HelperProgress struct {
	Stage string `json:"progress"`
}

// WriteHelperProgress writes a progress message on the control channel.
func WriteHelperProgress(control io.Writer, stage string) error {
	return writeMessage(control, HelperProgress{Stage: stage})
}

// ReadHelperReply reads a helper's reply: started, or a refusal. With
// onProgress set, at most one ProgressProfile message may come first and is
// passed to it; without, any progress message is refused.
func ReadHelperReply(control io.Reader, onProgress func(stage string)) (HelperReply, error) {
	progressed := false
	for {
		body, err := readBody(control)
		if err != nil {
			return HelperReply{}, err
		}
		var m struct {
			HelperReply
			Progress string `json:"progress"`
		}
		if err := decodeStrict(body, &m); err != nil {
			return HelperReply{}, errors.New("bad helper reply")
		}
		if m.Progress != "" {
			if onProgress == nil || progressed || m.Progress != ProgressProfile || m.Started || m.Refused != "" || len(m.Messages) > 0 {
				return HelperReply{}, errors.New("bad helper progress")
			}
			progressed = true
			onProgress(m.Progress)
			continue
		}
		if m.Started == (m.Refused != "") {
			return HelperReply{}, errors.New("bad helper reply")
		}
		return m.HelperReply, nil
	}
}

// startTimer is the part of *time.Timer a start bound uses.
type startTimer interface {
	Stop() bool
	Reset(time.Duration) bool
}

// startWatch bounds one helper start: helperStartTimeout, re-armed once to
// profileStartTimeout on the profile progress. At the bound it calls kill.
type startWatch struct {
	timer    startTimer
	timedOut atomic.Bool
}

func newStartWatch(after func(time.Duration, func()) startTimer, kill func()) *startWatch {
	w := &startWatch{}
	w.timer = after(helperStartTimeout, func() {
		w.timedOut.Store(true)
		kill()
	})
	return w
}

// progress re-arms the bound to profileStartTimeout. A bound that already
// fired stays fired: the start has timed out.
func (w *startWatch) progress() {
	if w.timer.Stop() {
		w.timer.Reset(profileStartTimeout)
	}
}

// stop ends the bound and reports whether it fired. A timer that fired
// counts even while its callback has not run yet: the kill follows.
func (w *startWatch) stop() bool {
	return !w.timer.Stop() || w.timedOut.Load()
}

// ReadHelperRequest reads the launcher's request on the helper's control
// channel.
func ReadHelperRequest(control io.Reader) (HelperRequest, error) {
	body, err := readBody(control)
	if err != nil {
		return HelperRequest{}, err
	}
	var req HelperRequest
	if err := decodeStrict(body, &req); err != nil {
		return HelperRequest{}, err
	}
	if !ValidEnv(req.Env) {
		return HelperRequest{}, errors.New("bad helper request environment")
	}
	if req.Root != "" && (req.Kind != KindSFTP || !filepath.IsAbs(req.Root)) {
		return HelperRequest{}, errors.New("bad helper request root")
	}
	if req.ClientAddr != "" && !ValidClientAddr(req.ClientAddr) {
		return HelperRequest{}, errors.New("bad helper request client address")
	}
	if req.HasPassword {
		if req.Password, err = readSecret(control); err != nil {
			return HelperRequest{}, err
		}
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
