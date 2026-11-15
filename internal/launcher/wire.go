// Package launcher is the privilege boundary between the unprivileged network
// agent and the root session launcher, `localport-session launcher`.
//
// The agent connects to the launcher's Unix socket, sends one Request (with
// the session channel's file descriptor attached for a session kind) and
// reads Responses until the connection ends. The launcher authorizes the
// connection by the peer's uid, re-reads the root-owned device config,
// refuses anything that config does not enable, and starts one
// `localport-session helper` per session. The helper and the agent then talk
// over the channel descriptor with the frames in frame.go; the launcher never
// sees session bytes.
//
// Every message on the request connection is a 4-byte big-endian length and
// a JSON object. The launcher never parses anything but these typed fields.
package launcher

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/localport/agent/internal/errcode"
)

// Version is the request schema version. A launcher refuses any other with
// CodeVersionMismatch.
const Version = 2

// AgentAccount is the system account the network agent runs as: the only
// peer the launcher serves, and the login of a run_as_agent session.
const AgentAccount = "localport"

// MaxMessage bounds one request or response body in bytes.
const MaxMessage = 4 << 10

// Kinds a request may carry.
const (
	KindTerminal = "terminal"
	KindExec     = "exec"
	KindSFTP     = "sftp"
	KindProbe    = "probe"
	// KindForward starts one connection's networking helper: the forward
	// server, run as the login, dials and listens for its port forwards
	// (forwardwire.go).
	KindForward = "forward"
)

// Refusal codes. The agent maps each to a session error code.
const (
	CodeBadRequest         = "bad_request"
	CodeUnsupportedKind    = "unsupported_kind"
	CodeDeviceUnknown      = "device_unknown"
	CodeKindNotEnabled     = "kind_not_enabled"
	CodeLoginNotEnabled    = "login_not_enabled"
	CodeBusy               = "busy"
	CodeAccountUnavailable = "account_unavailable"
	CodeAccountRefused     = "account_refused"
	CodePAMFailed          = "pam_failed"
	CodeSpawnFailed        = "spawn_failed"
	CodeConfigUnreadable   = "config_unreadable"
	CodeInternal           = "internal"
	// CodeVersionMismatch refuses a request of another Version: the agent
	// and the launcher service come from different releases.
	CodeVersionMismatch = "version_mismatch"
)

// Full Disk Access states a probe reports.
const (
	FullDiskAccessGranted = "granted"
	FullDiskAccessDenied  = "denied"
	FullDiskAccessUnknown = "unknown"
)

// Request is the one message an agent sends per connection.
type Request struct {
	V      int    `json:"v"`
	Kind   string `json:"kind"`
	Device string `json:"device,omitempty"`
	Login  string `json:"login,omitempty"`
	Cols   int    `json:"cols,omitempty"`
	Rows   int    `json:"rows,omitempty"`
	Term   string `json:"term,omitempty"`
	// Command is an exec session's command line, run by the login's shell
	// with -c; empty runs the login shell itself without a terminal. An exec
	// session has a PTY when Cols and Rows are set, else pipes.
	Command string `json:"command,omitempty"`
	// Env holds the client's LANG and LC_* variables (SSH env requests,
	// ValidEnv); the helper sets them after the login's environment.
	Env map[string]string `json:"env,omitempty"`
	// Pipe is the session channel on Windows: the named pipe the agent
	// created for this session (SessionPipePrefix and 32 hex digits). Unix
	// passes the channel as a descriptor and refuses the field.
	Pipe string `json:"pipe,omitempty"`
	// HasPassword announces a password trailer after the message (Windows):
	// the login's password for a full logon (LogonUser) instead of S4U.
	// Unix refuses it.
	HasPassword bool `json:"password,omitempty"`
	// FilesDownload and FilesUpload are an sftp session's access, from the
	// certificate's files@localport.io option: reading file contents and
	// changing the file system. Only an sftp request carries them.
	FilesDownload bool `json:"files_download,omitempty"`
	FilesUpload   bool `json:"files_upload,omitempty"`
	// ClientAddr is the session client's address, `ip:port` with an IP
	// literal and no zone, as the edge reported it; empty when unknown. The
	// helper gives it to PAM (PAM_RHOST), SSH_CLIENT, SSH_CONNECTION and
	// utmp.
	ClientAddr string `json:"client_addr,omitempty"`
	// Password travels outside JSON, as a raw length-prefixed trailer
	// (writeSecret, readSecret), so no encoder buffer ever holds it; each
	// hop zeroes its copy once used and nothing stores it.
	Password []byte `json:"-"`
}

// Limits a session request's fields must meet.
const (
	maxTerminalSize = 1000
	maxDeviceRef    = 128
	maxLogin        = 256
	MaxPassword     = 256
	// MaxCommand bounds an exec command line so the request fits MaxMessage.
	MaxCommand = 2 << 10
	// MaxEnvVars, MaxEnvValue and MaxEnvBytes bound a request's environment:
	// at most 16 variables, each value at most 256 bytes, names and values
	// together at most 1 KiB, so the request with a full command still fits
	// MaxMessage.
	MaxEnvVars  = 16
	MaxEnvValue = 256
	MaxEnvBytes = 1 << 10
)

// envNamePattern is the allow-list of client environment variables.
var envNamePattern = regexp.MustCompile(`^(LANG|LC_[A-Z]{1,24})$`)

// ValidEnvVar reports whether a client may set name to value: LANG or LC_*,
// a value of at most MaxEnvValue bytes of UTF-8 with no control character.
func ValidEnvVar(name, value string) bool {
	if !envNamePattern.MatchString(name) || len(value) > MaxEnvValue || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ValidEnv reports whether env is within the bounds and every variable valid.
func ValidEnv(env map[string]string) bool {
	if len(env) > MaxEnvVars {
		return false
	}
	total := 0
	for k, v := range env {
		if !ValidEnvVar(k, v) {
			return false
		}
		total += len(k) + len(v)
	}
	return total <= MaxEnvBytes
}

// SessionPipePrefix starts the name of every per-session channel pipe.
const SessionPipePrefix = `\\.\pipe\localport-session-`

var (
	termPattern = regexp.MustCompile(`^[a-zA-Z0-9.+-]{1,32}$`)
	pipePattern = regexp.MustCompile(`^` + regexp.QuoteMeta(SessionPipePrefix) + `[0-9a-f]{32}$`)
)

// Validate checks the fields of a request for its kind, without the config.
// An sftp request carries no terminal and no command.
func (r Request) Validate() error {
	if r.V != Version {
		return Refusal(CodeVersionMismatch)
	}
	if r.Kind != KindSFTP && (r.FilesDownload || r.FilesUpload) {
		return Refusal(CodeBadRequest)
	}
	switch r.Kind {
	case KindProbe:
		if r.Device != "" || r.Login != "" || r.Cols != 0 || r.Rows != 0 || r.Term != "" || r.Command != "" ||
			r.Pipe != "" || r.HasPassword || len(r.Password) != 0 || len(r.Env) != 0 || r.ClientAddr != "" {
			return Refusal(CodeBadRequest)
		}
		return nil
	case KindTerminal:
		if r.Command != "" {
			return Refusal(CodeBadRequest)
		}
	case KindExec:
		if len(r.Command) > MaxCommand || !utf8.ValidString(r.Command) || strings.ContainsRune(r.Command, 0) {
			return Refusal(CodeBadRequest)
		}
		if r.Cols == 0 && r.Rows == 0 && r.Term == "" {
			// No PTY: the size checks below do not apply.
			return r.validateCommon()
		}
	case KindSFTP, KindForward:
		// The file server and the forward server run on pipes: no terminal,
		// no command; the forward server takes no client environment.
		if r.Cols != 0 || r.Rows != 0 || r.Term != "" || r.Command != "" || (r.Kind == KindForward && len(r.Env) != 0) {
			return Refusal(CodeBadRequest)
		}
		return r.validateCommon()
	default:
		return Refusal(CodeBadRequest)
	}
	switch {
	case r.Cols < 1 || r.Cols > maxTerminalSize,
		r.Rows < 1 || r.Rows > maxTerminalSize,
		!termPattern.MatchString(r.Term):
		return Refusal(CodeBadRequest)
	}
	return r.validateCommon()
}

// validateCommon checks the fields every session kind shares.
func (r Request) validateCommon() error {
	switch {
	case r.Device == "" || len(r.Device) > maxDeviceRef,
		r.Login == "" || len(r.Login) > maxLogin,
		r.Pipe != "" && !pipePattern.MatchString(r.Pipe),
		r.HasPassword != (len(r.Password) > 0),
		len(r.Password) > MaxPassword,
		!ValidEnv(r.Env),
		r.ClientAddr != "" && !ValidClientAddr(r.ClientAddr):
		return Refusal(CodeBadRequest)
	}
	return nil
}

// OriginEnv is the SSH_CLIENT and SSH_CONNECTION a session with client address
// addr gets, as sshd sets them, none for an empty or invalid addr. A relayed
// session has no local socket, so the server end is 127.0.0.1 port 22; the
// fields are there because parsers expect four.
func OriginEnv(addr string) []string {
	ip, port, ok := SplitClientAddr(addr)
	if !ok {
		return nil
	}
	return []string{
		fmt.Sprintf("SSH_CLIENT=%s %d 22", ip, port),
		fmt.Sprintf("SSH_CONNECTION=%s %d 127.0.0.1 22", ip, port),
	}
}

// SplitClientAddr returns the IP and port of a valid client address.
func SplitClientAddr(addr string) (ip string, port uint16, ok bool) {
	if !ValidClientAddr(addr) {
		return "", 0, false
	}
	ap := netip.MustParseAddrPort(addr)
	return ap.Addr().String(), ap.Port(), true
}

// ValidClientAddr reports whether addr is `ip:port`: an IP literal without
// a zone and a port from 1 to 65535.
func ValidClientAddr(addr string) bool {
	ap, err := netip.ParseAddrPort(addr)
	return err == nil && ap.Addr().Zone() == "" && ap.Port() != 0
}

// Response is one launcher message. Exactly one of Started, Refused, Probe
// and Exit is set; Messages may stand beside Started or Refused.
type Response struct {
	Started *Started `json:"started,omitempty"`
	Refused *Refused `json:"refused,omitempty"`
	Probe   *Probe   `json:"probe,omitempty"`
	Exit    *Exit    `json:"exit,omitempty"`
	// Messages are the session setup's PAM messages for the client, in
	// order (HelperReply.Messages).
	Messages []string `json:"messages,omitempty"`
}

// maxCodeLen bounds every refusal code, so FitMessages can size a reply
// before its code is known.
const maxCodeLen = 32

// FitMessages returns msgs cut so that a HelperReply and a Response carrying
// them with their largest other fields encode within MaxMessage: whole
// messages are dropped from the end, then the last one kept is cut on a
// rune boundary.
func FitMessages(msgs []string) []string {
	if len(msgs) == 0 || messagesFit(msgs) {
		return msgs
	}
	out := slices.Clone(msgs)
	for len(out) > 0 && !messagesFit(out) {
		out = out[:len(out)-1]
	}
	if len(out) == len(msgs) {
		return out
	}
	// Add the first dropped message back, cut to the longest prefix that fits.
	next := msgs[len(out)]
	lo, hi := 0, len(next)
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if messagesFit(append(slices.Clone(out), validPrefix(next, mid))) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	if cut := validPrefix(next, lo); cut != "" {
		out = append(out, cut)
	}
	return out
}

// validPrefix is s cut to at most n bytes, on a rune boundary.
func validPrefix(s string, n int) string {
	for n > 0 && n < len(s) && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// messagesFit reports whether msgs fit the largest reply on both hops.
func messagesFit(msgs []string) bool {
	code := strings.Repeat("x", maxCodeLen)
	for _, v := range []any{
		HelperReply{Refused: code, Messages: msgs},
		Response{Started: &Started{SessionID: strings.Repeat("0", 32)}, Messages: msgs},
		Response{Refused: &Refused{Code: code}, Messages: msgs},
	} {
		b, err := json.Marshal(v)
		if err != nil || len(b) > MaxMessage {
			return false
		}
	}
	return true
}

// Started reports a helper that passed account and session setup and
// started the login's process.
type Started struct {
	SessionID string `json:"session_id"`
}

// Refused is a typed refusal.
type Refused struct {
	Code string `json:"code"`
}

// S4U states a Windows probe reports.
const (
	S4ULocal             = "local"
	S4UDomain            = "domain"
	S4UDomainUnreachable = "domain_unreachable"
	S4UUnknown           = "unknown"
)

// Probe reports what the launcher can offer sessions on this host.
type Probe struct {
	PAM            bool   `json:"pam"`
	FullDiskAccess string `json:"full_disk_access"`
	// S4U is the Windows password-less logon's reach, one of the S4U*
	// states; empty off Windows.
	S4U string `json:"s4u,omitempty"`
}

// Exit is the helper's exit as the launcher reaped it.
type Exit struct {
	Status int `json:"status"`
	Signal int `json:"signal,omitempty"`
}

// RefusalError is a refusal carried as an error; errors.As finds it.
// Messages are the PAM messages that came with it, for the client.
type RefusalError struct {
	Code     string
	Messages []string
}

func (e *RefusalError) Error() string { return "launcher refused: " + e.Code }

// Refusal returns a RefusalError for code.
func Refusal(code string) error { return &RefusalError{Code: code} }

// ErrLauncherVersion is the agent's error for a launcher of another
// release; errors.As still finds the RefusalError beside it.
var ErrLauncherVersion = errcode.New(errcode.LauncherVersion)

// clientRefusal is the error a client returns for a refusal it read.
func clientRefusal(code string, messages []string) error {
	r := &RefusalError{Code: code, Messages: messages}
	if code == CodeVersionMismatch {
		return ErrLauncherVersion.With(r, "")
	}
	return r
}

// CodeOf returns the refusal code err carries, or CodeInternal.
func CodeOf(err error) string {
	var r *RefusalError
	if errors.As(err, &r) {
		return r.Code
	}
	return CodeInternal
}

// errMessageTooLarge refuses a message over MaxMessage.
var errMessageTooLarge = errors.New("launcher: message too large")

// encode returns v as one length-prefixed message.
func encode(v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxMessage {
		return nil, errMessageTooLarge
	}
	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...), nil
}

// writeMessage writes v as one length-prefixed message.
func writeMessage(w io.Writer, v any) error {
	b, err := encode(v)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// readBody reads one length-prefixed body.
func readBody(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxMessage {
		return nil, errMessageTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("launcher: short message: %w", err)
	}
	return body, nil
}

// writeSecret writes secret as a 4-byte big-endian length and the raw bytes,
// in two writes, so no buffer but the caller's holds it.
func writeSecret(w io.Writer, secret []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(secret)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(secret)
	return err
}

// readSecret reads one writeSecret trailer of 1 to MaxPassword bytes into a
// buffer the caller owns and must clear.
func readSecret(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxPassword {
		return nil, Refusal(CodeBadRequest)
	}
	secret := make([]byte, n)
	if _, err := io.ReadFull(r, secret); err != nil {
		clear(secret)
		return nil, err
	}
	return secret, nil
}

// decodeRequest decodes a request body strictly: unknown fields and trailing
// data are refused. The version is read first, so a request of another
// Version, whose fields may differ, is refused as a version mismatch.
func decodeRequest(body []byte) (Request, error) {
	var head struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(body, &head); err == nil && head.V != Version {
		return Request{}, Refusal(CodeVersionMismatch)
	}
	var req Request
	if err := decodeStrict(body, &req); err != nil {
		return Request{}, Refusal(CodeBadRequest)
	}
	return req, nil
}

// readResponse reads and decodes one response.
func readResponse(r io.Reader) (Response, error) {
	body, err := readBody(r)
	if err != nil {
		return Response{}, err
	}
	var resp Response
	if err := decodeStrict(body, &resp); err != nil {
		return Response{}, fmt.Errorf("launcher: bad response: %w", err)
	}
	set := 0
	for _, p := range []bool{resp.Started != nil, resp.Refused != nil, resp.Probe != nil, resp.Exit != nil} {
		if p {
			set++
		}
	}
	if set != 1 {
		return Response{}, errors.New("launcher: bad response: exactly one field must be set")
	}
	if len(resp.Messages) > 0 && resp.Started == nil && resp.Refused == nil {
		return Response{}, errors.New("launcher: bad response: messages without started or refused")
	}
	return resp, nil
}
