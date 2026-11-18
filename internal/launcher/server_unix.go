//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/config"
)

// Server is the launcher daemon's configuration.
type Server struct {
	// AgentUID is the only peer uid the launcher serves on its request
	// socket, and the only publisher of the status document.
	AgentUID uint32
	// AgentGID is the agent group: its members, root and AgentUID read the
	// status document.
	AgentGID uint32
	// AgentAccount is the agent account's name, the login of a session
	// that runs as the agent account.
	AgentAccount string
	// LoadConfig reads the root-owned device config; called per request.
	LoadConfig func() (*config.LocalConfig, error)
	// HelperPath is the absolute path of localport-session.
	HelperPath string
	// Probe reports what this host offers sessions.
	Probe func() Probe
	// GroupMember, when set, reports whether the directory service lists a
	// uid in a group. It decides a status reader whose peer credential may be
	// truncated: on macOS an xucred carries at most 16 groups.
	GroupMember func(uid, gid uint32) (bool, error)
	Log         func(format string, args ...any)

	slots  chan struct{}
	wg     sync.WaitGroup
	status statusRelay
	// peerGroups is peerCredGroups; tests replace it.
	peerGroups func(*net.UnixConn) (uid uint32, gids []uint32, err error)
}

// ServeStatus serves the status document on ln until ctx ends: to root, the
// agent account and members of the agent group, by the kernel's record of
// the peer; anyone else is closed without a byte. The socket's mode admits
// the same set; this check holds if the mode is ever wider.
func (s *Server) ServeStatus(ctx context.Context, ln *net.UnixListener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var delay time.Duration
	for {
		conn, err := ln.AcceptUnix()
		if errors.Is(err, net.ErrClosed) {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("launcher: accept a status reader: %w", err)
		}
		if err != nil {
			// Any other failure (EMFILE, a timeout) is retried with a backoff,
			// so it never ends the status endpoint.
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			s.Log("launcher: accept a status reader: %v; retrying in %v", err, delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		delay = 0
		if !s.status.enterReader() {
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.status.leaveReader()
			s.serveStatusReader(conn)
		}()
	}
}

func (s *Server) serveStatusReader(conn *net.UnixConn) {
	defer conn.Close()
	read := s.peerGroups
	if read == nil {
		read = peerCredGroups
	}
	uid, gids, err := read(conn)
	if err != nil {
		s.Log("launcher: status reader credentials: %v", err)
		return
	}
	if uid != 0 && uid != s.AgentUID && !slices.Contains(gids, s.AgentGID) && !s.listedMember(uid, len(gids)) {
		s.Log("launcher: refused a status reader of uid %d: not root, the agent account or the agent group", uid)
		return
	}
	if err := s.status.writeTo(conn); err != nil {
		s.Log("launcher: write the status document: %v", err)
	}
}

// listedMember asks GroupMember whether uid is in the agent group, for a
// peer credential of n groups that a platform limit may have cut short
// (peerGroupsMax). False when GroupMember is unset or fails, which is logged.
func (s *Server) listedMember(uid uint32, n int) bool {
	if s.GroupMember == nil || n < peerGroupsMax {
		return false
	}
	member, err := s.GroupMember(uid, s.AgentGID)
	if err != nil {
		s.Log("launcher: status reader group membership: %v", err)
		return false
	}
	return member
}

// publish takes the publisher slot for conn, the agent account's KindStatus
// connection, and relays its frames until it closes. It takes no helper slot.
func (s *Server) publish(conn *net.UnixConn) {
	if !s.status.claim() {
		s.Log("launcher: refused a second status publisher")
		s.refuse(conn, CodeBusy)
		return
	}
	defer s.status.release()
	respond(conn, Response{Publishing: true})
	_ = conn.SetDeadline(time.Time{})
	if err := s.status.relay(conn); !errors.Is(err, io.EOF) {
		s.Log("launcher: status publisher: %v", err)
	}
}

// Serve accepts connections on ln until ctx ends. Running helpers outlive
// it: each holds its own channel to the agent.
func (s *Server) Serve(ctx context.Context, ln *net.UnixListener) error {
	s.slots = make(chan struct{}, maxHelpers)
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("launcher: accept: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn *net.UnixConn) {
	defer conn.Close()
	uid, pid, err := peerCred(conn)
	if err != nil {
		s.Log("launcher: peer credentials: %v", err)
		return
	}
	if uid != s.AgentUID {
		s.Log("launcher: refused a connection from uid %d (pid %d): not the agent account", uid, pid)
		return
	}
	var (
		req     Request
		channel *os.File
	)
	err = readWithin(conn, requestTimeout, func() (err error) {
		req, channel, err = recvRequest(conn)
		return err
	})
	if err != nil {
		var r *RefusalError
		if errors.As(err, &r) {
			s.refuse(conn, r.Code)
		}
		return
	}
	if channel != nil {
		defer channel.Close()
	}
	if err := req.Validate(); err != nil {
		s.refuse(conn, CodeOf(err))
		return
	}
	// The channel is the passed descriptor, and PAM never takes a password.
	if req.Pipe != "" || req.HasPassword {
		s.refuse(conn, CodeBadRequest)
		return
	}
	if req.Kind == KindStatus {
		if channel != nil {
			s.refuse(conn, CodeBadRequest)
			return
		}
		s.publish(conn)
		return
	}
	if req.Kind == KindProbe {
		if channel != nil {
			s.refuse(conn, CodeBadRequest)
			return
		}
		p := s.Probe()
		respond(conn, Response{Probe: &p})
		return
	}
	if channel == nil {
		s.refuse(conn, CodeBadRequest)
		return
	}
	hreq, err := s.authorize(req)
	if err != nil {
		s.Log("launcher: refused %s for device %q login %q: %v", req.Kind, req.Device, req.Login, err)
		s.refuse(conn, CodeOf(err))
		return
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.refuse(conn, CodeBusy)
		return
	}
	defer func() { <-s.slots }()
	s.run(conn, hreq, channel)
}

// authorize checks req against the device config it re-reads now.
func (s *Server) authorize(req Request) (HelperRequest, error) {
	return authorize(s.LoadConfig, s.AgentAccount, req)
}

// run starts one helper with channel on fd 3 and its control socket on fd
// 4, relays its start answer, then reports its exit.
func (s *Server) run(conn *net.UnixConn, req HelperRequest, channel *os.File) {
	ours, theirs, err := SocketPair()
	if err != nil {
		s.Log("launcher: control socketpair: %v", err)
		s.refuse(conn, CodeInternal)
		return
	}
	defer ours.Close()
	cmd := &exec.Cmd{
		Path:       s.HelperPath,
		Args:       []string{"localport-session", "helper"},
		Env:        []string{},
		Dir:        "/",
		Stderr:     os.Stderr,
		ExtraFiles: []*os.File{channel, theirs},
	}
	err = cmd.Start()
	_ = theirs.Close()
	_ = channel.Close()
	if err != nil {
		s.Log("launcher: start the helper: %v", err)
		s.refuse(conn, CodeSpawnFailed)
		return
	}
	exited := make(chan Exit, 1)
	go func() { exited <- waitExit(cmd) }()

	reply, err := s.start(ours, req)
	if err != nil {
		s.Log("launcher: helper %d: %v", cmd.Process.Pid, err)
		_ = cmd.Process.Kill()
		e := <-exited
		s.refuse(conn, startFailureCode(err))
		s.logExit(cmd.Process.Pid, e)
		return
	}
	if reply.Refused != "" {
		respond(conn, Response{Refused: &Refused{Code: reply.Refused}, Messages: reply.Messages})
		s.logExit(cmd.Process.Pid, <-exited)
		return
	}
	id := newSessionID()
	s.Log("launcher: session %s: %s for %q, helper %d", id, req.Kind, req.Login, cmd.Process.Pid)
	respond(conn, Response{Started: &Started{SessionID: id}, Messages: reply.Messages})
	e := <-exited
	s.logExit(cmd.Process.Pid, e)
	respond(conn, Response{Exit: &e})
}

// respond writes one response under its own write deadline.
func respond(conn *net.UnixConn, r Response) {
	_ = conn.SetWriteDeadline(time.Now().Add(replyTimeout))
	_ = sendMessage(conn, r, nil)
}

// start sends req on the control socket and reads the helper's one reply.
func (s *Server) start(control *os.File, req HelperRequest) (HelperReply, error) {
	_ = control.SetDeadline(time.Now().Add(helperStartTimeout))
	if err := WriteHelperRequest(control, req); err != nil {
		return HelperReply{}, err
	}
	reply, err := ReadHelperReply(control, nil)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return HelperReply{}, errHelperTimeout
	}
	return reply, err
}

func (s *Server) refuse(conn *net.UnixConn, code string) {
	respond(conn, Response{Refused: &Refused{Code: code}})
}

// logExit logs a helper's exit; a helper ended by a signal could not clear
// its utmp entry.
func (s *Server) logExit(pid int, e Exit) {
	if e.Signal != 0 {
		s.Log("launcher: helper %d ended by signal %d; its utmp entry, if any, is stale", pid, e.Signal)
	}
}

// waitExit reaps cmd and returns its exit status or signal.
func waitExit(cmd *exec.Cmd) Exit {
	_ = cmd.Wait()
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return Exit{Status: cmd.ProcessState.ExitCode()}
	}
	if ws.Signaled() {
		return Exit{Status: -1, Signal: int(ws.Signal())}
	}
	return Exit{Status: ws.ExitStatus()}
}

// SocketPair returns a connected pair of close-on-exec Unix stream sockets:
// ours non-blocking and pollable (deadlines, Close interrupts a Read),
// theirs blocking, to hand to another process. The agent makes the session
// channel with it; the launcher makes each helper's control socket.
func SocketPair() (ours, theirs *os.File, err error) {
	syscall.ForkLock.RLock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(fds[0])
		unix.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, err
	}
	// Non-blocking so os.NewFile makes it pollable and deadlines work. The
	// helper's end stays blocking: it is a separate open file description.
	if err := unix.SetNonblock(fds[0], true); err != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), "launcher-control"), os.NewFile(uintptr(fds[1]), "helper-control"), nil
}
