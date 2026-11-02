//go:build windows

package launcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/config"
)

// Server is the launcher service's configuration on Windows.
type Server struct {
	// AgentSID is the only client the launcher serves: the device service's
	// virtual account.
	AgentSID *windows.SID
	// LoadConfig reads the Administrators-owned device config; called per
	// request.
	LoadConfig func() (*config.LocalConfig, error)
	// HelperPath is the absolute path of localport-session.exe.
	HelperPath string
	// Probe reports what this host offers sessions.
	Probe func() Probe
	Log   func(format string, args ...any)

	slots chan struct{}
	wg    sync.WaitGroup
}

// Serve accepts connections on ln until ctx ends. Running helpers outlive
// it: each is its own process holding its own channel to the agent.
func (s *Server) Serve(ctx context.Context, ln *PipeListener) error {
	s.slots = make(chan struct{}, maxHelpers)
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
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

func (s *Server) handle(conn *os.File) {
	defer conn.Close()
	sid, err := pipeClientSID(conn)
	if err != nil {
		s.Log("launcher: pipe client: %v", err)
		return
	}
	if !sid.Equals(s.AgentSID) {
		s.Log("launcher: refused a connection from %s: not the device service", sid)
		return
	}
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))
	body, err := readBody(conn)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		return
	}
	req, err := decodeRequest(body)
	clear(body)
	defer clear(req.Password)
	if err != nil {
		s.refuse(conn, CodeOf(err))
		return
	}
	if err := req.Validate(); err != nil {
		s.refuse(conn, CodeOf(err))
		return
	}
	if req.Kind == KindProbe {
		p := s.Probe()
		respond(conn, Response{Probe: &p})
		return
	}
	if req.Pipe == "" {
		s.refuse(conn, CodeBadRequest)
		return
	}
	hreq, err := authorize(s.LoadConfig, "", req)
	if err != nil {
		s.Log("launcher: refused %s for device %s login %q: %v", req.Kind, req.Device, req.Login, err)
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
	s.run(conn, hreq)
}

// run starts one helper with its control channel on standard input and
// output, relays its start answer, then reports its exit. The helper opens
// the session channel pipe itself.
func (s *Server) run(conn *os.File, req HelperRequest) {
	cmd := exec.Command(s.HelperPath, "helper")
	cmd.Env = []string{}
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		s.refuse(conn, CodeInternal)
		return
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		s.refuse(conn, CodeInternal)
		return
	}
	if err := cmd.Start(); err != nil {
		s.Log("launcher: start the helper: %v", err)
		s.refuse(conn, CodeSpawnFailed)
		return
	}
	var timedOut atomic.Bool
	timer := time.AfterFunc(helperStartTimeout, func() {
		timedOut.Store(true)
		_ = cmd.Process.Kill()
	})
	err = WriteHelperRequest(in, req)
	clear(req.Password)
	_ = in.Close()
	var reply HelperReply
	if err == nil {
		reply, err = ReadHelperReply(out)
	}
	timer.Stop()
	if timedOut.Load() {
		err = errHelperTimeout
	}
	if err != nil {
		s.Log("launcher: helper %d: %v", cmd.Process.Pid, err)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		s.refuse(conn, startFailureCode(err))
		return
	}
	if reply.Refused != "" {
		_ = cmd.Wait()
		s.refuse(conn, reply.Refused)
		return
	}
	id := newSessionID()
	s.Log("launcher: session %s: %s for %q, helper %d", id, req.Kind, req.Login, cmd.Process.Pid)
	respond(conn, Response{Started: &Started{SessionID: id}})
	e := waitExit(cmd)
	respond(conn, Response{Exit: &e})
}

// waitExit waits for cmd and returns its exit code.
func waitExit(cmd *exec.Cmd) Exit {
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return Exit{Status: -1}
	}
	return Exit{Status: cmd.ProcessState.ExitCode()}
}

// respond writes one response under its own write deadline.
func respond(conn *os.File, r Response) {
	_ = conn.SetWriteDeadline(time.Now().Add(replyTimeout))
	_ = writeMessage(conn, r)
}

func (s *Server) refuse(conn *os.File, code string) {
	respond(conn, Response{Refused: &Refused{Code: code}})
}
