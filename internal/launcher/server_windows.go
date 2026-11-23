//go:build windows

package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/config"
)

// Server is the launcher service's configuration on Windows.
type Server struct {
	// AgentSID is the only client served: the device service's virtual account.
	AgentSID *windows.SID
	// LoadConfig reads the Administrators-owned device config on each request.
	LoadConfig func() (*config.LocalConfig, error)
	// HelperPath is the absolute path of localport-session.exe.
	HelperPath string
	// Probe reports what this host offers sessions.
	Probe func() Probe
	Log   func(format string, args ...any)

	slots  chan struct{}
	status statusRelay
}

// ServeStatus serves the status document on ln, the status pipe, until ctx
// ends. The pipe's DACL admits only SYSTEM and elevated Administrators; the
// launcher reads nothing from a reader, so it does not impersonate one.
func (s *Server) ServeStatus(ctx context.Context, ln *PipeListener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("launcher: accept a status reader: %w", err)
		}
		if err != nil {
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
		go func() {
			defer s.status.leaveReader()
			defer conn.Close()
			if err := s.status.writeTo(conn); err != nil {
				s.Log("launcher: write the status document: %v", err)
			}
		}()
	}
}

// publish takes the publisher slot for conn, the device service's KindStatus
// connection, and relays its frames until it closes. It takes no helper slot.
func (s *Server) publish(conn *os.File) {
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
// it: each is its own process holding its own channel to the agent.
func (s *Server) Serve(ctx context.Context, ln *PipeListener) error {
	s.slots = make(chan struct{}, maxHelpers)
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("launcher: accept: %w", err)
		}
		if err != nil {
			// Any other failure is retried with a backoff, as net/http's
			// Server does, so one bad instance never stops the launcher.
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			s.Log("launcher: accept: %v; retrying in %v", err, delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		delay = 0
		go s.handle(conn)
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
	var body []byte
	err = readWithin(conn, requestTimeout, func() (err error) {
		body, err = readBody(conn)
		return err
	})
	if err != nil {
		return
	}
	req, err := decodeRequest(body)
	if err != nil {
		s.refuse(conn, CodeOf(err))
		return
	}
	if req.HasPassword {
		err = readWithin(conn, requestTimeout, func() (err error) {
			req.Password, err = readSecret(conn)
			return err
		})
		if err != nil {
			s.refuse(conn, CodeBadRequest)
			return
		}
	}
	defer clear(req.Password)
	if err := req.Validate(); err != nil {
		s.refuse(conn, CodeOf(err))
		return
	}
	if req.Kind == KindStatus {
		s.publish(conn)
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
	hreq, err := authorize(s.LoadConfig, "", req, "")
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
	// startWatch carries the bound's logic and its fake-clock tests
	// (messages_test.go); here it runs on the real clock.
	watch := newStartWatch(func(d time.Duration, f func()) startTimer { return time.AfterFunc(d, f) }, func() { _ = cmd.Process.Kill() })
	err = WriteHelperRequest(in, req)
	clear(req.Password)
	_ = in.Close()
	var reply HelperReply
	if err == nil {
		reply, err = ReadHelperReply(out, req.Kind, func(string) { watch.progress() })
	}
	if watch.stop() {
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
		respond(conn, Response{Refused: &Refused{Code: reply.Refused}, Messages: reply.Messages})
		return
	}
	id := newSessionID()
	s.Log("launcher: session %s: %s for %q, helper %d", id, req.Kind, req.Login, cmd.Process.Pid)
	respond(conn, Response{Started: &Started{SessionID: id, Confined: reply.Confined, Home: reply.Home, WholeDisk: reply.WholeDisk}, Messages: reply.Messages})
	e := waitExit(cmd)
	if e.Status != 0 {
		s.Log("launcher: session %s: helper %d exited with status %d; a profile it loaded stays loaded until Windows unloads it", id, cmd.Process.Pid, e.Status)
	}
	respond(conn, Response{Exit: &e})
}

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
