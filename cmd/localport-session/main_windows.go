// Command localport-session is the Windows launcher service and its per-session helper.
//
//	localport-session launcher                          the LocalSystem service localport-session
//	localport-session helper                            one session; started only by the launcher
//	localport-session files-server <access> <root> <home> <handle>  one file session as the login; started only by a helper
//	localport-session forward-server                    one connection's port forwards as the login; started only by a helper
//
// Protocol: internal/launcher. Session setup: internal/sessionhelper.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
	"github.com/localport/agent/internal/sessionhelper"
)

// version is set at build time (-X main.version); the crash report names it.
var version = "dev"

func main() {
	logger := log.New(os.Stderr, "", 0)
	// The file server runs as the login: the helper passes the event pipe's
	// inherited handle as the last argument.
	if len(os.Args) == 6 && os.Args[1] == sessionhelper.FilesServerMode {
		access, ok := sessionhelper.ParseFilesAccess(os.Args[2])
		if !ok {
			os.Exit(2)
		}
		h, err := strconv.ParseUint(os.Args[5], 10, 64)
		if err != nil {
			os.Exit(2)
		}
		if err := sessionhelper.ServeFiles(stdio{}, os.Args[3], os.Args[4], false, access, os.NewFile(uintptr(h), "file-events")); err != nil {
			logger.Printf("localport-session: files: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// The forward server runs as the login on the helper's pipes.
	if len(os.Args) == 2 && os.Args[1] == sessionhelper.ForwardServerMode {
		if err := sessionhelper.RunForwardServer(logger.Printf); err != nil {
			logger.Printf("localport-session: forward: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) != 2 {
		logger.Print("usage: localport-session launcher | helper")
		os.Exit(2)
	}
	if !isLocalSystem() {
		logger.Print("localport-session: must run as LocalSystem")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "helper":
		os.Exit(sessionhelper.Run(logger.Printf))
	case "launcher":
		underSCM, err := service.RunLauncherUnderSCM(version, func(ctx context.Context, running func()) error {
			return runLauncher(ctx, running, logger)
		})
		if err == nil && !underSCM {
			err = errors.New("the launcher runs only as the localport-session service")
		}
		if err != nil {
			logger.Printf("localport-session: %v", err)
			os.Exit(1)
		}
	default:
		logger.Printf("localport-session: unknown mode %q", os.Args[1])
		os.Exit(2)
	}
}

// stdio is the file server's connection: standard input and output.
type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error                { return os.Stdout.Close() }

// s4uRefresh is how often the launcher re-checks the domain.
const s4uRefresh = time.Minute

func isLocalSystem() bool {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

func runLauncher(ctx context.Context, running func(), logger *log.Logger) error {
	agent, err := windows.StringToSid(security.ServiceSID(security.WindowsServiceName))
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	file, err := config.SystemLocalConfig()
	if err != nil {
		return err
	}
	ln, err := launcher.ListenPipe(agent)
	if err != nil {
		return err
	}
	// Domain controller discovery can block for seconds, and the agent
	// probes before every session, so the probe answers from a value kept
	// fresh in the background.
	var s4u atomic.Value
	s4u.Store(launcher.S4UUnknown)
	go func() {
		t := time.NewTicker(s4uRefresh)
		defer t.Stop()
		for {
			s4u.Store(sessionhelper.S4UAvailability())
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	s := &launcher.Server{
		AgentSID:   agent,
		LoadConfig: func() (*config.LocalConfig, error) { return config.LoadLocal(file) },
		HelperPath: exe,
		Probe: func() launcher.Probe {
			return launcher.Probe{PAM: false, FullDiskAccess: launcher.FullDiskAccessUnknown, S4U: s4u.Load().(string)}
		},
		Log: logger.Printf,
	}
	// The status endpoint never stops the launcher: a failure is logged and
	// session requests keep being served.
	if statusLn, err := launcher.ListenStatusPipe(); err != nil {
		logger.Printf("localport-session: status endpoint %s: %v", launcher.StatusPipePath, err)
	} else {
		go func() {
			if err := s.ServeStatus(ctx, statusLn); err != nil {
				logger.Printf("localport-session: status endpoint: %v", err)
			}
		}()
	}
	running()
	logger.Printf("localport-session: launcher serving %s for %s", launcher.PipePath, agent)
	if err := s.Serve(ctx, ln); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
