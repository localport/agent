// Command localport-session is the session launcher service and its
// per-session helper on Windows.
//
//	localport-session launcher   the LocalSystem service localport-session
//	localport-session helper     one session; started only by the launcher
//
// See internal/launcher for the protocol and internal/sessionhelper for the
// session setup.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
	"github.com/localport/agent/internal/sessionhelper"
)

func main() {
	logger := log.New(os.Stderr, "", 0)
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
		underSCM, err := service.RunLauncherUnderSCM(func(ctx context.Context, running func()) error {
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
	s := &launcher.Server{
		AgentSID:   agent,
		LoadConfig: func() (*config.LocalConfig, error) { return config.LoadLocal(file) },
		HelperPath: exe,
		Probe: func() launcher.Probe {
			return launcher.Probe{PAM: false, FullDiskAccess: launcher.FullDiskAccessUnknown}
		},
		Log: logger.Printf,
	}
	running()
	logger.Printf("localport-session: launcher serving %s for %s", launcher.PipePath, agent)
	if err := s.Serve(ctx, ln); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
