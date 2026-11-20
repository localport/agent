//go:build cgo && (linux || darwin)

// Command localport-session is the root session launcher and its per-session helper.
//
//	localport-session launcher                  the daemon the service manager starts
//	localport-session helper                    one session; started only by the launcher
//	localport-session files-server <access> <root> <home>  one file session as the login; started only by a helper
//	localport-session forward-server            one connection's port forwards as the login; started only by a helper
//	localport-session shell-exec <path> <argv0> [args...]  replaces itself with a session's shell, its own responsible process (macOS); started only by a helper
//
// Protocol: internal/launcher. Session setup: internal/sessionhelper.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/logfile"
	"github.com/localport/agent/internal/sessionhelper"
)

const agentAccount = launcher.AgentAccount

func init() {
	// The helper's PAM modules and the shell's fork act on the calling OS
	// thread; main keeps the thread init ran on.
	runtime.LockOSThread()
}

func main() {
	logger := log.New(os.Stderr, "", 0)
	if len(os.Args) < 2 {
		logger.Print("usage: localport-session launcher [--log-file <path>] | helper")
		os.Exit(2)
	}
	// The file server runs as the login, not as root: the helper starts it
	// with the event pipe on descriptor 3.
	if os.Args[1] == sessionhelper.FilesServerMode {
		if len(os.Args) != 5 {
			os.Exit(2)
		}
		access, ok := sessionhelper.ParseFilesAccess(os.Args[2])
		if !ok {
			os.Exit(2)
		}
		if err := sessionhelper.ServeFiles(stdio{}, os.Args[3], os.Args[4], access, os.NewFile(3, "file-events")); err != nil {
			logger.Printf("localport-session: files: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// The shell-exec mode runs as the login: the helper starts it in place of
	// the shell, and it replaces itself with the shell (macOS).
	if os.Args[1] == sessionhelper.ShellExecMode {
		os.Exit(sessionhelper.ShellExec(os.Args[2:], os.Stderr))
	}
	// The forward server runs as the login; the forward channel is descriptor 3.
	if os.Args[1] == sessionhelper.ForwardServerMode {
		if len(os.Args) != 2 {
			os.Exit(2)
		}
		if err := sessionhelper.RunForwardServer(logger.Printf); err != nil {
			logger.Printf("localport-session: forward: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Geteuid() != 0 {
		logger.Print("localport-session: must run as root")
		os.Exit(1)
	}
	catchHangupAndPipe()
	switch os.Args[1] {
	case "helper":
		if len(os.Args) != 2 {
			os.Exit(2)
		}
		os.Exit(sessionhelper.Run(logger.Printf))
	case "launcher":
		fs := flag.NewFlagSet("launcher", flag.ContinueOnError)
		logFile := fs.String("log-file", "", "write the log to this file and rotate it (launchd, OpenRC)")
		if err := fs.Parse(os.Args[2:]); err != nil || fs.NArg() != 0 {
			os.Exit(2)
		}
		if *logFile != "" {
			l, err := logfile.Open(*logFile)
			if err != nil {
				logger.Printf("localport-session: %v", err)
				os.Exit(1)
			}
			go l.Run(context.Background())
		}
		if err := runLauncher(logger); err != nil {
			logger.Printf("localport-session: %v", err)
			os.Exit(1)
		}
	default:
		logger.Printf("localport-session: unknown mode %q", os.Args[1])
		os.Exit(2)
	}
}

// catchHangupAndPipe keeps SIGHUP and SIGPIPE from ending the launcher and
// the helper. It catches them instead of ignoring them: a caught signal
// resets to the default in an exec'd child, an ignored one stays ignored, and
// a session must get the login's default dispositions. Notify also replaces
// a SIG_IGN inherited from whoever started this process.
func catchHangupAndPipe() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGPIPE)
	go func() {
		for range c {
		}
	}()
}

// stdio is the file server's connection: standard input and output.
type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error                { return os.Stdout.Close() }

func runLauncher(logger *log.Logger) error {
	uid, gid, err := sessionhelper.LookupIDs(agentAccount)
	if err != nil {
		return fmt.Errorf("the agent account %s: %w", agentAccount, err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	file, err := config.SystemLocalConfig()
	if err != nil {
		return err
	}
	ln, statusLn, statusErr, err := listeners(gid)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	s := &launcher.Server{
		AgentUID:     uid,
		AgentGID:     gid,
		AgentAccount: agentAccount,
		LoadConfig:   func() (*config.LocalConfig, error) { return config.LoadLocal(file) },
		HelperPath:   exe,
		Probe: func() launcher.Probe {
			return launcher.Probe{PAM: sessionhelper.PAMAvailable(), FullDiskAccess: launcher.ReadFullDiskAccess()}
		},
		FullDiskAccess: sessionFullDiskAccess,
		GroupMember:    groupMember,
		Log:            logger.Printf,
	}
	// The status endpoint never stops the launcher: a missing endpoint or a
	// failed accept loop is logged and session requests keep being served.
	if statusErr != nil {
		logger.Printf("localport-session: launcher serving %s for uid %d; status endpoint unavailable: %v; reinstall the service: sudo localport service install",
			launcher.SocketPath, uid, statusErr)
	} else {
		logger.Printf("localport-session: launcher serving %s for uid %d and %s", launcher.SocketPath, uid, launcher.StatusSocketPath)
		go func() {
			if err := s.ServeStatus(ctx, statusLn); err != nil {
				logger.Printf("localport-session: status endpoint: %v", err)
			}
		}()
	}
	return s.Serve(ctx, ln)
}
