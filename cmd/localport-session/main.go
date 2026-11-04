//go:build cgo && (linux || darwin)

// Command localport-session is the root session launcher and its
// per-session helper.
//
//	localport-session launcher                  the daemon the service manager starts
//	localport-session helper                    one session; started only by the launcher
//	localport-session files-server <root>       one file session as the login; started only by a helper
//
// See internal/launcher for the protocol and internal/sessionhelper for the
// session setup.
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
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		if err := sessionhelper.ServeFiles(stdio{}, os.Args[2], os.NewFile(3, "file-events")); err != nil {
			logger.Printf("localport-session: files: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Geteuid() != 0 {
		logger.Print("localport-session: must run as root")
		os.Exit(1)
	}
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
	ln, err := listener(gid)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	s := &launcher.Server{
		AgentUID:     uid,
		AgentAccount: agentAccount,
		LoadConfig:   func() (*config.LocalConfig, error) { return config.LoadLocal(file) },
		HelperPath:   exe,
		Probe: func() launcher.Probe {
			return launcher.Probe{PAM: sessionhelper.PAMAvailable(), FullDiskAccess: fullDiskAccess()}
		},
		Log: logger.Printf,
	}
	logger.Printf("localport-session: launcher serving %s for uid %d", launcher.SocketPath, uid)
	return s.Serve(ctx, ln)
}
