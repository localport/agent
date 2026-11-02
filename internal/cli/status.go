package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/service"
)

// runStatus prints the device service state and, to an account that can read
// the system config (root or a member of group localport), its devices and
// the launcher's state. The OS decides who reads the config: anyone else sees
// the service state only.
func runStatus(args []string) error {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "Usage: localport status")
		return fmt.Errorf("unexpected argument %q", args[0])
	}
	return printStatus(context.Background(), os.Stdout)
}

func printStatus(ctx context.Context, w io.Writer) error {
	if err := printServiceState(ctx, w); err != nil {
		return err
	}
	file, err := systemLocalConfig()
	if err != nil {
		return err
	}
	cfg, err := config.LoadLocal(file)
	switch {
	case errors.Is(err, fs.ErrPermission):
		fmt.Fprintf(w, "config     %s is readable by root and group localport only\n", file.Path)
		return nil
	case errors.Is(err, fs.ErrNotExist):
		fmt.Fprintf(w, "config     none at %s\n", file.Path)
		return nil
	case err != nil:
		return err
	}
	fmt.Fprintf(w, "config     %s\n", file.Path)
	for _, d := range cfg.Devices {
		enable := make([]string, len(d.Enable))
		for i, c := range d.Enable {
			enable[i] = string(c)
		}
		fmt.Fprintf(w, "device     %s\n  enable   %s\n  logins   %s\n  run_as_agent %t\n",
			d.Identity, listOrNone(enable), listOrNone(d.Logins), d.RunAsAgent)
	}
	if asAgentChild {
		// Root's status runs here as the agent account, which owns the keys.
		printFingerprints(w, cfg.Devices)
	}
	probe := probeLauncher(ctx, func(line string) { fmt.Fprintf(w, "launcher   %s\n", line) })
	auth := probe.sessionAuth
	if runtime.GOOS == "windows" && probe.answered {
		auth = "windows logon (S4U, or LogonUser with a password)"
	}
	fmt.Fprintf(w, "launcher   session auth %s\n", valueOrUnknown(auth))
	if probe.fullDiskAccess != "" {
		fmt.Fprintf(w, "launcher   full disk access %s\n", probe.fullDiskAccess)
	}
	return nil
}

// printServiceState prints whether the device service is installed and its
// main process.
func printServiceState(ctx context.Context, w io.Writer) error {
	m, err := newServiceManager()
	if errors.Is(err, service.ErrUnsupported) {
		fmt.Fprintln(w, "service    no supported service manager")
		return nil
	}
	if err != nil {
		return err
	}
	installed, err := m.Installed()
	if err != nil {
		return err
	}
	if !installed {
		fmt.Fprintf(w, "service    %s, not installed\n", m.Name())
		return nil
	}
	pid, err := m.MainPID(ctx)
	if err != nil {
		return err
	}
	if pid == 0 {
		fmt.Fprintf(w, "service    %s, installed, not running\n", m.Name())
		return nil
	}
	fmt.Fprintf(w, "service    %s, running, pid %d\n", m.Name(), pid)
	return nil
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ",")
}

func valueOrUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}
