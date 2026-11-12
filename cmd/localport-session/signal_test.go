//go:build cgo && (linux || darwin)

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
)

// signalTestStage selects what a re-executed test binary does.
const signalTestStage = "LOCALPORT_SIGNAL_TEST_STAGE"

func TestMain(m *testing.M) {
	switch os.Getenv(signalTestStage) {
	case "ignore":
		// Start the launcher stage with both signals inherited as SIG_IGN,
		// as a service manager or nohup would.
		signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
		os.Setenv(signalTestStage, "launcher")
		exe, _ := os.Executable()
		err := syscall.Exec(exe, os.Args, os.Environ())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	case "launcher":
		catchHangupAndPipe()
		// A shell that sends itself the signal survives only when it is
		// ignored. A Go child cannot report this: its runtime installs a
		// SIGPIPE handler whatever it inherited.
		for _, sig := range []string{"HUP", "PIPE"} {
			err := exec.Command("/bin/sh", "-c", "kill -"+sig+" $$; sleep 1").Run()
			fmt.Printf("%s-ignored=%t ", sig, err == nil)
		}
		fmt.Println()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// A launcher started with SIGHUP and SIGPIPE ignored still starts its
// children with both at the default disposition.
func TestCatchHangupAndPipeResetsChildDispositions(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), signalTestStage+"=ignore")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "HUP-ignored=false PIPE-ignored=false" {
		t.Fatalf("child dispositions: %s", got)
	}
}
