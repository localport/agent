package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/localport/agent/internal/cli"
	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/service"
)

func TestReportPrintsTheCodeOfAWrappedCodedError(t *testing.T) {
	var out bytes.Buffer
	// An agent-account child's exit status, passed on (agentchild_unix.go).
	const childStatus = 3
	err := &service.ExitError{Code: childStatus, Err: fmt.Errorf("run: %w", config.ErrRunLocked)}
	if code := report(&out, cli.New("test", "", ""), err); code != childStatus {
		t.Fatalf("report = %d, want %d", code, childStatus)
	}
	want := "error: localport is already running the devices of this config [AG021]\n"
	if out.String() != want {
		t.Fatalf("printed %q, want %q", out.String(), want)
	}
}

// -h prints the command's usage and exits 0 without an error line.
func TestReportHelpExitsZero(t *testing.T) {
	var out bytes.Buffer
	err := cli.New("test", "", "").Run([]string{"up", "-h"})
	if code := report(&out, cli.New("test", "", ""), err); code != 0 || out.Len() != 0 {
		t.Fatalf("report(%v) = %d, printed %q; want 0 and nothing", err, code, out.String())
	}
}
