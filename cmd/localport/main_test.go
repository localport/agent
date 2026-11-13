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
	err := &service.ExitError{Code: service.ExitRunLocked, Err: fmt.Errorf("run: %w", config.ErrRunLocked)}
	if code := report(&out, cli.New("test", "", ""), err); code != service.ExitRunLocked {
		t.Fatalf("report = %d, want %d", code, service.ExitRunLocked)
	}
	want := "error: localport is already running the devices of this config [AG021]\n"
	if out.String() != want {
		t.Fatalf("printed %q, want %q", out.String(), want)
	}
}
