//go:build unix

package session

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/localport/agent/internal/errcode"
)

// maxLookupOutput bounds the output of each lookup tool run and each account
// file read.
const maxLookupOutput = 64 << 10

// lookupWaitDelay bounds Wait after a lookup tool run is killed, in case a
// child of the tool (an NSS module's helper) still holds its stdout.
const lookupWaitDelay = 100 * time.Millisecond

var errLookupOutputTooLarge = errcode.New(errcode.LookupOutputTooLarge)

// runLookupTool runs a lookup tool (getent, dscl) at its fixed path with an
// empty environment from / and returns its output, at most maxLookupOutput
// bytes, and its exit status. It refuses to start once ctx is done; ctx's
// end kills the run.
func runLookupTool(ctx context.Context, tool string, args ...string) ([]byte, int, error) {
	name := filepath.Base(tool)
	if err := ctx.Err(); err != nil {
		return nil, 0, fmt.Errorf("%s %s: no time left: %w", name, args[0], err)
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	out := &boundedOutput{max: maxLookupOutput, overflow: stop}
	cmd := exec.CommandContext(runCtx, tool, args...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdout = out
	cmd.WaitDelay = lookupWaitDelay
	err := cmd.Run()
	switch {
	case out.overflowed:
		return nil, 0, fmt.Errorf("%s %s: %w", name, args[0], errLookupOutputTooLarge)
	case ctx.Err() != nil:
		return nil, 0, fmt.Errorf("%s %s timed out: %w", name, args[0], ctx.Err())
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.Exited() {
		return out.buf, exit.ExitCode(), nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("%s %s: %w", name, args[0], err)
	}
	return out.buf, 0, nil
}

// boundedOutput keeps at most max bytes; a longer write calls overflow,
// which kills the writer.
type boundedOutput struct {
	buf        []byte
	max        int
	overflow   func()
	overflowed bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(b.buf)+len(p) > b.max {
		b.overflowed = true
		b.overflow()
		return 0, errLookupOutputTooLarge
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}
