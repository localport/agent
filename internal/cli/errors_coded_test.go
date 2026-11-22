package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

// Argument and input errors reach the user coded, as usage errors or as
// Invalid: never the Unexpected line.
func TestCommandInputErrorsAreTyped(t *testing.T) {
	unexpected := errcode.New(errcode.Unexpected).Error()
	for _, c := range []struct {
		name string
		run  func() error
		want func(error) bool
	}{
		{"unknown flag", func() error { return runSet([]string{"--no-such-flag"}) }, isType[*errcode.Usage]},
		{"service extra argument", func() error { return runService([]string{"install", "extra"}) }, isCode(errcode.ExtraArgument)},
		{"status extra argument", func() error { return runStatus([]string{"extra"}) }, isCode(errcode.ExtraArgument)},
		{"set without a device", func() error { return runSet(nil) }, isType[*errcode.Invalid]},
		{"identity without a subcommand", func() error { return runIdentity(nil) }, isType[*errcode.Invalid]},
		{"service unknown subcommand", func() error { return runService([]string{"restart"}) }, isType[*errcode.Invalid]},
	} {
		err := c.run()
		if err == nil || !c.want(err) {
			t.Errorf("%s: %v (%T), wrong type", c.name, err, err)
			continue
		}
		if text, _ := errcode.Render(err); strings.Contains(text, unexpected) {
			t.Errorf("%s: renders %q", c.name, text)
		}
	}
}

func isType[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

func isCode(code errcode.Code) func(error) bool {
	return func(err error) bool {
		var coded *errcode.Error
		return errors.As(err, &coded) && coded.Code == code
	}
}
