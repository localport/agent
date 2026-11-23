package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

// Argument errors reach the user as usage errors, which carry no code, or
// with exactly one code: never the Unexpected line.
func TestCommandInputErrorsAreTyped(t *testing.T) {
	unexpected := errcode.New(errcode.Unexpected).Error()
	argument := "[" + string(errcode.InvalidArgument) + "]"
	for _, c := range []struct {
		name string
		run  func() error
		want func(error) bool
		code string
	}{
		{"unknown flag", func() error { return runSet([]string{"--no-such-flag"}) }, isType[*errcode.Usage], ""},
		{"service extra argument", func() error { return runService([]string{"install", "extra"}) }, isCode(errcode.ExtraArgument), "[" + string(errcode.ExtraArgument) + "]"},
		{"status extra argument", func() error { return runStatus([]string{"extra"}) }, isCode(errcode.ExtraArgument), "[" + string(errcode.ExtraArgument) + "]"},
		{"set without a device", func() error { return runSet(nil) }, isType[*errcode.Invalid], argument},
		{"identity without a subcommand", func() error { return runIdentity(nil) }, isType[*errcode.Invalid], argument},
		{"service unknown subcommand", func() error { return runService([]string{"restart"}) }, isType[*errcode.Invalid], argument},
	} {
		err := c.run()
		if err == nil || !c.want(err) {
			t.Errorf("%s: %v (%T), wrong type", c.name, err, err)
			continue
		}
		text, _ := errcode.Render(err)
		if strings.Contains(text, unexpected) {
			t.Errorf("%s: renders %q", c.name, text)
		}
		if c.code != "" && (!strings.HasSuffix(text, c.code) || strings.Count(text, "[AG") != 1) {
			t.Errorf("%s: renders %q, want the one code %s", c.name, text, c.code)
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
