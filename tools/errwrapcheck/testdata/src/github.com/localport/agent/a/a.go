package a

import (
	"errors"
	"fmt"

	"github.com/localport/agent/internal/errcode"
)

var ErrCoded = errcode.New("coded")

// ErrAlias is another name for a coded sentinel, as service.ErrUnsafeExecutable is.
var ErrAlias = ErrCoded

type CodedAlias = *errcode.Error

var errPlain = errors.New("plain")

func sites(param *errcode.Error, aliased CodedAlias, err error, name string) []error {
	return []error{
		fmt.Errorf("%w: detail", ErrCoded),                // want `format text around a coded error`
		fmt.Errorf("prefix %s: %w", name, ErrAlias),       // want `format text around a coded error`
		fmt.Errorf("ctx: %w", param),                      // want `format text around a coded error`
		fmt.Errorf("ctx: %w", aliased),                    // want `format text around a coded error`
		fmt.Errorf("%w and %w", errPlain, ErrCoded),       // want `format text around a coded error`
		fmt.Errorf("%[2]s: %[1]w", ErrCoded, name),        // want `format text around a coded error`
		fmt.Errorf("%*d %w", 3, 4, errcode.New("x")),      // want `format text around a coded error`
		errcode.Invalidf("device %s: %w", name, ErrCoded), // want `format text around a coded error`
		errcode.Invalidf("device %s: %w", name, err),
		fmt.Errorf("%w", ErrCoded),
		fmt.Errorf("%v: detail", ErrCoded),
		fmt.Errorf("ctx: %w", err),
		fmt.Errorf("ctx: %w", errPlain),
		fmt.Errorf("100%%: %s", name),
	}
}
