package errcode

type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func New(msg string) *Error { return &Error{Msg: msg} }

func Invalidf(format string, args ...any) error { return New(format) }
