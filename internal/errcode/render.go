package errcode

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
)

// Remote is a refusal the control plane or the edge sent. The agent shows
// its message and code exactly as received, never re-coded. Implementers
// sanitize both at decode (security.SanitizeDisplay).
type Remote interface {
	error
	// RemoteMessage is the server's message, or a text naming the HTTP
	// status class when the server sent none.
	RemoteMessage() string
	// RemoteCode is the server's code, empty when it sent none.
	RemoteCode() string
}

// Remedy is local text telling the user what to do about Err, which a
// caller adds to an error it did not create. Render prints it after Err's
// text and codes.
type Remedy struct {
	Err  error
	Text string
}

// WithRemedy returns err with the remedy text, local text only.
func WithRemedy(err error, text string) error { return &Remedy{Err: err, Text: text} }

func (r *Remedy) Error() string { return r.Err.Error() + "\n  " + r.Text }

func (r *Remedy) Unwrap() error { return r.Err }

// Invalid is local input the user must fix: a flag or config value, or the
// content of a local file its parser refused. Render prints its text. Build
// it with Invalidf from local input only, never around network, control
// plane or edge text; an Invalid whose chain holds a coded, remote or
// network error renders that chain by type instead.
type Invalid struct{ err error }

// Invalidf formats like fmt.Errorf, %w included.
func Invalidf(format string, args ...any) error {
	return &Invalid{err: fmt.Errorf(format, args...)}
}

func (e *Invalid) Error() string { return e.err.Error() }

func (e *Invalid) Unwrap() error { return e.err }

// Render is the user text of err, built from typed parts of its chain and
// never from a node's Error(): each *Error's message and detail, a local
// cause the user acts on (*fs.PathError, *os.LinkError, a listen address in
// use, an *Invalid) and a Remote's message, followed by every code,
// innermost first. Each error of a join prints on its own line.
// Other causes (network, TLS, server internals, plain wrappers) are left
// out; hidden reports that one was, so the caller can point at --verbose,
// which prints Error(). A chain with no *Error and no Remote is plain local
// text and prints as Error(), unless it holds a network error.
func Render(err error) (text string, hidden bool) {
	if err == nil {
		return "", false
	}
	var r renderer
	r.walk(err)
	if !r.typed {
		if isNetwork(err) {
			return "a network operation failed", true
		}
		return err.Error(), false
	}
	return r.text(), r.hidden
}

// renderer collects the shown parts of one chain. Each error of a join
// (errors.Join, or fmt.Errorf with several %w) is its own branch, rendered
// on its own line.
type renderer struct {
	parts, codes, remedies, branches []string
	typed, hidden                    bool
}

func (r *renderer) text() string {
	text := strings.Join(r.parts, ": ")
	for _, c := range r.codes {
		text += " [" + c + "]"
	}
	lines := make([]string, 0, 1+len(r.branches)+len(r.remedies))
	if text != "" {
		lines = append(lines, text)
	}
	indent := ""
	if text != "" {
		indent = "  "
	}
	for _, b := range r.branches {
		lines = append(lines, indent+strings.ReplaceAll(b, "\n", "\n"+indent))
	}
	for _, rem := range r.remedies {
		lines = append(lines, "  "+rem)
	}
	return strings.Join(lines, "\n")
}

func (r *renderer) walk(err error) {
	switch e := err.(type) {
	case *Remedy:
		r.walk(e.Err)
		r.remedies = append(r.remedies, e.Text)
		return
	case *Error:
		r.typed = true
		part := e.Msg
		if e.Detail != "" {
			part += ": " + e.Detail
		}
		r.parts = append(r.parts, part)
		if e.Err != nil {
			r.walk(e.Err)
		}
		r.codes = append(r.codes, string(e.Code))
		return
	case *Invalid:
		r.typed = true
		if holdsTyped(e.err) {
			r.walk(e.err)
		} else {
			r.parts = append(r.parts, e.Error())
		}
		return
	case Remote:
		r.typed = true
		r.parts = append(r.parts, e.RemoteMessage())
		if u, ok := e.(interface{ Unwrap() error }); ok && u.Unwrap() != nil {
			r.walk(u.Unwrap())
		}
		if c := e.RemoteCode(); c != "" {
			r.codes = append(r.codes, c)
		}
		return
	case *fs.PathError:
		r.parts = append(r.parts, e.Op+" "+e.Path+": "+errnoText(e.Err))
		return
	case *os.LinkError:
		r.parts = append(r.parts, e.Op+" "+e.Old+" "+e.New+": "+errnoText(e.Err))
		return
	case *os.SyscallError:
		r.parts = append(r.parts, e.Syscall+": "+errnoText(e.Err))
		return
	case syscall.Errno:
		r.parts = append(r.parts, e.Error())
		return
	case *net.OpError:
		if e.Op == "listen" && addrInUse(e.Err) && e.Addr != nil {
			r.parts = append(r.parts, "listen "+e.Addr.String()+": address already in use")
			return
		}
		// A network failure: its addresses and OS error stay out.
		r.hidden = true
		return
	case *url.Error, net.Error:
		r.hidden = true
		return
	}
	// A wrapper's own words are context, not a cause: it is passed through,
	// and only a cause at the end of the chain that is not shown marks the
	// text as incomplete.
	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		for _, inner := range u.Unwrap() {
			var b renderer
			b.walk(inner)
			r.typed = r.typed || b.typed
			r.hidden = r.hidden || b.hidden
			if t := b.text(); t != "" {
				r.branches = append(r.branches, t)
			}
		}
	case interface{ Unwrap() error }:
		if inner := u.Unwrap(); inner != nil {
			r.walk(inner)
		} else {
			r.hidden = true
		}
	default:
		r.hidden = true
	}
}

// errnoText is the OS error of a local file operation: an Errno's own text,
// else a generic one, since anything else may carry foreign detail.
func errnoText(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "no such file or directory"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, fs.ErrExist):
		return "file exists"
	}
	return "failed"
}

// holdsTyped reports whether err's chain holds a coded, remote or network
// error, which Render shows or hides by type rather than as text.
func holdsTyped(err error) bool {
	var coded *Error
	var remote Remote
	return errors.As(err, &coded) || errors.As(err, &remote) || isNetwork(err)
}

// isNetwork reports whether err's chain holds a network or URL error.
func isNetwork(err error) bool {
	var netErr net.Error
	var urlErr *url.Error
	return errors.As(err, &netErr) || errors.As(err, &urlErr)
}
