package errcode

import (
	"errors"
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

// Render is the user text of err, built from typed parts of its chain and
// never from a node's Error(): each *Error's message and detail, a local
// cause the user acts on (*fs.PathError, *os.LinkError, a listen address in
// use) and a Remote's message, followed by every code, innermost first.
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
	text = strings.Join(r.parts, ": ")
	for _, c := range r.codes {
		text += " [" + c + "]"
	}
	for _, rem := range r.remedies {
		text += "\n  " + rem
	}
	return text, r.hidden
}

type renderer struct {
	parts, codes, remedies []string
	typed, hidden          bool
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
		if e.Op == "listen" && errors.Is(e.Err, syscall.EADDRINUSE) && e.Addr != nil {
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
			r.walk(inner)
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

// isNetwork reports whether err's chain holds a network or URL error.
func isNetwork(err error) bool {
	var netErr net.Error
	var urlErr *url.Error
	return errors.As(err, &netErr) || errors.As(err, &urlErr)
}
