//go:build windows

package access

import (
	"errors"
	"net"
)

func listenSocket(string) (net.Listener, error) {
	return nil, errors.New("a unix: forward is not available on Windows; use a local port")
}
