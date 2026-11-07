package session

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/identity"
)

// Reasons a desktop connection's handshake check ends it with.
const (
	CloseDesktopKeyChanged     = "desktop_key_changed"
	CloseDesktopKeyDowngraded  = "desktop_key_downgraded"
	CloseDesktopKeyRejected    = "desktop_key_rejected"
	CloseDesktopKeyUnavailable = "desktop_key_unavailable"
	CloseDesktopHandshake      = "desktop_handshake_invalid"
)

const (
	// reqDesktopKey asks the client to trust the target's server key before
	// any key byte reaches it; its payload is the key's hex SHA-256 and
	// whether it is pinned, its reply the client's answer.
	reqDesktopKey = "desktop-key@localport.io"
	// desktopCheckTimeout bounds each target read of the handshake check;
	// time spent waiting for the client does not count.
	desktopCheckTimeout = 30 * time.Second
	// RFB security types noVNC 1.7.0 runs whose key the agent checks: RA2ne,
	// at top level or as a VeNCrypt subtype (core/rfb.js).
	rfbSecRA2ne    = 6
	rfbSecVeNCrypt = 19
	// RA2ne server key bounds noVNC accepts (core/ra2.js).
	rfbMinKeyBits, rfbMaxKeyBits = 1024, 8192
)

// DesktopKeys is the device's pinned desktop target keys
// (identity.DesktopPins).
type DesktopKeys interface {
	Lookup(kind, target string) (key [32]byte, held bool, err error)
	Pin(ctx context.Context, kind, target string, key [32]byte) (identity.PinResult, error)
}

// rfbServerVersion is the form of a server ProtocolVersion; noVNC accepts
// several versions beyond RFC 6143's (003.889, 004.00x, 005.000), so only the
// form is checked and the client's reply sets the framing.
var rfbServerVersion = regexp.MustCompile(`^RFB [0-9]{3}\.[0-9]{3}\n$`)

// errHandshake marks a malformed handshake.
var errHandshake = errors.New("malformed RFB handshake")

// rfbCheck reads a VNC connection's handshake up to its security type, and
// for RA2ne up to the server key, forwarding every byte unchanged. It holds
// buffered readers on both sides; the relay continues from them, so bytes
// read ahead are never lost.
type rfbCheck struct {
	c          *conn
	ch         ssh.Channel
	target     net.Conn
	fromClient *bufio.Reader
	fromTarget *bufio.Reader
	keys       DesktopKeys
	kind, addr string
	// timeout is the deadline of each target read.
	timeout time.Duration
}

// run runs the handshake check. It returns the reason to end the
// connection with, or "" to relay; err is set when an end of the connection
// or a broken side interrupted it (the connection's own end reports it).
func (k *rfbCheck) run(ctx context.Context) (reason string, err error) {
	defer func() { _ = k.target.SetReadDeadline(time.Time{}) }()
	reason, err = k.check(ctx)
	if errors.Is(err, errHandshake) || errors.Is(err, os.ErrDeadlineExceeded) {
		return CloseDesktopHandshake, nil
	}
	return reason, err
}

func (k *rfbCheck) check(ctx context.Context) (string, error) {
	sv, err := k.fromServer(12)
	if err != nil {
		return "", err
	}
	if !rfbServerVersion.Match(sv) || string(sv) == "RFB 000.000\n" {
		return "", errHandshake
	}
	cv, err := k.fromClientForward(12)
	if err != nil {
		return "", err
	}
	var choice uint32
	switch string(cv) {
	case "RFB 003.003\n":
		b, err := k.fromServer(4)
		if err != nil {
			return "", err
		}
		if choice = binary.BigEndian.Uint32(b); choice == 0 {
			return "", nil // a refusal and its reason follow
		}
	case "RFB 003.007\n", "RFB 003.008\n":
		n, err := k.fromServer(1)
		if err != nil {
			return "", err
		}
		if n[0] == 0 {
			return "", nil
		}
		if _, err := k.fromServer(int(n[0])); err != nil {
			return "", err
		}
		b, err := k.fromClientForward(1)
		if err != nil {
			return "", err
		}
		choice = uint32(b[0])
	default:
		return "", errHandshake
	}
	switch choice {
	case rfbSecRA2ne:
		return k.keyStep(ctx)
	case rfbSecVeNCrypt:
		sub, ok, err := k.veNCrypt()
		if err != nil || !ok {
			return "", err
		}
		if sub == rfbSecRA2ne {
			return k.keyStep(ctx)
		}
	}
	return k.nonRSA()
}

// veNCrypt reads the VeNCrypt negotiation (versions, ack, subtypes) and
// returns the client's subtype; ok is false when the server refused it.
func (k *rfbCheck) veNCrypt() (sub uint32, ok bool, err error) {
	if _, err := k.fromServer(2); err != nil {
		return 0, false, err
	}
	if _, err := k.fromClientForward(2); err != nil {
		return 0, false, err
	}
	ack, err := k.fromServer(1)
	if err != nil || ack[0] != 0 {
		return 0, false, err
	}
	n, err := k.fromServer(1)
	if err != nil {
		return 0, false, err
	}
	if _, err := k.fromServer(4 * int(n[0])); err != nil {
		return 0, false, err
	}
	b, err := k.fromClientForward(4)
	if err != nil {
		return 0, false, err
	}
	return binary.BigEndian.Uint32(b), true, nil
}

// nonRSA ends a connection whose target was pinned and now uses no key.
func (k *rfbCheck) nonRSA() (string, error) {
	_, held, err := k.keys.Lookup(k.kind, k.addr)
	switch {
	case err != nil:
		k.c.s.log("session: desktop key of %s: %v", k.addr, err)
		return CloseDesktopKeyUnavailable, nil
	case held:
		k.c.s.log("session: desktop target %s offered no server key, but one is pinned", k.addr)
		return CloseDesktopKeyDowngraded, nil
	}
	return "", nil
}

// keyStep reads the RA2ne server key, compares it with the pin, asks the
// client to trust it, pins it on first use, and only then forwards it.
func (k *rfbCheck) keyStep(ctx context.Context) (string, error) {
	hdr, err := k.readTarget(4)
	if err != nil {
		return "", err
	}
	bits := binary.BigEndian.Uint32(hdr)
	if bits < rfbMinKeyBits || bits > rfbMaxKeyBits {
		return "", errHandshake
	}
	body, err := k.readTarget(2 * int((bits+7)/8))
	if err != nil {
		return "", err
	}
	key := append(hdr, body...)
	sum := sha256.Sum256(key)
	pinned, held, err := k.keys.Lookup(k.kind, k.addr)
	if err != nil {
		k.c.s.log("session: desktop key of %s: %v", k.addr, err)
		return CloseDesktopKeyUnavailable, nil
	}
	if held && pinned != sum {
		k.c.s.log("session: desktop target %s presented key %x, pinned %x", k.addr, sum, pinned)
		return CloseDesktopKeyChanged, nil
	}
	ok, err := k.ch.SendRequest(reqDesktopKey, true, ssh.Marshal(struct {
		SHA256 string
		Pinned bool
	}{hex.EncodeToString(sum[:]), held}))
	if err != nil {
		return "", err
	}
	if !ok {
		return CloseDesktopKeyRejected, nil
	}
	if !held {
		switch r, err := k.keys.Pin(ctx, k.kind, k.addr, sum); {
		case err != nil:
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			k.c.s.log("session: pin desktop key of %s: %v", k.addr, err)
			return CloseDesktopKeyUnavailable, nil
		case r == identity.PinChanged:
			k.c.s.log("session: desktop target %s presented key %x, another was pinned first", k.addr, sum)
			return CloseDesktopKeyChanged, nil
		}
	}
	if _, err := k.ch.Write(key); err != nil {
		return "", err
	}
	return "", nil
}

// fromServer reads n target bytes and forwards them to the client.
func (k *rfbCheck) fromServer(n int) ([]byte, error) {
	b, err := k.readTarget(n)
	if err != nil {
		return nil, err
	}
	if _, err := k.ch.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

// fromClientForward reads n client bytes and forwards them to the target;
// they count as activity.
func (k *rfbCheck) fromClientForward(n int) ([]byte, error) {
	b, err := k.read(k.fromClient, n)
	if err != nil {
		return nil, err
	}
	k.c.active()
	if _, err := k.target.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

// readTarget reads n target bytes within the check's per-read deadline.
func (k *rfbCheck) readTarget(n int) ([]byte, error) {
	_ = k.target.SetReadDeadline(time.Now().Add(k.timeout))
	return k.read(k.fromTarget, n)
}

func (k *rfbCheck) read(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("read handshake: %w", err)
	}
	return b, nil
}
