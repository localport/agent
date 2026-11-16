package session

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/identity"
)

// Reasons a desktop connection's handshake ends it with, both kinds.
const (
	CloseDesktopKeyChanged     = "desktop_key_changed"
	CloseDesktopKeyDowngraded  = "desktop_key_downgraded"
	CloseDesktopKeyRejected    = "desktop_key_rejected"
	CloseDesktopKeyUnavailable = "desktop_key_unavailable"
	CloseDesktopHandshake      = "desktop_handshake_invalid"
	// CloseDesktopHandshakeTimeout: the client wait or a target deadline of
	// the handshake expired.
	CloseDesktopHandshakeTimeout = "desktop_handshake_timeout"
	// CloseDesktopTargetClosed: the target closed or failed, before or
	// during the relay.
	CloseDesktopTargetClosed = "desktop_target_closed"
)

const (
	// reqDesktopKey asks the client to trust the target's server key before
	// any key byte reaches it; its payload describes the key (vncKeyInfo,
	// rdpKeyInfo), its reply is the client's answer.
	reqDesktopKey = "desktop-key@localport.io"
	// desktopTargetTimeout bounds each target read and write of the
	// handshake; the deadlines are cleared before the relay.
	desktopTargetTimeout = 30 * time.Second
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

// vncKeyInfo is the desktop-key@localport.io payload of a vnc target: the
// RA2ne key's hex SHA-256 and whether it is pinned.
type vncKeyInfo struct {
	SHA256 string
	Pinned bool
}

// rfbServerVersion is the form of a server ProtocolVersion; noVNC accepts
// several versions beyond RFC 6143's (003.889, 004.00x, 005.000), so only the
// form is checked and the client's reply sets the framing.
var rfbServerVersion = regexp.MustCompile(`^RFB [0-9]{3}\.[0-9]{3}\n$`)

// rfbCheck reads a VNC connection's handshake up to its security type, and
// for RA2ne up to the server key, forwarding every byte unchanged. The relay
// continues from the handshake's buffered readers, so bytes read ahead are
// never lost. A client or server choice outside the types the filter frames
// ends the connection before it reaches the other side.
type rfbCheck struct {
	*desktopHandshake
	// version is the client's ProtocolVersion, which sets the framing.
	version string
	// auth is the security type in effect: the choice, or a VeNCrypt subtype.
	auth uint32
	// refusal says how the server refused the handshake, if it did.
	refusal rfbRefusal
}

// rfbRefusal is how a server refused the handshake during the check.
type rfbRefusal uint8

const (
	// rfbRefusedWithReason: a U32-length reason follows.
	rfbRefusedWithReason rfbRefusal = iota + 1
	// rfbRefusedNoReason: nothing follows (a VeNCrypt version refusal).
	rfbRefusedNoReason
)

// run runs the handshake check. It returns the reason to end the
// connection with, or "" to relay; err is a handshakeError or the
// connection's end (handshakeOutcome maps it).
func (k *rfbCheck) run(ctx context.Context) (reason string, err error) {
	defer func() { _ = k.target.SetDeadline(time.Time{}) }()
	return k.check(ctx)
}

func (k *rfbCheck) check(ctx context.Context) (string, error) {
	sv, err := k.fromServer(12)
	if err != nil {
		return "", err
	}
	if !rfbServerVersion.Match(sv) || string(sv) == "RFB 000.000\n" {
		return "", malformed(sideTarget, "server version %q", sv)
	}
	cv, err := k.fromClientForward(12)
	if err != nil {
		return "", err
	}
	k.version = string(cv)
	var choice uint32
	switch k.version {
	case "RFB 003.003\n":
		if err := k.clientWaitDone(); err != nil {
			return "", err
		}
		b, err := k.readTarget(k.fromTarget, 4)
		if err != nil {
			return "", err
		}
		choice = binary.BigEndian.Uint32(b)
		if choice != 0 && !rfbTypeAllowed(choice) {
			k.c.s.log("session: vnc target %s chose security type %d", k.addr, choice)
			return CloseDesktopProtocolViolation, nil
		}
		if err := k.writeClient(b); err != nil {
			return "", err
		}
		if choice == 0 {
			k.refusal = rfbRefusedWithReason
			return "", nil
		}
	case "RFB 003.007\n", "RFB 003.008\n":
		n, err := k.fromServer(1)
		if err != nil {
			return "", err
		}
		if n[0] == 0 {
			k.refusal = rfbRefusedWithReason
			return "", k.clientWaitDone()
		}
		if _, err := k.fromServer(int(n[0])); err != nil {
			return "", err
		}
		b, err := k.readClient(1)
		if err != nil {
			return "", err
		}
		choice = uint32(b[0])
		if !rfbTypeAllowed(choice) {
			k.c.s.log("session: vnc client chose security type %d", choice)
			return CloseDesktopProtocolViolation, nil
		}
		if err := k.writeTarget(b); err != nil {
			return "", err
		}
	default:
		return "", malformed(sideClient, "client version %q", cv)
	}
	k.auth = choice
	switch choice {
	case rfbSecRA2ne:
		if err := k.clientWaitDone(); err != nil {
			return "", err
		}
		return k.keyStep(ctx)
	case rfbSecVeNCrypt:
		sub, ok, reason, err := k.veNCrypt()
		if err != nil || reason != "" {
			return reason, err
		}
		if !ok {
			k.refusal = rfbRefusedNoReason
			return "", k.clientWaitDone()
		}
		if err := k.clientWaitDone(); err != nil {
			return "", err
		}
		k.auth = sub
		if sub == rfbSecRA2ne {
			return k.keyStep(ctx)
		}
	default:
		if err := k.clientWaitDone(); err != nil {
			return "", err
		}
	}
	return k.nonRSA()
}

// veNCrypt reads the VeNCrypt negotiation (versions, ack, subtypes) and
// returns the client's subtype; ok is false when the server refused it, and
// reason is set when the client chose a subtype the filter does not frame,
// which never reaches the server.
func (k *rfbCheck) veNCrypt() (sub uint32, ok bool, reason string, err error) {
	if _, err := k.fromServer(2); err != nil {
		return 0, false, "", err
	}
	if _, err := k.fromClientForward(2); err != nil {
		return 0, false, "", err
	}
	ack, err := k.fromServer(1)
	if err != nil || ack[0] != 0 {
		return 0, false, "", err
	}
	n, err := k.fromServer(1)
	if err != nil {
		return 0, false, "", err
	}
	if _, err := k.fromServer(4 * int(n[0])); err != nil {
		return 0, false, "", err
	}
	b, err := k.readClient(4)
	if err != nil {
		return 0, false, "", err
	}
	sub = binary.BigEndian.Uint32(b)
	if !rfbSubtypeAllowed(sub) {
		k.c.s.log("session: vnc client chose VeNCrypt subtype %d", sub)
		return 0, false, CloseDesktopProtocolViolation, nil
	}
	if err := k.writeTarget(b); err != nil {
		return 0, false, "", err
	}
	return sub, true, "", nil
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

// keyStep reads the RA2ne server key, runs the shared trust step on its
// SHA-256, and only then forwards it.
func (k *rfbCheck) keyStep(ctx context.Context) (string, error) {
	hdr, err := k.readTarget(k.fromTarget, 4)
	if err != nil {
		return "", err
	}
	bits := binary.BigEndian.Uint32(hdr)
	if bits < rfbMinKeyBits || bits > rfbMaxKeyBits {
		return "", malformed(sideTarget, "RA2ne key of %d bits", bits)
	}
	body, err := k.readTarget(k.fromTarget, 2*int((bits+7)/8))
	if err != nil {
		return "", err
	}
	key := append(hdr, body...)
	sum := sha256.Sum256(key)
	reason, err := k.trust(ctx, sum, func(pinned bool) []byte {
		return ssh.Marshal(vncKeyInfo{hex.EncodeToString(sum[:]), pinned})
	})
	if reason != "" || err != nil {
		return reason, err
	}
	return "", k.writeClient(key)
}

// fromServer reads n target bytes and forwards them to the client.
func (k *rfbCheck) fromServer(n int) ([]byte, error) {
	b, err := k.readTarget(k.fromTarget, n)
	if err != nil {
		return nil, err
	}
	return b, k.writeClient(b)
}

// fromClientForward reads n client bytes and forwards them to the target.
func (k *rfbCheck) fromClientForward(n int) ([]byte, error) {
	b, err := k.readClient(n)
	if err != nil {
		return nil, err
	}
	return b, k.writeTarget(b)
}
