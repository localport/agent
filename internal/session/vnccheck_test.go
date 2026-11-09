//go:build linux || darwin

package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// rsaKey is an RA2ne server key message of bits: the bit length, then
// modulus and exponent of ceil(bits/8) bytes.
func rsaKey(bits uint32, fill byte) []byte {
	n := int(bits+7) / 8
	b := binary.BigEndian.AppendUint32(nil, bits)
	return append(b, bytes.Repeat([]byte{fill}, 2*n)...)
}

// rfbServer is a scripted target: its version, then for 3.7+ the type list
// (types non-nil) or for 3.3 the chosen type, then after reads the client's
// choice runs after.
func rfbServer(version string, types []byte, type33 uint32, after func(c net.Conn) error) func(net.Conn) error {
	return func(c net.Conn) error {
		if _, err := io.WriteString(c, version); err != nil {
			return err
		}
		cv := make([]byte, 12)
		if _, err := io.ReadFull(c, cv); err != nil {
			return err
		}
		if types != nil {
			if _, err := c.Write(append([]byte{byte(len(types))}, types...)); err != nil {
				return err
			}
			if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
				return err
			}
		} else if _, err := c.Write(binary.BigEndian.AppendUint32(nil, type33)); err != nil {
			return err
		}
		return after(c)
	}
}

// sendKeyThenFrame writes the key.
func sendKeyThenFrame(key []byte) func(net.Conn) error {
	return func(c net.Conn) error {
		_, err := c.Write(key)
		return err
	}
}

// RA2ne messages after the server key, in the size noVNC 1.7.0 frames them
// for 1024-bit keys on both sides (core/ra2.js).
func ra2ClientKey() []byte { return rsaKey(1024, 2) }
func ra2Message(n int) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(n)), bytes.Repeat([]byte{9}, n)...)
}

// ra2Sealed is an authenticated message: length, payload and 16-byte tag.
func ra2Sealed(n int) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(n)), bytes.Repeat([]byte{8}, n+16)...)
}

// ra2ClientFirst is the client's key and random, sent together.
func ra2ClientFirst() []byte { return append(ra2ClientKey(), ra2Message(128)...) }

// ra2Server runs the server side of RA2ne: key and server random in one
// write, as a server may, then the rest through ServerInit. It answers key
// events afterwards.
func ra2Server(key []byte) func(net.Conn) error {
	return func(c net.Conn) error {
		if _, err := c.Write(append(append([]byte(nil), key...), ra2Message(128)...)); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, make([]byte, len(ra2ClientFirst())+len(ra2Sealed(20)))); err != nil {
			return err
		}
		if _, err := c.Write(append(ra2Sealed(20), ra2Sealed(1)...)); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, make([]byte, len(ra2Sealed(9)))); err != nil {
			return err
		}
		return finishNoneHandshake(c)
	}
}

// ra2Client runs the client side of RA2ne after the key was read.
func ra2Client(t *testing.T, ch ssh.Channel) {
	t.Helper()
	if _, err := ch.Write(ra2ClientFirst()); err != nil {
		t.Fatal(err)
	}
	readFor(t, ch, string(ra2Message(128)))
	if _, err := ch.Write(ra2Sealed(20)); err != nil {
		t.Fatal(err)
	}
	readFor(t, ch, string(append(ra2Sealed(20), ra2Sealed(1)...)))
	if _, err := ch.Write(ra2Sealed(9)); err != nil {
		t.Fatal(err)
	}
	if err := finishClientHandshake(ch); err != nil {
		t.Fatal(err)
	}
}

// keyRequest waits for the agent's desktop-key request and answers it.
func keyRequest(t *testing.T, reqs <-chan *ssh.Request, answer bool) (sum string, pinned bool) {
	t.Helper()
	select {
	case r, ok := <-reqs:
		if !ok {
			t.Fatal("the channel closed without a key request")
		}
		var p struct {
			SHA256 string
			Pinned bool
		}
		if r.Type != reqDesktopKey || !r.WantReply || ssh.Unmarshal(r.Payload, &p) != nil {
			t.Fatalf("request %q want-reply %v payload %q", r.Type, r.WantReply, r.Payload)
		}
		_ = r.Reply(answer, nil)
		return p.SHA256, p.Pinned
	case <-time.After(5 * time.Second):
		t.Fatal("no key request")
		return "", false
	}
}

// readAll reads the channel to its end and returns what arrived.
func readAll(ch ssh.Channel) []byte {
	b, _ := io.ReadAll(ch)
	return b
}

func keyFixture(t *testing.T, script func(net.Conn) error, keys *memKeys) (*sshFixture, *vncTarget) {
	t.Helper()
	target := newScriptedTarget(t, script)
	f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.DesktopKeys = keys })
	return f, target
}

// Client bytes sent ahead of the agent's handshake reads reach the target: the
// relay continues from the reader the check buffered them in.
func TestDesktopKeyHandOverKeepsPipelinedClientBytes(t *testing.T) {
	key := rsaKey(2048, 7)
	got := make(chan string, 1)
	script := rfbServer("RFB 003.008\n", []byte{6}, 0, func(c net.Conn) error {
		if err := sendKeyThenFrame(key)(c); err != nil {
			return err
		}
		ahead := make([]byte, len(ra2ClientKey()))
		if _, err := io.ReadFull(c, ahead); err != nil {
			return err
		}
		got <- string(ahead)
		return nil
	})
	f, _ := keyFixture(t, script, &memKeys{})
	client := f.connect(t, f.vncOpts())
	ch, reqs, err := openDesktopChannel(client, chanVNC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ch, make([]byte, 12)); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.Write(append([]byte("RFB 003.008\n\x06"), ra2ClientKey()...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ch, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	keyRequest(t, reqs, true)
	select {
	case ahead := <-got:
		if ahead != string(ra2ClientKey()) {
			t.Fatalf("target read %q", ahead)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the pipelined bytes never reached the target")
	}
}

// A first RA2ne key is asked for, pinned on trust and forwarded, and the
// bytes the server wrote after it reach the client through the filter; the
// next connection asks with pinned set.
func TestDesktopKeyFirstUseAndMatch(t *testing.T) {
	key := rsaKey(2048, 7)
	keys := &memKeys{}
	f, target := keyFixture(t, rfbServer("RFB 003.008\n", []byte{6}, 0, ra2Server(key)), keys)
	for _, step := range []struct {
		serial     uint64
		wantPinned bool
	}{{42, false}, {43, true}} {
		serial, wantPinned := step.serial, step.wantPinned
		o := f.vncOpts()
		o.serial = serial
		client := f.connect(t, o)
		ch, reqs, err := openDesktopChannel(client, chanVNC)
		if err != nil {
			t.Fatal(err)
		}
		if err := clientHandshake(ch, "RFB 003.008\n", 6); err != nil {
			t.Fatal(err)
		}
		sum, pinned := keyRequest(t, reqs, true)
		want := sha256.Sum256(key)
		if sum != hex.EncodeToString(want[:]) || pinned != wantPinned {
			t.Fatalf("key request %s pinned %v, want %x pinned %v", sum, pinned, want, wantPinned)
		}
		readFor(t, ch, string(key))
		ra2Client(t, ch)
		desktopPing(t, ch)
		_ = ch.Close()
		target.waitClosed(t)
		if serial == 42 {
			if k, held, _ := keys.Lookup("vnc", target.ln.Addr().String()); !held || k != want {
				t.Fatal("the trusted key was not pinned")
			}
		}
	}
}

// A refused key, a changed key, a downgrade after a pin, an unreadable store
// and a malformed handshake each end the connection with their reason before
// any key byte reaches the client; nothing is pinned.
func TestDesktopKeyRefusals(t *testing.T) {
	key, other := rsaKey(2048, 7), rsaKey(2048, 9)
	for _, tc := range []struct {
		name    string
		script  func(net.Conn) error
		keys    func(addr string) *memKeys
		version string
		choice  byte
		ask     bool // a key request arrives and is refused
		want    string
	}{
		{"rejected", rfbServer("RFB 003.008\n", []byte{6}, 0, sendKeyThenFrame(key)), func(string) *memKeys { return &memKeys{} }, "RFB 003.008\n", 6, true, CloseDesktopKeyRejected},
		{"changed", rfbServer("RFB 003.008\n", []byte{6}, 0, sendKeyThenFrame(key)), func(addr string) *memKeys {
			m := &memKeys{}
			_, _ = m.Pin(context.Background(), "vnc", addr, sha256.Sum256(other))
			return m
		}, "RFB 003.008\n", 6, false, CloseDesktopKeyChanged},
		{"downgraded", rfbServer("RFB 003.008\n", []byte{2}, 0, func(net.Conn) error { return nil }), func(addr string) *memKeys {
			m := &memKeys{}
			_, _ = m.Pin(context.Background(), "vnc", addr, sha256.Sum256(key))
			return m
		}, "RFB 003.008\n", 2, false, CloseDesktopKeyDowngraded},
		{"store unreadable", rfbServer("RFB 003.008\n", []byte{6}, 0, sendKeyThenFrame(key)), func(string) *memKeys {
			return &memKeys{err: errors.New("corrupt")}
		}, "RFB 003.008\n", 6, false, CloseDesktopKeyUnavailable},
		{"key too short", rfbServer("RFB 003.008\n", []byte{6}, 0, sendKeyThenFrame(rsaKey(512, 1))), func(string) *memKeys { return &memKeys{} }, "RFB 003.008\n", 6, false, CloseDesktopHandshake},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var keys *memKeys
			target := newScriptedTarget(t, tc.script)
			keys = tc.keys(target.ln.Addr().String())
			f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.DesktopKeys = keys })
			client := f.connect(t, f.vncOpts())
			ch, reqs, err := openDesktopChannel(client, chanVNC)
			if err != nil {
				t.Fatal(err)
			}
			if err := clientHandshake(ch, tc.version, tc.choice); err != nil {
				t.Fatal(err)
			}
			if tc.ask {
				keyRequest(t, reqs, false)
			}
			if reason := waitEndRequest(t, reqs); reason != tc.want {
				t.Fatalf("end reason %q, want %q", reason, tc.want)
			}
			if rest := readAll(ch); len(rest) != 0 {
				t.Fatalf("%d bytes reached the client after the check refused", len(rest))
			}
			if tc.name == "rejected" {
				if _, held, _ := keys.Lookup("vnc", target.ln.Addr().String()); held {
					t.Fatal("a rejected key was pinned")
				}
			}
			waitClosed(t, client)
		})
	}
}

// The handshake check reads 3.3 framing, VeNCrypt with an RA2ne subtype, and
// Apple's 003.889 server version; a repeater and a malformed version end it.
func TestDesktopKeyFraming(t *testing.T) {
	key := rsaKey(1024, 3)
	t.Run("3.3", func(t *testing.T) {
		f, _ := keyFixture(t, rfbServer("RFB 003.003\n", nil, 6, sendKeyThenFrame(key)), &memKeys{})
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openDesktopChannel(client, chanVNC)
		if err != nil {
			t.Fatal(err)
		}
		readFor(t, ch, "RFB 003.003\n")
		_, _ = io.WriteString(ch, "RFB 003.003\n")
		readFor(t, ch, string(binary.BigEndian.AppendUint32(nil, 6)))
		keyRequest(t, reqs, true)
		readFor(t, ch, string(key))
	})
	t.Run("VeNCrypt RA2ne", func(t *testing.T) {
		script := rfbServer("RFB 003.889\n", []byte{19}, 0, func(c net.Conn) error {
			if _, err := c.Write([]byte{0, 2}); err != nil {
				return err
			}
			if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
				return err
			}
			msg := []byte{0, 2}
			msg = binary.BigEndian.AppendUint32(msg, 256)
			msg = binary.BigEndian.AppendUint32(msg, 6)
			if _, err := c.Write(msg); err != nil {
				return err
			}
			if _, err := io.ReadFull(c, make([]byte, 4)); err != nil {
				return err
			}
			return sendKeyThenFrame(key)(c)
		})
		f, _ := keyFixture(t, script, &memKeys{})
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openDesktopChannel(client, chanVNC)
		if err != nil {
			t.Fatal(err)
		}
		if err := clientHandshake(ch, "RFB 003.008\n", 19); err != nil {
			t.Fatal(err)
		}
		readFor(t, ch, "\x00\x02")
		_, _ = ch.Write([]byte{0, 2})
		readFor(t, ch, "\x00\x02\x00\x00\x01\x00\x00\x00\x00\x06")
		_, _ = ch.Write(binary.BigEndian.AppendUint32(nil, 6))
		keyRequest(t, reqs, true)
		readFor(t, ch, string(key))
	})
	for name, version := range map[string]string{"repeater": "RFB 000.000\n", "malformed": "SSH-2.0-xx\r\n"} {
		t.Run(name, func(t *testing.T) {
			f, _ := keyFixture(t, rfbServer(version, []byte{2}, 0, func(net.Conn) error { return nil }), &memKeys{})
			client := f.connect(t, f.vncOpts())
			_, reqs, err := openDesktopChannel(client, chanVNC)
			if err != nil {
				t.Fatal(err)
			}
			if reason := waitEndRequest(t, reqs); reason != CloseDesktopHandshake {
				t.Fatalf("end reason %q, want %q", reason, CloseDesktopHandshake)
			}
		})
	}
}

// The check's target deadline runs per read: a slow client whose two
// replies together take longer than the deadline does not end a target that
// answers each at once.
func TestDesktopKeyCheckDeadlinePerRead(t *testing.T) {
	const timeout = time.Second
	key := rsaKey(2048, 7)
	target := newScriptedTarget(t, rfbServer("RFB 003.008\n", []byte{6}, 0, sendKeyThenFrame(key)))
	f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) {
		c.DesktopKeys = &memKeys{}
		c.desktopCheckTimeout = timeout
	})
	client := f.connect(t, f.vncOpts())
	ch, reqs, err := openDesktopChannel(client, chanVNC)
	if err != nil {
		t.Fatal(err)
	}
	readFor(t, ch, "RFB 003.008\n")
	time.Sleep(timeout * 7 / 10)
	_, _ = io.WriteString(ch, "RFB 003.008\n")
	readFor(t, ch, "\x01\x06")
	time.Sleep(timeout * 7 / 10)
	_, _ = ch.Write([]byte{6})
	keyRequest(t, reqs, true)
	readFor(t, ch, string(key))
}

// A target silent past the deadline ends the check desktop_handshake_timeout.
func TestDesktopKeyCheckSilentTarget(t *testing.T) {
	target := newScriptedTarget(t, func(c net.Conn) error {
		if _, err := io.WriteString(c, "RFB 003.008\n"); err != nil {
			return err
		}
		return errors.New("silent") // reads until the agent closes
	})
	f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) {
		c.DesktopKeys = &memKeys{}
		c.desktopCheckTimeout = 200 * time.Millisecond
	})
	client := f.connect(t, f.vncOpts())
	ch, reqs, err := openDesktopChannel(client, chanVNC)
	if err != nil {
		t.Fatal(err)
	}
	readFor(t, ch, "RFB 003.008\n")
	_, _ = io.WriteString(ch, "RFB 003.008\n")
	if reason := waitEndRequest(t, reqs); reason != CloseDesktopHandshakeTimeout {
		t.Fatalf("end reason %q, want %q", reason, CloseDesktopHandshakeTimeout)
	}
}

// An end while the agent waits for the client's trust answer ends the
// connection without pinning; the target closes.
func TestDesktopKeyEndDuringTheQuestion(t *testing.T) {
	key := rsaKey(2048, 5)
	keys := &memKeys{}
	f, target := keyFixture(t, rfbServer("RFB 003.008\n", []byte{6}, 0, sendKeyThenFrame(key)), keys)
	client := f.connect(t, f.vncOpts())
	ch, reqs, err := openDesktopChannel(client, chanVNC)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientHandshake(ch, "RFB 003.008\n", 6); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-reqs:
		if r.Type != reqDesktopKey {
			t.Fatalf("request %q", r.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no key request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown during the question: %v", err)
	}
	target.waitClosed(t)
	if _, held, _ := keys.Lookup("vnc", target.ln.Addr().String()); held {
		t.Fatal("a key was pinned without an answer")
	}
}
