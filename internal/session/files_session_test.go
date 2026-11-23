//go:build linux || darwin

package session

import (
	"encoding/json"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/launcher"
)

// openSFTP opens a raw session channel on client, requests the sftp
// subsystem and returns the channel requests that arrived before the reply.
func openSFTP(t *testing.T, client *ssh.Client) []*ssh.Request {
	t.Helper()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ch.Close() })
	ok, err := ch.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
	if err != nil || !ok {
		t.Fatalf("subsystem: %v %v", ok, err)
	}
	// Requests are queued in arrival order before the reply is returned.
	var got []*ssh.Request
	for {
		select {
		case r := <-reqs:
			got = append(got, r)
		default:
			return got
		}
	}
}

// A files connection's sftp channel gets one files-session request, before
// the subsystem reply, carrying the launcher's view and Full Disk Access
// reading; an ssh connection's gets none.
func TestFilesSessionMessage(t *testing.T) {
	f := newSSHFixture(t, func(c *ServerConfig) { c.Capabilities = []string{"terminal", "files"} })
	f.launcher.confined, f.launcher.home, f.launcher.wholeDisk, f.launcher.fda = true, "Users/x", true, launcher.FullDiskAccessDenied
	o := f.defaults()
	o.kind = "files"
	got := openSFTP(t, f.connect(t, o))
	if len(got) != 1 || got[0].Type != FilesSessionRequest || got[0].WantReply {
		t.Fatalf("requests before the reply: %d %+v", len(got), got)
	}
	var p struct{ JSON string }
	if err := ssh.Unmarshal(got[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(p.JSON), &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 4 || m["confined"] != true || m["home"] != "Users/x" || m["whole_disk"] != true || m["full_disk_access"] != launcher.FullDiskAccessDenied {
		t.Fatalf("message %s", p.JSON)
	}

	o.kind = "ssh"
	if got := openSFTP(t, f.connect(t, o)); len(got) != 0 {
		t.Fatalf("ssh connection got %d requests", len(got))
	}
}

// Off macOS and unconfined, the message is {"confined":false} alone.
func TestFilesSessionPayloadOmitsUnset(t *testing.T) {
	var p struct{ JSON string }
	if err := ssh.Unmarshal(filesSessionPayload(&launcher.Session{}), &p); err != nil {
		t.Fatal(err)
	}
	if p.JSON != `{"confined":false}` {
		t.Fatalf("payload %s", p.JSON)
	}
}
