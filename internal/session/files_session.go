package session

import (
	"encoding/json"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/launcher"
)

// FilesSessionRequest is the channel request a files connection's sftp
// channel receives once its file server started, before the subsystem
// reply: the session's view for the page (docs/PROTOCOL.md files-session).
const FilesSessionRequest = "files-session@localport.io"

// filesSession is the FilesSessionRequest JSON. Home is relative to the
// served folder and never absolute; WholeDisk marks a served folder that is
// the file system root; FullDiskAccess is set on macOS only.
type filesSession struct {
	Confined       bool   `json:"confined"`
	Home           string `json:"home,omitempty"`
	WholeDisk      bool   `json:"whole_disk,omitempty"`
	FullDiskAccess string `json:"full_disk_access,omitempty"`
}

// filesSessionPayload is the FilesSessionRequest payload for sess: one SSH
// string holding the JSON.
func filesSessionPayload(sess *launcher.Session) []byte {
	b, _ := json.Marshal(filesSession{Confined: sess.Confined, Home: sess.Home, WholeDisk: sess.WholeDisk, FullDiskAccess: sess.FullDiskAccess}) // plain struct, cannot fail
	return ssh.Marshal(struct{ JSON string }{string(b)})
}
