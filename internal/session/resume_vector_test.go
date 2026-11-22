package session

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A client accepts an end reason of at most 64 bytes of [a-z_] and treats any
// other as unknown.
func TestEndReasonIsBounded(t *testing.T) {
	long := string(bytes.Repeat([]byte{'a'}, maxEndReasonLen))
	for reason, want := range map[string]string{
		CloseIdle: CloseIdle, CloseDetachTimeout: CloseDetachTimeout, long: long,
		long + "a": "", "Idle": "", "idle\x1b[2J": "", "idle-x": "", "": "",
	} {
		if got := endReason(reason); got != want {
			t.Errorf("endReason(%q) = %q, want %q", reason, got, want)
		}
	}
}

// TestResumeWireVector pins the prelude transcript, the close resume message
// and its transcript, token, proof, closeTag and ended proof reply encoding.
// The browser client pins the same vector.
func TestResumeWireVector(t *testing.T) {
	hello := helloMsg{Version: preludeVersion, ClientKey: bytes.Repeat([]byte{1}, 32), Cert: []byte("cert")}
	reply := helloReplyMsg{AgentKey: bytes.Repeat([]byte{2}, 32), Handle: bytes.Repeat([]byte{3}, resumeHandleLen)}
	th := transcript(hello.noSig(), reply.noSig())
	priv, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{4}, 32))
	peer, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{5}, 32))
	token, err := resumeToken(priv, peer.PublicKey().Bytes(), th)
	if err != nil {
		t.Fatal(err)
	}
	resume := resumeMsg{Version: preludeVersion, Handle: reply.Handle, ClientKey: hello.ClientKey, Position: 7, Close: true, Cert: hello.Cert}
	resumeReply := resumeReplyMsg{AgentKey: reply.AgentKey, Position: 9}
	for name, c := range map[string][2]string{
		"transcript":        {hex.EncodeToString(th), "765a0e44eee3def40bf33ded3d6d76df3cc66ec7ebd80bb3618573d193ddf35d"},
		"close resume":      {hex.EncodeToString(ssh.Marshal(resume.noSig())), "a2000000030000001003030303030303030303030303030303000000200101010101010101010101010101010101010101010101010101010101010101000000000000000701000000046365727400000000"},
		"resume transcript": {hex.EncodeToString(transcript(resume.noSig(), resumeReply.noSig())), "6d8ef9d65773c48ea962155923135baf073f13b4261623019edda046a672061c"},
		"token":             {hex.EncodeToString(token), "12c12d8d22a6e5c38722d5c07666464b18aebc4af182c902c22329de2fcf7066"},
		"proof":             {hex.EncodeToString(resumeProof(token, th)), "879083080b38c39ff47b7f402ea3d5dc86f92bbfea8fe9acd7460d4f48e9de1c"},
		"closeTag":          {hex.EncodeToString(binary.AppendUvarint(nil, closeTag)), "ffffffffffffffffff01"},
		"ended proof reply": {hex.EncodeToString(ssh.Marshal(proofReplyMsg{Status: statusEnded, Reason: CloseIdle})), "a5000000040000000469646c65"},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %s, want %s", name, c[0], c[1])
		}
	}
}
