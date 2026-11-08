package session

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestResumeWireVector pins the prelude transcript, the close resume message
// and its transcript, token, proof and closeTag encoding. web/wasm/sshclient/client
// holds the same test, so the two implementations cannot drift.
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
		"transcript":        {hex.EncodeToString(th), "66e18f4517e05de10724c8b72777da6110476a06657287a541ba706e61e37915"},
		"close resume":      {hex.EncodeToString(ssh.Marshal(resume.noSig())), "a2000000020000001003030303030303030303030303030303000000200101010101010101010101010101010101010101010101010101010101010101000000000000000701000000046365727400000000"},
		"resume transcript": {hex.EncodeToString(transcript(resume.noSig(), resumeReply.noSig())), "764a280a0ef37aa4fa1eef1bd69fda317a3897d3737a1ec6b48fbd3433eb5566"},
		"token":             {hex.EncodeToString(token), "01c6f548677d8313766615560ee00e0a499b2680008248761f7651fd759cd12b"},
		"proof":             {hex.EncodeToString(resumeProof(token, th)), "b8c76fd56b9cfffd1054d47b4da6678805f1a81f7d4db02310461fd0a28f9a67"},
		"closeTag":          {hex.EncodeToString(binary.AppendUvarint(nil, closeTag)), "ffffffffffffffffff01"},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %s, want %s", name, c[0], c[1])
		}
	}
}
