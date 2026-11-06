package session

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestResumeWireVector pins the prelude transcript, token, proof and
// closeTag encoding. web/wasm/sshclient/client holds the same test, so the
// two implementations cannot drift.
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
	for name, c := range map[string][2]string{
		"transcript": {hex.EncodeToString(th), "d530d326bab17596e813ab5463b5d5a4aa7163b535c807b78f3e092356c363bf"},
		"token":      {hex.EncodeToString(token), "2c08b9288a15608ae439c5290c103a680581954f7fc6f797c306212fb6a25d9b"},
		"proof":      {hex.EncodeToString(resumeProof(token, th)), "23b9a01044025cc737745db07e65c4cea601f378c81242f68375c4bbfea23b83"},
		"closeTag":   {hex.EncodeToString(binary.AppendUvarint(nil, closeTag)), "ffffffffffffffffff01"},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %s, want %s", name, c[0], c[1])
		}
	}
}
