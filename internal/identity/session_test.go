package identity

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// The control plane's tests pin the same vector, so a change on either side
// fails.
func TestSessionRequestDigestGoldenVector(t *testing.T) {
	got := sessionRequestDigest(mintSessionBody{
		DeviceHost: "gw-01-factory.eu.localport.dev", Kind: "ssh", Login: "pi",
		ClientSSHPubKey: "ssh-ed25519 AAAA", CertChain: "PEM", Timestamp: 1700000000,
	})
	const want = "51e9a08783bb56b5accf563a08e7bea097cc3567a0c040bf612e69a7c8eff158"
	if hex.EncodeToString(got) != want {
		t.Fatalf("digest = %x, want %s", got, want)
	}
}

func TestMintSessionSendsASignedRequest(t *testing.T) {
	cur := credentialFor(t, "spiffe://01kpq7x2abcd34.mtls.localport.dev/user/ana")
	want := SessionCertificate{Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA", URL: "wss://edge/v1/session", HostKey: "ecdsa-sha2-nistp256 AAAA", DeviceHost: "gw-01-factory.eu.localport.dev"}
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sessions" {
			t.Errorf("request = %s %s, want POST /v1/sessions", r.Method, r.URL.Path)
		}
		var body mintSessionBody
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			t.Errorf("body: %v", err)
		}
		if body.DeviceHost != want.DeviceHost || body.Kind != "ssh" || body.Login != "pi" || body.ClientSSHPubKey != "ssh-ed25519 AAAA" {
			t.Errorf("body = %+v", body)
		}
		leaf, err := leafOf([]byte(body.CertChain))
		if err != nil {
			t.Fatal(err)
		}
		if mine, _ := leafOf(cur.CertPEM); !leaf.Equal(mine) {
			t.Error("cert_chain is not the current certificate")
		}
		sig, err := base64.StdEncoding.DecodeString(body.Sig)
		if err != nil {
			t.Fatalf("sig is not standard base64: %v", err)
		}
		if !ecdsa.VerifyASN1(leaf.PublicKey.(*ecdsa.PublicKey), sessionRequestDigest(body), sig) {
			t.Error("sig does not verify over the session request digest")
		}
		_ = json.NewEncoder(w).Encode(want)
	})
	got, err := (&Client{BaseURL: srv.URL, HTTP: srv.Client()}).MintSession(context.Background(), &cur, SessionRequest{
		DeviceHost: want.DeviceHost, Kind: "ssh", Login: "pi", ClientSSHPubKey: "ssh-ed25519 AAAA",
	})
	if err != nil || *got != want {
		t.Fatalf("MintSession = %+v, %v; want %+v", got, err, want)
	}
}

func TestMintSessionRefusesADeviceCredential(t *testing.T) {
	cur := Material{Meta: Meta{Kind: KindDevice, Identity: "factory.gw-01"}}
	if _, err := (&Client{BaseURL: "http://127.0.0.1:1"}).MintSession(context.Background(), &cur, SessionRequest{}); !errors.Is(err, ErrDeviceCredential) {
		t.Fatalf("MintSession = %v, want ErrDeviceCredential", err)
	}
}
