package identity

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

func wantCode(t *testing.T, err error, code errcode.Code) {
	t.Helper()
	if !errors.Is(err, errcode.New(code)) {
		t.Fatalf("err = %v, want code %s", err, code)
	}
}

// A call with no answer is AG126 and stays retryable; a 2xx body the agent
// cannot parse is AG127 and final.
func TestControlPlaneFailuresAreCoded(t *testing.T) {
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{")) })
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	var out struct{}
	err := c.post(context.Background(), "/v1/x", "", "", map[string]string{}, &out)
	wantCode(t, err, errcode.ControlPlaneAnswer)
	if Retryable(err) {
		t.Fatal("an unparsable answer must be final")
	}

	srv.Close()
	err = c.post(context.Background(), "/v1/x", "", "", map[string]string{}, &out)
	wantCode(t, err, errcode.ControlPlaneUnreachable)
	if !Retryable(err) {
		t.Fatal("a call with no answer must stay retryable")
	}
}

func TestResolveFailuresAreCoded(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	_, err := store.Resolve(Selector{})
	wantCode(t, err, errcode.NoCredential)

	for _, uri := range []string{
		"spiffe://02mfr8y3bcde45.mtls.localport.dev/client/deploy-prod",
		"spiffe://03ngs9z4cdef56.mtls.localport.dev/client/deploy-prod",
	} {
		if _, err := store.Save(context.Background(), credentialFor(t, uri)); err != nil {
			t.Fatal(err)
		}
	}
	_, err = store.Resolve(Selector{Identity: "deploy-prod"})
	wantCode(t, err, errcode.CredentialsAmbiguous)
	_, err = store.Resolve(Selector{Identity: "nobody"})
	wantCode(t, err, errcode.NoMatchingCredential)
}

func TestLoadOfAMissingCredentialIsCoded(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	_, err := store.Load(Ref{Team: "02mfr8y3bcde45", Kind: KindClient, Identity: "deploy-prod"})
	wantCode(t, err, errcode.CredentialUnreadable)
}
