package identity

import (
	"encoding/json"
	"testing"
	"time"
)

// team_name is optional. A record without it still loads.
func TestMetaWithoutTeamNameStillValidates(t *testing.T) {
	m := Meta{
		Identity: "gw-01",
		Team:     "01kpq7x2",
		Kind:     KindClient,
		Source:   SourceToken,
		NotAfter: time.Now().Add(time.Hour),
		Cert:     "cert-1.pem",
		Key:      KeyRef{Backing: BackingFile, File: "key-1.pem"},
	}
	if err := m.validate(); err != nil {
		t.Fatalf("a credential with no team name must still load: %v", err)
	}
}

// An empty team name is omitted from meta.json.
func TestTeamNameIsOmittedWhenEmpty(t *testing.T) {
	raw, err := json.Marshal(Meta{
		Identity: "gw-01", Team: "01kpq7x2", Kind: KindClient,
		Source: SourceToken, NotAfter: time.Now(),
		Cert: "cert-1.pem", Key: KeyRef{Backing: BackingFile, File: "key-1.pem"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := back["team_name"]; present {
		t.Fatal("team_name must be omitted when empty, not written as an empty string")
	}
}

func TestTeamNameRoundTrips(t *testing.T) {
	in := Meta{
		Identity: "gw-01", Team: "01kpq7x2", TeamName: "Acme Robotics",
		Kind: KindClient, Source: SourceToken, NotAfter: time.Now().UTC().Truncate(time.Second),
		Cert: "cert-1.pem", Key: KeyRef{Backing: BackingFile, File: "key-1.pem"},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Meta
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TeamName != in.TeamName {
		t.Fatalf("team_name = %q, want %q", out.TeamName, in.TeamName)
	}
	if err := out.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}
