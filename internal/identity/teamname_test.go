package identity

import (
	"encoding/json"
	"testing"
	"time"
)

// Absent must SERIALISE as absent, not as an empty string that later reads as a
// team genuinely called "".
func TestTeamNameIsOmittedWhenEmpty(t *testing.T) {
	raw, err := json.Marshal(Meta{
		Identity: "gw-01", Team: "01kpq7x2", Kind: KindClient,
		Source: SourceToken, NotAfter: time.Now(),
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
	if got := out.DisplayTeam(); got != "Acme Robotics (01kpq7x2)" {
		t.Fatalf("DisplayTeam = %q", got)
	}
}
