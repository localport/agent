package identity

import "testing"

func TestParseSelector(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    Selector
		wantErr bool
	}{
		{"empty matches everything", "", Selector{}, false},
		{"bare identity", "gw-01", Selector{Identity: "gw-01"}, false},
		{
			// Two segments are TEAM/identity, NOT kind/identity. One rule beats a
			// heuristic that guesses from the shape of the first segment.
			"two segments are team and identity",
			"01kpq7x2/gw-01",
			Selector{Team: "01kpq7x2", Identity: "gw-01"},
			false,
		},
		{
			"three segments are fully qualified",
			"01kpq7x2/client/gw-01",
			Selector{Team: "01kpq7x2", Kind: KindClient, Identity: "gw-01"},
			false,
		},
		{
			"a person is addressable the same way",
			"01kpq7x2/user/7k2p9xq4mn3vb",
			Selector{Team: "01kpq7x2", Kind: KindUser, Identity: "7k2p9xq4mn3vb"},
			false,
		},
		{"unknown kind is refused", "01kpq7x2/robot/gw-01", Selector{}, true},
		{"too many segments", "a/b/c/d", Selector{}, true},
		{"empty part", "01kpq7x2//gw-01", Selector{}, true},
		{"trailing slash", "gw-01/", Selector{}, true},
		{"leading slash", "/gw-01", Selector{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSelector(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSelector(%q) = %+v, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSelector(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseSelector(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

// Every ambiguity error prints Ref.String(), so that value MUST parse back into
// a selector that names exactly the credential it came from. If these two ever
// drift, the fix an operator is handed does not work.
func TestRefStringRoundTripsThroughParseSelector(t *testing.T) {
	refs := []Ref{
		{Team: "01kpq7x2", Kind: KindClient, Identity: "gw-01"},
		{Team: "01kpq7x2", Kind: KindUser, Identity: "7k2p9xq4mn3vb"},
	}
	for _, ref := range refs {
		sel, err := ParseSelector(ref.String())
		if err != nil {
			t.Fatalf("ParseSelector(%q): %v", ref.String(), err)
		}
		if !sel.Matches(ref) {
			t.Fatalf("%q does not select the ref it was printed from", ref.String())
		}
		// And it must not select the OTHER namespace's same-named credential,
		// which is the whole reason the kind segment exists.
		other := ref
		if other.Kind == KindClient {
			other.Kind = KindUser
		} else {
			other.Kind = KindClient
		}
		if sel.Matches(other) {
			t.Fatalf("%q also selects %q; the kind segment is not binding", ref.String(), other.String())
		}
	}
}

// A `client` identity and a `user` username can legitimately collide inside one
// team: the server validates a client identity as lowercase alphanumerics, and a
// username is exactly that. The two-segment form must therefore match BOTH, so
// the ambiguity is reported rather than silently resolved to one of them.
func TestTeamAndNameMatchesBothNamespaces(t *testing.T) {
	const team, name = "01kpq7x2", "7k2p9xq4mn3vb"
	sel, err := ParseSelector(team + "/" + name)
	if err != nil {
		t.Fatalf("ParseSelector: %v", err)
	}
	asUser := Ref{Team: team, Kind: KindUser, Identity: name}
	asClient := Ref{Team: team, Kind: KindClient, Identity: name}
	if !sel.Matches(asUser) || !sel.Matches(asClient) {
		t.Fatal("the two-segment form must match both namespaces so Resolve can report the ambiguity")
	}
}
