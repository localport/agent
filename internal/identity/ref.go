package identity

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
)

// Kind mirrors the SPIFFE path prefix. `user` and `client` are separate
// namespaces and may hold the same identity string.
type Kind string

const (
	KindUser   Kind = "user"
	KindClient Kind = "client"
	KindDevice Kind = "device"
)

// Valid reports whether k is a namespace this build knows. An unknown kind is
// refused, since it would be stored under its own directory and resolved
// through the wrong SPIFFE namespace.
func (k Kind) Valid() bool {
	switch k {
	case KindUser, KindClient, KindDevice:
		return true
	default:
		return false
	}
}

// Ref locates one stored credential at `<team>/<kind>-<identity>`. A machine
// can hold credentials for several teams, and `user` and `client` may share an
// identity string, so both components are required. The issuing control plane
// is recorded in Meta.APIURL.
type Ref struct {
	Team     string
	Kind     Kind
	Identity string
}

// String returns the full selector form, `<team>/<kind>/<identity>`.
// Ambiguity errors print it so it can be passed back to --identity.
func (r Ref) String() string {
	return r.Team + "/" + string(r.Kind) + "/" + r.Identity
}

// dir is the Ref's path relative to the store root. Components are used
// verbatim, and valid() keeps them safe as path segments.
func (r Ref) dir() string {
	return r.Team + "/" + string(r.Kind) + "-" + r.Identity
}

// maxRefComponent bounds a path component for path safety. The control plane
// applies its own, stricter limits.
const maxRefComponent = 64

// valid reports whether every component is a safe path segment. Components
// come from certificates, so they must match the server grammar of lowercase
// alphanumerics and internal dashes. Invalid components are refused and not
// repaired.
func (r Ref) valid() bool {
	return r.Kind.Valid() && validRefComponent(r.Team) && validRefComponent(r.Identity)
}

func validRefComponent(s string) bool {
	if s == "" || len(s) > maxRefComponent {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// Label is the word shown to a person. The SPIFFE path and the selector keep
// the wire values `client` and `user`.
func (k Kind) Label() string {
	switch k {
	case KindUser:
		return "Member"
	case KindClient:
		return "Machine"
	case KindDevice:
		return "Device"
	default:
		return string(k)
	}
}

// DisplayTeam renders the team as `name (id)`, or the id alone when no name is
// known. The id is what --identity accepts.
func (m Meta) DisplayTeam() string {
	if m.TeamName != "" {
		return fmt.Sprintf("%s (%s)", m.TeamName, m.Team)
	}
	return m.Team
}

// Selector narrows the store to one Ref. Empty fields match anything.
type Selector struct {
	Team     string
	Kind     Kind
	Identity string
}

// Matches reports whether a Ref satisfies this selector.
func (s Selector) Matches(r Ref) bool {
	return (s.Team == "" || s.Team == r.Team) &&
		(s.Kind == "" || s.Kind == r.Kind) &&
		(s.Identity == "" || s.Identity == r.Identity)
}

// ParseSelector reads --identity, by segment count:
//
//	gw-01                     a bare identity
//	<team>/gw-01              narrowed to one team
//	<team>/client/gw-01       fully qualified
//
// Two segments are always team/identity. The three-segment form disambiguates a
// team holding a client and a user credential under the same name.
func ParseSelector(raw string) (Selector, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Selector{}, nil
	}
	parts := strings.Split(raw, "/")
	for _, p := range parts {
		if p == "" {
			return Selector{}, fmt.Errorf("identity %q has an empty part; use <identity>, <team>/<identity> or <team>/<kind>/<identity>", raw)
		}
	}
	switch len(parts) {
	case 1:
		return Selector{Identity: parts[0]}, nil
	case 2:
		return Selector{Team: parts[0], Identity: parts[1]}, nil
	case 3:
		kind := Kind(parts[1])
		if !kind.Valid() {
			return Selector{}, fmt.Errorf("unknown identity kind %q (want user, client or device)", parts[1])
		}
		return Selector{Team: parts[0], Kind: kind, Identity: parts[2]}, nil
	default:
		return Selector{}, fmt.Errorf("identity %q has too many parts; use <identity>, <team>/<identity> or <team>/<kind>/<identity>", raw)
	}
}

// RefFromCert reads the Ref from the leaf's SPIFFE URI SAN. The certificate is
// authoritative over response fields.
func RefFromCert(leaf *x509.Certificate) (Ref, error) {
	for _, u := range leaf.URIs {
		if u.Scheme != "spiffe" {
			continue
		}
		team, rest, ok := strings.Cut(u.Host, ".")
		if !ok || team == "" || !strings.HasPrefix(rest, "mtls.") {
			continue
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		// A device path has the tunnel between kind and identity.
		switch {
		case len(parts) == 2:
			return Ref{Team: team, Kind: Kind(parts[0]), Identity: parts[1]}, nil
		case len(parts) == 3 && Kind(parts[0]) == KindDevice:
			return Ref{Team: team, Kind: KindDevice, Identity: parts[2]}, nil
		}
	}
	return Ref{}, fmt.Errorf("certificate carries no Localport SPIFFE identity")
}

// SpiffeURI returns the certificate's SPIFFE URI SAN, for display and for the
// principal pin.
func SpiffeURI(leaf *x509.Certificate) string {
	for _, u := range leaf.URIs {
		if u.Scheme == "spiffe" {
			return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
		}
	}
	return ""
}
