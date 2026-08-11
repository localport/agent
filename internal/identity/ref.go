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

// Valid reports whether k is a namespace this build knows. A positive allowlist:
// an unrecognised kind would be filed under its own directory and resolved
// through the wrong SPIFFE namespace, so it is refused rather than carried.
func (k Kind) Valid() bool {
	switch k {
	case KindUser, KindClient, KindDevice:
		return true
	default:
		return false
	}
}

// Ref locates one stored credential: `<team>/<kind>-<identity>`.
//
// Both components are load-bearing. Team, because one machine legitimately holds
// credentials for several. Kind, because `user` and `client` may hold the same
// identity string, so keying on team alone lets `localport login` and
// `localport enroll` overwrite each other.
//
// No control-plane component: which plane issued a credential is recorded in
// Meta.APIURL, which is what renewal reads.
type Ref struct {
	Team     string
	Kind     Kind
	Identity string
}

// String is the CANONICAL selector form, `<team>/<kind>/<identity>`. Every
// ambiguity error prints it, so the value a person reads pastes straight back
// into --identity.
func (r Ref) String() string {
	return r.Team + "/" + string(r.Kind) + "/" + r.Identity
}

// dir is the Ref's path relative to the store root. Components are used
// verbatim; valid() is what keeps them safe as path segments.
func (r Ref) dir() string {
	return r.Team + "/" + string(r.Kind) + "-" + r.Identity
}

// valid reports whether every component is safe to use as a path segment.
//
// RefFromCert reads these out of a certificate, so a component of `..` would
// escape the store root. Refused rather than repaired: a repaired component
// names a different credential than the certificate does.
func (r Ref) valid() bool {
	for _, part := range []string{r.Team, string(r.Kind), r.Identity} {
		if part == "" || part == "." || part == ".." {
			return false
		}
		if strings.ContainsAny(part, `/\:`) {
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

// RefFromCert reads the identity out of a leaf's SPIFFE URI SAN. The
// certificate is authoritative: a directory named from a response field could
// disagree with the material inside it.
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
		// device carries its tunnel between kind and identity.
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
