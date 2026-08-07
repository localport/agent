package identity

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
)

// Kind mirrors the SPIFFE path prefix the control plane issues under.
type Kind string

const (
	KindClient Kind = "client"
	KindDevice Kind = "device"
)

// Ref locates one stored credential: `<team>/<identity>`.
//
// The team is load-bearing: one machine legitimately holds credentials for
// several, and an identity is unique only inside one of them.
//
// No control-plane component: which plane issued a credential is recorded in
// Meta.APIURL, which is what renewal reads.
type Ref struct {
	Team     string
	Kind     Kind
	Identity string
}

// String is the CANONICAL selector form. Every ambiguity error prints it, so
// the value a person reads pastes straight back into --identity.
func (r Ref) String() string {
	return r.Team + "/" + r.Identity
}

// dir is the Ref's path relative to the store root. Components are used
// verbatim; valid() is what keeps them safe as path segments.
func (r Ref) dir() string {
	return r.Team + "/" + r.Identity
}

// valid reports whether every component is safe to use as a path segment.
//
// RefFromCert reads these out of a certificate, so a component of `..` would
// escape the store root. Refused rather than repaired: a repaired component
// names a different credential than the certificate does.
func (r Ref) valid() bool {
	for _, part := range []string{r.Team, r.Identity} {
		if part == "" || part == "." || part == ".." {
			return false
		}
		if strings.ContainsAny(part, `/\:`) {
			return false
		}
	}
	return true
}

// Selector narrows the store to one Ref. Empty fields match anything.
type Selector struct {
	Team     string
	Identity string
}

// Matches reports whether a Ref satisfies this selector.
func (s Selector) Matches(r Ref) bool {
	return (s.Team == "" || s.Team == r.Team) &&
		(s.Identity == "" || s.Identity == r.Identity)
}

// ParseSelector reads --identity, by segment count:
//
//	gw-01             a bare identity
//	<team>/gw-01      narrowed to one team
func ParseSelector(raw string) (Selector, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Selector{}, nil
	}
	parts := strings.Split(raw, "/")
	for _, p := range parts {
		if p == "" {
			return Selector{}, fmt.Errorf("identity %q has an empty part; use <identity> or <team>/<identity>", raw)
		}
	}
	switch len(parts) {
	case 1:
		return Selector{Identity: parts[0]}, nil
	case 2:
		return Selector{Team: parts[0], Identity: parts[1]}, nil
	default:
		return Selector{}, fmt.Errorf("identity %q has too many parts; use <identity> or <team>/<identity>", raw)
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
