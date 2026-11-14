package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/localport/agent/internal/security"
)

// DeviceInfo is what enrolment reports about a device besides its
// certificate. The certificate stays authoritative for team and identity.
type DeviceInfo struct {
	// Host is the device's public address, `<prefix>.<base>`.
	Host string `json:"host"`
	// Region is where the device's edge runs.
	Region string `json:"region"`
}

// DeviceKeys mirrors the control plane's DeviceKeys: the session CA keys
// and the team's recording public key. The device keeps
// them in its TicketKeys, never in meta.json.
type DeviceKeys struct {
	TicketKeys   []TicketKey `json:"ticket_keys"`
	RecordingKey string      `json:"recording_key"`
}

// TicketKey is one session CA key (an SSH user certificate signer).
type TicketKey struct {
	KID       string `json:"kid"`
	PublicKey string `json:"public_key"`
}

// enrolResponse is POST /v1/devices/enrol.
type enrolResponse struct {
	CertPEM          string     `json:"cert_pem"`
	CAChainPEM       string     `json:"ca_chain_pem"`
	TeamID           string     `json:"team_id"`
	TunnelIdentifier string     `json:"tunnel_identifier"`
	Prefix           string     `json:"prefix"`
	DeviceHost       string     `json:"device_host"`
	Region           string     `json:"region"`
	RenewAfter       string     `json:"renew_after"`
	Keys             DeviceKeys `json:"keys"`
}

// EnrolDevice redeems a single-use join token for a device credential. The key
// is generated here and only its CSR is sent. The token is not written to
// disk. budget bounds retries against an unreachable control plane; refusals
// are not retried, and a token the server redeemed before a lost response is
// refused on the retry.
func (c *Client) EnrolDevice(
	ctx context.Context, joinToken string, budget time.Duration, onWait RetryNotice,
) (*Material, error) {
	joinToken = strings.TrimSpace(joinToken)
	if joinToken == "" {
		return nil, errors.New("join token required")
	}
	kp, err := newKeyPair("")
	if err != nil {
		return nil, err
	}

	var resp enrolResponse
	key := newIdempotencyKey()
	if err := retry(ctx, budget, onWait, func() error {
		resp = enrolResponse{}
		return c.post(ctx, "/v1/devices/enrol", "", key, map[string]string{
			"join_token": joinToken,
			"csr_pem":    string(kp.csrPEM),
		}, &resp, joinToken)
	}); err != nil {
		return nil, err
	}
	if resp.CertPEM == "" {
		return nil, errAnswer.With(nil, "no certificate for the CSR")
	}
	// DNS names compare without case; the host is stored lowercase. A fleet
	// without a public domain has no device host.
	// The shown value is the one received, so redaction matches an echo.
	host := resp.DeviceHost
	resp.DeviceHost = lowerASCII(host)
	if resp.DeviceHost != "" && !validDeviceHost(resp.DeviceHost) {
		return nil, errAnswer.With(fmt.Errorf("device host %q", security.RedactString(security.SanitizeDisplay(host), joinToken)), "invalid device host")
	}
	if resp.Region != "" && !ValidRegion(resp.Region) {
		return nil, errAnswer.With(fmt.Errorf("region %q", security.RedactString(security.SanitizeDisplay(resp.Region), joinToken)), "invalid region")
	}

	m, err := c.assemble(kp.key, issuedMaterial{
		CertPEM:    resp.CertPEM,
		ChainPEM:   resp.CAChainPEM,
		Source:     SourceToken,
		RenewAfter: resp.RenewAfter,
		Device:     &DeviceInfo{Host: resp.DeviceHost, Region: resp.Region},
	})
	if err != nil {
		return nil, err
	}
	// A missing set stays nil; KeyRefresher fetches one once the device runs.
	m.DeviceKeys = issuedKeys(&resp.Keys)
	// The response's description of the device must match the certificate,
	// which must carry the key generated above.
	want := Ref{Team: resp.TeamID, Kind: KindDevice, Identity: resp.TunnelIdentifier + "." + resp.Prefix}
	if err := checkIssued(m, want); err != nil {
		return nil, err
	}
	return m, nil
}

// issuedKeys is the key set of an enrolment or renewal response, or nil when
// the response carries none or a null ticket_keys: storing that would drop
// every key the device holds, so it is refused as FetchDeviceKeys refuses it.
// An empty ticket_keys array is a valid set.
func issuedKeys(keys *DeviceKeys) *DeviceKeys {
	if keys == nil || keys.TicketKeys == nil {
		return nil
	}
	return keys
}

// maxRegionLength bounds a region name, a single DNS label.
const maxRegionLength = 48

// ValidRegion reports whether s is a region name: one DNS label of lowercase
// letters, digits and internal dashes, at most maxRegionLength bytes. The
// agent builds the edge's dial host from it.
func ValidRegion(s string) bool {
	return validLabel(s, maxRegionLength)
}

// validDeviceHost reports whether s is a lowercase DNS hostname of at most 253
// bytes whose labels are at most 63 bytes.
func validDeviceHost(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !validLabel(l, 63) {
			return false
		}
	}
	return true
}

// lowerASCII lowercases A to Z only, so a non-ASCII byte stays and fails
// validation instead of folding into an ASCII letter.
func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// validLabel reports whether s is 1 to maxLen lowercase letters, digits and
// dashes, starting and ending with a letter or digit.
func validLabel(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
