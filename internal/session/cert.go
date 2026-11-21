package session

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// Critical option and extension names of a session certificate, and the one
// principal of a desktop certificate. The control plane mints them; structured
// values are compact JSON.
const (
	optionDevice     = "device@localport.io"
	optionResume     = "resume@localport.io"
	optionFiles      = "files@localport.io"
	optionClipboard  = "clipboard@localport.io"
	optionIdle       = "idle@localport.io"
	extKind          = "kind@localport.io"
	extSubject       = "subject@localport.io"
	extRec           = "rec@localport.io"
	extForwardLocal  = "port-forwarding-local@localport.io"
	extForwardRemote = "port-forwarding-remote@localport.io"
	desktopPrincipal = "localport-desktop"
)

// certSkew is the clock skew tolerated on a certificate's validity window,
// the same at the edge.
const certSkew = 30 * time.Second

// Recording policies a certificate's rec names.
const (
	RecPolicyBestEffort = "best_effort"
	RecPolicyStrict     = "strict"
)

// Device names the device a certificate must be for.
type Device struct {
	// Prefix is the device prefix the device option carries.
	Prefix string
	// SPKISHA256 is SPKIHash of the device certificate's leaf public key.
	SPKISHA256 string
}

// SPKIHash is the unpadded base64url SHA-256 of a DER SubjectPublicKeyInfo,
// the encoding a certificate's device option carries.
func SPKIHash(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// certRec is a recorded session's rec extension.
type certRec struct {
	Policy    string `json:"policy"`
	PubSHA256 string `json:"pub_sha256"`
}

// admission is what a verified certificate admits: the identity channel
// handlers read and the wire form a recording open forwards.
type admission struct {
	Kind    string
	Login   string
	Subject string
	Rec     *certRec
	Cert    []byte
	// ForwardLocal and ForwardRemote are the certificate's forwarding
	// extensions, honoured on an ssh connection only.
	ForwardLocal  bool
	ForwardRemote bool
	// Files is the files@localport.io restriction of a files or ssh
	// certificate: the SFTP directions its channels may use. Zero for every
	// other kind, which serves no SFTP.
	Files filesAccess
	// Clipboard is the clipboard@localport.io restriction of a vnc or rdp
	// certificate: the directions its desktop channel may move clipboard
	// text. Zero for every other kind, which has no desktop channel.
	Clipboard clipboardAccess
	// Idle is the idle@localport.io timeout: the time without client activity
	// after which the connection ends with CloseIdle.
	Idle time.Duration
}

// maxIdleSeconds keeps the conversion to a Duration from overflowing. The
// policy range is the signer's; the agent checks only the form.
const maxIdleSeconds = math.MaxInt64 / int64(time.Second)

// parseIdle parses an optionIdle value: positive whole seconds in decimal
// without leading zeros.
func parseIdle(v string) (time.Duration, bool) {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || strconv.FormatInt(n, 10) != v || n < 1 || n > maxIdleSeconds {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

// clipboardAccess is a clipboard@localport.io value: whether clipboard text
// may move device to browser (Copy) and browser to device (Paste).
type clipboardAccess struct {
	Copy  bool
	Paste bool
}

// filesAccess is a files@localport.io value: whether SFTP may read file
// contents (Download) and change the file system (Upload).
type filesAccess struct {
	Download bool
	Upload   bool
}

// covers reports whether a allows everything b allows.
func (a filesAccess) covers(b filesAccess) bool {
	return (a.Download || !b.Download) && (a.Upload || !b.Upload)
}

// carriesFiles reports whether certificates of kind carry optionFiles.
func carriesFiles(kind string) bool { return kind == "files" || kind == "ssh" }

// parseFilesAccess parses an optionFiles value: "", "download", "upload" or
// "download,upload", nothing else.
func parseFilesAccess(v string) (filesAccess, bool) {
	switch v {
	case "":
		return filesAccess{}, true
	case "download":
		return filesAccess{Download: true}, true
	case "upload":
		return filesAccess{Upload: true}, true
	case "download,upload":
		return filesAccess{Download: true, Upload: true}, true
	}
	return filesAccess{}, false
}

// carriesClipboard reports whether certificates of kind carry optionClipboard.
func carriesClipboard(kind string) bool { return kind == "vnc" || kind == "rdp" }

// parseClipboardAccess parses an optionClipboard value: "", "copy", "paste" or
// "copy,paste", nothing else.
func parseClipboardAccess(v string) (clipboardAccess, bool) {
	switch v {
	case "":
		return clipboardAccess{}, true
	case "copy":
		return clipboardAccess{Copy: true}, true
	case "paste":
		return clipboardAccess{Paste: true}, true
	case "copy,paste":
		return clipboardAccess{Copy: true, Paste: true}, true
	}
	return clipboardAccess{}, false
}

// errCertRefused is every certificate refusal; the detail goes to the log
// only, as an SSH client learns nothing but the userauth failure.
var errCertRefused = errors.New("session certificate refused")

func refuseCert(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errCertRefused, fmt.Sprintf(format, args...))
}

// verifyCert checks a user certificate whose key possession userauth proved:
// signed by one of cas, exactly the serial the edge admitted, valid at now
// within certSkew, for principal user, with exactly these critical options:
// the device option (naming device), optionIdle, optionFiles for a files or
// ssh certificate and optionClipboard for vnc or rdp. A resume certificate is
// refused (its option is unknown here). It returns the claims; the caller
// applies the local config.
func verifyCert(cert *ssh.Certificate, user string, cas []ed25519.PublicKey, device Device, serial uint64, now time.Time) (*admission, error) {
	return checkCert(cert, user, cas, device, serial, now, []string{optionDevice, optionIdle})
}

// verifyResumeCert checks a resume prelude's certificate as verifyCert does
// for its one principal, plus optionResume naming original, the serial of the
// connection it resumes.
func verifyResumeCert(cert *ssh.Certificate, cas []ed25519.PublicKey, device Device, serial, original uint64, now time.Time) (*admission, error) {
	if len(cert.ValidPrincipals) != 1 {
		return nil, refuseCert("want one principal")
	}
	if cert.CriticalOptions[optionResume] != strconv.FormatUint(original, 16) {
		return nil, refuseCert("resumes another connection")
	}
	return checkCert(cert, cert.ValidPrincipals[0], cas, device, serial, now, []string{optionDevice, optionIdle, optionResume})
}

func checkCert(cert *ssh.Certificate, user string, cas []ed25519.PublicKey, device Device, serial uint64, now time.Time, options []string) (*admission, error) {
	if cert.CertType != ssh.UserCert {
		return nil, refuseCert("not a user certificate")
	}
	if cert.Serial != serial {
		return nil, refuseCert("serial %x is not the admitted serial %x", cert.Serial, serial)
	}
	kind := cert.Extensions[extKind]
	if carriesFiles(kind) {
		options = append(slices.Clone(options), optionFiles)
	}
	if carriesClipboard(kind) {
		options = append(slices.Clone(options), optionClipboard)
	}
	// CheckCert refuses an option outside the list; the count refuses a
	// missing one, so a certificate without its restriction never admits
	// unrestricted SFTP, an unrestricted clipboard or no idle end.
	if len(cert.CriticalOptions) != len(options) {
		return nil, refuseCert("want exactly the critical options %v", options)
	}
	if !signedByCA(cert, cas) {
		return nil, refuseCert("not signed by a session CA key")
	}
	// The control plane mints short-lived certificates; an open-ended or empty
	// window is malformed, and the bound keeps both ends inside int64 seconds.
	if cert.ValidBefore > 1<<62 || cert.ValidAfter >= cert.ValidBefore {
		return nil, refuseCert("validity window malformed")
	}
	after, before := time.Unix(int64(cert.ValidAfter), 0), time.Unix(int64(cert.ValidBefore), 0)
	if now.Add(certSkew).Before(after) || !now.Add(-certSkew).Before(before) {
		return nil, refuseCert("outside its validity window (%v to %v, now %v)", after.UTC(), before.UTC(), now.UTC())
	}
	checker := ssh.CertChecker{
		SupportedCriticalOptions: options,
		// The window was checked above with the skew; CheckCert sees a time
		// inside it, and checks the signature, the principal and the options.
		Clock: func() time.Time { return clampInto(now, after, before) },
	}
	if err := checker.CheckCert(user, cert); err != nil {
		return nil, refuseCert("%v", err)
	}
	var d struct {
		Tunnel     string `json:"tunnel"`
		Prefix     string `json:"prefix"`
		SPKISHA256 string `json:"spki_sha256"`
	}
	if err := strictJSON(cert.CriticalOptions[optionDevice], &d); err != nil || d.Tunnel == "" {
		return nil, refuseCert("device option malformed")
	}
	if d.Prefix != device.Prefix || d.SPKISHA256 != device.SPKISHA256 {
		return nil, refuseCert("for device %q, not this device", d.Prefix)
	}
	idle, ok := parseIdle(cert.CriticalOptions[optionIdle])
	if !ok {
		return nil, refuseCert("idle option malformed")
	}
	a := &admission{Kind: kind, Login: user, Cert: cert.Marshal(), Idle: idle}
	_, a.ForwardLocal = cert.Extensions[extForwardLocal]
	_, a.ForwardRemote = cert.Extensions[extForwardRemote]
	if carriesFiles(kind) {
		files, ok := parseFilesAccess(cert.CriticalOptions[optionFiles])
		if !ok {
			return nil, refuseCert("files option malformed")
		}
		a.Files = files
	}
	if carriesClipboard(kind) {
		clipboard, ok := parseClipboardAccess(cert.CriticalOptions[optionClipboard])
		if !ok {
			return nil, refuseCert("clipboard option malformed")
		}
		a.Clipboard = clipboard
	}
	var s struct {
		Subject string `json:"subject"`
		UserID  string `json:"user_id,omitempty"`
	}
	if err := strictJSON(cert.Extensions[extSubject], &s); err != nil || s.Subject == "" {
		return nil, refuseCert("subject extension malformed")
	}
	a.Subject = s.Subject
	if raw, ok := cert.Extensions[extRec]; ok {
		var r certRec
		if err := strictJSON(raw, &r); err != nil || (r.Policy != RecPolicyBestEffort && r.Policy != RecPolicyStrict) || r.PubSHA256 == "" {
			return nil, refuseCert("rec extension malformed")
		}
		a.Rec = &r
	}
	return a, nil
}

// signedByCA reports whether cert's signature key is one of cas. CheckCert
// verifies the signature itself.
func signedByCA(cert *ssh.Certificate, cas []ed25519.PublicKey) bool {
	ck, ok := cert.SignatureKey.(ssh.CryptoPublicKey)
	if !ok || cert.SignatureKey.Type() != ssh.KeyAlgoED25519 {
		return false
	}
	pub, ok := ck.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return false
	}
	for _, ca := range cas {
		if bytes.Equal(ca, pub) {
			return true
		}
	}
	return false
}

// clampInto returns t moved into [after, before).
func clampInto(t, after, before time.Time) time.Time {
	if t.Before(after) {
		return after
	}
	if !t.Before(before) {
		return before.Add(-time.Second)
	}
	return t
}

// strictJSON decodes one JSON value into v, refusing unknown fields and trailing data.
func strictJSON(s string, v any) error {
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}
