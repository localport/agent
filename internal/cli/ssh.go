package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/session"
)

const (
	// sshSessionKind is the session kind the native client mints.
	sshSessionKind = "ssh"
	// sshCertMinRemaining is the validity a cached certificate must still
	// have to be reused; below it ssh-cert mints a new one.
	sshCertMinRemaining = 60 * time.Second
	// sshLockWait bounds how long ssh-cert waits for a concurrent one. The
	// lock holder's mint ends sooner (sshMintTimeout).
	sshLockWait = 30 * time.Second
	// sshDialTimeout bounds the WebSocket dial and the certificate write.
	sshDialTimeout = 30 * time.Second
	// sshPQMinMajor and sshPQMinMinor are the first OpenSSH release that
	// offers mlkem768x25519-sha256, the device's post-quantum key exchange.
	sshPQMinMajor, sshPQMinMinor = 9, 9
	// sshNameFilterMajor and sshNameFilterMinor are the first OpenSSH
	// release that refuses shell characters in command-line user and host
	// names before expanding them into ProxyCommand and Match exec.
	sshNameFilterMajor, sshNameFilterMinor = 9, 6
)

// sshMintTimeout bounds the mint ssh-cert makes under the shared lock, below
// sshLockWait so a concurrent ssh-cert waiting for the lock outlasts it. A
// variable so tests can shorten it.
var sshMintTimeout = sshLockWait - 5*time.Second

// sessionMinter asks the control plane for a session certificate.
type sessionMinter func(ctx context.Context, req identity.SessionRequest) (*identity.SessionCertificate, error)

// sshTarget is one device reached with one consumer credential.
type sshTarget struct {
	store *identity.Store
	ref   identity.Ref
	host  string
}

// mintWithAPI signs the request with the target's credential and sends it to
// the control plane the credential came from.
func (t sshTarget) mintWithAPI(ctx context.Context, req identity.SessionRequest) (*identity.SessionCertificate, error) {
	cur, err := t.store.Load(t.ref)
	if err != nil {
		return nil, err
	}
	if time.Now().After(cur.Meta.NotAfter) {
		return nil, errcode.New(errcode.CredentialExpired).With(nil, fmt.Sprintf("%s expired at %s; renew it with: localport identity renew, or sign in again with: localport login",
			t.ref, cur.Meta.NotAfter.Format(time.RFC3339)))
	}
	client, err := identity.NewClient(firstNonEmpty(cur.Meta.APIURL, resolveAPIURL("")))
	if err != nil {
		return nil, err
	}
	return client.MintSession(ctx, cur, req)
}

// sshFiles are the client files of a target. The client key, its
// certificate and the edge URL are per credential, device and login, so runs
// for two logins never replace each other's certificate; known_hosts is per
// credential, so a mint with one credential never replaces the host key
// another trusts; the lock is shared, so one lock covers every write ssh
// reads.
type sshFiles struct {
	key, cert, url, knownHosts, lock string
}

// files are the client files of login, which checkSSHLogin has accepted.
func (t sshTarget) files(login string) sshFiles {
	root, _ := t.store.StateRoot()
	dir := t.clientDir(root)
	key := filepath.Join(dir, login+"@"+t.host)
	return sshFiles{
		key:        key,
		cert:       key + "-cert.pub",
		url:        key + ".url",
		knownHosts: filepath.Join(dir, "known_hosts"),
		lock:       filepath.Join(root, "ssh", ".lock"),
	}
}

// clientDir holds the target's per-login client files under the state root.
func (t sshTarget) clientDir(root string) string {
	return filepath.Join(root, "ssh", t.ref.Path())
}

// sshLoginShellChars are refused in a login: ssh_config passes %r to sh -c
// inside double quotes, and these are the characters OpenSSH 9.6 refuses in
// a command-line login (valid_ruser) plus $, which double quotes still
// expand.
const sshLoginShellChars = "'`\";&<>|(){}$"

// checkSSHLogin refuses a login that cannot name a client file or travel
// through ssh_config's shell commands on a goos client: outside the login
// grammar (config.ValidLogin), starting with '-', or holding a shell
// character. A backslash is refused on Windows, where file names cannot
// hold it, and elsewhere when it would escape the next backslash or the
// closing quote. A Windows domain account is written in its UPN form,
// alice@corp.example, which splitLoginHost keeps whole.
func checkSSHLogin(login, goos string) error {
	bad := !config.ValidLogin(login) || login[0] == '-' || strings.ContainsAny(login, sshLoginShellChars)
	if goos == "windows" {
		bad = bad || strings.ContainsAny(login, `\*?`)
	} else {
		bad = bad || strings.HasSuffix(login, `\`) || strings.Contains(login, `\\`)
	}
	if bad {
		return errcode.New(errcode.SSHLoginRefused).With(nil, fmt.Sprintf("%q", security.SanitizeDisplay(login)))
	}
	return nil
}

// deviceHostPattern is a lowercase DNS name of two or more labels; the host
// names files, so nothing else is accepted.
var deviceHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func parseDeviceHost(raw string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if len(host) > 253 || !deviceHostPattern.MatchString(host) {
		return "", fmt.Errorf("%q is not a device host, such as gw-01-factory.eu.localport.dev", security.SanitizeDisplay(raw))
	}
	return host, nil
}

// resolveSSHTarget picks the consumer credential (--identity, then
// LOCALPORT_IDENTITY, then the only one or a prompt when interactive).
func resolveSSHTarget(identityArg, rawHost string, interactive bool) (sshTarget, error) {
	host, err := parseDeviceHost(rawHost)
	if err != nil {
		return sshTarget{}, err
	}
	store, err := currentInvoker(false).store()
	if err != nil {
		return sshTarget{}, err
	}
	ref, err := resolveCredential(store, firstNonEmpty(identityArg, os.Getenv(identityEnv)), interactive, true)
	if err != nil {
		return sshTarget{}, err
	}
	return sshTarget{store: store, ref: ref, host: host}, nil
}

// ensureCert makes sure the target has a client key and a certificate for
// login with at least sshCertMinRemaining left, minting one otherwise. The
// mint writes the device host key into known_hosts, then the edge URL, then
// the certificate, each atomically and all under the shared lock, so
// concurrent connections mint once and never see the key change.
func (t sshTarget) ensureCert(ctx context.Context, login string, mint sessionMinter, now time.Time) error {
	if err := checkSSHLogin(login, runtime.GOOS); err != nil {
		return err
	}
	f := t.files(login)
	base, follow := t.store.StateRoot()
	if err := security.EnsurePrivateDir(base, filepath.Dir(f.key), follow); err != nil {
		return errcode.New(errcode.SSHClientFiles).With(err, "ssh client directory")
	}
	release, err := identity.WaitLockFile(ctx, f.lock, sshLockWait, errSSHFilesBusy)
	if errors.Is(err, errSSHFilesBusy) {
		return err
	}
	if err != nil {
		return errcode.New(errcode.SSHClientFiles).With(err, "lock "+f.lock)
	}
	defer release()

	signer, err := loadOrCreateClientKey(f.key)
	if err != nil {
		return err
	}
	if cachedCertFresh(f, t.host, signer.PublicKey(), login, now) {
		return nil
	}
	mintCtx, cancel := context.WithTimeout(ctx, sshMintTimeout)
	resp, err := mint(mintCtx, identity.SessionRequest{
		DeviceHost:      t.host,
		Kind:            sshSessionKind,
		Login:           login,
		ClientSSHPubKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
	})
	cancel()
	if err != nil {
		return errcode.New(errcode.SessionMintFailed).With(err, login+"@"+t.host)
	}
	cert, hostKey, edgeURL, err := checkSessionCertificate(resp, signer.PublicKey(), login, now)
	if err != nil {
		return err
	}
	if err := writeKnownHost(f.knownHosts, t.host, hostKey); err != nil {
		return err
	}
	if err := security.WritePrivateFileAtomic(f.url, []byte(edgeURL+"\n")); err != nil {
		return err
	}
	return security.WritePrivateFileAtomic(f.cert, ssh.MarshalAuthorizedKey(cert))
}

var (
	// errSSHFilesBusy: another ssh-cert held the client files' lock for all
	// of sshLockWait.
	errSSHFilesBusy = errcode.New(errcode.SSHFilesBusy)
	// errNoSessionCert: ssh-proxy found no certificate, edge URL or client
	// key; ssh-cert writes them.
	errNoSessionCert = errcode.New(errcode.NoSessionCert)
)

// loadClientKey reads the target's ed25519 client key; a missing key is
// fs.ErrNotExist in the chain.
func loadClientKey(path string) (ssh.Signer, error) {
	raw, err := security.ReadPrivateFile(path)
	if err != nil {
		return nil, errcode.New(errcode.SSHClientFiles).With(err, "ssh client key "+path)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, errcode.New(errcode.SSHClientFiles).With(err, "ssh client key "+path)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, errcode.New(errcode.SSHClientFiles).With(nil, fmt.Sprintf("ssh client key %s is %s, not ed25519", path, signer.PublicKey().Type()))
	}
	return signer, nil
}

// loadOrCreateClientKey reads the target's ed25519 client key, generating it
// on first use. The key never leaves this machine. Called under the lock.
func loadOrCreateClientKey(path string) (ssh.Signer, error) {
	signer, err := loadClientKey(path)
	if !errors.Is(err, fs.ErrNotExist) {
		return signer, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ssh client key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "localport")
	if err != nil {
		return nil, fmt.Errorf("encode ssh client key: %w", err)
	}
	if err := security.WritePrivateFileAtomic(path, pem.EncodeToMemory(block)); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// cachedCertFresh reports whether the stored certificate is for key and
// login, has sshCertMinRemaining left, and its edge URL and known_hosts entry
// are in place.
func cachedCertFresh(f sshFiles, host string, key ssh.PublicKey, login string, now time.Time) bool {
	raw, err := os.ReadFile(f.cert)
	if err != nil {
		return false
	}
	cert, err := parseUserCertificate(raw)
	if err != nil || !bytes.Equal(cert.Key.Marshal(), key.Marshal()) || !slices.Equal(cert.ValidPrincipals, []string{login}) {
		return false
	}
	if now.Add(sshCertMinRemaining).Unix() > int64(min(cert.ValidBefore, 1<<62)) {
		return false
	}
	if _, err := os.Stat(f.url); err != nil {
		return false
	}
	known, err := os.ReadFile(f.knownHosts)
	return err == nil && knownHostsHasAlias(known, host)
}

func parseUserCertificate(line []byte) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok || cert.CertType != ssh.UserCert {
		return nil, errors.New("not an SSH user certificate")
	}
	return cert, nil
}

// checkSessionCertificate validates a mint response before anything is
// written: a user certificate for key and exactly login, still valid, an
// ecdsa-sha2-nistp256 host key and a wss URL.
func checkSessionCertificate(resp *identity.SessionCertificate, key ssh.PublicKey, login string, now time.Time) (*ssh.Certificate, ssh.PublicKey, string, error) {
	cert, err := parseUserCertificate([]byte(resp.Certificate))
	if err != nil {
		return nil, nil, "", errcode.New(errcode.SessionCertRefused).With(err, "")
	}
	if !bytes.Equal(cert.Key.Marshal(), key.Marshal()) {
		return nil, nil, "", errcode.New(errcode.SessionCertRefused).With(nil, "the certificate is for another key")
	}
	if !slices.Equal(cert.ValidPrincipals, []string{login}) {
		return nil, nil, "", errcode.New(errcode.SessionCertRefused).With(nil, "the certificate names another login")
	}
	if now.Unix() >= int64(min(cert.ValidBefore, 1<<62)) {
		return nil, nil, "", errcode.New(errcode.SessionCertRefused).With(nil, "the certificate has already expired; check this machine's clock")
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.HostKey))
	if err != nil || hostKey.Type() != ssh.KeyAlgoECDSA256 {
		return nil, nil, "", errcode.New(errcode.SessionCertRefused).With(nil, "no ecdsa-sha2-nistp256 host key")
	}
	u, err := url.Parse(resp.URL)
	if err != nil || u.Scheme != "wss" || u.Host == "" {
		return nil, nil, "", errcode.New(errcode.SessionCertRefused).With(nil, "no wss URL")
	}
	return cert, hostKey, u.String(), nil
}

// writeKnownHost replaces every known_hosts line for alias with one line
// holding key, keeping the other lines, so ssh with StrictHostKeyChecking yes
// accepts exactly the host key of the latest mint.
func writeKnownHost(path, alias string, key ssh.PublicKey) error {
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errcode.New(errcode.SSHClientFiles).With(err, "read "+path)
	}
	var out bytes.Buffer
	for line := range bytes.Lines(old) {
		if knownHostsLineAlias(line) == alias {
			continue
		}
		out.Write(line)
		if !bytes.HasSuffix(line, []byte("\n")) {
			out.WriteByte('\n')
		}
	}
	out.WriteString(alias)
	out.WriteByte(' ')
	out.Write(ssh.MarshalAuthorizedKey(key))
	return security.WritePrivateFileAtomic(path, out.Bytes())
}

func knownHostsLineAlias(line []byte) string {
	fields := strings.Fields(string(line))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func knownHostsHasAlias(data []byte, alias string) bool {
	for line := range bytes.Lines(data) {
		if knownHostsLineAlias(line) == alias {
			return true
		}
	}
	return false
}

// sshResumableEnds are the edge close reasons after which ssh-proxy resumes
// the connection on a new stream; a stream that ends without a close frame
// (a network loss) resumes too. Any other reason (revocation, lock, kick,
// wrong_host, a refusal, a reason added later) ends the session.
var sshResumableEnds = []string{"closed", "edge_shutdown", "edge_lost", "device_offline", "agent_closed",
	"no_session_mux", "edge_full", "wrong_edge"}

const (
	// sshResumeWindow is how long a dropped connection may take to resume,
	// the agent's detach timeout.
	sshResumeWindow = 5 * time.Minute
	// sshResumeBackoffMax caps the wait between resume attempts.
	sshResumeBackoffMax = 15 * time.Second
)

// sessionStream is one session WebSocket as a byte stream; closeReason is
// the edge's close reason once a read ended on a close frame, "" otherwise.
type sessionStream struct {
	net.Conn
	ws *websocket.Conn

	mu     sync.Mutex
	reason string
	closed bool
}

func (s *sessionStream) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if err != nil {
		var ce websocket.CloseError
		if errors.As(err, &ce) {
			s.mu.Lock()
			if !s.closed {
				s.reason, s.closed = ce.Reason, true
			}
			s.mu.Unlock()
		}
	}
	return n, err
}

// closeReason is the base close reason ("reason" of "reason:code") and
// whether a close frame arrived.
func (s *sessionStream) closeReason() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	base, _, _ := strings.Cut(s.reason, ":")
	return base, s.closed
}

// dialSession opens a session WebSocket and sends the certificate in wire
// form as its first binary message.
func dialSession(ctx context.Context, rawURL string, certWire []byte, opts *websocket.DialOptions) (*sessionStream, error) {
	dialCtx, cancel := context.WithTimeout(ctx, sshDialTimeout)
	defer cancel()
	ws, _, err := websocket.Dial(dialCtx, rawURL, opts)
	if err != nil {
		return nil, errcode.New(errcode.SessionConnectFailed).With(err, "connect to the edge")
	}
	if err := ws.Write(dialCtx, websocket.MessageBinary, certWire); err != nil {
		_ = ws.CloseNow()
		return nil, errcode.New(errcode.SessionConnectFailed).With(err, "send the session certificate")
	}
	return &sessionStream{Conn: websocket.NetConn(ctx, ws, websocket.MessageBinary), ws: ws}, nil
}

// knownHostKey reads alias's host key from known_hosts.
func knownHostKey(path, alias string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for line := range bytes.Lines(data) {
		if knownHostsLineAlias(line) != alias {
			continue
		}
		_, rest, _ := bytes.Cut(bytes.TrimSpace(line), []byte(" "))
		key, _, _, _, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			return nil, errcode.New(errcode.SSHClientFiles).With(err, "known_hosts entry for "+alias)
		}
		return key, nil
	}
	return nil, errNoSessionCert.With(nil, "known_hosts holds no entry for "+alias)
}

// proxy carries one SSH connection between in and out and the device over a
// resumable connection (agent/docs/PROTOCOL.md "Resumable connections"). It
// dials the edge URL of the last mint with that certificate, runs the
// prelude against the host key known_hosts holds now (kept in memory, so a
// later mint cannot change the pin), then relays. When the stream drops for
// a resumable reason it mints a resume certificate (never written to the
// certificate file, which OpenSSH and later runs keep using) and resumes on a
// new stream within sshResumeWindow. The end of in is a deliberate close.
func (t sshTarget) proxy(ctx context.Context, login string, in io.Reader, out io.Writer, opts *websocket.DialOptions, mint sessionMinter) error {
	if err := checkSSHLogin(login, runtime.GOOS); err != nil {
		return err
	}
	f := t.files(login)
	// ssh-proxy only reads: ssh-cert writes these files under the lock.
	missing := func(err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return errNoSessionCert.With(nil, fmt.Sprintf("%s@%s; run: localport ssh-cert --identity %s %s %s", login, t.host, t.ref, login, t.host))
		}
		return err
	}
	rawURL, err := os.ReadFile(f.url)
	if err != nil {
		return missing(err)
	}
	rawCert, err := os.ReadFile(f.cert)
	if err != nil {
		return missing(err)
	}
	cert, err := parseUserCertificate(rawCert)
	if err != nil {
		return errcode.New(errcode.SSHClientFiles).With(err, "session certificate "+f.cert)
	}
	key, err := loadClientKey(f.key)
	if err != nil {
		return missing(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		return errcode.New(errcode.SSHClientFiles).With(err, "session certificate "+f.cert)
	}
	hostKey, err := knownHostKey(f.knownHosts, t.host)
	if err != nil {
		return fmt.Errorf("device host key: %w", err)
	}
	stream, cr, reason, err := openSession(ctx, strings.TrimSpace(string(rawURL)), cert, certSigner, hostKey, opts)
	if err != nil && slices.Contains(sshRetryEnds, reason) {
		// One new certificate and one more try, before the connection runs.
		// Like a resume certificate it stays in memory: the file keeps the
		// one OpenSSH presents to the device.
		if cert, certSigner, rawURL, err = t.mintAgain(ctx, login, key, mint); err != nil {
			return errcode.New(errcode.SessionMintFailed).With(err, "after the session ended: "+security.SanitizeDisplay(reason))
		}
		stream, cr, _, err = openSession(ctx, string(rawURL), cert, certSigner, hostKey, opts)
	}
	if err != nil {
		return err
	}

	go func() {
		_, _ = io.Copy(cr.Conn, in)
		_ = cr.Conn.Close()
	}()
	copied := make(chan error, 1)
	go func() {
		_, err := io.Copy(out, cr.Conn)
		copied <- err
	}()
	var pos uint64
	for cr.Conn.Attach(stream, pos) == session.Detached {
		if reason, closed := stream.closeReason(); closed && !slices.Contains(sshResumableEnds, reason) {
			cr.Conn.End(errSessionEnded)
			<-copied
			return errcode.New(errcode.SessionEnded).With(nil, security.SanitizeDisplay(reason))
		}
		if stream, pos, err = t.resume(ctx, sshResumeWindow, cr, cert, key, mint, opts); err != nil {
			cr.Conn.End(errSessionEnded)
			<-copied
			return err
		}
	}
	err = <-copied
	if err == nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if errors.Is(err, session.ErrResumeLost) {
		return errcode.New(errcode.SessionEnded).With(nil, "resume_lost")
	}
	return errcode.New(errcode.SessionConnectFailed).With(err, "session stream")
}

var errSessionEnded = errors.New("ssh-proxy: session ended")

// sshRetryEnds are the edge close reasons of a refused first stream after
// which ssh-proxy mints one new certificate and tries once more
// (docs/COMMUNICATION.md, end reasons).
var sshRetryEnds = []string{"edge_full", "no_session_mux", "wrong_edge", "edge_shutdown"}

// openSession dials edgeURL with cert and runs the prelude against the pinned
// hostKey. On a refusal it returns the edge's close reason, when one came,
// with the error.
func openSession(ctx context.Context, edgeURL string, cert *ssh.Certificate, signer ssh.Signer, hostKey ssh.PublicKey, opts *websocket.DialOptions) (*sessionStream, *session.ClientResumable, string, error) {
	stream, err := dialSession(ctx, edgeURL, cert.Marshal(), opts)
	if err != nil {
		return nil, nil, "", err
	}
	_ = stream.SetDeadline(time.Now().Add(sshDialTimeout))
	cr, err := session.Hello(stream, signer, hostKey)
	if err != nil {
		_ = stream.Close()
		if reason, ok := stream.closeReason(); ok {
			return nil, nil, reason, errcode.New(errcode.SessionEnded).With(nil, security.SanitizeDisplay(reason))
		}
		return nil, nil, "", errcode.New(errcode.SessionConnectFailed).With(err, "session prelude")
	}
	_ = stream.SetDeadline(time.Time{})
	return stream, cr, "", nil
}

// mintAgain mints a new certificate for login and key under sshMintTimeout,
// returning it, its signer and its edge URL.
func (t sshTarget) mintAgain(ctx context.Context, login string, key ssh.Signer, mint sessionMinter) (*ssh.Certificate, ssh.Signer, []byte, error) {
	mintCtx, cancel := context.WithTimeout(ctx, sshMintTimeout)
	resp, err := mint(mintCtx, identity.SessionRequest{
		DeviceHost:      t.host,
		Kind:            sshSessionKind,
		Login:           login,
		ClientSSHPubKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))),
	})
	cancel()
	if err != nil {
		return nil, nil, nil, err
	}
	cert, _, edgeURL, err := checkSessionCertificate(resp, key.PublicKey(), login, time.Now())
	if err != nil {
		return nil, nil, nil, err
	}
	signer, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, signer, []byte(edgeURL), nil
}

// resume mints a resume certificate for original and resumes cr on a new
// stream, retrying with backoff within window (sshResumeWindow in
// production). Each mint is bounded by the time left in the window. A mint
// refusal or a final agent refusal ends the session.
func (t sshTarget) resume(ctx context.Context, window time.Duration, cr *session.ClientResumable, original *ssh.Certificate, key ssh.Signer, mint sessionMinter, opts *websocket.DialOptions) (*sessionStream, uint64, error) {
	deadline := time.Now().Add(window)
	backoff := 500 * time.Millisecond
	for {
		stream, pos, retry, err := t.resumeAttempt(ctx, deadline, cr, original, key, mint, opts)
		if !retry {
			return stream, pos, err
		}
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		if time.Now().Add(backoff).After(deadline) {
			return nil, 0, errcode.New(errcode.SessionEnded).With(err, fmt.Sprintf("not resumed within %s", window))
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, sshResumeBackoffMax)
	}
}

// resumeAttempt makes one mint, dial and resume. retry reports whether a
// later attempt may succeed; err is final when retry is false. The mint runs
// under deadline; the dial does not, since the stream lives on ctx.
func (t sshTarget) resumeAttempt(ctx context.Context, deadline time.Time, cr *session.ClientResumable, original *ssh.Certificate, key ssh.Signer, mint sessionMinter, opts *websocket.DialOptions) (stream *sessionStream, pos uint64, retry bool, err error) {
	login := original.ValidPrincipals[0]
	mintCtx, cancel := context.WithDeadline(ctx, deadline)
	resp, err := mint(mintCtx, identity.SessionRequest{
		DeviceHost:        t.host,
		Kind:              sshSessionKind,
		Login:             login,
		ClientSSHPubKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))),
		ResumeCertificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(original))),
	})
	cancel()
	if err != nil {
		if !identity.Retryable(err) {
			return nil, 0, false, errcode.New(errcode.SessionConnectFailed).With(err, "resume the session")
		}
		return nil, 0, true, err
	}
	resumeCert, _, edgeURL, err := checkSessionCertificate(resp, key.PublicKey(), login, time.Now())
	if err != nil {
		return nil, 0, false, errcode.New(errcode.SessionConnectFailed).With(err, "resume the session")
	}
	signer, err := ssh.NewCertSigner(resumeCert, key)
	if err != nil {
		return nil, 0, false, errcode.New(errcode.SessionConnectFailed).With(err, "resume the session")
	}
	stream, err = dialSession(ctx, edgeURL, resumeCert.Marshal(), opts)
	if err != nil {
		return nil, 0, true, err
	}
	_ = stream.SetDeadline(time.Now().Add(sshDialTimeout))
	if pos, err = cr.Resume(stream, signer); err == nil {
		_ = stream.SetDeadline(time.Time{})
		return stream, pos, false, nil
	}
	_ = stream.Close()
	var refused *session.ResumeError
	if errors.As(err, &refused) && !refused.Retryable() {
		return nil, 0, false, errcode.New(errcode.SessionEnded).With(nil, refused.Code)
	}
	if reason, closed := stream.closeReason(); closed && !slices.Contains(sshResumableEnds, reason) {
		return nil, 0, false, errcode.New(errcode.SessionEnded).With(nil, security.SanitizeDisplay(reason))
	}
	return nil, 0, true, err
}

// sshConfigOptions are the client options of a target, shared by the
// ssh-config block and `localport ssh`. exe is the localport command.
func (t sshTarget) sshConfigOptions(exe string) ([][2]string, error) {
	root, _ := t.store.StateRoot()
	dir := t.clientDir(root)
	knownHosts := t.files("").knownHosts
	for _, p := range []string{exe, dir, knownHosts} {
		if err := checkSSHConfigPath(p, runtime.GOOS); err != nil {
			return nil, err
		}
	}
	// ssh expands %r to the login, naming the per-login files of files().
	key := sshConfigValueWithLogin(dir, "@"+t.host)
	return [][2]string{
		{"ProxyCommand", sshCommandLine(exe, "ssh-proxy", t.ref.String())},
		{"IdentityFile", key},
		{"CertificateFile", sshConfigValueWithLogin(dir, "@"+t.host+"-cert.pub")},
		{"UserKnownHostsFile", sshConfigValue(knownHosts)},
		{"HostKeyAlias", t.host},
		{"StrictHostKeyChecking", "yes"},
		{"IdentitiesOnly", "yes"},
	}, nil
}

// checkSSHConfigPath refuses a path ssh_config cannot carry on a goos
// client: a quote or line break ends the value, $ starts an environment
// expansion in the file options and in sh, and ` and, outside Windows, \
// act inside the double quotes of a shell command.
func checkSSHConfigPath(p, goos string) error {
	bad := strings.ContainsAny(p, "\"`$\n\r") || (goos != "windows" && strings.Contains(p, `\`))
	if bad {
		return errcode.New(errcode.SSHConfigPathUnsafe).With(nil, fmt.Sprintf("%q", security.SanitizeDisplay(p)))
	}
	return nil
}

// sshCommandLine is `<exe> <command> --identity <ref> "%r" "%h"`, which
// ssh_config runs through the shell in ProxyCommand and Match exec: exe,
// the login and the host are double-quoted, which leaves only the
// characters checkSSHConfigPath and checkSSHLogin refuse active, and every
// literal % in exe is doubled.
func sshCommandLine(exe, command, ref string) string {
	return `"` + strings.ReplaceAll(exe, "%", "%%") + `" ` + command + " --identity " + ref + ` "%r" "%h"`
}

// sshConfigValue doubles % and quotes a value holding a space or tab.
func sshConfigValue(s string) string {
	return sshConfigQuote(strings.ReplaceAll(s, "%", "%%"))
}

// sshConfigValueWithLogin is the path dir/%r<suffix>: dir and suffix with
// every % doubled, and %r, which ssh expands to the login, between them.
func sshConfigValueWithLogin(dir, suffix string) string {
	escape := func(s string) string { return strings.ReplaceAll(s, "%", "%%") }
	return sshConfigQuote(escape(dir+string(filepath.Separator)) + "%r" + escape(suffix))
}

func sshConfigQuote(s string) string {
	if strings.ContainsAny(s, " \t") {
		return `"` + s + `"`
	}
	return s
}

// sshConfigBlock is the ssh_config text for a target. The Host block always
// routes the connection through ssh-proxy, so a failed mint stops ssh at the
// proxy instead of connecting to the host name directly. The Match exec line
// that follows runs ssh-cert while ssh reads its config, before it loads the
// certificate and starts the proxy.
func (t sshTarget) sshConfigBlock(exe string) (string, error) {
	opts, err := t.sshConfigOptions(exe)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# localport: %s as %s\nHost %s\n", t.host, t.ref, t.host)
	for _, o := range opts {
		fmt.Fprintf(&b, "  %s %s\n", o[0], o[1])
	}
	certCmd := strings.ReplaceAll(sshCommandLine(exe, "ssh-cert", t.ref.String()), `"`, `\"`)
	fmt.Fprintf(&b, "Match host %s exec \"%s\"\n", t.host, certCmd)
	return b.String(), nil
}

// configCommand is the localport command an ssh_config names: `localport`
// when PATH resolves it to this binary, which survives package upgrades that
// move the binary, else this binary's absolute path.
func configCommand() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", errcode.New(errcode.ExecutableUnknown).With(err, "")
	}
	if onPath, err := exec.LookPath("localport"); err == nil && sameFile(onPath, self) {
		return "localport", nil
	}
	return self, nil
}

func sameFile(a, b string) bool {
	ia, errA := os.Stat(a)
	ib, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ia, ib)
}

// opensshVersionPattern matches `ssh -V` output on Unix and Windows builds.
var opensshVersionPattern = regexp.MustCompile(`OpenSSH_(?:for_Windows_)?(\d+)\.(\d+)`)

// opensshBefore reports whether `ssh -V` output names an OpenSSH release
// older than wantMajor.wantMinor, and the version it found.
func opensshBefore(versionOutput string, wantMajor, wantMinor int) (string, bool) {
	m := opensshVersionPattern.FindStringSubmatch(versionOutput)
	if m == nil {
		return "", false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return m[1] + "." + m[2], major < wantMajor || (major == wantMajor && minor < wantMinor)
}

// opensshVersion is the output of `<sshPath> -V`, empty when it fails.
func opensshVersion(sshPath string) string {
	out, err := exec.Command(sshPath, "-V").CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

// splitLoginHost splits `[login@]host`; without a login it is the current
// user's name, without any Windows domain prefix, as ssh defaults it.
func splitLoginHost(arg string) (string, string, error) {
	// At the last @, as ssh does, so a UPN login keeps its own @.
	if i := strings.LastIndexByte(arg, '@'); i >= 0 {
		if i == 0 {
			return "", "", errors.New("empty login before @")
		}
		return arg[:i], arg[i+1:], nil
	}
	u, err := user.Current()
	if err != nil {
		return "", "", errcode.New(errcode.CurrentUserUnknown).With(err, "no login given")
	}
	name := u.Username
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	return name, arg, nil
}

// parseSSHHelperArgs parses `[--identity <ref>] <login> <host>`, the form
// ssh_config passes to ssh-cert and ssh-proxy.
func parseSSHHelperArgs(name string, args []string) (identityArg, login, host string, err error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	ident := fs.String("identity", "", "credential to present: `<identity>`, <team>/<identity> or <team>/<kind>/<identity>")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: localport %s [--identity <ref>] <login> <device-host>\n\nRun by ssh through the lines localport ssh-config prints.\n", name)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return "", "", "", err
	}
	if fs.NArg() != 2 || fs.Arg(0) == "" {
		fs.Usage()
		return "", "", "", errors.New("want a login and a device host")
	}
	return *ident, fs.Arg(0), fs.Arg(1), nil
}

// runSSHCert is `localport ssh-cert`: ssh_config's Match exec.
func runSSHCert(args []string) error {
	identityArg, login, host, err := parseSSHHelperArgs("ssh-cert", args)
	if err != nil {
		return err
	}
	t, err := resolveSSHTarget(identityArg, host, false)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext(nil)
	defer cancel()
	return t.ensureCert(ctx, login, t.mintWithAPI, time.Now())
}

// runSSHProxy is `localport ssh-proxy`: ssh_config's ProxyCommand.
func runSSHProxy(args []string) error {
	identityArg, login, host, err := parseSSHHelperArgs("ssh-proxy", args)
	if err != nil {
		return err
	}
	t, err := resolveSSHTarget(identityArg, host, false)
	if err != nil {
		return err
	}
	return t.proxy(context.Background(), login, os.Stdin, os.Stdout, nil, t.mintWithAPI)
}

// runSSHConfig is `localport ssh-config`: it prints an ssh_config block per
// device host and writes nothing.
func runSSHConfig(args []string) error {
	fs := flag.NewFlagSet("ssh-config", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	ident := fs.String("identity", "", "credential to present: `<identity>`, <team>/<identity> or <team>/<kind>/<identity>")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: localport ssh-config [--identity <ref>] <device-host>...

Prints the ssh_config lines that let ssh, scp, sftp and rsync reach each
device through Localport. Add them to ~/.ssh/config:

  localport ssh-config gw-01-factory.eu.localport.dev >> ~/.ssh/config

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return errors.New("name at least one device host")
	}
	exe, err := configCommand()
	if err != nil {
		return err
	}
	var out strings.Builder
	for i, host := range fs.Args() {
		t, err := resolveSSHTarget(*ident, host, i == 0)
		if err != nil {
			return err
		}
		// Every host uses the credential chosen for the first.
		*ident = t.ref.String()
		block, err := t.sshConfigBlock(exe)
		if err != nil {
			return err
		}
		out.WriteString(block)
	}
	if sshPath, err := exec.LookPath("ssh"); err == nil {
		if version, old := opensshBefore(opensshVersion(sshPath), sshNameFilterMajor, sshNameFilterMinor); old {
			fmt.Fprint(os.Stderr, opensshNameFilterWarning(version))
		}
	}
	_, err = os.Stdout.WriteString(out.String())
	return err
}

// opensshNameFilterWarning tells the user of OpenSSH version, older than
// 9.6, that ssh passes command-line names to these lines unfiltered.
func opensshNameFilterWarning(version string) string {
	return fmt.Sprintf("localport: OpenSSH %s passes a user or host name given on its command line to ProxyCommand and Match exec unfiltered, "+
		"so a program that runs ssh with an untrusted name (such as git) can run shell commands through these lines; "+
		"OpenSSH 9.6 or later refuses such names (CVE-2023-51385)\n", version)
}

// runSSH is `localport ssh [--identity <ref>] [login@]<device-host> [ssh
// arguments]`: it mints a certificate as ssh-cert does and runs the system
// ssh with the ssh-config options.
func runSSH(args []string) error {
	fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	ident := fs.String("identity", "", "credential to present: `<identity>`, <team>/<identity> or <team>/<kind>/<identity>")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: localport ssh [--identity <ref>] [login@]<device-host> [ssh arguments]\n\nOpens an SSH session on a device with the system ssh.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return errors.New("name a device host")
	}
	login, host, err := splitLoginHost(fs.Arg(0))
	if err != nil {
		return err
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return errcode.New(errcode.OpenSSHUnavailable).With(err, "not installed or not on PATH")
	}
	t, err := resolveSSHTarget(*ident, host, true)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext(nil)
	err = t.ensureCert(ctx, login, t.mintWithAPI, time.Now())
	cancel()
	if err != nil {
		return err
	}
	if version, old := opensshBefore(opensshVersion(sshPath), sshPQMinMajor, sshPQMinMinor); old {
		fmt.Fprintf(os.Stderr, "localport: OpenSSH %s negotiates curve25519-sha256; OpenSSH 9.9 or later adds post-quantum key exchange (mlkem768x25519-sha256)\n", version)
	}
	self, err := os.Executable()
	if err != nil {
		return errcode.New(errcode.ExecutableUnknown).With(err, "")
	}
	opts, err := t.sshConfigOptions(self)
	if err != nil {
		return err
	}
	argv := []string{"ssh"}
	for _, o := range opts {
		argv = append(argv, "-o", o[0]+"="+o[1])
	}
	argv = append(argv, "-l", login, t.host)
	argv = append(argv, fs.Args()[1:]...)
	return execSSH(sshPath, argv)
}
