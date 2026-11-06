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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

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
	// sshLockWait bounds how long ssh-cert waits for a concurrent one.
	sshLockWait = 30 * time.Second
	// sshDialTimeout bounds the WebSocket dial and the certificate write.
	sshDialTimeout = 30 * time.Second
	// sshPQMinMajor and sshPQMinMinor are the first OpenSSH release that
	// offers mlkem768x25519-sha256, the device's post-quantum key exchange.
	sshPQMinMajor, sshPQMinMinor = 9, 9
)

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
		return nil, fmt.Errorf("credential %s expired at %s; renew it with: localport identity renew, or sign in again with: localport login",
			t.ref, cur.Meta.NotAfter.Format(time.RFC3339))
	}
	client, err := identity.NewClient(firstNonEmpty(cur.Meta.APIURL, resolveAPIURL("")))
	if err != nil {
		return nil, err
	}
	return client.MintSession(ctx, cur, req)
}

// sshFiles are the client files of a target. The client key, its
// certificate and the edge URL are per credential and device; known_hosts and
// the lock are shared, so one lock covers every write ssh reads.
type sshFiles struct {
	key, cert, url, knownHosts, lock string
}

func (t sshTarget) files() sshFiles {
	root, _ := t.store.StateRoot()
	key := filepath.Join(root, "ssh", t.ref.Path(), t.host)
	return sshFiles{
		key:        key,
		cert:       key + "-cert.pub",
		url:        key + ".url",
		knownHosts: filepath.Join(root, "known_hosts"),
		lock:       filepath.Join(root, "ssh", ".lock"),
	}
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
	f := t.files()
	base, follow := t.store.StateRoot()
	if err := security.EnsurePrivateDir(base, filepath.Dir(f.key), follow); err != nil {
		return fmt.Errorf("ssh client directory: %w", err)
	}
	release, err := lockSSHFiles(ctx, f.lock)
	if err != nil {
		return err
	}
	defer release()

	signer, err := loadOrCreateClientKey(f.key)
	if err != nil {
		return err
	}
	if cachedCertFresh(f, t.host, signer.PublicKey(), login, now) {
		return nil
	}
	resp, err := mint(ctx, identity.SessionRequest{
		DeviceHost:      t.host,
		Kind:            sshSessionKind,
		Login:           login,
		ClientSSHPubKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
	})
	if err != nil {
		return fmt.Errorf("session certificate for %s@%s: %w", login, t.host, err)
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

// lockSSHFiles takes the exclusive lock on path, waiting up to sshLockWait.
func lockSSHFiles(ctx context.Context, path string) (func(), error) {
	f, err := security.OpenLockFile(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	deadline := time.Now().Add(sshLockWait)
	for {
		held, err := security.TryLockFile(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if held {
			return func() {
				_ = security.UnlockFile(f)
				f.Close()
			}, nil
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("lock %s: another localport ssh-cert still holds it after %s", path, sshLockWait)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// loadOrCreateClientKey reads the target's ed25519 client key, generating it
// on first use. The key never leaves this machine.
func loadOrCreateClientKey(path string) (ssh.Signer, error) {
	raw, err := security.ReadPrivateFile(path)
	if err == nil {
		signer, parseErr := ssh.ParsePrivateKey(raw)
		if parseErr != nil {
			return nil, fmt.Errorf("ssh client key %s: %w", path, parseErr)
		}
		if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
			return nil, fmt.Errorf("ssh client key %s is %s, not ed25519", path, signer.PublicKey().Type())
		}
		return signer, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("ssh client key %s: %w", path, err)
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
		return nil, nil, "", fmt.Errorf("session certificate: %w", err)
	}
	if !bytes.Equal(cert.Key.Marshal(), key.Marshal()) {
		return nil, nil, "", errors.New("session certificate is for another key")
	}
	if !slices.Equal(cert.ValidPrincipals, []string{login}) {
		return nil, nil, "", errors.New("session certificate names another login")
	}
	if now.Unix() >= int64(min(cert.ValidBefore, 1<<62)) {
		return nil, nil, "", errors.New("session certificate has already expired; check this machine's clock")
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.HostKey))
	if err != nil || hostKey.Type() != ssh.KeyAlgoECDSA256 {
		return nil, nil, "", errors.New("session response carries no ecdsa-sha2-nistp256 host key")
	}
	u, err := url.Parse(resp.URL)
	if err != nil || u.Scheme != "wss" || u.Host == "" {
		return nil, nil, "", errors.New("session response carries no wss URL")
	}
	return cert, hostKey, u.String(), nil
}

// writeKnownHost replaces every known_hosts line for alias with one line
// holding key, keeping the other lines, so ssh with StrictHostKeyChecking yes
// accepts exactly the host key of the latest mint.
func writeKnownHost(path, alias string, key ssh.PublicKey) error {
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read %s: %w", path, err)
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
		return nil, fmt.Errorf("connect to the edge: %w", err)
	}
	if err := ws.Write(dialCtx, websocket.MessageBinary, certWire); err != nil {
		_ = ws.CloseNow()
		return nil, fmt.Errorf("send the session certificate: %w", err)
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
			return nil, fmt.Errorf("known_hosts entry for %s: %w", alias, err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("known_hosts holds no entry for %s", alias)
}

// proxy carries one SSH connection between in and out and the device over a
// resumable connection (agent/docs/PROTOCOL.md "Resumable connections"). It
// dials the edge URL of the last mint with that certificate, runs the
// prelude against the host key known_hosts holds now (kept in memory, so a
// later mint cannot change the pin), then relays. When the stream drops for
// a resumable reason it mints a resume certificate (never written to the
// certificate file, which OpenSSH and later runs keep using) and resumes on a
// new stream within sshResumeWindow. The end of in is a deliberate close.
func (t sshTarget) proxy(ctx context.Context, in io.Reader, out io.Writer, opts *websocket.DialOptions, mint sessionMinter) error {
	f := t.files()
	rawURL, err := os.ReadFile(f.url)
	if err != nil {
		return fmt.Errorf("no session certificate for %s; run: localport ssh-cert --identity %s <login> %s", t.host, t.ref, t.host)
	}
	rawCert, err := os.ReadFile(f.cert)
	if err != nil {
		return fmt.Errorf("no session certificate for %s; run: localport ssh-cert --identity %s <login> %s", t.host, t.ref, t.host)
	}
	cert, err := parseUserCertificate(rawCert)
	if err != nil {
		return fmt.Errorf("session certificate %s: %w", f.cert, err)
	}
	key, err := loadOrCreateClientKey(f.key)
	if err != nil {
		return err
	}
	certSigner, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		return fmt.Errorf("session certificate %s: %w", f.cert, err)
	}
	hostKey, err := knownHostKey(f.knownHosts, t.host)
	if err != nil {
		return fmt.Errorf("device host key: %w", err)
	}
	stream, err := dialSession(ctx, strings.TrimSpace(string(rawURL)), cert.Marshal(), opts)
	if err != nil {
		return err
	}
	_ = stream.SetDeadline(time.Now().Add(sshDialTimeout))
	cr, err := session.Hello(stream, certSigner, hostKey)
	if err != nil {
		_ = stream.Close()
		if reason, ok := stream.closeReason(); ok {
			return fmt.Errorf("session ended: %s", security.SanitizeDisplay(reason))
		}
		return fmt.Errorf("session prelude: %w", err)
	}
	_ = stream.SetDeadline(time.Time{})

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
			return fmt.Errorf("session ended: %s", security.SanitizeDisplay(reason))
		}
		if stream, pos, err = t.resume(ctx, cr, cert, key, mint, opts); err != nil {
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
		return errors.New("session ended: resume_lost")
	}
	return fmt.Errorf("session stream: %w", err)
}

var errSessionEnded = errors.New("ssh-proxy: session ended")

// resume mints a resume certificate for original and resumes cr on a new
// stream, retrying with backoff within sshResumeWindow. A mint refusal or a
// final agent refusal ends the session.
func (t sshTarget) resume(ctx context.Context, cr *session.ClientResumable, original *ssh.Certificate, key ssh.Signer, mint sessionMinter, opts *websocket.DialOptions) (*sessionStream, uint64, error) {
	deadline := time.Now().Add(sshResumeWindow)
	login := original.ValidPrincipals[0]
	backoff := 500 * time.Millisecond
	for {
		resp, err := mint(ctx, identity.SessionRequest{
			DeviceHost:        t.host,
			Kind:              sshSessionKind,
			Login:             login,
			ClientSSHPubKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))),
			ResumeCertificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(original))),
		})
		if err != nil {
			return nil, 0, fmt.Errorf("resume the session: %w", err)
		}
		resumeCert, _, edgeURL, err := checkSessionCertificate(resp, key.PublicKey(), login, time.Now())
		if err != nil {
			return nil, 0, fmt.Errorf("resume the session: %w", err)
		}
		signer, err := ssh.NewCertSigner(resumeCert, key)
		if err != nil {
			return nil, 0, fmt.Errorf("resume the session: %w", err)
		}
		stream, err := dialSession(ctx, edgeURL, resumeCert.Marshal(), opts)
		if err == nil {
			_ = stream.SetDeadline(time.Now().Add(sshDialTimeout))
			var pos uint64
			if pos, err = cr.Resume(stream, signer); err == nil {
				_ = stream.SetDeadline(time.Time{})
				return stream, pos, nil
			}
			_ = stream.Close()
			var refused *session.ResumeError
			if errors.As(err, &refused) && !refused.Retryable() {
				return nil, 0, fmt.Errorf("session ended: %s", refused.Code)
			}
			if reason, closed := stream.closeReason(); closed && !slices.Contains(sshResumableEnds, reason) {
				return nil, 0, fmt.Errorf("session ended: %s", security.SanitizeDisplay(reason))
			}
		}
		if time.Now().Add(backoff).After(deadline) {
			return nil, 0, fmt.Errorf("session ended: not resumed within %s: %w", sshResumeWindow, err)
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, sshResumeBackoffMax)
	}
}

// sshConfigOptions are the client options of a target, shared by the
// ssh-config block and `localport ssh`. exe is the localport command.
func (t sshTarget) sshConfigOptions(exe string) ([][2]string, error) {
	f := t.files()
	for _, p := range []string{exe, f.key, f.knownHosts} {
		if strings.ContainsAny(p, "\"\n\r") {
			return nil, fmt.Errorf("path %q holds a quote or line break, which ssh_config cannot carry", p)
		}
	}
	return [][2]string{
		{"ProxyCommand", sshCommandLine(exe, "ssh-proxy", t.ref.String())},
		{"IdentityFile", sshConfigValue(f.key)},
		{"CertificateFile", sshConfigValue(f.cert)},
		{"UserKnownHostsFile", sshConfigValue(f.knownHosts)},
		{"HostKeyAlias", t.host},
		{"StrictHostKeyChecking", "yes"},
		{"IdentitiesOnly", "yes"},
	}, nil
}

// sshCommandLine is `<exe> <command> --identity <ref> %r %h` with exe quoted
// when it holds a space and every literal % doubled, as ssh_config expands
// % tokens in ProxyCommand and Match exec.
func sshCommandLine(exe, command, ref string) string {
	return sshConfigValue(exe) + " " + command + " --identity " + ref + " %r %h"
}

// sshConfigValue doubles % and quotes a value holding a space or tab.
func sshConfigValue(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
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
		return "", fmt.Errorf("locate this binary: %w", err)
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

// opensshBeforePQ reports whether `ssh -V` output names an OpenSSH release
// older than sshPQMinMajor.sshPQMinMinor, and the version it found.
func opensshBeforePQ(versionOutput string) (string, bool) {
	m := opensshVersionPattern.FindStringSubmatch(versionOutput)
	if m == nil {
		return "", false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return m[1] + "." + m[2], major < sshPQMinMajor || (major == sshPQMinMajor && minor < sshPQMinMinor)
}

// splitLoginHost splits `[login@]host`; without a login it is the current
// user's name, without any Windows domain prefix, as ssh defaults it.
func splitLoginHost(arg string) (string, string, error) {
	if login, host, ok := strings.Cut(arg, "@"); ok {
		if login == "" {
			return "", "", errors.New("empty login before @")
		}
		return login, host, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", "", fmt.Errorf("no login given and the current user cannot be looked up: %w", err)
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
	identityArg, _, host, err := parseSSHHelperArgs("ssh-proxy", args)
	if err != nil {
		return err
	}
	t, err := resolveSSHTarget(identityArg, host, false)
	if err != nil {
		return err
	}
	return t.proxy(context.Background(), os.Stdin, os.Stdout, nil, t.mintWithAPI)
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
	_, err = os.Stdout.WriteString(out.String())
	return err
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
		return fmt.Errorf("the OpenSSH client (ssh) is not installed or not on PATH: %w", err)
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
	if out, verErr := exec.Command(sshPath, "-V").CombinedOutput(); verErr == nil {
		if version, old := opensshBeforePQ(string(out)); old {
			fmt.Fprintf(os.Stderr, "localport: OpenSSH %s negotiates curve25519-sha256; OpenSSH 9.9 or later adds post-quantum key exchange (mlkem768x25519-sha256)\n", version)
		}
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate this binary: %w", err)
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
