//go:build !windows

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/service"
)

func TestAgentChildCmdPassesNoEnvironment(t *testing.T) {
	t.Setenv("LOCALPORT_HOME", "/tmp/elsewhere")
	cmd := agentChildCmd("/usr/bin/localport", service.Account{UID: 990, GID: 991}, []string{"enrol"})
	if cmd.Env == nil || len(cmd.Env) != 0 {
		t.Errorf("Env = %q, want an empty, non-nil environment", cmd.Env)
	}
	if !slices.Equal(cmd.Args, []string{"/usr/bin/localport", agentChildCommand, "enrol"}) {
		t.Errorf("Args = %q", cmd.Args)
	}
	if cmd.Dir != "/" {
		t.Errorf("Dir = %q, want /", cmd.Dir)
	}
	c := cmd.SysProcAttr.Credential
	if c == nil || c.Uid != 990 || c.Gid != 991 || !slices.Equal(c.Groups, []uint32{991}) {
		t.Errorf("Credential = %+v, want uid 990, gid 991, groups [991]", c)
	}
}

// The hidden command runs only as the agent account.
func TestAgentChildRefusesAnyOtherAccount(t *testing.T) {
	restore := lookupAgentAccount
	t.Cleanup(func() { lookupAgentAccount = restore; asAgentChild = false })
	lookupAgentAccount = func() (service.Account, error) { return service.Account{UID: os.Geteuid() + 1}, nil }
	err := runAgentChild(New("test", "", ""), []string{"status"})
	if err == nil || !strings.Contains(err.Error(), "started only by localport") || asAgentChild {
		t.Fatalf("runAgentChild as another account = %v (asAgentChild %v), want a refusal", err, asAgentChild)
	}
	lookupAgentAccount = func() (service.Account, error) { return service.Account{UID: os.Geteuid()}, nil }
	if err := runAgentChild(New("test", "", ""), []string{"connect"}); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("runAgentChild connect = %v, want unknown command", err)
	}
}

func TestRootRunsAsAgentOnlyOnTheSystemLayout(t *testing.T) {
	restoreRoot, restoreFile := agentChildRoot, systemLocalConfig
	t.Cleanup(func() { agentChildRoot, systemLocalConfig = restoreRoot, restoreFile })
	agentChildRoot = func() bool { return true }
	systemLocalConfig = func() (config.LocalConfigFile, error) {
		return config.LocalConfigFile{Path: "/etc/localport-device/agent.yaml", Base: "/etc/localport-device", System: true}, nil
	}
	for cmd, want := range map[string]bool{"run": true, "status": true, "identity": true, "login": true, "setup": true, "access": true, "connect": false, "set": false, "service": false, "enrol": false, "purge": false} {
		if got := rootRunsAsAgent(cmd); got != want {
			t.Errorf("rootRunsAsAgent(%q) = %v, want %v", cmd, got, want)
		}
	}
	agentChildRoot = func() bool { return false }
	if rootRunsAsAgent("identity") {
		t.Error("a process that is not root re-executes itself")
	}
}

func TestEnrolChildRefusesUnknownFields(t *testing.T) {
	err := runEnrolChild(strings.NewReader(`{"join_token":"x","extra":1}`), os.Stdout)
	if err == nil || !strings.Contains(err.Error(), "read the request") {
		t.Fatalf("runEnrolChild = %v, want a decode refusal", err)
	}
}

func TestKeyFingerprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "d"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	got, err := keyFingerprint(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil || got != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("keyFingerprint = %q, %v", got, err)
	}
	if _, err := keyFingerprint([]byte("not pem")); err == nil {
		t.Fatal("keyFingerprint accepted no certificate")
	}
}

func statGID(t *testing.T, path string) int {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return int(fi.Sys().(*syscall.Stat_t).Gid)
}

func self() service.Account { return service.Account{UID: os.Getuid(), GID: os.Getgid()} }

func TestChownTreeWalksAndRefusesLinks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "identity")
	for _, d := range []string{"team/device-a", "recordings/0b6f"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "team/device-a/key.pem"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := chownTree(root, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("chownTree = %v", err)
	}
	if err := os.Symlink("/etc/shadow", filepath.Join(root, "team/device-a/planted")); err != nil {
		t.Fatal(err)
	}
	if err := chownTree(root, os.Getuid(), os.Getgid()); err == nil || !strings.Contains(err.Error(), "planted") {
		t.Fatalf("chownTree over a symlink = %v, want a refusal naming it", err)
	}
	// The refusal comes from the first pass, before anything changes: the
	// tree keeps its group although a sibling sorts before the link.
	if os.Getuid() != 0 {
		groups, err := os.Getgroups()
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range groups {
			if g == os.Getgid() {
				continue
			}
			key := filepath.Join(root, "team/device-a/key.pem")
			if err := chownTree(root, os.Getuid(), g); err == nil {
				t.Fatal("chownTree over a symlink succeeded")
			}
			if st := statGID(t, key); st != os.Getgid() {
				t.Fatalf("a refused walk changed %s to gid %d", key, st)
			}
			break
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := chownTree(link, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("chownTree followed a symlinked root")
	}
}

func TestEnsureIdentityDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	if convert, err := ensureIdentityDir(dir, self()); err != nil || convert {
		t.Fatalf("new dir: convert %v, %v", convert, err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if convert, err := ensureIdentityDir(dir, self()); err != nil || convert {
		t.Fatalf("own dir: convert %v, %v", convert, err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v, want 0700", fi.Mode().Perm())
	}
	other := service.Account{UID: os.Getuid() + 1, GID: os.Getgid()}
	if os.Getuid() != 0 {
		if _, err := ensureIdentityDir(dir, other); err == nil || !strings.Contains(err.Error(), "neither root nor") {
			t.Fatalf("foreign owner = %v, want a refusal", err)
		}
	}
	link := filepath.Join(t.TempDir(), "identity")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureIdentityDir(link, self()); err == nil {
		t.Fatal("ensureIdentityDir followed a symlink")
	}
}

// The account stays while the identity directory still holds credentials,
// so they keep their owner's uid.
func TestRemoveAgentAccountKeepsAnAccountWithCredentials(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "identity", "team", "client-a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeAgentAccount(t.Context(), dir); err != nil {
		t.Fatalf("removeAgentAccount = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity", "team", "client-a")); err != nil {
		t.Fatalf("the credentials went: %v", err)
	}
}

// Purge removes the device credentials, the spool and the team directories
// they leave empty, so an identity directory that held only devices ends
// empty and removeAgentAccount can take the account; another credential
// keeps its team directory.
func TestPurgeStoreLeavesNoEmptyTeamDirectory(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"t1/device-a.gw", "t2/device-b.gw", "t2/client-c", "recordings/0b6f"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	store := &identity.Store{Root: root, Base: root}
	if err := purgeStore(store); err != nil {
		t.Fatalf("purgeStore = %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"t2"}) {
		t.Fatalf("left %q, want only t2 (it holds a client credential)", names)
	}
	if _, err := os.Stat(filepath.Join(root, "t2", "client-c")); err != nil {
		t.Fatalf("the client credential went: %v", err)
	}
}

func TestMoveSpool(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "recordings"), filepath.Join(dir, "identity", "recordings")
	if err := moveSpool(from, to); err != nil {
		t.Fatalf("no spool: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(from, "0b6f"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "identity"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := moveSpool(from, to); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(to, "0b6f")); err != nil {
		t.Fatalf("spool not moved: %v", err)
	}
	if err := os.WriteFile(from, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := moveSpool(from, filepath.Join(dir, "x")); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a file in the spool's place = %v, want a refusal", err)
	}
}
