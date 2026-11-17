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
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/service"
	"github.com/localport/agent/internal/testroot"
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

// --verbose reaches the child as a global flag before the child command,
// where App.Run parses it.
func TestAgentChildCmdCarriesVerbose(t *testing.T) {
	t.Cleanup(func() { verbose = false })
	if err := New("test", "", "").Run([]string{"--verbose", "version"}); err != nil || !verbose {
		t.Fatalf("Run(--verbose version) = %v, verbose %v; want parsed", err, verbose)
	}
	cmd := agentChildCmd("/usr/bin/localport", service.Account{UID: 990, GID: 991}, []string{"status"})
	if !slices.Equal(cmd.Args, []string{"/usr/bin/localport", "--verbose", agentChildCommand, "status"}) {
		t.Errorf("Args = %q", cmd.Args)
	}
}

// The hidden command runs only as the agent account, and never as root even
// when the agent account resolves to uid 0.
func TestAgentChildRefusesAnyOtherAccount(t *testing.T) {
	restoreLookup, restoreEUID := lookupAgentAccount, currentEUID
	t.Cleanup(func() { lookupAgentAccount, currentEUID = restoreLookup, restoreEUID; asAgentChild = false })
	as := func(euid, agentUID int) {
		currentEUID = func() int { return euid }
		lookupAgentAccount = func() (service.Account, error) { return service.Account{UID: agentUID}, nil }
	}
	for _, c := range []struct {
		name           string
		euid, agentUID int
	}{
		{"another account", 1001, 990},
		{"root with the agent account at uid 0", 0, 0},
	} {
		as(c.euid, c.agentUID)
		err := runAgentChild(New("test", "", ""), []string{"status"})
		if !errors.Is(err, errcode.New(errcode.AgentChildOnly)) || asAgentChild {
			t.Fatalf("runAgentChild as %s = %v (asAgentChild %v), want a refusal", c.name, err, asAgentChild)
		}
	}
	as(990, 990)
	if err := runAgentChild(New("test", "", ""), []string{"up"}); !errors.Is(err, errcode.New(errcode.AgentChildOnly)) || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("runAgentChild up = %v, want unknown command", err)
	}
	// devices is dispatched to runDevicesChild, which reads the system config:
	// an unusable one fails there, not as an unknown command.
	restoreFile := systemLocalConfig
	t.Cleanup(func() { systemLocalConfig = restoreFile })
	dir := t.TempDir()
	systemLocalConfig = func() (config.LocalConfigFile, error) {
		return config.LocalConfigFile{Path: filepath.Join(dir, "agent.yaml"), Base: dir, System: true}, nil
	}
	if err := runAgentChild(New("test", "", ""), []string{"devices"}); err == nil || errors.Is(err, errcode.New(errcode.AgentChildOnly)) || !errors.Is(err, errcode.New(errcode.LocalConfigUnusable)) {
		t.Fatalf("runAgentChild devices = %v, want runDevicesChild's config error", err)
	}
}

func TestRootRunsAsAgentOnlyOnTheSystemLayout(t *testing.T) {
	restoreRoot, restoreFile := agentChildRoot, systemLocalConfig
	t.Cleanup(func() { agentChildRoot, systemLocalConfig = restoreRoot, restoreFile })
	agentChildRoot = func() bool { return true }
	systemLocalConfig = func() (config.LocalConfigFile, error) {
		return config.LocalConfigFile{Path: "/etc/localport-device/agent.yaml", Base: "/etc/localport-device", System: true}, nil
	}
	for cmd, want := range map[string]bool{"run": true, "status": true, "identity": true, "login": true, "setup": true, "access": true, "up": false, "down": false, "set": false, "service": false, "enrol": false, "purge": false, "set-pins": false, "devices": false} {
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

func self() service.Account { return service.Account{UID: os.Getuid(), GID: os.Getgid()} }

func TestEnsureIdentityDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	if err := ensureIdentityDir(dir, self()); err != nil {
		t.Fatalf("new dir: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureIdentityDir(dir, self()); err != nil {
		t.Fatalf("own dir: %v", err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v, want 0700", fi.Mode().Perm())
	}
	other := service.Account{UID: os.Getuid() + 1, GID: os.Getgid()}
	if os.Getuid() != 0 {
		if err := ensureIdentityDir(dir, other); err == nil || !strings.Contains(err.Error(), "not the account") {
			t.Fatalf("foreign owner = %v, want a refusal", err)
		}
	}
	link := filepath.Join(t.TempDir(), "identity")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureIdentityDir(link, self()); err == nil {
		t.Fatal("ensureIdentityDir followed a symlink")
	}
}

// An empty root-owned identity directory, left by a crash between Mkdir and
// Fchown, is given to the account; one that holds anything is refused.
func TestRootEnsureIdentityDirAdoptsAnEmptyRootDir(t *testing.T) {
	if os.Getuid() != 0 {
		testroot.Require(t, "needs root")
	}
	acct := service.Account{UID: 65534, GID: 65534}
	dir := filepath.Join(t.TempDir(), "identity")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensureIdentityDir(dir, acct); err != nil {
		t.Fatalf("empty root dir: %v", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != acct.UID || int(st.Gid) != acct.GID {
		t.Fatalf("owner = %d:%d, want %d:%d", st.Uid, st.Gid, acct.UID, acct.GID)
	}

	full := filepath.Join(t.TempDir(), "identity")
	if err := os.Mkdir(full, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "key"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureIdentityDir(full, acct); err == nil || !strings.Contains(err.Error(), "not the account") {
		t.Fatalf("non-empty root dir = %v, want a refusal", err)
	}
}

// The identity directory and the log directory stay while the identity
// directory still holds credentials, so they keep their owner's uid; an
// empty one is removed with the log directory.
func TestRemoveAgentDirsKeepsCredentials(t *testing.T) {
	newLogDir := func() string {
		logDir := filepath.Join(t.TempDir(), "log")
		if err := os.Mkdir(logDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(logDir, "agent.log"), nil, 0o640); err != nil {
			t.Fatal(err)
		}
		return logDir
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "identity", "team", "client-a"), 0o700); err != nil {
		t.Fatal(err)
	}
	logDir := newLogDir()
	if err := removeAgentDirs(config.LocalConfigFile{Path: filepath.Join(dir, "agent.yaml")}, logDir); err != nil {
		t.Fatalf("removeAgentDirs = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity", "team", "client-a")); err != nil {
		t.Fatalf("the credentials went: %v", err)
	}
	if _, err := os.Stat(filepath.Join(logDir, "agent.log")); err != nil {
		t.Fatalf("the log went while credentials remain: %v", err)
	}

	empty := t.TempDir()
	if err := os.Mkdir(filepath.Join(empty, "identity"), 0o700); err != nil {
		t.Fatal(err)
	}
	logDir = newLogDir()
	if err := removeAgentDirs(config.LocalConfigFile{Path: filepath.Join(empty, "agent.yaml")}, logDir); err != nil {
		t.Fatalf("removeAgentDirs = %v", err)
	}
	if _, err := os.Stat(filepath.Join(empty, "identity")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("empty identity dir: %v, want it removed", err)
	}
	if _, err := os.Stat(logDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("log dir: %v, want it removed", err)
	}
}

// Purge keeps the account and names the host's commands that remove it.
func TestKeptAccountNoticeNamesTheRemoval(t *testing.T) {
	got := keptAccountNotice([]string{"/usr/sbin/userdel", "localport"}, []string{"/usr/sbin/groupdel", "localport"})
	if !strings.Contains(got, "kept the account "+service.AgentAccount) || !strings.Contains(got, "sudo /usr/sbin/userdel localport, then sudo /usr/sbin/groupdel localport") {
		t.Fatalf("notice = %q", got)
	}
	if runtime.GOOS == "darwin" {
		want := "kept the account _localport (it may own files elsewhere); to remove it: sudo /usr/bin/dscl . -delete /Users/_localport, then sudo /usr/bin/dscl . -delete /Groups/_localport if the group remains"
		if got := keptAccountNotice(service.AccountRemoval()); got != want {
			t.Fatalf("macOS notice = %q, want %q", got, want)
		}
	}
	if got := keptAccountNotice(nil, nil); !strings.Contains(got, "package that created it owns it") {
		t.Fatalf("notice without a tool = %q", got)
	}
}

// Purge removes the device credentials, the spool, the team directories they
// leave empty and the lock files, so an identity directory that held only
// devices ends empty and removeAgentDirs can remove it; another credential
// keeps its team directory and the store lock it is locked under.
func TestPurgeStoreLeavesNoEmptyTeamDirectory(t *testing.T) {
	for _, tc := range []struct {
		name string
		dirs []string
		want []string
	}{
		{"devices only", []string{"t1/device-a.gw", "recordings/0b6f", identity.LocksDir + "/0f"}, nil},
		{"a client credential", []string{"t1/device-a.gw", "t2/device-b.gw", "t2/client-c", "recordings/0b6f"}, []string{".store.lock", "t2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range tc.dirs {
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
			if !slices.Equal(names, tc.want) {
				t.Fatalf("left %q, want %q", names, tc.want)
			}
		})
	}
}
