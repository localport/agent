package cli

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
)

// Root never opens a path inside the system identity directory, which the
// agent account owns: every privileged command that reads or writes the
// system store runs that part in a child process re-executed as the agent
// account (runAsAgentAccount), the rule runuser follows. The child's first
// argument is agentChildCommand; it marks the process as serving the
// machine-wide devices, as `run --system` does, and grants nothing the OS
// does not.
const agentChildCommand = "__agent"

// asAgentChild is set in a process root started as the agent account; it
// makes currentInvoker privileged, so the command uses the system paths.
var asAgentChild bool

// agentChildCommands are the commands a child runs whole, with root's argv;
// enrol and purge are the parts of connect and service uninstall --purge
// that touch the store.
var agentChildCommands = []string{"run", "status", "identity", "login", "setup", "access", "enrol", "purge"}

// needsAgentChild reports whether this process is root and file is the
// system config, so the store must be reached through the agent account.
// Windows keeps the Administrators-owned store (file.System is false there).
func needsAgentChild(file config.LocalConfigFile) bool {
	return file.System && agentChildRoot()
}

// agentChildRoot is euid 0; tests run unprivileged and keep the in-process
// path.
var agentChildRoot = func() bool { return os.Geteuid() == 0 }

// lookupAgentAccount is service.LookupAccount; tests name their own uid.
var lookupAgentAccount = service.LookupAccount

// rootRunsAsAgent reports whether command, run whole, re-executes itself as
// the agent account: root, on a platform with the system layout.
func rootRunsAsAgent(command string) bool {
	if !slices.Contains(agentChildCommands, command) || command == "enrol" || command == "purge" {
		return false
	}
	file, err := systemLocalConfig()
	return err == nil && needsAgentChild(file)
}

// runAgentChild runs a command in a process root started as the agent
// account. It refuses unless the process runs as that account, so the hidden
// command is no shortcut for anyone else.
func runAgentChild(app *App, args []string) error {
	acct, err := lookupAgentAccount()
	if err != nil {
		return err
	}
	if euid := os.Geteuid(); euid != acct.UID || euid == 0 {
		return fmt.Errorf("%s is started only by localport, as the account %s", agentChildCommand, service.AgentAccount)
	}
	if len(args) == 0 || !slices.Contains(agentChildCommands, args[0]) {
		return fmt.Errorf("%s: unknown command", agentChildCommand)
	}
	asAgentChild = true
	switch args[0] {
	case "enrol":
		return runEnrolChild(os.Stdin, os.Stdout)
	case "purge":
		return runPurgeChild()
	}
	return app.Run(args)
}

// enrolRequest is what connect, as root, sends the enrol child on its stdin.
type enrolRequest struct {
	JoinToken string        `json:"join_token"`
	APIURL    string        `json:"api_url"`
	Wait      time.Duration `json:"wait"`
}

// enrolResult is what the enrol child writes on its stdout.
type enrolResult struct {
	Ref  identity.Ref `json:"ref"`
	Host string       `json:"host,omitempty"`
}

// enrolInStore readies the store, spends the join token, saves the issued
// credential and its ticket keys, and prints the credential. connect runs
// it in-process or, as root, in the enrol child.
func enrolInStore(store *identity.Store, req enrolRequest) (enrolResult, error) {
	if err := store.EnsureRoot(); err != nil {
		return enrolResult{}, err
	}
	client, err := identity.NewClient(req.APIURL)
	if err != nil {
		return enrolResult{}, err
	}
	ctx, cancel := signalContext(nil)
	defer cancel()
	notice := func(attempt int, in time.Duration, err error) {
		fmt.Fprintf(os.Stderr, "  control plane unreachable (attempt %d), retrying in %s\n", attempt, in.Round(time.Second))
	}
	material, err := enrolDevice(client, ctx, req.JoinToken, req.Wait, notice)
	if err != nil {
		// The error may quote the request. Keep the token out of terminals and
		// logs.
		err = security.SanitizeError(err, req.JoinToken)
		if mayHaveSpent(err) {
			return enrolResult{}, fmt.Errorf("%w\n  if the control plane redeemed the token before this failure, %s", err, joinTokenSpent)
		}
		return enrolResult{}, err
	}
	ref, err := saveIssued(store, ctx, *material)
	if err != nil {
		return enrolResult{}, fmt.Errorf("save the device credential: %w\n  %s", err, joinTokenSpent)
	}
	storeEnrolledKeys(store, ref, material.DeviceKeys)
	fmt.Fprintf(os.Stderr, "\n  enrolled\n")
	printCredential(store, ref, material.Meta)
	res := enrolResult{Ref: ref}
	if material.Meta.Device != nil {
		res.Host = material.Meta.Device.Host
	}
	return res, nil
}

func runEnrolChild(in io.Reader, out io.Writer) error {
	var req enrolRequest
	dec := json.NewDecoder(io.LimitReader(in, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return fmt.Errorf("%s enrol: read the request: %w", agentChildCommand, err)
	}
	store, err := currentInvoker(false).store()
	if err != nil {
		return err
	}
	res, err := enrolInStore(store, req)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(res)
}

// enrolAsAgent runs enrolInStore in the enrol child: the join token goes
// over the child's stdin, never its argv or environment.
func enrolAsAgent(req enrolRequest) (enrolResult, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return enrolResult{}, err
	}
	var out bytes.Buffer
	if err := runAsAgentAccount([]string{"enrol"}, bytes.NewReader(raw), &out); err != nil {
		return enrolResult{}, err
	}
	var res enrolResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return enrolResult{}, fmt.Errorf("read the enrolment result: %w\n  %s", err, joinTokenSpent)
	}
	return res, nil
}

// runPurgeChild deletes the device credentials and the recording spool of
// the system store. Root holds run.lock and the config's lock meanwhile.
func runPurgeChild() error {
	store, err := currentInvoker(false).store()
	if err != nil {
		return err
	}
	return purgeStore(store)
}

// purgeStore deletes the device credentials of store and its recording
// spool, printing each deletion.
func purgeStore(store *identity.Store) error {
	removed, err := store.RemoveDevices()
	for _, d := range removed {
		fmt.Fprintf(os.Stderr, "  deleted %s\n", d)
	}
	if err != nil {
		return err
	}
	spool := recordingSpoolDir(store)
	if err := os.RemoveAll(spool); err != nil {
		return fmt.Errorf("remove %s: %w", spool, err)
	}
	fmt.Fprintf(os.Stderr, "  deleted %s; other credentials in %s remain\n", spool, store.Root)
	return nil
}

// keyFingerprint is the SHA-256 of the leaf certificate's public key, as
// `sha256:<hex>`.
func keyFingerprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// printFingerprints prints the key fingerprint of each device whose
// credential this process can read: the agent account (the status child) or
// the owner of a user store.
func printFingerprints(w io.Writer, devices []config.LocalDevice) {
	store, err := currentInvoker(false).store()
	if err != nil {
		return
	}
	for _, d := range devices {
		m, err := store.Load(d.Identity)
		if err != nil {
			continue
		}
		if fp, err := keyFingerprint(m.CertPEM); err == nil {
			fmt.Fprintf(w, "key        %s %s\n", d.Identity, fp)
		}
	}
}
