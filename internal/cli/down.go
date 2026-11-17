package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/status"
)

// runDown pauses enrolled devices: it sets paused on each selected entry of
// the system config and reloads the device service, which stops their
// tunnels. The pause lasts across restarts until `localport up`.
func runDown(args []string) error { return runPause("down", args, true) }

// runPause is `down` (pause) and `up` without a join token (resume). Root
// only: it writes the system config. It records its outcome in the system log.
func runPause(command string, args []string, pause bool) (err error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	all := fs.Bool("all", false, "act on every enrolled device")
	fs.Usage = func() { usagePause(command, fs) }
	selector, rest := "", args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		selector, rest = args[0], args[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if selector == "" && fs.NArg() > 0 {
		selector = fs.Arg(0)
		rest = fs.Args()[1:]
	} else {
		rest = fs.Args()
	}
	if len(rest) > 0 {
		fs.Usage()
		return errExtraArgument.With(nil, fmt.Sprintf("%q", security.SanitizeDisplay(rest[0])))
	}
	if *all && selector != "" {
		return fmt.Errorf("name a device or give --all, not both")
	}

	who := currentInvoker(false)
	if !who.privileged {
		return errcode.WithRemedy(config.ErrSystemNotRoot.With(nil, command), "run it "+elevatedCommand(command))
	}
	defer func() { logOutcome(append([]string{command}, args...), err, true) }()
	file, err := who.localConfigFile()
	if err != nil {
		return err
	}
	changed, unchanged, err := setPaused(file, who, selector, *all, pause)
	if err != nil {
		return err
	}
	for _, ref := range unchanged {
		fmt.Fprintf(os.Stderr, "  %s is already %s\n", ref, pausedWord(pause))
	}
	if len(changed) == 0 && pause {
		return nil
	}
	for _, ref := range changed {
		fmt.Fprintf(os.Stderr, "  %s %s in %s\n", ref, pausedWord(pause), file.Path)
	}
	// up also retries parked devices and starts a stopped service, so it
	// applies even when no entry changed.
	applied := time.Now()
	running, err := applyPause(pause)
	if err != nil || !running {
		return err
	}
	selected := append(slices.Clone(changed), unchanged...)
	awaitDeviceStates(os.Stderr, selected, pause, applied)
	return nil
}

// elevatedCommand names how to run command with the privilege it needs on
// this OS.
func elevatedCommand(command string) string {
	if runtime.GOOS == "windows" {
		return "from an elevated prompt: localport " + command
	}
	return "with sudo: sudo localport " + command
}

// Polling of the status endpoint after up or down.
const (
	awaitStatesFor   = 10 * time.Second
	awaitStatesEvery = 250 * time.Millisecond
)

// readDocument is status.Read; tests replace it.
var readDocument = status.Read

// awaitDeviceStates polls the status endpoint until every device of refs
// leaves connecting and, for down, is paused, for up is running or reports a
// state entered at applied or later (so a parked device is not read from the
// document before its retry), at most awaitStatesFor, then prints each
// device's state. A timeout prints the last states with a note; the config is
// written either way.
func awaitDeviceStates(w io.Writer, refs []identity.Ref, pause bool, applied time.Time) {
	if len(refs) == 0 {
		return
	}
	deadline := time.Now().Add(awaitStatesFor)
	var doc *status.Document
	var err error
	for {
		doc, err = readDocument(context.Background())
		if err == nil && statesSettled(doc, refs, pause, applied) {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(awaitStatesEvery)
	}
	if err != nil {
		fmt.Fprintf(w, "  state unknown: %s\n", statusUnavailable(err))
		return
	}
	for _, ref := range refs {
		fmt.Fprintf(w, "  %s %s\n", ref, describeRow(rowOf(doc, ref)))
	}
	if !statesSettled(doc, refs, pause, applied) {
		fmt.Fprintf(w, "  the device service has not applied it yet; check with: localport status\n")
	}
}

func statesSettled(doc *status.Document, refs []identity.Ref, pause bool, applied time.Time) bool {
	for _, ref := range refs {
		row := rowOf(doc, ref)
		switch {
		case row == nil || row.State == status.StateConnecting:
			return false
		case pause:
			if row.State != status.StatePaused {
				return false
			}
		case row.State == status.StatePaused:
			return false
		case row.State != status.StateRunning && row.Since.Before(applied):
			return false
		}
	}
	return true
}

func rowOf(doc *status.Document, ref identity.Ref) *status.Device {
	for i := range doc.Devices {
		if doc.Devices[i].Identity == ref.Identity {
			return &doc.Devices[i]
		}
	}
	return nil
}

func pausedWord(pause bool) string {
	if pause {
		return "paused"
	}
	return "resumed"
}

// applyPause reloads the running device service. A stopped one is started by
// up (resume) and left stopped by down (pause), which applies at its next
// start. It reports whether the service runs the change now. With no service
// installed it says so.
func applyPause(pause bool) (running bool, err error) {
	m, installed, err := installedDeviceService()
	if err != nil {
		return false, err
	}
	if !installed {
		fmt.Fprintf(os.Stderr, "  no device service is installed; install it with: %s\n", serviceInstallCommand)
		return false, nil
	}
	pid, err := m.MainPID(context.Background())
	if err != nil {
		return false, err
	}
	switch {
	case pid == 0 && pause:
		fmt.Fprintf(os.Stderr, "  the device service is not running; it applies this when it starts\n")
		return false, nil
	case pid == 0:
		if err := m.Restart(context.Background()); err != nil {
			return false, err
		}
		fmt.Fprintf(os.Stderr, "  started the device service\n")
		return true, nil
	}
	if err := m.Reload(context.Background()); err != nil {
		return false, errcode.WithRemedy(errcode.New(errcode.SettingsNotApplied).With(err, ""), "apply them with: "+serviceInstallCommand)
	}
	fmt.Fprintf(os.Stderr, "  reloaded the device service\n")
	return true, nil
}

// setPaused writes paused on the selected devices under the local config's
// lock, which also covers reading the store facts, so a concurrent `up
// <join-token>` cannot be pruned by a tombstone read before its enrolment. It
// drops entries of removed devices. It returns the devices it changed and the
// selected ones already in that state.
func setPaused(file config.LocalConfigFile, who invoker, selector string, all, pause bool) (changed, unchanged []identity.Ref, err error) {
	unlock, err := config.LockLocal(file)
	if err != nil {
		return nil, nil, err
	}
	defer unlock()
	local, err := config.LoadLocal(file)
	if err != nil {
		return nil, nil, err
	}
	facts, err := readFacts(file, who, local.Devices)
	if err != nil {
		return nil, nil, err
	}
	pruned := pruneRemoved(local, facts)
	idx, err := selectDevices(local.Devices, facts, selector, all, "localport "+map[bool]string{true: "down", false: "up"}[pause])
	if err != nil {
		return nil, nil, errors.Join(err, writePruned(file, local, pruned))
	}
	for _, i := range idx {
		d := &local.Devices[i]
		if d.Paused == pause {
			unchanged = append(unchanged, d.Identity)
			continue
		}
		d.Paused = pause
		changed = append(changed, d.Identity)
	}
	if len(changed) == 0 {
		return nil, unchanged, writePruned(file, local, pruned)
	}
	if err := config.WriteLocal(file, local, identity.Ref{}); err != nil {
		return nil, nil, err
	}
	reportPruned(pruned)
	return changed, unchanged, nil
}

// pruneRemoved drops the entries of devices the store forgot (a tombstone and
// no credential) and returns the facts of those it dropped. The caller writes
// local and then reports them (reportPruned).
func pruneRemoved(local *config.LocalConfig, facts map[identity.Ref]deviceFact) []deviceFact {
	var pruned []deviceFact
	local.Devices = slices.DeleteFunc(local.Devices, func(d config.LocalDevice) bool {
		f, ok := facts[d.Identity]
		if !ok || f.Removed == "" {
			return false
		}
		pruned = append(pruned, f)
		return true
	})
	return pruned
}

// writePruned writes local when pruneRemoved dropped entries from it, and
// reports them once written.
func writePruned(file config.LocalConfigFile, local *config.LocalConfig, pruned []deviceFact) error {
	if len(pruned) == 0 {
		return nil
	}
	if err := config.WriteLocal(file, local, identity.Ref{}); err != nil {
		return err
	}
	reportPruned(pruned)
	return nil
}

func reportPruned(pruned []deviceFact) {
	for _, f := range pruned {
		fmt.Fprintf(os.Stderr, "  removed %s from the config: the control plane refused it with %s (removed or enrolled again); enrol it again %s\n",
			f.Ref, f.Removed, elevatedCommand("up <join-token>"))
	}
}

// deviceFactsVersion is the version of the devices child's output.
const deviceFactsVersion = 1

// maxDeviceFacts bounds the devices child's output root reads.
const maxDeviceFacts = 64 << 10

// deviceFact is what the store holds about one configured device that root
// may show: its public address, team name and, when the device was forgotten,
// the refusal code. Nothing secret.
type deviceFact struct {
	Version int    `json:"version"`
	Ref     string `json:"ref"`
	Host    string `json:"host,omitempty"`
	Team    string `json:"team,omitempty"`
	Removed string `json:"removed,omitempty"`
}

// runDevicesChild prints one deviceFact per device of the system config. Root
// runs it as the devices store part.
func runDevicesChild(w io.Writer) error {
	who := currentInvoker(false)
	file, err := who.localConfigFile()
	if err != nil {
		return err
	}
	local, err := config.LoadLocal(file)
	if err != nil {
		return err
	}
	store, err := who.store()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	for _, d := range local.Devices {
		if err := enc.Encode(storeFact(store, d.Identity)); err != nil {
			return err
		}
	}
	return nil
}

// storeFact reads ref's fact from store. A tombstone counts only when the
// credential is gone: a re-enrolled device runs its credential.
func storeFact(store *identity.Store, ref identity.Ref) deviceFact {
	f := deviceFact{Version: deviceFactsVersion, Ref: ref.String()}
	m, err := store.Load(ref)
	if err == nil {
		if m.Meta.Device != nil {
			f.Host = m.Meta.Device.Host
		}
		f.Team = m.Meta.DisplayTeam()
		return f
	}
	if _, statErr := os.Stat(store.Dir(ref)); errors.Is(statErr, os.ErrNotExist) {
		if ts, err := store.ReadTombstone(ref); err == nil && ts != nil {
			f.Removed = ts.Code
		}
	}
	return f
}

// runDevicesStorePart is runAsAgentAccount for the devices store part; tests
// replace it.
var runDevicesStorePart = runAsAgentAccount

// readFacts is readDeviceFacts; tests replace it to observe the lock it runs
// under.
var readFacts = readDeviceFacts

// readDeviceFacts returns the store facts of devices: on the system layout as
// root through the devices agent child, whose output is untrusted (bounded,
// strictly decoded, only refs of devices kept, strings sanitized), otherwise
// from the store in process.
func readDeviceFacts(file config.LocalConfigFile, who invoker, devices []config.LocalDevice) (map[identity.Ref]deviceFact, error) {
	facts := make(map[identity.Ref]deviceFact, len(devices))
	if !needsAgentChild(file) {
		store, err := who.store()
		if err != nil {
			return nil, err
		}
		for _, d := range devices {
			facts[d.Identity] = storeFact(store, d.Identity)
		}
		return facts, nil
	}
	out := &cappedBuffer{max: maxDeviceFacts}
	if err := runDevicesStorePart([]string{"devices"}, nil, out); err != nil {
		return nil, errcode.New(errcode.AgentChildFailed).With(err, "read the enrolled devices")
	}
	parsed, err := decodeDeviceFacts(out.Bytes())
	if err != nil {
		return nil, errcode.New(errcode.AgentChildFailed).With(err, "read the enrolled devices")
	}
	for _, d := range devices {
		if f, ok := parsed[d.Identity]; ok {
			facts[d.Identity] = f
		}
	}
	return facts, nil
}

// decodeDeviceFacts decodes the devices child's lines strictly: unknown
// fields, another version or an invalid ref refuse the whole output.
func decodeDeviceFacts(raw []byte) (map[identity.Ref]deviceFact, error) {
	facts := map[identity.Ref]deviceFact{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 4096), maxDeviceFacts)
	for sc.Scan() {
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		var f deviceFact
		if err := dec.Decode(&f); err != nil {
			return nil, err
		}
		if f.Version != deviceFactsVersion {
			return nil, fmt.Errorf("device facts version %d, this agent reads %d", f.Version, deviceFactsVersion)
		}
		ref, err := identity.ParseDeviceRef(f.Ref)
		if err != nil {
			return nil, err
		}
		f.Host, f.Team = security.SanitizeDisplay(f.Host), security.SanitizeDisplay(f.Team)
		if f.Removed != "" && !identity.IsRemovalCode(f.Removed) {
			return nil, fmt.Errorf("device %s: unexpected removal code %q", ref, security.SanitizeDisplay(f.Removed))
		}
		facts[ref] = f
	}
	return facts, sc.Err()
}

// errOutputTooLarge refuses child output past its cap.
var errOutputTooLarge = errors.New("output over its size limit")

// cappedBuffer collects writes and refuses one past max. It wraps rather than
// embeds bytes.Buffer, so no promoted WriteString or ReadFrom bypasses the cap.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.max {
		return 0, errOutputTooLarge
	}
	return b.buf.Write(p)
}

// Bytes returns what was written.
func (b *cappedBuffer) Bytes() []byte { return b.buf.Bytes() }

func usagePause(command string, fs *flag.FlagSet) {
	verb := "Pause"
	detail := "Its tunnel stops and it stays offline across restarts until `localport up`."
	if command == "up" {
		verb, detail = "Resume", "A paused device connects again, and a device the agent stopped after a refusal retries."
	}
	fmt.Fprintf(os.Stderr, `Usage: sudo localport %[1]s [<device> | --all]

  %[2]s an enrolled device and apply it to the running device service.
  %[3]s
  With one device enrolled, it acts on that one. With several, name it by
  its identity, <team>/<prefix>, or a unique prefix; in a terminal with no
  argument, it asks which.

Flags:
`, command, verb, detail)
	fs.PrintDefaults()
}
