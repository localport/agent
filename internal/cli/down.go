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
	"unicode/utf8"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
	"github.com/localport/agent/internal/status"
)

// runDown pauses enrolled devices: it sets paused on each selected entry of
// the system config and makes the process serving the devices reload
// (applyConfig), which stops their tunnels. The pause lasts across restarts
// until `localport up`.
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
		return errcode.UsageError(err)
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
		return errExtraArgument.With(nil, "name a device or give --all, not both")
	}

	who := currentInvoker(false)
	if !who.privileged {
		return errcode.WithRemedy(config.ErrSystemNotRoot.With(nil, command), "run it "+elevatedCommand(command))
	}
	// The reload may end the terminal session this runs in (a localport
	// session on this device): run to the end and record the outcome.
	ignoreHangup()
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
	target, err := applyConfig(!pause)
	if err != nil || target == appliedNowhere {
		return err
	}
	selected := append(slices.Clone(changed), unchanged...)
	awaitDeviceStates(os.Stderr, selected, pause, applied, target)
	return nil
}

// elevatedLocalport is how a command that needs root or an elevated
// Administrator starts on this OS, and elevatedNote the help text's hint for
// it ("" on Unix, where sudo says it).
func elevatedLocalport() string {
	if runtime.GOOS == "windows" {
		return "localport"
	}
	return "sudo localport"
}

func elevatedNote() string {
	if runtime.GOOS == "windows" {
		return " (from an elevated prompt)"
	}
	return ""
}

// elevatedStop is the command that stops the device service m, as an
// administrator runs it on this OS.
func elevatedStop(m service.Manager) string {
	if runtime.GOOS == "windows" {
		return m.StopCommand() + elevatedNote()
	}
	return "sudo " + m.StopCommand()
}

// elevatedCommand names how to run command with the privilege this OS needs.
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
// leaves connecting and, for down, is paused; for up, is not paused and, when
// parked, parked again at applied or later (so the refusal read is the one
// after up's retry). It waits at most awaitStatesFor, then prints each
// device's state, with a note on a timeout. The config is written either way.
// A foreground run publishes to the session launcher only when the device
// service installed it, so with target a foreground run and no launcher it
// stops at once and points to the run's terminal.
func awaitDeviceStates(w io.Writer, refs []identity.Ref, pause bool, applied time.Time, target applyTarget) {
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
		if target == appliedByForegroundRun && errors.Is(err, launcher.ErrUnavailable) {
			fmt.Fprintf(w, "  the foreground run shows the devices' states in its terminal\n")
			return
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
		fmt.Fprintf(w, "  the run has not applied it yet; check with: localport status\n")
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
		case row.State == status.StateParked && row.Since.Before(applied):
			// up retries a parked device; until then the row is the old refusal.
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

// applyTarget is the run that applied a config change.
type applyTarget int

const (
	appliedNowhere applyTarget = iota // applies at the devices' next start
	appliedByService
	appliedByForegroundRun
)

// requestReload is launcher.RequestReload; tests replace it.
var requestReload = launcher.RequestReload

// applyConfig makes the run serving the system devices apply a config change.
// A foreground run is asked through its control endpoint first, so a stopped
// service is never started beside it; one that holds run.lock but has not yet
// read the config reads the change with it, so it applies when the run starts
// serving (launcher.ErrRunStarting). Otherwise the installed device service
// is reloaded; a stopped one is started when start is set (up) and otherwise
// left to apply the change when it starts. It prints what it did and returns
// the run that applies the change now.
func applyConfig(start bool) (applyTarget, error) {
	switch err := requestReload(context.Background()); {
	case err == nil:
		fmt.Fprintf(os.Stderr, "  reloaded the foreground run\n")
		return appliedByForegroundRun, nil
	case errors.Is(err, launcher.ErrRunStarting):
		fmt.Fprintf(os.Stderr, "  saved; the foreground run applies it when it starts\n")
		return appliedNowhere, nil
	case errors.Is(err, launcher.ErrControlUntrusted):
		return appliedNowhere, errcode.WithRemedy(errcode.New(errcode.SettingsNotApplied).With(err, "ask the foreground run to reload"),
			"a foreground run's control endpoint is root's (SYSTEM and Administrators' on Windows) and closed to everyone else; find what created this one and remove it")
	case !errors.Is(err, launcher.ErrNoForegroundRun):
		return appliedNowhere, errcode.WithRemedy(errcode.New(errcode.SettingsNotApplied).With(err, "ask the foreground run to reload"),
			"stop the foreground run and start it again")
	}
	m, installed, err := installedDeviceService()
	if err != nil {
		return appliedNowhere, err
	}
	if !installed {
		fmt.Fprintf(os.Stderr, "  no device service is installed and no foreground run serves the devices; it applies when they next run (install the service with: %s)\n", serviceInstallCommand)
		return appliedNowhere, nil
	}
	pid, err := m.MainPID(context.Background())
	if err != nil {
		return appliedNowhere, err
	}
	switch {
	case pid == 0 && !start:
		fmt.Fprintf(os.Stderr, "  the device service is not running; it applies this when it starts\n")
		return appliedNowhere, nil
	case pid == 0:
		if err := m.Restart(context.Background()); err != nil {
			return appliedNowhere, notApplied(err)
		}
		fmt.Fprintf(os.Stderr, "  started the device service\n")
		return appliedByService, nil
	}
	if err := m.Reload(context.Background()); err != nil {
		return appliedNowhere, notApplied(err)
	}
	fmt.Fprintf(os.Stderr, "  reloaded the device service\n")
	return appliedByService, nil
}

// notApplied is a service start or reload that failed after the config was saved.
func notApplied(err error) error {
	return errcode.WithRemedy(errcode.New(errcode.SettingsNotApplied).With(err, ""), "apply them with: "+serviceInstallCommand)
}

// setPaused writes paused on the selected devices under the local config's
// lock, which also covers reading the store facts, so a concurrent `up
// <join-token>` cannot be pruned by a tombstone read before its enrolment. It
// drops entries of removed devices. A choice asked in the terminal is made
// with no lock held, then applied to the config as read again under the lock
// (pauseLocked), so a prompt left open never blocks up, set or a purge. It
// returns the devices it changed and the selected ones already in that state.
func setPaused(file config.LocalConfigFile, who invoker, selector string, all, pause bool) (changed, unchanged []identity.Ref, err error) {
	command := "up"
	if pause {
		command = "down"
	}
	// chosen is the terminal's choice, asked with no lock held; the write
	// then applies it to the config as read again under the lock.
	var chosen []identity.Ref
	for {
		changed, unchanged, err = pauseLocked(file, who, selector, all, pause, command, chosen)
		var ask *choiceNeeded
		if !errors.As(err, &ask) {
			return changed, unchanged, err
		}
		idx, err := askDevices(ask.devices, ask.facts)
		if err != nil {
			// Removed devices' entries go even when no device was chosen, as
			// every other refused selection drops them.
			_, _, pruneErr := pauseLocked(file, who, selector, all, pause, command, []identity.Ref{})
			return nil, nil, errors.Join(err, pruneErr)
		}
		chosen = make([]identity.Ref, 0, len(idx))
		for _, i := range idx {
			chosen = append(chosen, ask.devices[i].Identity)
		}
	}
}

// askDevices asks the terminal which devices to act on; tests replace it.
var askDevices = func(devices []config.LocalDevice, facts map[identity.Ref]deviceFact) ([]int, error) {
	return chooseDevices(os.Stdin, os.Stderr, devices, facts)
}

// choiceNeeded carries what pauseLocked read for the terminal's choice.
type choiceNeeded struct {
	devices []config.LocalDevice
	facts   map[identity.Ref]deviceFact
}

func (*choiceNeeded) Error() string { return errChoiceNeeded.Error() }

// pauseLocked is one pass of setPaused under the config's lock: with chosen
// set it acts on those devices, a chosen one gone since the choice being
// DeviceNotFound; otherwise on selectDevices' answer, returning choiceNeeded
// when the terminal must choose.
func pauseLocked(file config.LocalConfigFile, who invoker, selector string, all, pause bool, command string, chosen []identity.Ref) (changed, unchanged []identity.Ref, err error) {
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
	var idx []int
	if chosen != nil {
		idx, err = indexesOf(local.Devices, chosen)
	} else {
		idx, err = selectDevices(local.Devices, selector, all, command)
	}
	if errors.Is(err, errChoiceNeeded) {
		// The pruned entries are written by the pass after the choice.
		return nil, nil, &choiceNeeded{devices: local.Devices, facts: facts}
	}
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

// indexesOf returns the index in devices of each of refs; one no longer
// there is DeviceNotFound.
func indexesOf(devices []config.LocalDevice, refs []identity.Ref) ([]int, error) {
	idx := make([]int, 0, len(refs))
	for _, ref := range refs {
		i := slices.IndexFunc(devices, func(d config.LocalDevice) bool { return d.Identity == ref })
		if i < 0 {
			return nil, errcode.New(errcode.DeviceNotFound).With(nil, fmt.Sprintf("%s left the local config while it was chosen", ref))
		}
		idx = append(idx, i)
	}
	return idx, nil
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
	facts := make([]deviceFact, 0, len(local.Devices))
	for _, d := range local.Devices {
		facts = append(facts, storeFact(store, d.Identity))
	}
	return writeDeviceFacts(w, facts)
}

// writeDeviceFacts writes one JSON line per fact. HTML characters stay
// unescaped, so a line's size is bounded by its strings' bounds.
func writeDeviceFacts(w io.Writer, facts []deviceFact) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, f := range facts {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	return nil
}

// Bounds on a fact's strings, which the control plane sets, so the output of a
// full config (config.MaxDevices) fits maxDeviceFacts.
const (
	maxHostName    = 253 // a DNS name
	maxTeamDisplay = 128
)

// validHostName reports whether host is at most maxHostName bytes of DNS name
// characters, which JSON writes unescaped.
func validHostName(host string) bool {
	if host == "" || len(host) > maxHostName {
		return false
	}
	for i := range len(host) {
		switch c := host[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

// truncateDisplay cuts s to at most n bytes on a rune boundary, marking a cut
// with an ellipsis.
func truncateDisplay(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// storeFact reads ref's fact from store. A tombstone counts only when the
// credential is gone: a re-enrolled device runs its credential.
func storeFact(store *identity.Store, ref identity.Ref) deviceFact {
	f := deviceFact{Version: deviceFactsVersion, Ref: ref.String()}
	m, err := store.Load(ref)
	if err == nil {
		if m.Meta.Device != nil && validHostName(m.Meta.Device.Host) {
			f.Host = m.Meta.Device.Host
		}
		team := security.SanitizeDisplay(strings.ToValidUTF8(m.Meta.DisplayTeam(), ""))
		f.Team = truncateDisplay(team, maxTeamDisplay)
		return f
	}
	if _, statErr := os.Stat(store.Dir(ref)); errors.Is(statErr, os.ErrNotExist) {
		if ts, err := store.ReadTombstone(ref); err == nil && ts != nil {
			f.Removed = ts.Code
		}
	}
	return f
}

// runDevicesStorePart is runAsAgentAccount for the devices store part, replaced in tests.
var runDevicesStorePart = runAsAgentAccount

// readFacts is readDeviceFacts; tests replace it to observe the lock held.
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
	runErr := runDevicesStorePart([]string{"devices"}, nil, out)
	// Over the cap the child dies on its next write, so the overflow, not its
	// exit status, says what failed.
	if out.overflowed {
		return nil, errcode.New(errcode.AgentChildOutput).With(errOutputTooLarge, "read the enrolled devices")
	}
	if runErr != nil {
		return nil, runErr
	}
	parsed, err := decodeDeviceFacts(out.Bytes())
	if err != nil {
		return nil, errcode.New(errcode.AgentChildOutput).With(err, "read the enrolled devices")
	}
	for _, d := range devices {
		if f, ok := parsed[d.Identity]; ok {
			facts[d.Identity] = f
		}
	}
	return facts, nil
}

// decodeDeviceFacts decodes the devices child's lines strictly: unknown
// fields, data after the object, another version, an invalid ref or an
// unexpected removal code refuse the whole output.
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
		if _, err := dec.Token(); err != io.EOF {
			return nil, errors.New("device facts: data after the object on a line")
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

// cappedBuffer collects writes and refuses one past max, recording that it
// did. It wraps rather than embeds bytes.Buffer, so no promoted WriteString or
// ReadFrom bypasses the cap.
type cappedBuffer struct {
	buf        bytes.Buffer
	max        int
	overflowed bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.max {
		b.overflowed = true
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
	fmt.Fprintf(os.Stderr, `Usage: %[4]s %[1]s [<device> | --all]%[5]s

  %[2]s an enrolled device and apply it at once: a localport run or up
  --foreground in a terminal reloads, else the running device service does.
  up starts a stopped service; down leaves it to apply the pause when it
  starts.
  %[3]s
  With one device enrolled, it acts on that one. With several, name it by
  its identity, <team>/<prefix>, or a unique prefix; in a terminal with no
  argument, it asks which.

Flags:
`, command, verb, detail, elevatedLocalport(), elevatedNote())
	fs.PrintDefaults()
}
