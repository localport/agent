package service

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Crash capture keeps the Go runtime's fatal error output (an unrecovered
// panic, a fatal runtime error) of a Windows service, which no log sees
// otherwise. Each service has its own directory; the runtime writes to
// current.crash there, and the next start keeps a non-empty one.
const (
	// crashFile is the file debug.SetCrashOutput writes to.
	crashFile = "current.crash"
	// crashTimeLayout names a kept crash by its UTC modification time; the
	// name is valid on Windows (no colons) and sorts by time.
	crashTimeLayout = "20060102T150405Z"
	// keptCrashes is how many kept crash files stay; older ones are removed.
	keptCrashes = 5
)

// captureCrashes runs at service start, before the service does any work. It
// checks dir with trusted and, when that refuses it, calls warn and leaves
// crash capture off. Otherwise it keeps a non-empty current.crash as
// <UTC mtime>.crash (with a -N suffix on a name already taken), removes all
// but the keptCrashes newest kept files, calls report once for the kept
// crash with its time, the service, the agent version and the file (never
// its text: the Application log is readable by every user), and arms crash
// output on a fresh, empty current.crash. A failing step calls warn and the
// service still runs.
func captureCrashes(dir, service, version string, trusted func(string) error, warn, report func(string)) {
	if err := trusted(dir); err != nil {
		warn(fmt.Sprintf("%s: crash capture is off: %v", service, err))
		return
	}
	kept, at, err := keepCrash(dir)
	if err != nil {
		warn(fmt.Sprintf("%s: keep the last crash: %v", service, err))
	} else if kept != "" {
		report(fmt.Sprintf("%s %s stopped on a fatal error at %s; its output is in %s",
			service, version, at.UTC().Format(time.RFC3339), kept))
	}
	if err := pruneCrashes(dir); err != nil {
		warn(fmt.Sprintf("%s: remove old crash files: %v", service, err))
	}
	if err := armCrashOutput(dir); err != nil {
		warn(fmt.Sprintf("%s: crash capture is off: %v", service, err))
	}
}

// keepCrash renames a non-empty current.crash to its kept name and returns
// that path and the crash time; "" when there was none.
func keepCrash(dir string) (string, time.Time, error) {
	current := filepath.Join(dir, crashFile)
	fi, err := os.Lstat(current)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", time.Time{}, nil
	case err != nil:
		return "", time.Time{}, err
	case !fi.Mode().IsRegular():
		return "", time.Time{}, fmt.Errorf("%s is not a regular file", current)
	case fi.Size() == 0:
		return "", time.Time{}, nil
	}
	base := fi.ModTime().UTC().Format(crashTimeLayout)
	for n := 0; ; n++ {
		name := base + ".crash"
		if n > 0 {
			name = base + "-" + strconv.Itoa(n) + ".crash"
		}
		kept := filepath.Join(dir, name)
		if _, err := os.Lstat(kept); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", time.Time{}, err
		}
		if err := os.Rename(current, kept); err != nil {
			return "", time.Time{}, err
		}
		return kept, fi.ModTime(), nil
	}
}

// pruneCrashes removes all but the keptCrashes newest kept crash files.
func pruneCrashes(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type kept struct {
		name string
		at   time.Time
	}
	var all []kept
	for _, e := range entries {
		if e.Name() == crashFile || !strings.HasSuffix(e.Name(), ".crash") || !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			return err
		}
		all = append(all, kept{e.Name(), fi.ModTime()})
	}
	slices.SortFunc(all, func(a, b kept) int {
		return cmp.Or(b.at.Compare(a.at), strings.Compare(b.name, a.name))
	})
	var errs []error
	for _, k := range all[min(keptCrashes, len(all)):] {
		errs = append(errs, os.Remove(filepath.Join(dir, k.name)))
	}
	return errors.Join(errs...)
}

// armCrashOutput opens an empty current.crash in dir and hands it to the
// runtime, which keeps its own duplicate of the handle.
func armCrashOutput(dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, crashFile), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return debug.SetCrashOutput(f, debug.CrashOptions{})
}
