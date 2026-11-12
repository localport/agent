package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/localport/agent/internal/security"
)

// ServiceSnapshot is one owned service's full definition and run state as
// the install transaction found it, so a rollback writes it back exactly.
// Existed false means there was no service under Name.
type ServiceSnapshot struct {
	Name            string               `json:"name"`
	Existed         bool                 `json:"existed"`
	Running         bool                 `json:"running"`
	Config          mgr.Config           `json:"config"`
	Privileges      []string             `json:"privileges"`
	Recovery        []mgr.RecoveryAction `json:"recovery"`
	ResetPeriod     uint32               `json:"reset_period"`
	RecoveryCommand string               `json:"recovery_command"`
	NonCrash        bool                 `json:"non_crash"`
}

// SnapshotOwned records the device and launcher services. A service under
// either name that localport did not create is refused (ErrForeignUnit).
func SnapshotOwned() ([]ServiceSnapshot, error) {
	var snaps []ServiceSnapshot
	for _, name := range ownedServiceNames {
		snap := ServiceSnapshot{Name: name}
		err := openService(name, func(_ *mgr.Mgr, s *mgr.Service) error {
			if s == nil {
				return nil
			}
			cfg, err := ownedService(name, s)
			if err != nil {
				return err
			}
			snap.Existed, snap.Config = true, cfg
			status, err := s.Query()
			if err != nil {
				return fmt.Errorf("query service %s: %w", name, err)
			}
			snap.Running = status.State != svc.Stopped && status.State != svc.StopPending
			if snap.Privileges, err = requiredPrivileges(s.Handle); err != nil {
				return fmt.Errorf("read required privileges of service %s: %w", name, err)
			}
			if snap.Recovery, err = s.RecoveryActions(); err != nil {
				return fmt.Errorf("read recovery of service %s: %w", name, err)
			}
			if snap.ResetPeriod, err = s.ResetPeriod(); err != nil {
				return fmt.Errorf("read recovery of service %s: %w", name, err)
			}
			if snap.RecoveryCommand, err = s.RecoveryCommand(); err != nil {
				return fmt.Errorf("read recovery of service %s: %w", name, err)
			}
			if snap.NonCrash, err = s.RecoveryActionsOnNonCrashFailures(); err != nil {
				return fmt.Errorf("read recovery of service %s: %w", name, err)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		snaps = append(snaps, snap)
	}
	return snaps, nil
}

// RestoreOwned writes the snapshot's definitions back and leaves every owned
// service stopped: a service that existed is created or rewritten to its
// recorded configuration, privileges, recovery and Event Log source; one
// that did not is stopped and deleted with its source. A service whose
// recorded program will not pass the device service binary rule (deleted,
// or replaceable by another account) is deleted instead of restored, since
// it would run that program as its account; removed names those services.
// programAt maps the recorded program to the file that will be at its path
// once the caller's rollback is done, "" when none will be. The caller
// starts the services that were running once their files are back.
func RestoreOwned(ctx context.Context, snaps []ServiceSnapshot, programAt func(string) string) (removed []string, err error) {
	var errs []error
	for _, snap := range snaps {
		gone, err := restoreOne(ctx, snap, programAt)
		if gone {
			removed = append(removed, snap.Name)
		}
		errs = append(errs, err)
	}
	return removed, errors.Join(errs...)
}

func restoreOne(ctx context.Context, snap ServiceSnapshot, programAt func(string) string) (removed bool, err error) {
	unsafeProgram := false
	if snap.Existed {
		program := programAt(programOf(snap.Config.BinaryPathName))
		unsafeProgram = program == "" || security.CheckServiceBinary(program) != nil
	}
	err = openService(snap.Name, func(m *mgr.Mgr, s *mgr.Service) error {
		if s != nil {
			if _, err := ownedService(snap.Name, s); err != nil {
				return err
			}
			if err := stop(ctx, snap.Name, scmService{s}); err != nil {
				return err
			}
		}
		if !snap.Existed || unsafeProgram {
			if s == nil {
				return nil
			}
			if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
				return fmt.Errorf("delete service %s: %w", snap.Name, err)
			}
			return removeEventSource(snap.Name)
		}
		if err := registerEventSource(snap.Name); err != nil {
			return err
		}
		if s == nil {
			// CreateService escapes its program argument, so it takes a
			// placeholder; UpdateConfig then writes the recorded command line.
			created, err := m.CreateService(snap.Name, `C:\`, snap.Config)
			if err != nil {
				return markedForDelete(fmt.Errorf("create service %s: %w", snap.Name, err))
			}
			defer created.Close()
			s = created
		}
		if err := s.UpdateConfig(snap.Config); err != nil {
			return markedForDelete(fmt.Errorf("restore service %s: %w", snap.Name, err))
		}
		if err := setRequiredPrivileges(s.Handle, snap.Privileges); err != nil {
			return fmt.Errorf("restore required privileges of service %s: %w", snap.Name, err)
		}
		if len(snap.Recovery) > 0 {
			if err := s.SetRecoveryActions(snap.Recovery, snap.ResetPeriod); err != nil {
				return fmt.Errorf("restore recovery of service %s: %w", snap.Name, err)
			}
		} else if err := s.ResetRecoveryActions(); err != nil {
			return fmt.Errorf("restore recovery of service %s: %w", snap.Name, err)
		}
		if err := s.SetRecoveryCommand(snap.RecoveryCommand); err != nil {
			return fmt.Errorf("restore recovery of service %s: %w", snap.Name, err)
		}
		if err := s.SetRecoveryActionsOnNonCrashFailures(snap.NonCrash); err != nil {
			return fmt.Errorf("restore recovery of service %s: %w", snap.Name, err)
		}
		return nil
	})
	return unsafeProgram && err == nil, err
}

// programOf is the program of a service command line this package wrote:
// the quoted first argument, or the text up to the first space.
func programOf(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if rest, ok := strings.CutPrefix(cmd, `"`); ok {
		program, _, _ := strings.Cut(rest, `"`)
		return program
	}
	program, _, _ := strings.Cut(cmd, " ")
	return program
}

// MarshalSnapshots and UnmarshalSnapshots carry snapshots in the install
// journal, which the platform-neutral transaction keeps opaque.
func MarshalSnapshots(snaps []ServiceSnapshot) (json.RawMessage, error) { return json.Marshal(snaps) }

func UnmarshalSnapshots(raw json.RawMessage) ([]ServiceSnapshot, error) {
	var snaps []ServiceSnapshot
	if err := json.Unmarshal(raw, &snaps); err != nil {
		return nil, fmt.Errorf("read the service snapshot: %w", err)
	}
	return snaps, nil
}

// requiredPrivileges reads the required privileges list of service h.
func requiredPrivileges(h windows.Handle) ([]string, error) {
	var need uint32
	err := windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, nil, 0, &need)
	if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, err
	}
	if need == 0 {
		return nil, nil
	}
	buf := make([]byte, need)
	if err := windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &buf[0], need, &need); err != nil {
		return nil, err
	}
	info := (*serviceRequiredPrivilegesInfo)(unsafe.Pointer(&buf[0]))
	return multiString(info.requiredPrivileges), nil
}

// multiString splits a REG_MULTI_SZ list ending in an empty string.
func multiString(p *uint16) []string {
	var out []string
	for p != nil {
		n := 0
		for *(*uint16)(unsafe.Add(unsafe.Pointer(p), n*2)) != 0 {
			n++
		}
		if n == 0 {
			return out
		}
		out = append(out, windows.UTF16ToString(unsafe.Slice(p, n)))
		p = (*uint16)(unsafe.Add(unsafe.Pointer(p), (n+1)*2))
	}
	return out
}
