//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/service"
)

// needsSystemLayout reports whether this process is root acting on the
// system config, which prepareSystemLayout readies.
func needsSystemLayout(file config.LocalConfigFile) bool { return needsAgentChild(file) }

// prepareSystemLayout readies the machine-wide state for the agent account,
// as root, before the agent service runs or a child touches the store: the
// account (service.EnsureAccount; on macOS a recreated account takes the ids
// that own an existing identity directory, so its credentials keep their
// owner), the device directory root:AgentGroup 0750 with run.lock
// root:AgentGroup 0660 (config.EnsureSystemRunLock) and the identity
// directory owned by the account with mode 0700. agent.yaml gets
// root:AgentGroup 0640 from config.WriteLocal. An unsafe account is refused
// before any file is written. It is idempotent.
func prepareSystemLayout(ctx context.Context, file config.LocalConfigFile) error {
	idDir := filepath.Join(filepath.Dir(file.Path), "identity")
	acct, err := service.EnsureAccount(ctx, idDir)
	if err != nil {
		return err
	}
	if err := config.EnsureSystemRunLock(file); err != nil {
		return err
	}
	return ensureIdentityDir(idDir, acct)
}

// ensureIdentityDir creates the identity directory owned by acct, mode
// 0700, or secures an existing one acct owns. An existing empty directory
// owned by root is given to acct. It refuses any other owner, a non-empty
// root-owned directory and a link.
func ensureIdentityDir(path string, acct service.Account) error {
	created := true
	if err := os.Mkdir(path, 0o700); errors.Is(err, fs.ErrExist) {
		created = false
	} else if err != nil {
		return errcode.New(errcode.CredentialStoreUnusable).With(err, "create "+path)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errcode.New(errcode.CredentialStoreUnusable).With(err, "open "+path)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return errcode.New(errcode.CredentialStoreUnusable).With(err, "inspect "+path)
	}
	if int(st.Uid) != acct.UID {
		// Root's directory is adopted when this call created it, or when it
		// is empty: a crash between Mkdir and Fchown leaves one behind.
		adopt := st.Uid == 0 && created
		if st.Uid == 0 && !created {
			if adopt, err = dirEmpty(fd, path); err != nil {
				return err
			}
		}
		if !adopt {
			return errcode.New(errcode.UntrustedPath).With(nil, fmt.Sprintf("%s is owned by uid %d, not the account %s; move it aside, then run the command again", path, st.Uid, service.AgentAccount))
		}
		if err := unix.Fchown(fd, acct.UID, acct.GID); err != nil {
			return errcode.New(errcode.CredentialStoreUnusable).With(err, "chown "+path)
		}
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return errcode.New(errcode.CredentialStoreUnusable).With(err, "secure "+path)
	}
	return nil
}

// dirEmpty reports whether the directory open as fd has no entries. It reads
// through a duplicate close-on-exec descriptor, so fd stays open for the
// caller and a concurrent exec does not inherit the copy.
func dirEmpty(fd int, path string) (bool, error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return false, errcode.New(errcode.CredentialStoreUnusable).With(err, "inspect "+path)
	}
	dir := os.NewFile(uintptr(dup), path)
	defer dir.Close()
	switch _, err := dir.Readdirnames(1); {
	case errors.Is(err, io.EOF):
		return true, nil
	case err != nil:
		return false, errcode.New(errcode.CredentialStoreUnusable).With(err, "inspect "+path)
	}
	return false, nil
}

// removeAgentDirs runs after `service uninstall --purge` emptied the store:
// when the identity directory holds nothing more it removes it and the
// agent's log directory logDir (service.AgentLogDir). While the directory
// still holds credentials (machine credentials from setup) both stay.
// identity.Store.PurgeDevices always deletes the credential lock directory
// and deletes the store lock too when no credential remains, so a kept
// directory keeps only the store lock. The
// account and its group always stay (service.AccountRemoval says why); the
// message names the commands that remove them.
func removeAgentDirs(file config.LocalConfigFile, logDir string) error {
	idDir := filepath.Join(filepath.Dir(file.Path), "identity")
	switch err := os.Remove(idDir); {
	case err == nil, errors.Is(err, fs.ErrNotExist):
	case errors.Is(err, syscall.ENOTEMPTY), errors.Is(err, syscall.EEXIST):
		fmt.Fprintf(os.Stderr, "  kept %s: it holds credentials that are not device credentials\n", idDir)
		return nil
	default:
		return errcode.New(errcode.StoreNotPurged).With(err, "remove "+idDir)
	}
	// Its parent, /var/log, is writable by root only; RemoveAll unlinks a
	// link instead of following it.
	if err := os.RemoveAll(logDir); err != nil {
		return errcode.New(errcode.StoreNotPurged).With(err, "remove "+logDir)
	}
	fmt.Fprintf(os.Stderr, "  %s\n", keptAccountNotice(service.AccountRemoval()))
	return nil
}

// keptAccountNotice tells the administrator that the account stays and how
// to remove it: usr and group are service.AccountRemoval's commands, nil
// where the host's package owns the account.
func keptAccountNotice(usr, group []string) string {
	if usr == nil {
		return fmt.Sprintf("kept the account %s: the package that created it owns it", service.AgentAccount)
	}
	return fmt.Sprintf("kept the account %s (it may own files elsewhere); to remove it: sudo %s, then sudo %s if the group remains",
		service.AgentAccount, strings.Join(usr, " "), strings.Join(group, " "))
}
