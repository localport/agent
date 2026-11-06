//go:build windows

// Package sessionhelper is `localport-session helper`: one SYSTEM process
// per session that the launcher starts with its control channel on standard
// input and output. It opens the agent's session channel pipe, logs the
// login on (S4U, or LogonUser when the request carries a password), loads
// the login's profile, and starts cmd.exe as the login with the login's
// environment and the client's LANG and LC_* (exec_windows.go): a terminal,
// or an exec with a terminal, in a pseudoconsole; an exec without one on
// pipes in a kill-on-close job. It relays the session over the channel's
// frames. Every process of the session ends when the pseudoconsole or the
// job closes.
package sessionhelper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/security"
)

// helperPrivileges are the launcher service's required privileges the
// helper uses: S4U registration, assigning the primary token, quotas, and
// loading the profile hive.
var helperPrivileges = []string{"SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeBackupPrivilege", "SeRestorePrivilege"}

// channelOpenTimeout bounds opening the agent's session channel pipe.
const channelOpenTimeout = 5 * time.Second

// Run serves one session and returns the helper's exit status: 0 after a
// session ran, 1 when it did not start.
func Run(log func(string, ...any)) int {
	req, err := launcher.ReadHelperRequest(os.Stdin)
	if err != nil {
		log("sessionhelper: read the request: %v", err)
		return 1
	}
	defer clear(req.Password)
	refuse := func(code string, err error) int {
		log("sessionhelper: %s for %q: %v", code, req.Login, err)
		_ = launcher.WriteHelperReply(os.Stdout, launcher.HelperReply{Refused: code})
		return 1
	}
	if req.Kind != launcher.KindTerminal && req.Kind != launcher.KindExec && req.Kind != launcher.KindSFTP && req.Kind != launcher.KindForward {
		return refuse(launcher.CodeUnsupportedKind, errors.New(req.Kind))
	}
	if err := enablePrivileges(helperPrivileges...); err != nil {
		return refuse(launcher.CodeInternal, err)
	}
	agent, err := windows.StringToSid(security.ServiceSID(security.WindowsServiceName))
	if err != nil {
		return refuse(launcher.CodeInternal, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), channelOpenTimeout)
	channel, err := launcher.OpenSessionChannel(ctx, req.Pipe, agent)
	cancel()
	if err != nil {
		return refuse(launcher.CodeBadRequest, err)
	}
	defer channel.Close()

	l, err := parseLogin(req.Login)
	if err != nil {
		return refuse(launcher.CodeAccountUnavailable, err)
	}
	var token windows.Token
	if len(req.Password) > 0 {
		token, err = passwordLogonToken(l, req.Password)
	} else {
		token, err = s4uLogonToken(l)
	}
	if err != nil {
		if errors.Is(err, errAccount) {
			return refuse(launcher.CodeAccountRefused, err)
		}
		return refuse(launcher.CodeInternal, err)
	}
	defer token.Close()
	unload, err := loadProfile(token, l.User)
	if err != nil {
		return refuse(launcher.CodeSpawnFailed, err)
	}
	defer unload()

	shell, err := shellPath()
	if err != nil {
		return refuse(launcher.CodeSpawnFailed, err)
	}
	env, err := environment(token, req.Env)
	if err != nil {
		return refuse(launcher.CodeSpawnFailed, err)
	}
	// A terminal, and an exec with a terminal, run in a pseudoconsole; an
	// exec without one, the file server and the forward server run on pipes.
	app, cmdLine := shell, commandLine(shell, req.Command)
	switch req.Kind {
	case launcher.KindSFTP:
		if app, cmdLine, err = filesServerCommand(token, req.Root, FilesAccess{Download: req.FilesDownload, Upload: req.FilesUpload}); err != nil {
			return refuse(launcher.CodeSpawnFailed, err)
		}
	case launcher.KindForward:
		if app, cmdLine, err = forwardServerCommand(); err != nil {
			return refuse(launcher.CodeSpawnFailed, err)
		}
	}
	if req.Kind == launcher.KindSFTP || req.Kind == launcher.KindForward || (req.Kind == launcher.KindExec && req.Cols == 0) {
		p, err := startPiped(token, app, cmdLine, env, req.Kind == launcher.KindSFTP)
		if err != nil {
			return refuse(launcher.CodeSpawnFailed, err)
		}
		if err := launcher.WriteHelperReply(os.Stdout, launcher.HelperReply{Started: true}); err != nil {
			log("sessionhelper: reply started: %v", err)
			p.close()
		}
		_ = os.Stdout.Close()
		p.relay(channel, log)
		return 0
	}
	k, err := startConsole(token, uint16(req.Cols), uint16(req.Rows), shell, cmdLine, env)
	if err != nil {
		return refuse(launcher.CodeSpawnFailed, err)
	}
	if err := launcher.WriteHelperReply(os.Stdout, launcher.HelperReply{Started: true}); err != nil {
		log("sessionhelper: reply started: %v", err)
		k.close()
	}
	_ = os.Stdout.Close()
	k.relay(channel, log)
	return 0
}

// console is a shell attached to a pseudoconsole. The helper holds the
// shell by its process handle, so the exit code is never another process's.
type console struct {
	process windows.Handle
	input   *os.File
	output  *os.File

	// mu guards pc against a resize racing its close: pc is never used once
	// closed is set.
	mu     sync.Mutex
	pc     windows.Handle
	closed bool
}

// startConsole starts cmdLine of shell (%SystemRoot%\System32\cmd.exe) as
// token's user in a new pseudoconsole of cols by rows, in the user's profile
// directory with env (environment).
func startConsole(token windows.Token, cols, rows uint16, shell, cmdLine string, env []uint16) (*console, error) {
	var inRead, inWrite, outRead, outWrite windows.Handle
	if err := windows.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		return nil, fmt.Errorf("console input pipe: %w", err)
	}
	if err := windows.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		windows.CloseHandle(inRead)
		windows.CloseHandle(inWrite)
		return nil, fmt.Errorf("console output pipe: %w", err)
	}
	// The pseudoconsole holds its own references to its ends; ours close
	// once the shell started, so EOF follows its close.
	defer windows.CloseHandle(inRead)
	defer windows.CloseHandle(outWrite)
	k := &console{input: os.NewFile(uintptr(inWrite), "console-input"), output: os.NewFile(uintptr(outRead), "console-output")}
	if err := windows.CreatePseudoConsole(windows.Coord{X: int16(cols), Y: int16(rows)}, inRead, outWrite, 0, &k.pc); err != nil {
		k.input.Close()
		k.output.Close()
		return nil, fmt.Errorf("CreatePseudoConsole: %w", err)
	}
	if err := k.spawn(token, shell, cmdLine, env); err != nil {
		windows.ClosePseudoConsole(k.pc)
		k.input.Close()
		k.output.Close()
		return nil, err
	}
	return k, nil
}

func (k *console) spawn(token windows.Token, shell, cmdLine string, env []uint16) error {
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return err
	}
	defer attrs.Delete()
	// The attribute's value is the HPCON itself, not a pointer to it.
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, *(*unsafe.Pointer)(unsafe.Pointer(&k.pc)), unsafe.Sizeof(k.pc)); err != nil {
		return fmt.Errorf("pseudoconsole attribute: %w", err)
	}
	dir, err := token.GetUserProfileDirectory()
	if err != nil {
		return fmt.Errorf("profile directory: %w", err)
	}
	app, err := windows.UTF16PtrFromString(shell)
	if err != nil {
		return err
	}
	line, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return err
	}
	wd, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	// An empty desktop connects the shell to a window station of its own
	// logon session; inheriting the helper's (the SYSTEM service desktop)
	// would deny the user and fail the start.
	desktop, err := windows.UTF16PtrFromString("")
	if err != nil {
		return err
	}
	si := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(si))
	si.StartupInfo.Desktop = desktop
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, app, line, nil, nil, false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT, &env[0], wd, &si.StartupInfo, &pi); err != nil {
		return fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	k.process = pi.Process
	return nil
}

// close ends the pseudoconsole, which ends every process attached to it.
// The output reader keeps draining meanwhile, as ClosePseudoConsole needs.
func (k *console) close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return
	}
	k.closed = true
	windows.ClosePseudoConsole(k.pc)
	_ = k.input.Close()
}

// resize resizes the pseudoconsole unless it is closed.
func (k *console) resize(cols, rows uint16) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.closed {
		_ = windows.ResizePseudoConsole(k.pc, windows.Coord{X: int16(cols), Y: int16(rows)})
	}
}

// relay serves the channel until the shell exits or the agent ends the
// channel, then writes the exit frame.
func (k *console) relay(channel *os.File, log func(string, ...any)) {
	defer windows.CloseHandle(k.process)
	var wmu sync.Mutex
	write := func(f launcher.Frame) error {
		wmu.Lock()
		defer wmu.Unlock()
		return launcher.WriteFrame(channel, f)
	}
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		buf := make([]byte, launcher.MaxFrameData)
		failed := false
		for {
			n, err := k.output.Read(buf)
			if n > 0 && !failed {
				failed = write(launcher.Frame{Type: launcher.FrameData, Data: buf[:n]}) != nil
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		fr := launcher.NewFrameReader(channel)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				break
			}
			switch f.Type {
			case launcher.FrameData:
				if _, err := k.input.Write(f.Data); err != nil {
					log("sessionhelper: input: %v", err)
				}
			case launcher.FrameResize:
				k.resize(f.Cols, f.Rows)
			}
		}
		// The agent ended the channel: end the session.
		k.close()
	}()
	_, _ = windows.WaitForSingleObject(k.process, windows.INFINITE)
	k.close()
	<-outputDone
	_ = k.output.Close()
	var code uint32
	if err := windows.GetExitCodeProcess(k.process, &code); err != nil {
		code = 1
	}
	_ = write(launcher.Frame{Type: launcher.FrameExit, Code: int32(code)})
}
