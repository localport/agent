//go:build windows

// Package sessionhelper is `localport-session helper`: one SYSTEM process
// per session that the launcher starts with its control channel on standard
// input and output. It opens the agent's session channel pipe, logs the
// login on (S4U, or LogonUser when the request carries a password), loads
// the login's profile, and starts cmd.exe as the login with the login's
// environment and the client's LANG and LC_* (exec_windows.go): a terminal,
// or an exec with a terminal, under a headless console host run as the
// login; an exec without one on pipes. Every process it starts is suspended,
// put in a kill-on-close job, then resumed (spawnInJob). It relays the
// session over the channel's frames. Every process of the session ends when
// the job closes.
package sessionhelper

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

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
	// A first logon or a roaming profile can take minutes to load: the
	// launcher extends its start bound once on this message.
	if err := launcher.WriteHelperProgress(os.Stdout, launcher.ProgressProfile); err != nil {
		log("sessionhelper: report the profile load: %v", err)
	}
	unload, err := loadProfile(token, l.User)
	if err != nil {
		return refuse(launcher.CodeSpawnFailed, err)
	}
	defer unload()

	shell, err := shellPath()
	if err != nil {
		return refuse(launcher.CodeSpawnFailed, err)
	}
	env, err := environment(token, req.ClientAddr, req.Env)
	if err != nil {
		return refuse(launcher.CodeSpawnFailed, err)
	}
	// A terminal, and an exec with a terminal, run under the console host;
	// an exec without one, the file server and the forward server run on
	// pipes.
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
	k, err := startConsole(token, uint16(req.Cols), uint16(req.Rows), cmdLine, env)
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

// console is a shell under a headless console host (conhost.exe) that runs
// as the login, as Win32-OpenSSH runs it: no console host of the session
// runs as SYSTEM. The helper holds the console host by its process handle,
// so the exit code is never another process's, and the session's processes
// by a kill-on-close job.
type console struct {
	process windows.Handle
	job     windows.Handle
	input   *os.File
	output  *os.File

	// mu guards signal against a resize racing its close: signal is never
	// written once closed is set.
	mu     sync.Mutex
	signal *os.File
	closed bool
}

// consoleHostCommandLine runs cmdLine under conhost, cols by rows character
// cells, with its signal pipe's read end (inherited, by handle value).
func consoleHostCommandLine(conhost string, cols, rows uint16, signal windows.Handle, cmdLine string) string {
	return fmt.Sprintf("%s --headless --width %d --height %d --signal 0x%x -- %s", syscall.EscapeArg(conhost), cols, rows, uintptr(signal), cmdLine)
}

// resizeMessage is conhost's ResizeWindow signal: id 8, then columns and
// rows, each a little-endian u16, written in one WriteFile.
func resizeMessage(cols, rows uint16) []byte {
	b := make([]byte, 6)
	binary.LittleEndian.PutUint16(b[0:], 8)
	binary.LittleEndian.PutUint16(b[2:], cols)
	binary.LittleEndian.PutUint16(b[4:], rows)
	return b
}

// startConsole starts cmdLine (of %SystemRoot%\System32\cmd.exe) as token's
// user under a console host of cols by rows, in the user's profile directory
// with env (environment). The console host inherits exactly its input, its
// output (standard output and error) and its signal pipe.
func startConsole(token windows.Token, cols, rows uint16, cmdLine string, env []uint16) (*console, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	conhost := filepath.Join(sys, "conhost.exe")
	var ends [3][2]windows.Handle // input, output, signal: [read, write]
	closeAll := func() {
		for _, e := range ends {
			for _, h := range e {
				if h != 0 {
					windows.CloseHandle(h)
				}
			}
		}
	}
	for i := range ends {
		if err := windows.CreatePipe(&ends[i][0], &ends[i][1], nil, 0); err != nil {
			closeAll()
			return nil, fmt.Errorf("console pipe: %w", err)
		}
	}
	in, out, sig := ends[0][0], ends[1][1], ends[2][0]
	inherit := []windows.Handle{in, out, sig}
	for _, h := range inherit {
		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			closeAll()
			return nil, fmt.Errorf("console pipe inheritance: %w", err)
		}
	}
	job, err := killOnCloseJob()
	if err != nil {
		closeAll()
		return nil, err
	}
	process, err := spawnInJob(token, job, conhost, consoleHostCommandLine(conhost, cols, rows, sig, cmdLine), env,
		[3]windows.Handle{in, out, out}, inherit)
	// The console host holds its own references to its ends; ours close now,
	// so EOF follows its exit.
	for _, h := range inherit {
		windows.CloseHandle(h)
	}
	if err != nil {
		windows.CloseHandle(ends[0][1])
		windows.CloseHandle(ends[1][0])
		windows.CloseHandle(ends[2][1])
		windows.CloseHandle(job)
		return nil, err
	}
	return &console{
		process: process, job: job,
		input:  os.NewFile(uintptr(ends[0][1]), "console-input"),
		output: os.NewFile(uintptr(ends[1][0]), "console-output"),
		signal: os.NewFile(uintptr(ends[2][1]), "console-signal"),
	}, nil
}

// close ends the session: closing the job ends the console host and every
// process of the session; the signal pipe's close alone also ends conhost.
func (k *console) close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return
	}
	k.closed = true
	windows.CloseHandle(k.job)
	_ = k.signal.Close()
	_ = k.input.Close()
}

// resize sends conhost a ResizeWindow signal unless the console is closed.
func (k *console) resize(cols, rows uint16) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.closed {
		_, _ = k.signal.Write(resizeMessage(cols, rows))
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
