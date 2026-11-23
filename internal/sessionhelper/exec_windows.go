//go:build windows

package sessionhelper

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/launcher"
)

// shellPath is %SystemRoot%\System32\cmd.exe, the shell of every session.
func shellPath() (string, error) {
	sysRoot, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(sysRoot, "System32", "cmd.exe"), nil
}

// commandLine is the shell's command line: the shell alone for a login shell
// (command ""), else `"<shell>" /c "<command>"`, the form Win32-OpenSSH uses
// for cmd.exe (contrib/win32/win32compat/w32-doexec.c).
func commandLine(shell, command string) string {
	if command == "" {
		return `"` + shell + `"`
	}
	return `"` + shell + `" /c "` + command + `"`
}

// filesServerCommand is the file server command run as the login:
// `"<exe>" files-server <access> "<root>" "<home>"`. root is files_root or
// empty; home is empty with a root, else the profile directory, which must be
// a directory. startPiped appends the event pipe's handle. view is the
// session's view (filesView); with a root the profile directory sets only
// view.Home, omitted when unreadable.
func filesServerCommand(token windows.Token, root string, access FilesAccess) (app, cmdLine string, view launcher.Started, err error) {
	if app, err = os.Executable(); err != nil {
		return "", "", view, err
	}
	profile, perr := token.GetUserProfileDirectory()
	if perr != nil && root == "" {
		return "", "", view, fmt.Errorf("profile directory: %w", perr)
	}
	home, err := filesHome(root, profile)
	if err != nil {
		return "", "", view, fmt.Errorf("profile directory: %w", err)
	}
	if perr == nil {
		view = filesView(root, profile, false)
	} else {
		view.Confined = true
	}
	return app, syscall.EscapeArg(app) + " " + FilesServerMode + " " + access.Arg() + " " + syscall.EscapeArg(root) + " " + syscall.EscapeArg(home), view, nil
}

// environment is the login's environment block (CreateEnvironmentBlock) with
// SSH_CLIENT and SSH_CONNECTION for clientAddr and the client's LANG and LC_*
// variables set over it, as Win32-OpenSSH sets them, as a UTF-16 block ready
// for CreateProcessAsUser with CREATE_UNICODE_ENVIRONMENT. Names compare
// case-insensitively, as Windows compares them.
func environment(token windows.Token, clientAddr string, client map[string]string) ([]uint16, error) {
	var block *uint16
	if err := windows.CreateEnvironmentBlock(&block, token, false); err != nil {
		return nil, fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer func() { _ = windows.DestroyEnvironmentBlock(block) }()
	return mergeEnvironment(environmentStrings(block), launcher.OriginEnv(clientAddr), client), nil
}

// environmentStrings splits a NUL-separated, double-NUL-terminated block.
func environmentStrings(block *uint16) []string {
	var out []string
	for p := unsafe.Pointer(block); ; {
		s := windows.UTF16PtrToString((*uint16)(p))
		if s == "" {
			return out
		}
		out = append(out, s)
		p = unsafe.Add(p, (len(utf16.Encode([]rune(s)))+1)*2)
	}
}

// mergeEnvironment sets each origin KEY=VALUE (launcher.OriginEnv), then
// each client variable, over env and encodes the block.
func mergeEnvironment(env, origin []string, client map[string]string) []uint16 {
	vars := make([][2]string, 0, len(origin)+len(client))
	for _, kv := range origin {
		k, v, _ := strings.Cut(kv, "=")
		vars = append(vars, [2]string{k, v})
	}
	for _, name := range slices.Sorted(maps.Keys(client)) {
		vars = append(vars, [2]string{name, client[name]})
	}
	for _, nv := range vars {
		name, value := nv[0], nv[1]
		replaced := false
		for i, kv := range env {
			if k, _, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, name) {
				env[i], replaced = name+"="+value, true
			}
		}
		if !replaced {
			env = append(env, name+"="+value)
		}
	}
	var block []uint16
	for _, kv := range env {
		block = append(block, utf16.Encode([]rune(kv))...)
		block = append(block, 0)
	}
	return append(block, 0)
}

// killOnCloseJob is a job object that ends every process in it when its
// handle closes: the helper's hold on an exec session's process tree.
func killOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return job, nil
}

// piped is a command on plain pipes: standard input, output and error apart,
// its process tree held by a kill-on-close job.
type piped struct {
	process windows.Handle
	job     windows.Handle
	stdin   *os.File
	stdout  *os.File
	stderr  *os.File
	// events is the read end of the file server's event pipe, nil otherwise.
	events *os.File

	closeOnce sync.Once
}

// startPiped starts cmdLine of app as token's user on pipes, in the user's
// profile directory with env. With withEvents the child also inherits the
// write end of an event pipe, whose handle value is appended to cmdLine (the
// file server's last argument). The child inherits exactly its pipe ends
// (PROC_THREAD_ATTRIBUTE_HANDLE_LIST) and starts suspended until it is in
// the job, so no process it starts escapes the job.
func startPiped(token windows.Token, app, cmdLine string, env []uint16, withEvents bool) (*piped, error) {
	n := 3
	if withEvents {
		n = 4
	}
	ends := make([][2]windows.Handle, n) // stdin, stdout, stderr, events: [read, write]
	closeAll := func() {
		for _, e := range ends {
			for _, h := range e {
				if h != 0 {
					_ = windows.CloseHandle(h)
				}
			}
		}
	}
	for i := range ends {
		if err := windows.CreatePipe(&ends[i][0], &ends[i][1], nil, 0); err != nil {
			closeAll()
			return nil, fmt.Errorf("exec pipe: %w", err)
		}
	}
	child := []windows.Handle{ends[0][0], ends[1][1], ends[2][1]}
	if withEvents {
		child = append(child, ends[3][1])
		cmdLine += " " + strconv.FormatUint(uint64(ends[3][1]), 10)
	}
	for _, h := range child {
		if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			closeAll()
			return nil, fmt.Errorf("exec pipe inheritance: %w", err)
		}
	}
	job, err := killOnCloseJob()
	if err != nil {
		closeAll()
		return nil, err
	}
	process, err := spawnInJob(token, job, app, cmdLine, env, [3]windows.Handle{child[0], child[1], child[2]}, child)
	// The child holds its own references to its ends; ours close now, so
	// EOF follows the child's exit.
	for _, h := range child {
		_ = windows.CloseHandle(h)
	}
	if err != nil {
		_ = windows.CloseHandle(ends[0][1])
		for _, e := range ends[1:] {
			_ = windows.CloseHandle(e[0])
		}
		_ = windows.CloseHandle(job)
		return nil, err
	}
	p := &piped{
		process: process, job: job,
		stdin:  os.NewFile(uintptr(ends[0][1]), "exec-stdin"),
		stdout: os.NewFile(uintptr(ends[1][0]), "exec-stdout"),
		stderr: os.NewFile(uintptr(ends[2][0]), "exec-stderr"),
	}
	if withEvents {
		p.events = os.NewFile(uintptr(ends[3][0]), "file-events")
	}
	return p, nil
}

// spawnInJob starts every process the helper runs: as token's user,
// suspended, assigned to job before its first instruction, then resumed, so
// no process it starts escapes the job. std are its standard handles and
// inherit exactly the handles it inherits (each inheritable, none twice).
func spawnInJob(token windows.Token, job windows.Handle, app, cmdLine string, env []uint16, std [3]windows.Handle, inherit []windows.Handle) (windows.Handle, error) {
	process, thread, err := spawnSuspended(token, app, cmdLine, env, std, inherit)
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(thread) }()
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		_ = windows.TerminateProcess(process, 1)
		_ = windows.CloseHandle(process)
		return 0, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	if _, err := windows.ResumeThread(thread); err != nil {
		_ = windows.TerminateProcess(process, 1)
		windows.CloseHandle(process)
		return 0, fmt.Errorf("ResumeThread: %w", err)
	}
	return process, nil
}

// spawnSuspended creates the suspended child for spawnInJob.
func spawnSuspended(token windows.Token, appPath, cmdLine string, env []uint16, std [3]windows.Handle, inherit []windows.Handle) (process, thread windows.Handle, err error) {
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return 0, 0, err
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherit[0]),
		uintptr(len(inherit))*unsafe.Sizeof(inherit[0])); err != nil {
		return 0, 0, fmt.Errorf("handle list attribute: %w", err)
	}
	dir, err := token.GetUserProfileDirectory()
	if err != nil {
		return 0, 0, fmt.Errorf("profile directory: %w", err)
	}
	app, err := windows.UTF16PtrFromString(appPath)
	if err != nil {
		return 0, 0, err
	}
	line, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return 0, 0, err
	}
	wd, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0, err
	}
	desktop, err := windows.UTF16PtrFromString("")
	if err != nil {
		return 0, 0, err
	}
	si := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop = desktop
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput, si.StdOutput, si.StdErr = std[0], std[1], std[2]
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, app, line, nil, nil, true,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		&env[0], wd, &si.StartupInfo, &pi); err != nil {
		return 0, 0, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	return pi.Process, pi.Thread, nil
}

// close ends the command's process tree.
func (p *piped) close() {
	p.closeOnce.Do(func() {
		windows.CloseHandle(p.job)
		_ = p.stdin.Close()
	})
}

// relay serves the channel until the command exits or the agent ends the
// channel: client data to standard input (eof closes it), standard output
// and error to data and stderr frames, then the exit frame.
func (p *piped) relay(channel *os.File, log func(string, ...any)) {
	defer windows.CloseHandle(p.process)
	var wmu sync.Mutex
	write := func(f launcher.Frame) error {
		wmu.Lock()
		defer wmu.Unlock()
		return launcher.WriteFrame(channel, f)
	}
	var drained sync.WaitGroup
	for _, s := range []struct {
		f    *os.File
		kind byte
	}{{p.stdout, launcher.FrameData}, {p.stderr, launcher.FrameStderr}} {
		drained.Go(func() {
			buf := make([]byte, launcher.MaxFrameData)
			failed := false
			for {
				n, err := s.f.Read(buf)
				if n > 0 && !failed {
					failed = write(launcher.Frame{Type: s.kind, Data: buf[:n]}) != nil
				}
				if err != nil {
					return
				}
			}
		})
	}
	if p.events != nil {
		// Each frame must be a valid file event from the file server, which
		// runs as the login; anything else ends the session.
		drained.Go(func() {
			fr := launcher.NewFrameReader(p.events)
			for {
				f, err := fr.ReadFrame()
				if err != nil {
					return
				}
				if _, err := launcher.ParseFileEvent(f.Data); err != nil || f.Type != launcher.FrameEvent {
					log("sessionhelper: bad file event: %v", err)
					p.close()
					return
				}
				if write(f) != nil {
					return
				}
			}
		})
	}
	go func() {
		fr := launcher.NewFrameReader(channel)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				break
			}
			switch f.Type {
			case launcher.FrameData:
				if _, err := p.stdin.Write(f.Data); err != nil {
					log("sessionhelper: exec input: %v", err)
				}
			case launcher.FrameEOF:
				_ = p.stdin.Close()
			}
		}
		// The agent ended the channel: end the command's process tree.
		p.close()
	}()
	_, _ = windows.WaitForSingleObject(p.process, windows.INFINITE)
	// The tree ends with the command, as a console session's does; a
	// background process still holding the pipes would otherwise keep the
	// output open after the exit.
	p.close()
	drained.Wait()
	_ = p.stdout.Close()
	_ = p.stderr.Close()
	if p.events != nil {
		_ = p.events.Close()
	}
	var code uint32
	if err := windows.GetExitCodeProcess(p.process, &code); err != nil {
		code = 1
	}
	_ = write(launcher.Frame{Type: launcher.FrameExit, Code: int32(code)})
}
