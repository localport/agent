package sessionhelper

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pkg/sftp"

	"github.com/localport/agent/internal/launcher"
)

// FilesServerMode is the localport-session mode that runs ServeFiles as the
// login over standard input and output:
// `files-server <access> <root> <home>` on Unix (event pipe on descriptor 3),
// `files-server <access> <root> <home> <handle>` on Windows (event pipe
// handle). access is FilesAccess.Arg; home is empty with a root.
const FilesServerMode = "files-server"

// FilesAccess is what an SFTP session may do beyond listing: read file
// contents (Download) and change the file system (Upload: create, write,
// setstat, rename, remove, mkdir, rmdir, symlink, link). Without Upload the
// server behaves as OpenSSH's sftp-server -R.
type FilesAccess struct {
	Download bool
	Upload   bool
}

// Arg is the FilesServerMode access argument: "none", "download", "upload"
// or "download,upload".
func (a FilesAccess) Arg() string {
	switch {
	case a.Download && a.Upload:
		return "download,upload"
	case a.Download:
		return "download"
	case a.Upload:
		return "upload"
	}
	return "none"
}

// ParseFilesAccess parses Arg output; any other value is refused.
func ParseFilesAccess(v string) (FilesAccess, bool) {
	for _, a := range []FilesAccess{{}, {Download: true}, {Upload: true}, {Download: true, Upload: true}} {
		if a.Arg() == v {
			return a, true
		}
	}
	return FilesAccess{}, false
}

// ServeFiles serves one SFTP session on rwc as the calling user until the
// client ends it. With root the client sees root as "/" (os.Root); without it,
// the real file system (on Windows a virtual "/" of drives), with relative
// paths starting at home, which must be a directory. Each logged operation,
// permission refusals included, writes a launcher.FileEvent to events; a
// malformed request writes none.
func ServeFiles(rwc io.ReadWriteCloser, root, home string, access FilesAccess, events io.Writer) error {
	s := &filesServer{access: access, events: events, start: "/"}
	if root != "" {
		r, err := os.OpenRoot(root)
		if err != nil {
			return err
		}
		defer r.Close()
		s.fs = rootFS{root: r}
	} else {
		start, err := startDir(home)
		if err != nil {
			return err
		}
		s.fs, s.start = osFS{}, start
	}
	return serveSFTP(rwc, s)
}

// serveSFTP runs the request server over s until the client ends the session.
func serveSFTP(rwc io.ReadWriteCloser, s *filesServer) error {
	err := sftp.NewRequestServer(rwc, sftp.Handlers{FileGet: s, FilePut: s, FileCmd: s, FileList: s}, sftp.WithStartDirectory(s.start)).Serve()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// filesServer implements the request server's handlers over fs.
type filesServer struct {
	fs filesFS
	// start is the client path relative paths resolve against.
	start  string
	access FilesAccess
	// mu serializes event frames; events is the helper's event pipe.
	mu     sync.Mutex
	events io.Writer
}

// emit writes one event, its names escaped and bounded by launcher.EventName so
// no file name keeps an operation out of the log. A broken event pipe drops it:
// the helper ends the channel when its pipe breaks.
func (s *filesServer) emit(ev launcher.FileEvent) {
	ev.Path, ev.Target = launcher.EventName(ev.Path), launcher.EventName(ev.Target)
	b, err := ev.Marshal()
	if err != nil {
		// Unreachable with escaped names; a programming error, not input.
		panic(fmt.Sprintf("files event %q: %v", ev.Op, err))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = launcher.WriteFrame(s.events, launcher.Frame{Type: launcher.FrameEvent, Data: b})
}

// result is the files log's result of err.
func result(err error) string {
	switch {
	case err == nil:
		return launcher.ResultOK
	case errors.Is(err, fs.ErrNotExist):
		return "no_such_file"
	case errors.Is(err, fs.ErrPermission):
		return "permission_denied"
	case errors.Is(err, fs.ErrExist):
		return "file_exists"
	}
	return "failure"
}

// openRegular opens name with flag, refusing anything but a regular file.
func (s *filesServer) openRegular(name string, flag int, perm fs.FileMode) (*os.File, error) {
	return s.openChecked(name, flag, perm, false)
}

// openChecked opens name with flag and refuses anything that is not a
// regular file, or with dir a directory. openNonblock keeps a FIFO from
// blocking the open, and checkOpened refuses what the platform cannot stat
// as a disk file.
func (s *filesServer) openChecked(name string, flag int, perm fs.FileMode, dir bool) (*os.File, error) {
	f, err := s.fs.OpenFile(name, flag|openNonblock, perm)
	if err != nil {
		return nil, err
	}
	if err := checkOpened(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if dir != fi.IsDir() || (!dir && !fi.Mode().IsRegular()) {
		_ = f.Close()
		// EACCES, which the request server answers SSH_FX_PERMISSION_DENIED.
		return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.EACCES}
	}
	// O_NONBLOCK has no effect on a regular file's or directory's reads.
	return f, nil
}

// StatVFS answers statvfs@openssh.com (`df` in sftp) for the file system
// holding the request's path: files_root's, or without one the path's own
// (on Windows the volume its data is on; the virtual top has none).
func (s *filesServer) StatVFS(r *sftp.Request) (*sftp.StatVFS, error) {
	return s.fs.StatVFS(r.Filepath)
}

// denied writes ev's event with a permission refusal and returns it as the
// EACCES path error the request server answers SSH_FX_PERMISSION_DENIED.
func (s *filesServer) denied(ev launcher.FileEvent) error {
	err := &fs.PathError{Op: ev.Op, Path: ev.Path, Err: syscall.EACCES}
	ev.Result = result(err)
	s.emit(ev)
	return err
}

// Fileread opens a file for reading.
func (s *filesServer) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if !s.access.Download {
		return nil, s.denied(launcher.FileEvent{Op: launcher.OpRead, Path: r.Filepath})
	}
	f, err := s.openRegular(r.Filepath, os.O_RDONLY, 0)
	if err != nil {
		s.emit(launcher.FileEvent{Op: launcher.OpRead, Path: r.Filepath, Result: result(err)})
		return nil, err
	}
	return &countedFile{File: f, s: s, op: launcher.OpRead, path: r.Filepath}, nil
}

// writeFlags maps a request's open flags; append is not passed to the OS:
// writes go to the offsets the client names (os.File.WriteAt refuses a file
// opened with O_APPEND), as OpenSSH's sftp-server does.
func writeFlags(r *sftp.Request, base int) int {
	pf := r.Pflags()
	flag := base
	if pf.Creat {
		flag |= os.O_CREATE
	}
	if pf.Trunc {
		flag |= os.O_TRUNC
	}
	if pf.Excl {
		flag |= os.O_EXCL
	}
	return flag
}

// createPerm is a new entry's mode: the client's permissions if sent, else
// 0666 or 0777, less the process umask.
func createPerm(r *sftp.Request, def fs.FileMode) fs.FileMode {
	if r.AttrFlags().Permissions {
		return r.Attributes().FileMode().Perm()
	}
	return def
}

// Filewrite opens a file for writing.
func (s *filesServer) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	return s.openWrite(r, os.O_WRONLY)
}

// OpenFile opens a file for reading and writing.
func (s *filesServer) OpenFile(r *sftp.Request) (sftp.WriterAtReaderAt, error) {
	return s.openWrite(r, os.O_RDWR)
}

func (s *filesServer) openWrite(r *sftp.Request, base int) (*countedFile, error) {
	// A read-write handle reads contents too, so it needs both directions.
	if !s.access.Upload || base == os.O_RDWR && !s.access.Download {
		return nil, s.denied(launcher.FileEvent{Op: launcher.OpWrite, Path: r.Filepath})
	}
	f, err := s.openRegular(r.Filepath, writeFlags(r, base), createPerm(r, 0o666))
	if err != nil {
		s.emit(launcher.FileEvent{Op: launcher.OpWrite, Path: r.Filepath, Result: result(err)})
		return nil, err
	}
	return &countedFile{File: f, s: s, op: launcher.OpWrite, path: r.Filepath}, nil
}

// countedFile counts the bytes read or written through one handle and
// writes its read or write event when the handle closes.
type countedFile struct {
	*os.File
	s     *filesServer
	op    string
	path  string
	bytes atomic.Int64
	once  sync.Once
}

func (c *countedFile) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.File.ReadAt(p, off)
	if c.op == launcher.OpRead {
		c.bytes.Add(int64(n))
	}
	return n, err
}

func (c *countedFile) WriteAt(p []byte, off int64) (int, error) {
	n, err := c.File.WriteAt(p, off)
	c.bytes.Add(int64(n))
	return n, err
}

func (c *countedFile) Close() error {
	err := c.File.Close()
	c.once.Do(func() {
		c.s.emit(launcher.FileEvent{Op: c.op, Path: c.path, Bytes: c.bytes.Load(), Result: result(err)})
	})
	return err
}

// Filecmd applies setstat, rename, rmdir, remove, mkdir, symlink and link,
// each needing Upload and writing its event.
func (s *filesServer) Filecmd(r *sftp.Request) error {
	ev := launcher.FileEvent{Path: r.Filepath}
	var apply func() error
	switch r.Method {
	case "Setstat":
		ev.Op = launcher.OpSetstat
		apply = func() error { return s.setstat(r) }
	case "Rename":
		ev.Op, ev.Target = launcher.OpRename, r.Target
		apply = func() error { return s.rename(r.Filepath, r.Target) }
	case "Rmdir":
		ev.Op = launcher.OpRmdir
		apply = func() error { return s.removeKind(r.Filepath, true) }
	case "Remove":
		ev.Op = launcher.OpRemove
		apply = func() error { return s.removeKind(r.Filepath, false) }
	case "Mkdir":
		ev.Op = launcher.OpMkdir
		apply = func() error { return s.fs.Mkdir(r.Filepath, createPerm(r, 0o777)) }
	case "Symlink":
		// Filepath is the link's target text, as the client sent it, Target
		// the link's path. An empty target creates nothing and has no event.
		if r.Filepath == "" {
			return sftp.ErrSSHFxBadMessage
		}
		ev.Op, ev.Path, ev.Target = launcher.OpSymlink, r.Target, r.Filepath
		apply = func() error { return s.fs.Symlink(r.Filepath, r.Target) }
	case "Link":
		ev.Op, ev.Target = launcher.OpLink, r.Target
		apply = func() error { return s.fs.Link(r.Filepath, r.Target) }
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
	if !s.access.Upload {
		return s.denied(ev)
	}
	err := apply()
	ev.Result = result(err)
	s.emit(ev)
	return err
}

// PosixRename renames over an existing target (posix-rename@openssh.com).
func (s *filesServer) PosixRename(r *sftp.Request) error {
	if !s.access.Upload {
		return s.denied(launcher.FileEvent{Op: launcher.OpRename, Path: r.Filepath, Target: r.Target})
	}
	err := s.fs.Rename(r.Filepath, r.Target)
	s.emit(launcher.FileEvent{Op: launcher.OpRename, Path: r.Filepath, Target: r.Target, Result: result(err)})
	return err
}

// rename is SFTP v3 rename, which never replaces the target: link then unlink
// for a regular file, as OpenSSH does, else a rename refusing an existing target.
func (s *filesServer) rename(from, to string) error {
	fi, err := s.fs.Lstat(from)
	if err != nil {
		return err
	}
	if fi.Mode().IsRegular() {
		if err := s.fs.Link(from, to); err == nil {
			return s.fs.Remove(from)
		} else if errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return s.fs.RenameNoReplace(from, to)
}

// removeKind removes a directory (dir) or anything else, refusing the other
// kind as the SFTP operations require.
func (s *filesServer) removeKind(name string, dir bool) error {
	fi, err := s.fs.Lstat(name)
	if err != nil {
		return err
	}
	if fi.IsDir() != dir {
		return &fs.PathError{Op: "remove", Path: name, Err: syscall.EINVAL}
	}
	return s.fs.Remove(name)
}

// setstat applies the attributes the request carries: size, permissions,
// owner and times.
func (s *filesServer) setstat(r *sftp.Request) error {
	name, flags, a := r.Filepath, r.AttrFlags(), r.Attributes()
	if flags.Size {
		f, err := s.openRegular(name, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		err = f.Truncate(int64(a.Size))
		if cErr := f.Close(); err == nil {
			err = cErr
		}
		if err != nil {
			return err
		}
	}
	if flags.Permissions {
		if err := s.fs.Chmod(name, a.FileMode().Perm()); err != nil {
			return err
		}
	}
	if flags.UidGid {
		if err := s.fs.Chown(name, int(a.UID), int(a.GID)); err != nil {
			return err
		}
	}
	if flags.Acmodtime {
		if err := s.fs.Chtimes(name, a.AccessTime(), a.ModTime()); err != nil {
			return err
		}
	}
	return nil
}

// Filelist answers List (a directory's entries, one event), Stat and Readlink.
func (s *filesServer) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	name := r.Filepath
	switch r.Method {
	case "List":
		entries, err := s.readDir(name)
		s.emit(launcher.FileEvent{Op: launcher.OpList, Path: r.Filepath, Result: result(err)})
		if err != nil {
			return nil, err
		}
		return listerAt(entries), nil
	case "Stat":
		fi, err := s.fs.Stat(name)
		if err != nil {
			return nil, err
		}
		return listerAt{fi}, nil
	case "Readlink":
		target, err := s.fs.Readlink(name)
		if err != nil {
			return nil, err
		}
		return listerAt{namedInfo(target)}, nil
	}
	return nil, sftp.ErrSSHFxOpUnsupported
}

// Lstat stats a name without following a final symlink.
func (s *filesServer) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	fi, err := s.fs.Lstat(r.Filepath)
	if err != nil {
		return nil, err
	}
	return listerAt{fi}, nil
}

// RealPath cleans a client path, a relative one against the start
// directory, as the request server resolves request paths; "." is the start
// directory. It does not resolve symlinks.
func (s *filesServer) RealPath(p string) (string, error) {
	p = filepath.ToSlash(filepath.Clean(p))
	if !path.IsAbs(p) {
		p = path.Join(s.start, p)
	}
	return osClientName(p), nil
}

func (s *filesServer) readDir(name string) ([]fs.FileInfo, error) {
	if entries, ok, err := s.fs.virtualDir(name); ok {
		return entries, err
	}
	d, err := s.openChecked(name, os.O_RDONLY, 0, true)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]fs.FileInfo, 0, len(entries))
	for _, e := range entries {
		if fi, err := e.Info(); err == nil {
			out = append(out, fi)
		}
	}
	return out, nil
}

// listerAt serves a fixed list of entries.
type listerAt []fs.FileInfo

func (l listerAt) ListAt(out []fs.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(out, l[off:])
	if off+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

// namedInfo is the entry of a Readlink answer, which carries only a name.
type namedInfo string

func (n namedInfo) Name() string     { return string(n) }
func (namedInfo) Size() int64        { return 0 }
func (namedInfo) Mode() fs.FileMode  { return 0 }
func (namedInfo) ModTime() time.Time { return time.Time{} }
func (namedInfo) IsDir() bool        { return false }
func (namedInfo) Sys() any           { return nil }
