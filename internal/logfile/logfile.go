//go:build linux || darwin

// Package logfile is a service process's own log file, rotated in process:
// stdout and stderr point at the current file, a timer checks its size, and
// past MaxSize the file is renamed through MaxBackups numbered copies and a
// new one takes its place on both descriptors. launchd and OpenRC open a
// service's output file once, so only the process itself can rotate it.
package logfile

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	// MaxSize is the size past which the file rotates.
	MaxSize = 10 << 20
	// MaxBackups is how many rotated copies are kept: path.1 (newest) to
	// path.MaxBackups.
	MaxBackups = 5
	// checkInterval is how often the size is checked.
	checkInterval = time.Minute
)

// File is the open log file behind stdout and stderr.
type File struct {
	path string
	max  int64
	keep int

	mu sync.Mutex
	f  *os.File
}

// Open opens path for appending (created 0600) and points stdout and stderr
// at it.
func Open(path string) (*File, error) {
	l := &File{path: path, max: MaxSize, keep: MaxBackups}
	if err := l.reopen(); err != nil {
		return nil, err
	}
	return l, nil
}

// Run checks the file's size every minute and rotates it past MaxSize,
// until ctx ends. A failed rotation is written to the current file and
// retried at the next check.
func (l *File) Run(ctx context.Context) {
	t := time.NewTicker(checkInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.RotateIfLarge(); err != nil {
				fmt.Fprintf(os.Stderr, "logfile: rotate %s: %v\n", l.path, err)
			}
		}
	}
}

// RotateIfLarge rotates the file when it is past its size cap.
func (l *File) RotateIfLarge() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	fi, err := l.f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() < l.max {
		return nil
	}
	for i := l.keep - 1; i >= 1; i-- {
		err := os.Rename(l.path+"."+strconv.Itoa(i), l.path+"."+strconv.Itoa(i+1))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return err
	}
	return l.reopenLocked()
}

func (l *File) reopen() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.reopenLocked()
}

// reopenLocked opens a fresh file at path and moves stdout and stderr to it.
// The previous file closes after the move, so no write is lost.
func (l *File) reopenLocked() error {
	if fi, err := os.Lstat(l.path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", l.path)
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	for _, fd := range []int{1, 2} {
		if err := dupOnto(int(f.Fd()), fd); err != nil {
			f.Close()
			return fmt.Errorf("point descriptor %d at %s: %w", fd, l.path, err)
		}
	}
	if l.f != nil {
		_ = l.f.Close()
	}
	l.f = f
	return nil
}
