// Command zipdist writes a reproducible zip of files, each stored under its
// base name, so the release workflow on Windows and the packaging check on
// Linux produce the same archive from the same files.
//
//	go run ./scripts/release/zipdist <out.zip> <file>...
//
// Entries keep the given order, use deflate, and carry SOURCE_DATE_EPOCH
// (seconds, required) as their time; .exe files are marked executable.
package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "zipdist:", err)
		os.Exit(1)
	}
}

func run(args []string) (err error) {
	if len(args) < 2 {
		return errors.New("want the output zip and at least one file: zipdist <out.zip> <file> [<file>]")
	}
	epoch, err := strconv.ParseInt(os.Getenv("SOURCE_DATE_EPOCH"), 10, 64)
	if err != nil {
		return fmt.Errorf("SOURCE_DATE_EPOCH must be set to seconds: %w", err)
	}
	mtime := time.Unix(epoch, 0).UTC()
	out, err := os.Create(args[0])
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	zw := zip.NewWriter(out)
	for _, path := range args[1:] {
		if err := add(zw, path, mtime); err != nil {
			return err
		}
	}
	return zw.Close()
}

func add(zw *zip.Writer, path string, mtime time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := &zip.FileHeader{Name: filepath.Base(path), Method: zip.Deflate, Modified: mtime}
	mode := os.FileMode(0o644)
	if strings.HasSuffix(strings.ToLower(path), ".exe") {
		mode = 0o755
	}
	h.SetMode(mode)
	w, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}
