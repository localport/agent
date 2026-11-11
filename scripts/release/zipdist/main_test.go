package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The same files and SOURCE_DATE_EPOCH give the same bytes, with base names,
// the given order and the fixed time.
func TestZipIsReproducible(t *testing.T) {
	dir := t.TempDir()
	exe, notice := filepath.Join(dir, "localport.exe"), filepath.Join(dir, "NOTICE")
	if err := os.WriteFile(exe, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notice, []byte("notice"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "1762905600")
	var outs [][]byte
	for _, name := range []string{"a.zip", "b.zip"} {
		out := filepath.Join(dir, name)
		if err := run([]string{out, exe, notice}); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, raw)
	}
	if !bytes.Equal(outs[0], outs[1]) {
		t.Fatal("two runs differ")
	}
	r, err := zip.NewReader(bytes.NewReader(outs[0]), int64(len(outs[0])))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.File) != 2 || r.File[0].Name != "localport.exe" || r.File[1].Name != "NOTICE" ||
		r.File[0].Mode().Perm() != 0o755 || r.File[0].Modified.Unix() != 1762905600 {
		t.Fatalf("entries %+v", r.File)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "")
	if err := run([]string{filepath.Join(dir, "c.zip"), exe}); err == nil {
		t.Fatal("ran without SOURCE_DATE_EPOCH")
	}
}
