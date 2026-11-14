package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/localport/agent/internal/errcode"
)

func wantCode(t *testing.T, err error, code errcode.Code) {
	t.Helper()
	if !errors.Is(err, errcode.New(code)) {
		t.Fatalf("err = %v, want code %s", err, code)
	}
}

// A tunnel config failure is AG144 and shows the entry at fault.
func TestTunnelConfigFailuresAreCoded(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	wantCode(t, err, errcode.TunnelConfigInvalid)

	path := filepath.Join(t.TempDir(), "localport.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ntunnels:\n  - name: web\n    upstream: http://localhost:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Load(path)
	wantCode(t, err, errcode.TunnelConfigInvalid)
	if text, _ := errcode.Render(err); !strings.Contains(text, `tunnel "web": token is required`) {
		t.Fatalf("Render = %q, want the invalid entry named", text)
	}
}

// A local config that cannot be read is AG141 and keeps its fs cause.
func TestUnreadableLocalConfigIsCoded(t *testing.T) {
	f := testRunFile(t)
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := LoadLocal(f)
	wantCode(t, err, errcode.LocalConfigUnusable)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want the missing file still matchable", err)
	}
}
