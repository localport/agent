package connect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConnectConfigBundleMode(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "client.pem")
	if err := os.WriteFile(bundle, []byte("not real but exists"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	yamlPath := writeYAML(t, dir, `
connections:
  - name: postgres
    remote: db.tunnel.localport.dev:5432
    local_port: "5432"
    bundle: `+bundle+`
`)
	cc, err := LoadConnectConfig(yamlPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cc.Connections) != 1 {
		t.Fatalf("connections = %d", len(cc.Connections))
	}
	if cc.Connections[0].Bundle != bundle {
		t.Fatalf("Bundle = %q", cc.Connections[0].Bundle)
	}
}

func TestLoadConnectConfigRejectsAmbiguousMode(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "client.pem")
	p12 := filepath.Join(dir, "client.p12")
	_ = os.WriteFile(bundle, []byte("x"), 0o600)
	_ = os.WriteFile(p12, []byte("x"), 0o600)

	yamlPath := writeYAML(t, dir, `
connections:
  - name: pg
    remote: db:5432
    local_port: "5432"
    bundle: `+bundle+`
    p12: `+p12+`
`)
	if _, err := LoadConnectConfig(yamlPath); err == nil {
		t.Fatal("expected error when both bundle and p12 are set")
	}
}

func TestLoadConnectConfigRejectsMissing(t *testing.T) {
	yamlPath := writeYAML(t, t.TempDir(), `
connections:
  - name: pg
    remote: ""
    local_port: "5432"
    bundle: foo
`)
	if _, err := LoadConnectConfig(yamlPath); err == nil {
		t.Fatal("expected missing-remote rejection")
	}
}

func writeYAML(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "connect.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	return path
}
