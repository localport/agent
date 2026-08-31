package access

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAccessConfigBundleMode(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "client.pem")
	if err := os.WriteFile(bundle, []byte("not real but exists"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	yamlPath := writeYAML(t, dir, `
version: 1
connections:
  - name: postgres
    remote: db.tunnel.localport.dev:5432
    local_port: "5432"
    bundle: `+bundle+`
`)
	cc, err := LoadAccessConfig(yamlPath)
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

func TestLoadAccessConfigRejectsAmbiguousMode(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "client.pem")
	p12 := filepath.Join(dir, "client.p12")
	_ = os.WriteFile(bundle, []byte("x"), 0o600)
	_ = os.WriteFile(p12, []byte("x"), 0o600)

	yamlPath := writeYAML(t, dir, `
version: 1
connections:
  - name: pg
    remote: db:5432
    local_port: "5432"
    bundle: `+bundle+`
    p12: `+p12+`
`)
	if _, err := LoadAccessConfig(yamlPath); err == nil {
		t.Fatal("expected error when both bundle and p12 are set")
	}
}

func TestLoadAccessConfigAcceptsIdentityMode(t *testing.T) {
	// No bundle and no p12 is the stored-identity path, not a broken config.
	yamlPath := writeYAML(t, t.TempDir(), `
version: 1
connections:
  - name: gw
    remote: gw-01.eu.localport.dev:22
    local_port: "2222"
`)
	cc, err := LoadAccessConfig(yamlPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cc.Connections[0].UsesIdentity() {
		t.Fatal("a connection with no credential file should use the stored identity")
	}
}

func TestLoadAccessConfigRejectsIdentityWithACredentialFile(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "client.pem")
	_ = os.WriteFile(bundle, []byte("x"), 0o600)

	yamlPath := writeYAML(t, dir, `
version: 1
connections:
  - name: gw
    remote: gw-01.eu.localport.dev:22
    local_port: "2222"
    identity: 01kpq7x2/client/deploy-prod
    bundle: `+bundle+`
`)
	if _, err := LoadAccessConfig(yamlPath); err == nil {
		t.Fatal("expected 'identity' to be refused alongside a credential file")
	}
}

func TestLoadAccessConfigRejectsMissing(t *testing.T) {
	yamlPath := writeYAML(t, t.TempDir(), `
version: 1
connections:
  - name: pg
    remote: ""
    local_port: "5432"
    bundle: foo
`)
	if _, err := LoadAccessConfig(yamlPath); err == nil {
		t.Fatal("expected missing-remote rejection")
	}
}

// A file written for another schema must fail on the version line, not on a
// field this build happens to ignore.
func TestLoadAccessConfigRejectsUnknownVersion(t *testing.T) {
	for _, body := range []string{
		"connections:\n  - name: gw\n    remote: gw:22\n    local_port: \"2222\"\n",
		"version: 2\nconnections:\n  - name: gw\n    remote: gw:22\n    local_port: \"2222\"\n",
	} {
		if _, err := LoadAccessConfig(writeYAML(t, t.TempDir(), body)); err == nil {
			t.Fatalf("expected a version rejection for:\n%s", body)
		}
	}
}

// Two connections on one port bind the same address, so the second listener
// fails after the first is already serving.
func TestLoadAccessConfigRejectsDuplicateLocalPort(t *testing.T) {
	yamlPath := writeYAML(t, t.TempDir(), `
version: 1
connections:
  - name: gw
    remote: gw-01.eu.localport.dev:22
    local_port: "2222"
  - name: gw2
    remote: gw-02.eu.localport.dev:22
    local_port: "2222"
`)
	if _, err := LoadAccessConfig(yamlPath); err == nil {
		t.Fatal("expected a duplicate local_port rejection")
	}
}

// Port 0 asks the OS for a free one, so repeats never collide.
func TestLoadAccessConfigAllowsRepeatedEphemeralPort(t *testing.T) {
	yamlPath := writeYAML(t, t.TempDir(), `
version: 1
connections:
  - name: gw
    remote: gw-01.eu.localport.dev:22
    local_port: "0"
  - name: gw2
    remote: gw-02.eu.localport.dev:22
    local_port: "0"
`)
	if _, err := LoadAccessConfig(yamlPath); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func writeYAML(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "access.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	return path
}
