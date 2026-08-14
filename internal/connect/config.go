package connect

import (
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v4"
)

// ConnectConfig describes a list of mTLS targets that should each be
// exposed locally via the connect subcommand.
type ConnectConfig struct {
	// Version gates the schema, as the tunnel config does. Required, so a file
	// written for a later shape fails on the version line rather than on a field
	// this build silently ignores.
	Version     int          `yaml:"version"`
	Connections []Connection `yaml:"connections"`
}

// Connection is one target. It may specify at most one of Bundle or P12; with
// neither, the machine's stored identity is used (see `localport identity`).
// The password for P12 may be inlined (discouraged), read from a file, or
// sourced from an env variable.
type Connection struct {
	Name        string `yaml:"name"`
	Remote      string `yaml:"remote"`
	LocalPort   string `yaml:"local_port"`
	Bundle      string `yaml:"bundle"`
	P12         string `yaml:"p12"`
	P12Pass     string `yaml:"p12_pass,omitempty"`
	P12PassFile string `yaml:"p12_pass_file,omitempty"`
	P12PassEnv  string `yaml:"p12_pass_env,omitempty"`
	// Identity selects which stored credential to present: `<identity>`,
	// `<team>/<identity>` or `<team>/<kind>/<identity>`. Only needed when the
	// machine holds more than one.
	Identity string `yaml:"identity,omitempty"`
}

// UsesIdentity reports whether this connection presents the stored identity
// rather than a credential file.
func (c *Connection) UsesIdentity() bool { return c.Bundle == "" && c.P12 == "" }

// LoadConnectConfig reads and validates a connect YAML file.
func LoadConnectConfig(path string) (*ConnectConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cc ConnectConfig
	if err := yaml.Unmarshal(raw, &cc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cc.Version != 1 {
		return nil, fmt.Errorf("parse %s: unsupported config version %d (only v1 is recognized)", path, cc.Version)
	}
	if len(cc.Connections) == 0 {
		return nil, fmt.Errorf("connect config: no connections defined")
	}
	// Two connections on one local port bind the same address. Caught here
	// rather than at listen, where the second one fails after the first is
	// already serving and the command looks half-working.
	ports := make(map[string]string, len(cc.Connections))
	for i, c := range cc.Connections {
		label := c.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
		}
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("connection %s: %w", label, err)
		}
		if c.LocalPort == "0" {
			continue // the OS picks a free port, so these never collide
		}
		if prev, dup := ports[c.LocalPort]; dup {
			return nil, fmt.Errorf("connections %s and %s both listen on local port %s", prev, label, c.LocalPort)
		}
		ports[c.LocalPort] = label
	}
	return &cc, nil
}

func (c *Connection) validate() error {
	if c.Remote == "" {
		return fmt.Errorf("'remote' is required")
	}
	if c.LocalPort == "" {
		return fmt.Errorf("'local_port' is required")
	}
	if c.Bundle != "" && c.P12 != "" {
		return fmt.Errorf("set at most one of 'bundle' or 'p12' (omit both to use the stored identity)")
	}
	if c.Identity != "" && !c.UsesIdentity() {
		return fmt.Errorf("'identity' selects a stored credential, so it cannot be combined with 'bundle' or 'p12'")
	}

	var missing []string
	for _, f := range []string{c.Bundle, c.P12, c.P12PassFile} {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); os.IsNotExist(err) {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("file(s) not found: %s", strings.Join(missing, ", "))
	}
	return nil
}
