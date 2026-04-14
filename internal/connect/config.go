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
	Connections []Connection `yaml:"connections"`
}

// Connection is one target. Each connection must specify exactly one of
// Bundle or P12; the password for P12 may be inlined (discouraged), read
// from a file, or sourced from an env variable.
type Connection struct {
	Name        string `yaml:"name"`
	Remote      string `yaml:"remote"`
	LocalPort   string `yaml:"local_port"`
	Bundle      string `yaml:"bundle"`
	P12         string `yaml:"p12"`
	P12Pass     string `yaml:"p12_pass,omitempty"`
	P12PassFile string `yaml:"p12_pass_file,omitempty"`
	P12PassEnv  string `yaml:"p12_pass_env,omitempty"`
}

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
	if len(cc.Connections) == 0 {
		return nil, fmt.Errorf("connect config: no connections defined")
	}
	for i, c := range cc.Connections {
		if err := c.validate(); err != nil {
			label := c.Name
			if label == "" {
				label = fmt.Sprintf("#%d", i+1)
			}
			return nil, fmt.Errorf("connection %s: %w", label, err)
		}
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
	if !exactlyOne(c.Bundle != "", c.P12 != "") {
		return fmt.Errorf("set exactly one of 'bundle' or 'p12'")
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
