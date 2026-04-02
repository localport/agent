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

type Connection struct {
	Name      string `yaml:"name"`
	Remote    string `yaml:"remote"`
	LocalPort string `yaml:"local_port"`
	Cert      string `yaml:"cert"`
	Key       string `yaml:"key"`
	CA        string `yaml:"ca"`
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
	if c.Cert == "" || c.Key == "" || c.CA == "" {
		return fmt.Errorf("'cert', 'key', and 'ca' are all required")
	}

	var missing []string
	for _, f := range []string{c.Cert, c.Key, c.CA} {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("file(s) not found: %s", strings.Join(missing, ", "))
	}
	return nil
}
