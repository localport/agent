package access

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v4"
)

// AccessConfig lists the mTLS devices the access subcommand forwards locally.
type AccessConfig struct {
	// Version is required. A file written for a newer schema fails on this
	// field instead of on an unknown one.
	Version int     `yaml:"version"`
	Access  []Entry `yaml:"access"`
}

// Entry is one device and the ports forwarded from it. At most one of PEM or
// P12 is set. With neither, the stored identity is used (see `localport
// identity`). The P12 password comes inline, from a file or from an env
// variable.
type Entry struct {
	Device string `yaml:"device"`
	// Forward lists `[local:]remote` pairs in -L syntax.
	Forward     []string `yaml:"forward"`
	PEM         string   `yaml:"pem"`
	P12         string   `yaml:"p12"`
	P12Pass     string   `yaml:"p12_pass,omitempty"`
	P12PassFile string   `yaml:"p12_pass_file,omitempty"`
	P12PassEnv  string   `yaml:"p12_pass_env,omitempty"`
	// Identity selects the stored credential as `<identity>`,
	// `<team>/<identity>` or `<team>/<kind>/<identity>`. Required only when
	// the machine holds more than one.
	Identity string `yaml:"identity,omitempty"`
}

// UsesIdentity reports whether the entry presents the stored identity.
func (e *Entry) UsesIdentity() bool { return e.PEM == "" && e.P12 == "" }

// LoadAccessConfig reads and validates an access YAML file.
func LoadAccessConfig(path string) (*AccessConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cc AccessConfig
	if err := yaml.Unmarshal(raw, &cc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cc.Version != 1 {
		return nil, fmt.Errorf("parse %s: unsupported config version %d (only v1 is recognized)", path, cc.Version)
	}
	if len(cc.Access) == 0 {
		return nil, errors.New("access config: no devices listed")
	}
	// Local ports must be unique across entries since every forward binds on
	// this machine.
	boundBy := make(map[string]string)
	for i := range cc.Access {
		entry := &cc.Access[i]
		label := entry.Device
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
		}
		if err := entry.validate(); err != nil {
			return nil, fmt.Errorf("device %s: %w", label, err)
		}
		for _, raw := range entry.Forward {
			f, err := ParseForward(raw, "127.0.0.1")
			if err != nil {
				return nil, fmt.Errorf("device %s: %w", label, err)
			}
			// Port 0 is assigned by the OS and never collides.
			if strings.HasSuffix(f.LocalAddr, ":0") {
				continue
			}
			if prev, dup := boundBy[f.LocalAddr]; dup {
				return nil, fmt.Errorf("devices %s and %s both listen on %s", prev, label, f.LocalAddr)
			}
			boundBy[f.LocalAddr] = label
		}
	}
	return &cc, nil
}

func (e *Entry) validate() error {
	if e.Device == "" {
		return errors.New("'device' is required")
	}
	if len(e.Forward) == 0 {
		return errors.New("'forward' needs at least one port")
	}
	if e.PEM != "" && e.P12 != "" {
		return errors.New("set at most one of 'pem' or 'p12' (omit both to use the stored identity)")
	}
	if e.Identity != "" && !e.UsesIdentity() {
		return errors.New("'identity' selects a stored credential, so it cannot be combined with 'pem' or 'p12'")
	}

	var missing []string
	for _, f := range []string{e.PEM, e.P12, e.P12PassFile} {
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
