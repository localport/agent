package security

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ResolveToken returns a token from the flag value, the environment variable or
// the file it names, in that order. It is an error for all three to be empty.
func ResolveToken(flagValue, envName string) (string, error) {
	token, err := ResolveOptionalToken(flagValue, envName)
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", fmt.Errorf("token required (set --token, %s or %s_FILE)", envName, envName)
	}
	return token, nil
}

// ResolveOptionalToken is like ResolveToken but returns an empty token instead
// of an error when no source is set.
//
// The `<NAME>_FILE` form keeps the secret out of the process environment, where
// /proc/<pid>/environ exposes it to root and to anything running as the same
// user. It is what systemd's LoadCredential= writes and what the services'
// docker secrets use. Precedence matches theirs, so an explicit value still
// wins over the file.
func ResolveOptionalToken(flagValue, envName string) (string, error) {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v, nil
	}
	if envName == "" {
		return "", nil
	}
	if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
		return v, nil
	}
	path := strings.TrimSpace(os.Getenv(envName + "_FILE"))
	if path == "" {
		return "", nil
	}
	// A token is a bearer secret, so the file holding it is read under the same
	// owner-only rules as a private key.
	data, err := ReadPrivateFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", envName, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// RedactString returns text with every occurrence of each secret swapped
// for [REDACTED]. Empty secrets are skipped.
func RedactString(text string, secrets ...string) string {
	out := text
	for _, s := range secrets {
		if s == "" {
			continue
		}
		out = strings.ReplaceAll(out, s, "[REDACTED]")
	}
	return out
}

// SanitizeError wraps an error with its message redacted of the given
// secrets. The returned error is a plain string; the original is discarded
// because keeping the underlying err exposes the secret through %+v.
func SanitizeError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return errors.New(RedactString(err.Error(), secrets...))
}
