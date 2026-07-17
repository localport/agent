package security

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ResolveToken returns a token from the flag value or env variable, in that
// order. It is an error for both to be empty.
func ResolveToken(flagValue, envName string) (string, error) {
	token := ResolveOptionalToken(flagValue, envName)
	if token == "" {
		return "", fmt.Errorf("token required (set --token or %s)", envName)
	}
	return token, nil
}

// ResolveOptionalToken is like ResolveToken but returns an empty token
// instead of an error when neither source is set.
func ResolveOptionalToken(flagValue, envName string) string {
	if v := strings.TrimSpace(flagValue); v != "" {
		return v
	}
	if envName == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(envName))
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

// ValidatePrivateKeyPermissions refuses a key file that is readable by
// group or other. The check is best-effort on Windows where mode bits
// are mostly cosmetic.
func ValidatePrivateKeyPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat key %s: %w", path, err)
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf("key file %s has too-open permissions %#o (want 0600 or stricter)", path, mode)
	}
	return nil
}
