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

// ResolveOptionalToken is like ResolveToken but returns an empty token when no
// source is set.
//
// The `<NAME>_FILE` form keeps the secret out of /proc/<pid>/environ and
// works with systemd LoadCredential= and Docker secrets. An explicit value
// takes precedence over the file.
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
	// Token files follow the owner-only rules for private keys.
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

// SanitizeDisplay strips characters that a terminal or log viewer could
// interpret, such as escape sequences for title changes, hidden text or OSC 52
// clipboard writes. Call it where an untrusted value enters the agent.
//
// It removes C0 including ESC, DEL, C1, and the bidi and zero-width formatting
// characters of CVE-2021-42574. The bidi set is explicit because Unicode Cf
// also contains marks used in Arabic.
func SanitizeDisplay(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			return -1
		case r >= 0x200b && r <= 0x200f, // ZWSP, ZWNJ, ZWJ, LRM, RLM
			r >= 0x202a && r <= 0x202e, // LRE, RLE, PDF, LRO, RLO
			r >= 0x2060 && r <= 0x2064, // word joiner, invisible operators
			r >= 0x2066 && r <= 0x2069, // LRI, RLI, FSI, PDI
			r == 0xfeff:                // ZWNBSP
			return -1
		}
		return r
	}, s)
}
