package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// interpolate substitutes environment references in Compose syntax.
//
//	${VAR}             the value, and an error when unset or empty
//	${VAR:-default}    the value, or default when unset or empty
//	${VAR:?message}    the value, or an error carrying message
//	$$                 a literal $
//
// References are resolved before YAML parsing. An unterminated `${` is an
// error.
func interpolate(raw string) (string, error) {
	var (
		out     strings.Builder
		missing []string
	)
	out.Grow(len(raw))

	for i := 0; i < len(raw); {
		c := raw[i]
		if c != '$' {
			out.WriteByte(c)
			i++
			continue
		}
		if i+1 < len(raw) && raw[i+1] == '$' {
			out.WriteByte('$')
			i += 2
			continue
		}
		if i+1 >= len(raw) || raw[i+1] != '{' {
			out.WriteByte(c)
			i++
			continue
		}
		end := strings.IndexByte(raw[i:], '}')
		if end < 0 {
			return "", errors.New("unterminated ${ in config")
		}
		ref := raw[i+2 : i+end]
		value, err := resolveRef(ref)
		if err != nil {
			missing = append(missing, err.Error())
		}
		out.WriteString(value)
		i += end + 1
	}

	if len(missing) > 0 {
		return "", fmt.Errorf("%s", strings.Join(missing, "; "))
	}
	return out.String(), nil
}

func resolveRef(ref string) (string, error) {
	if name, fallback, ok := strings.Cut(ref, ":-"); ok {
		if value := os.Getenv(name); value != "" {
			return value, nil
		}
		return fallback, nil
	}
	if name, message, ok := strings.Cut(ref, ":?"); ok {
		if value := os.Getenv(name); value != "" {
			return value, nil
		}
		if message == "" {
			return "", fmt.Errorf("%s is not set", name)
		}
		return "", fmt.Errorf("%s: %s", name, message)
	}
	if value := os.Getenv(ref); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("%s is not set", ref)
}
