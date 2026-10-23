package secrets

import (
	"fmt"
	"strings"
)

// MaxNameLen bounds secret names for every provider.
const MaxNameLen = 256

// ValidName checks a secret name for the writable stores and the file
// provider. Names are '/'-separated segments of [a-zA-Z0-9_.-]; segments may
// not be empty, "." or "..", or start with '.' (hidden files are reserved for
// the stores' own temp files). This rules out absolute paths, traversal and
// NUL bytes, so a name always maps to a path inside the store's directory.
func ValidName(name string) error {
	if name == "" || len(name) > MaxNameLen {
		return fmt.Errorf("invalid secret name: length must be 1..%d", MaxNameLen)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("invalid secret name %q: must not contain \"..\"", name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" {
			return fmt.Errorf("invalid secret name %q: empty path segment (absolute paths and '//' are not allowed)", name)
		}
		if seg[0] == '.' {
			return fmt.Errorf("invalid secret name %q: path segments must not start with '.'", name)
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
			if !ok {
				return fmt.Errorf("invalid secret name %q: allowed characters are [a-zA-Z0-9_./-]", name)
			}
		}
	}
	return nil
}
