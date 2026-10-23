package integrations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"unicode"
)

// MaxErrorLen caps sanitised error messages stored in last_error and the Diary.
const MaxErrorLen = 500

// Fingerprint is the first 8 hex characters of sha256(value): enough to tell
// in the Diary that a secret changed (or did not) without revealing it.
func Fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:4])
}

// Sanitize makes an error message from a live test safe to store and show:
// every occurrence of a secret value (and of its JSON-escaped form, its
// individual lines, and the string fields inside JSON secrets such as a
// service account's private_key) is replaced with ***, control characters
// are flattened and the result is capped at MaxErrorLen bytes.
func Sanitize(msg string, secretValues map[string]string) string {
	var needles []string
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(needles, s) {
			needles = append(needles, s)
		}
	}
	var addValue func(v string, depth int)
	addValue = func(v string, depth int) {
		add(v)
		if b, err := json.Marshal(v); err == nil {
			add(string(b[1 : len(b)-1])) // JSON-escaped (\n etc.)
		}
		if strings.ContainsAny(v, "\r\n") {
			for _, line := range strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == '\r' }) {
				if len(strings.TrimSpace(line)) >= 8 {
					add(line)
				}
			}
		}
		if depth > 0 {
			return
		}
		var obj map[string]any
		if json.Unmarshal([]byte(v), &obj) == nil {
			for _, f := range obj {
				if s, ok := f.(string); ok && len(s) >= 8 {
					addValue(s, depth+1)
				}
			}
		}
	}
	for _, v := range secretValues {
		addValue(v, 0)
	}
	// Longest first, so a value's substrings never leave fragments of it.
	slices.SortFunc(needles, func(a, b string) int { return len(b) - len(a) })
	for _, n := range needles {
		msg = strings.ReplaceAll(msg, n, "***")
	}
	msg = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, msg)
	msg = strings.Join(strings.Fields(msg), " ")
	return truncate(msg, MaxErrorLen)
}
