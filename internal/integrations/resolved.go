package integrations

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
)

// Typed accessors for adapters reading Resolved.ConfigMap (values decoded
// from JSON: strings, float64, []any, bool). Missing or mistyped values
// return the zero value; adapters validate what they require.

// Text returns a string config value.
func (r Resolved) Text(key string) string {
	s, _ := r.ConfigMap[key].(string)
	return s
}

// Strings returns a list config value.
func (r Resolved) Strings(key string) []string {
	switch v := r.ConfigMap[key].(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Int returns an integer config value (e.g. postgres port).
func (r Resolved) Int(key string) int {
	switch v := r.ConfigMap[key].(type) {
	case float64:
		if v == math.Trunc(v) && math.Abs(v) < 1<<53 {
			return int(v)
		}
	case int64:
		return int(v)
	case int:
		return v
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int(i)
		}
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return 0
}

// Bool returns a boolean config value.
func (r Resolved) Bool(key string) bool {
	b, _ := r.ConfigMap[key].(bool)
	return b
}

// Secret returns a secret value ("" if unset).
func (r Resolved) Secret(field string) string { return r.Secrets[field] }

// Name is the instance name: the part after "postgres:" or "memory:" for
// multi-instance systems, otherwise the key itself.
func (r Resolved) Name() string {
	for _, sys := range []string{SystemPostgres, SystemMemory} {
		if name, ok := strings.CutPrefix(r.Key, sys+":"); ok && name != "" {
			return name
		}
	}
	return r.Key
}

// String, GoString, LogValue and MarshalJSON keep secret values out of
// logs, error messages and JSON even when a caller prints a whole Resolved.

func (r Resolved) String() string {
	return fmt.Sprintf("integration(%s, status=%s, secrets=%v redacted)", r.Key, r.Status, r.SecretFields)
}

func (r Resolved) GoString() string { return r.String() }

func (r Resolved) LogValue() slog.Value {
	return slog.GroupValue(slog.String("key", r.Key), slog.String("status", r.Status), slog.Any("secret_fields", r.SecretFields))
}

func (r Resolved) MarshalJSON() ([]byte, error) { return json.Marshal(r.Integration) }
