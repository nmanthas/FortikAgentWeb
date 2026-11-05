package nsquickstart

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
)

// validateArgs checks arguments against the tool's discovered input schema:
// required properties, additionalProperties false, and each top-level
// property's type, enum and simple bounds. A subset of JSON Schema: nested
// values are left to the server (which validates them again). Returns at
// most five problems; messages name properties, never values.
func validateArgs(schema json.RawMessage, args map[string]json.RawMessage) []string {
	var s struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
		Additional *json.RawMessage           `json:"additionalProperties"`
	}
	if json.Unmarshal(schema, &s) != nil {
		return []string{"the tool's input schema could not be read"}
	}
	var out []string
	add := func(format string, a ...any) {
		if len(out) < 5 {
			out = append(out, fmt.Sprintf(format, a...))
		}
	}
	for _, r := range s.Required {
		if _, ok := args[r]; !ok {
			add("required argument %q is missing", clip(r, 64))
		}
	}
	closed := s.Additional != nil && string(bytes.TrimSpace(*s.Additional)) == "false"
	names := make([]string, 0, len(args))
	for k := range args {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		ps, known := s.Properties[k]
		if !known {
			if closed {
				add("argument %q is not in the tool's schema", clip(k, 64))
			}
			continue
		}
		if p := checkValue(ps, args[k]); p != "" {
			add("argument %q %s", clip(k, 64), p)
		}
	}
	return out
}

type propSchema struct {
	Type      json.RawMessage   `json:"type"`
	OneOf     []json.RawMessage `json:"oneOf"`
	Enum      []json.RawMessage `json:"enum"`
	Minimum   *float64          `json:"minimum"`
	Maximum   *float64          `json:"maximum"`
	MinLength *int              `json:"minLength"`
	MaxLength *int              `json:"maxLength"`
	MinItems  *int              `json:"minItems"`
	MaxItems  *int              `json:"maxItems"`
}

// checkValue returns "" when v fits the property schema (as far as checked).
func checkValue(raw json.RawMessage, v json.RawMessage) string {
	var p propSchema
	if json.Unmarshal(raw, &p) != nil {
		return ""
	}
	kind := jsonKind(v)
	if len(p.OneOf) > 0 {
		for _, alt := range p.OneOf {
			var a propSchema
			if json.Unmarshal(alt, &a) == nil && (len(a.Type) == 0 || typeAllows(a.Type, kind, v)) {
				return ""
			}
		}
		return "has a type none of the schema's alternatives allow"
	}
	if len(p.Type) > 0 && !typeAllows(p.Type, kind, v) {
		return "has the wrong type (" + kind + ")"
	}
	if len(p.Enum) > 0 {
		c := compactJSON(v)
		if !slices.ContainsFunc(p.Enum, func(e json.RawMessage) bool { return compactJSON(e) == c }) {
			return "is not one of the allowed values"
		}
	}
	switch kind {
	case "number", "integer":
		var f float64
		_ = json.Unmarshal(v, &f)
		if p.Minimum != nil && f < *p.Minimum || p.Maximum != nil && f > *p.Maximum {
			return "is out of range"
		}
	case "string":
		var str string
		_ = json.Unmarshal(v, &str)
		n := len([]rune(str))
		if p.MinLength != nil && n < *p.MinLength || p.MaxLength != nil && n > *p.MaxLength {
			return "has an invalid length"
		}
	case "array":
		var arr []json.RawMessage
		_ = json.Unmarshal(v, &arr)
		if p.MinItems != nil && len(arr) < *p.MinItems || p.MaxItems != nil && len(arr) > *p.MaxItems {
			return "has an invalid number of items"
		}
	}
	return ""
}

func typeAllows(t json.RawMessage, kind string, v json.RawMessage) bool {
	var one string
	var many []string
	if json.Unmarshal(t, &one) == nil {
		many = []string{one}
	} else if json.Unmarshal(t, &many) != nil {
		return true
	}
	for _, x := range many {
		if x == kind || x == "number" && kind == "integer" {
			return true
		}
	}
	return false
}

func jsonKind(v json.RawMessage) string {
	v = bytes.TrimSpace(v)
	if len(v) == 0 {
		return "null"
	}
	switch v[0] {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	}
	var n json.Number
	d := json.NewDecoder(bytes.NewReader(v))
	d.UseNumber()
	if d.Decode(&n) == nil {
		if _, err := n.Int64(); err == nil {
			return "integer"
		}
		return "number"
	}
	return "unknown"
}

func compactJSON(v json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, v) != nil {
		return string(v)
	}
	return b.String()
}
