package delegation

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// TaskScope is what a delegated task may do, declared by the delegator on the
// DELEGATE action (target.task_scope) and signed into the delegation token.
// An empty list means "not restricted by the task" for that dimension: the
// inherited restrictions of every upstream agent (POL-601) still apply.
// Scopes only ever narrow along a chain: a child hop's scope is the
// intersection of its parent's scope and its own (Intersect), so a downstream
// agent can never widen what its caller's task allowed.
type TaskScope struct {
	Systems []string `json:"systems,omitempty"` // e.g. ["postgres", "gmail"]
	Verbs   []string `json:"verbs,omitempty"`   // e.g. ["READ"]
	Domains []string `json:"domains,omitempty"` // external destinations allowed ("example.com" also covers subdomains)
}

const maxScopeEntries = 32

var (
	scopeSystemRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	scopeVerbRe   = regexp.MustCompile(`^[A-Z]{3,12}$`)
	scopeDomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$`)
)

// ErrInvalidScope: a malformed task_scope (fails the DELEGATE closed).
var ErrInvalidScope = errors.New("invalid delegation task scope")

// IsZero reports whether the scope restricts nothing.
func (s *TaskScope) IsZero() bool {
	return s == nil || (len(s.Systems) == 0 && len(s.Verbs) == 0 && len(s.Domains) == 0)
}

// Validate checks every entry (bounded, canonical spelling).
func (s *TaskScope) Validate() error {
	if s == nil {
		return nil
	}
	check := func(name string, xs []string, re *regexp.Regexp) error {
		if len(xs) > maxScopeEntries {
			return fmt.Errorf("%w: at most %d %s", ErrInvalidScope, maxScopeEntries, name)
		}
		for _, x := range xs {
			if !re.MatchString(x) || len(x) > 253 {
				return fmt.Errorf("%w: malformed %s entry", ErrInvalidScope, name)
			}
		}
		return nil
	}
	if err := check("systems", s.Systems, scopeSystemRe); err != nil {
		return err
	}
	if err := check("verbs", s.Verbs, scopeVerbRe); err != nil {
		return err
	}
	return check("domains", s.Domains, scopeDomainRe)
}

// ParseTaskScope reads target.task_scope from a DELEGATE action (nil when
// absent). Unknown keys and non-string entries are refused.
func ParseTaskScope(v any) (*TaskScope, error) {
	if v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: must be an object", ErrInvalidScope)
	}
	s := &TaskScope{}
	for k, raw := range m {
		var list []string
		switch xs := raw.(type) {
		case []any:
			for _, x := range xs {
				str, ok := x.(string)
				if !ok {
					return nil, fmt.Errorf("%w: %s entries must be strings", ErrInvalidScope, k)
				}
				list = append(list, str)
			}
		case []string:
			list = xs
		default:
			return nil, fmt.Errorf("%w: %s must be a list", ErrInvalidScope, k)
		}
		switch k {
		case "systems":
			s.Systems = lowerAll(list)
		case "verbs":
			s.Verbs = upperAll(list)
		case "domains":
			s.Domains = lowerAll(list)
		default:
			return nil, fmt.Errorf("%w: unknown key %q", ErrInvalidScope, k)
		}
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.IsZero() {
		return nil, nil
	}
	return s, nil
}

// Intersect narrows a by b. For each dimension: unrestricted (empty) on one
// side takes the other side; both restricted takes the common entries, and an
// empty intersection becomes the deny-all marker ["-"] so that "nothing in
// common" can never read as "unrestricted".
func Intersect(a, b *TaskScope) *TaskScope {
	if a.IsZero() {
		return clone(b)
	}
	if b.IsZero() {
		return clone(a)
	}
	return &TaskScope{
		Systems: meet(a.Systems, b.Systems),
		Verbs:   meet(a.Verbs, b.Verbs),
		Domains: meetDomains(a.Domains, b.Domains),
	}
}

// DenyAll is the marker an empty intersection becomes (no system, verb or
// domain is spelled "-", so it matches nothing).
const DenyAll = "-"

func meet(a, b []string) []string {
	switch {
	case len(a) == 0:
		return slices.Clone(b)
	case len(b) == 0:
		return slices.Clone(a)
	}
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) && x != DenyAll {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return []string{DenyAll}
	}
	return out
}

// meetDomains: a domain survives when the other side allows it or a parent
// domain of it ("mail.example.com" within "example.com").
func meetDomains(a, b []string) []string {
	switch {
	case len(a) == 0:
		return slices.Clone(b)
	case len(b) == 0:
		return slices.Clone(a)
	}
	var out []string
	add := func(d string) {
		if d != DenyAll && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	for _, x := range a {
		if domainWithin(x, b) {
			add(x)
		}
	}
	for _, y := range b {
		if domainWithin(y, a) {
			add(y)
		}
	}
	if len(out) == 0 {
		return []string{DenyAll}
	}
	return out
}

func domainWithin(d string, allowed []string) bool {
	for _, a := range allowed {
		if a != DenyAll && (d == a || strings.HasSuffix(d, "."+a)) {
			return true
		}
	}
	return false
}

func clone(s *TaskScope) *TaskScope {
	if s.IsZero() {
		return nil
	}
	return &TaskScope{Systems: slices.Clone(s.Systems), Verbs: slices.Clone(s.Verbs), Domains: slices.Clone(s.Domains)}
}

func lowerAll(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strings.ToLower(strings.TrimSpace(x))
	}
	return out
}

func upperAll(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strings.ToUpper(strings.TrimSpace(x))
	}
	return out
}
