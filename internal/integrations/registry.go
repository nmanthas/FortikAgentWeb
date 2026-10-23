package integrations

import (
	"fmt"
	"sync"
)

// Registry holds the live connection testers, one per system. Adapters
// register theirs at startup (google, github, aws, postgres).
type Registry struct {
	mu sync.RWMutex
	m  map[string]Tester
}

func NewRegistry() *Registry { return &Registry{m: map[string]Tester{}} }

// Register adds a tester. A nil tester, an unknown system or a second tester
// for the same system is an error (wiring mistakes surface at startup).
func (r *Registry) Register(t Tester) error {
	if t == nil {
		return fmt.Errorf("integrations: nil tester")
	}
	sys := t.System()
	if _, ok := SchemaFor(sys); !ok {
		return fmt.Errorf("integrations: tester for unknown system %q", sys)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.m[sys]; dup {
		return fmt.Errorf("integrations: tester for %s already registered", sys)
	}
	r.m[sys] = t
	return nil
}

// Tester returns the tester for a system.
func (r *Registry) Tester(system string) (Tester, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.m[system]
	return t, ok
}
