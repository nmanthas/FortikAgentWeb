package memory

import (
	"context"
	"time"

	"fortik/internal/broker"
)

// CredentialAdapter is the broker.Adapter for system "memory". Agents never
// hold vector-store credentials: Fortik's memory gateway uses the store
// integration's admin credentials on their behalf, after a decision. So there
// is nothing to mint and nothing to recall, and RevokeAgent says exactly
// that. Registering it in the broker's adapters makes containment's
// "revoke vector-store credentials" step report memory explicitly.
type CredentialAdapter struct{}

var _ broker.Adapter = CredentialAdapter{}

func (CredentialAdapter) System() string { return System }

// Mint always refuses: memory is reached only through the gateway.
func (CredentialAdapter) Mint(context.Context, string, map[string]any, time.Duration) (broker.Credential, error) {
	return broker.Credential{}, broker.ErrUnsupported
}

// RevokeAgent revokes nothing because nothing was issued; access itself is
// cut with the memory access mode (memory_remove).
func (CredentialAdapter) RevokeAgent(context.Context, string) (string, error) {
	return "no vector-store credentials are ever issued to agents (memory is reached only through the Fortik memory gateway): nothing to recall; memory access is cut by the memory access mode", nil
}
