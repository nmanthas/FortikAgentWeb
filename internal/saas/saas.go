// Package saas is the contract every SaaS agent integration implements
// (NetSuite, Salesforce Agentforce, SAP, ServiceNow): connection health,
// tenant identity, capability declaration, agent inventory, activity
// ingestion normalized to Fortik Actions, containment, and verification of
// containment. It plugs into the existing models; it is not a parallel engine:
//
//   - inventory reconciles into the agents registry (platform, tenant, native id);
//   - activity becomes normalized action.Actions evaluated by Decide (observed
//     after the fact unless the integration is a pre-execution path);
//   - containment results feed containment receipts (confirmed / partially
//     confirmed / failed / unknown), never a bare HTTP success;
//   - the declaration feeds the coverage report (internal/coverage).
//
// Implementations must never return credentials to callers, must be
// idempotent for containment, and must say "unknown" rather than guess.
package saas

import (
	"context"
	"time"

	"fortik/internal/action"
	"fortik/internal/coverage"
)

// Tenant identifies the connected customer account.
type Tenant struct {
	System   string `json:"system"`    // "netsuite", "salesforce", ...
	TenantID string `json:"tenant_id"` // account id / org id / subdomain
	Name     string `json:"name,omitempty"`
}

// InventoryAgent is one agent the platform exposes (documented APIs only).
type InventoryAgent struct {
	NativeID   string     `json:"native_id"`
	Name       string     `json:"name"`
	Type       string     `json:"type,omitempty"`
	Status     string     `json:"status,omitempty"`    // as the platform reports it (active, inactive, draft...)
	Principal  string     `json:"principal,omitempty"` // the identity it runs as
	Owner      string     `json:"owner,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	ModifiedAt *time.Time `json:"modified_at,omitempty"`
}

// Inventory is one synchronization result.
type Inventory struct {
	Tenant   Tenant           `json:"tenant"`
	Agents   []InventoryAgent `json:"agents"`
	Complete bool             `json:"complete"` // false: the API exposes only part of the inventory (say why in Note)
	Note     string           `json:"note,omitempty"`
	SyncedAt time.Time        `json:"synced_at"`
}

// Activity is one platform event, normalized. Observed is true when the
// event arrived after execution (an audit log): it is evidence for detection
// and containment, never a pre-execution decision.
type Activity struct {
	NativeEventID string        `json:"native_event_id"`
	AgentNativeID string        `json:"agent_native_id,omitempty"` // empty: not attributable to an agent
	Action        action.Action `json:"action"`
	At            time.Time     `json:"at"`
	Observed      bool          `json:"observed"`
	Source        string        `json:"source"` // which log/API it came from
}

// ContainResult is the platform's answer to a containment request.
type ContainResult struct {
	Operation string `json:"operation"` // e.g. "deactivate_agent", "revoke_role", "revoke_tokens"
	Status    string `json:"status"`    // confirmed | partially_confirmed | failed | unknown (containment.Outcome*)
	Evidence  string `json:"evidence"`  // the authoritative read-back, or why there is none
	Residual  string `json:"residual,omitempty"`
}

// Connector is implemented by each SaaS integration.
type Connector interface {
	System() string
	// Declaration states what this connector can observe, block, revoke,
	// suspend and undo, with the evidence for each claim.
	Declaration() coverage.Declaration
	// Health checks credentials and reachability without side effects.
	Health(ctx context.Context) (Tenant, error)
	// Inventory lists the agents the platform's documented APIs expose.
	Inventory(ctx context.Context) (Inventory, error)
	// Activity returns events after cursor (opaque, connector-defined) and
	// the next cursor. It must tolerate rate limits and partial pages.
	Activity(ctx context.Context, cursor string) ([]Activity, string, error)
	// Contain applies a containment operation to one agent; it must be
	// idempotent and must report what it could not do.
	Contain(ctx context.Context, agentNativeID, operation, reason string) (ContainResult, error)
	// Verify re-reads the platform's state for a previous containment.
	Verify(ctx context.Context, agentNativeID, operation string) (ContainResult, error)
}
