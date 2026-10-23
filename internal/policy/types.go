// Package policy evaluates the Rego policy bundle. Rules decide, not a model:
// the same Input always yields the same Result, and every Result names the
// rule that produced it.
package policy

import (
	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/control"
)

// Class is the single classification every Action receives.
type Class string

const (
	Green  Class = "green"
	Yellow Class = "yellow"
	Red    Class = "red"
)

// Severity orders classes so the worst one wins.
func (c Class) Severity() int {
	switch c {
	case Green:
		return 0
	case Yellow:
		return 1
	case Red:
		return 2
	}
	return 3
}

// Decision is what the interception point must enforce.
type Decision string

const (
	Allow        Decision = "allow"         // run as requested
	AllowReduced Decision = "allow_reduced" // run only in ReducedForm (snapshot first, narrowed, delayed...)
	Hold         Decision = "hold"          // never run now; recorded in held_actions, may be approved later
	Deny         Decision = "deny"          // refused (control level, unknown, unregistered); not approvable
)

// Executes reports whether the interception point may run the call at all.
func (d Decision) Executes() bool { return d == Allow || d == AllowReduced }

// Input is everything the policy sees. Later phases add overrides, swarm,
// copies and baseline here; their zero values are safe defaults.
type Input struct {
	Action action.Action  `json:"action"`
	Agent  control.State  `json:"agent"`
	Config map[string]any `json:"config,omitempty"`
	// Access is the agent's current access profile for the action's system
	// (Phase 2). Nil only when Decide runs without an access source (tests);
	// production startup refuses to run without one.
	Access *access.PolicyInput `json:"access,omitempty"`
	// Context carries enrichment from Phase 3+ subsystems, read by Rego as
	// input.context.<key>: delegation (chain), population (copies, spawn
	// rate), overrides (timed suspensions), grant (approved hold), rate.
	Context map[string]any `json:"context,omitempty"`
}

// Match is one rule that fired.
type Match struct {
	RuleID string `json:"rule_id"`
	Class  Class  `json:"class"`
	Reason string `json:"reason"`
}

// LadderChange is a step-down a rule requests. Decide applies it only if it
// moves the agent to a MORE restricted level than it is at now.
type LadderChange struct {
	To     string `json:"to"`
	Reason string `json:"reason,omitempty"`
}

// Result is the policy output, per the plan:
// {class, decision, reduced_form, ladder_change, reason, rule_id}.
type Result struct {
	Class        Class          `json:"class"`
	Decision     Decision       `json:"decision"`
	ReducedForm  map[string]any `json:"reduced_form,omitempty"`
	LadderChange *LadderChange  `json:"ladder_change,omitempty"`
	Reason       string         `json:"reason"`
	RuleID       string         `json:"rule_id"`
	Matched      []Match        `json:"matched,omitempty"`
	// GrantID is set when a held yellow action is allowed by a one-time
	// approval grant (the only way a yellow runs without a reduced form).
	GrantID string `json:"grant_id,omitempty"`
	// ApprovalsRequired is set on a hold that needs more than one distinct
	// approver (e.g. calls held by the swarm breaker need two).
	ApprovalsRequired int    `json:"approvals_required,omitempty"`
	PolicyVersion     string `json:"policy_version,omitempty"`
}
