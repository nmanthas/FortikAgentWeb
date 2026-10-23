package decide

import (
	"context"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/policy"
)

// Decider is the one logical Decide service every interception point calls.
// Go interception points embed it in-process (no network hop on the hot
// path); others call POST /v1/actions/decide, which wraps the same Service.
//
// Contract: Decide never returns an executable decision on an internal
// failure. Internal failures (store down, policy error) yield an Outcome with
// FailClosed=true and a non-executing decision (except the configured
// green-read allowlist). The returned error is non-nil only for structurally
// invalid input (wraps action.ErrInvalid); callers must then refuse the call.
type Decider interface {
	Decide(ctx context.Context, a action.Action) (Outcome, error)
}

// Outcome is the decision plus the facts needed to enforce and explain it.
type Outcome struct {
	Action      action.Action `json:"action"`
	Result      policy.Result `json:"result"`
	LevelBefore control.Level `json:"level_before"`
	LevelAfter  control.Level `json:"level_after"`
	Held        bool          `json:"held"`
	FailClosed  bool          `json:"fail_closed"`
	LatencyUS   int64         `json:"latency_us"`
}
