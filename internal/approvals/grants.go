package approvals

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/policy"
)

// GrantKey is the input.context key the grants enricher fills.
const GrantKey = "grant"

// ErrGrantConsumed means the grant the policy relied on was used, expired or
// does not match by the time the decision was recorded (e.g. two identical
// retries raced): the decision fails closed.
var ErrGrantConsumed = errors.New("approval grant was already used or is no longer valid")

// GrantEnricher supplies input.context.grant when an unexpired, unused grant
// matches the action's agent and hash. One indexed query
// (approval_grants_usable) per decision.
type GrantEnricher struct{ pool *pgxpool.Pool }

// NewGrantEnricher returns the "grant" enricher for decide.Service.Enrichers.
func NewGrantEnricher(pool *pgxpool.Pool) *GrantEnricher { return &GrantEnricher{pool: pool} }

var _ decide.Enricher = (*GrantEnricher)(nil)

func (e *GrantEnricher) Key() string { return GrantKey }

// Enrich returns a PolicyContext, or nil (no key) when no usable grant exists.
// Errors fail the decision closed.
func (e *GrantEnricher) Enrich(ctx context.Context, a action.Action, st control.State) (any, error) {
	if !st.Registered {
		return nil, nil // unregistered agents are refused by policy; grants never apply
	}
	var pc PolicyContext
	err := e.pool.QueryRow(ctx, `
		SELECT g.grant_id, g.expires_at,
		       (SELECT count(DISTINCT v.approver) FROM held_approvals v WHERE v.action_id = g.action_id AND v.decision = 'approve')::int
		FROM approval_grants g
		WHERE g.agent_id = $1 AND g.action_hash = $2 AND g.used_at IS NULL AND g.expires_at > now()
		ORDER BY 3 DESC, g.expires_at LIMIT 1`, a.AgentID, a.Hash()).Scan(&pc.GrantID, &pc.ExpiresAt, &pc.Approvals)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("approval grants: %w", err)
	}
	return pc, nil
}

// GrantObserver consumes the grant inside the decision transaction when the
// policy released a held yellow action with it (Result.GrantID set and
// decision allow). Exactly one decision can consume a grant: the UPDATE only
// matches an unused, unexpired grant of the same agent and action hash, and
// any other outcome rolls the decision back (fail closed).
type GrantObserver struct{ diary *diary.Diary }

// NewGrantObserver returns the grant-consuming observer for decide.Service.Observers.
func NewGrantObserver(d *diary.Diary) *GrantObserver { return &GrantObserver{diary: d} }

var _ decide.Observer = (*GrantObserver)(nil)

func (o *GrantObserver) AfterDecide(ctx context.Context, tx pgx.Tx, out *decide.Outcome, _ policy.Input) error {
	if out == nil || out.Result.GrantID == "" || out.Result.Decision != policy.Allow {
		// A gate can refuse an action the grant would have released; the
		// grant then stays available for a retry that passes the gates.
		return nil
	}
	a := out.Action
	var approvedAction string
	var usedAt time.Time
	err := tx.QueryRow(ctx, `
		UPDATE approval_grants SET used_at = now(), used_by_action = $2
		WHERE grant_id = $1 AND agent_id = $3 AND action_hash = $4 AND used_at IS NULL AND expires_at > now()
		RETURNING action_id, used_at`, out.Result.GrantID, a.ActionID, a.AgentID, a.Hash()).Scan(&approvedAction, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: grant %s", ErrGrantConsumed, out.Result.GrantID)
	}
	if err != nil {
		return fmt.Errorf("consume grant: %w", err)
	}
	_, err = o.diary.AppendTx(ctx, tx, diary.Event{AgentID: a.AgentID, EventType: EventGrantUsed, Actor: "system:approvals", Data: map[string]any{
		"grant_id": out.Result.GrantID, "approved_action_id": approvedAction, "used_by_action": a.ActionID,
		"action_hash": a.Hash(), "used_at": usedAt.UTC().Format(time.RFC3339Nano),
	}})
	return err
}
