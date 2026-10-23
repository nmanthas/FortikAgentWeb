package delegation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/decide"
)

// Key is the input.context key the enricher fills.
const Key = "delegation"

// Sources of an attribution.
const (
	SourceToken    = "token"
	SourceInferred = "inferred"
)

// Attribution is the enricher's value for input.context.delegation. It
// marshals as PolicyContext plus token_error (when the presented token did
// not verify). The fields tagged "-" are for the observer only and never
// reach policy, the actions table or the Diary.
type Attribution struct {
	PolicyContext
	// TokenError is set (with Present) when a token was presented but did
	// not verify; policy denies with POL-604. It never contains the token.
	TokenError string `json:"token_error,omitempty"`
	// MaxDepth is config delegation.max_depth. Policy uses the lower of it
	// and data.fortik.delegation.max_depth, so the configured limit (which
	// also bounds what the store records) is the one enforced.
	MaxDepth int `json:"max_depth,omitempty"`
	// Lineage is the full chain root ... executor the executor acts under
	// (token: the claims' chain; inferred: every upstream agent, then the
	// executor). A DELEGATE extends it with the delegatee.
	Lineage []string `json:"-"`
	// Roots are the originating agents (chain[0] of the token, or of every
	// open inbound chain when inferred) stepped down on POL-601.
	Roots []string `json:"-"`
}

// Enricher implements decide.Enricher for input.context.delegation
// (docs/PHASE3_DESIGN.md §1.2):
//
//  1. token: a token from the request context (WithToken) that verifies for
//     the acting agent and whose hop is still open, merged with the agent's
//     other open inbound hops (a token never hides a stricter inbound
//     chain); an invalid one yields {present, token_error};
//  2. inferred: no token, the agent has delegation_strict and open inbound
//     hops: the union of their upstream agents (most restrictive);
//  3. otherwise {present: false}.
//
// It costs one query for the open hops (plus one for a token's hop) and one
// batched query for the chain agents' levels and profiles.
type Enricher struct {
	store *PGStore
	pool  *pgxpool.Pool
	now   func() time.Time
}

var _ decide.Enricher = (*Enricher)(nil)

// NewEnricher returns the delegation enricher.
func NewEnricher(store *PGStore) *Enricher {
	return &Enricher{store: store, pool: store.pool, now: store.now}
}

// Key implements decide.Enricher.
func (e *Enricher) Key() string { return Key }

// Enrich implements decide.Enricher. Store errors are returned (the decision
// fails closed); a bad token is not an error but a refusal (POL-604).
func (e *Enricher) Enrich(ctx context.Context, a action.Action, _ control.State) (any, error) {
	att, err := e.attribute(ctx, a)
	if err != nil {
		return nil, err
	}
	att.MaxDepth = e.store.MaxDepth()
	return att, nil
}

func (e *Enricher) attribute(ctx context.Context, a action.Action) (*Attribution, error) {
	if tok, ok := TokenFrom(ctx); ok {
		c, err := e.store.Verify(ctx, tok, a.AgentID)
		switch {
		case errors.Is(err, ErrExpiredToken), errors.Is(err, ErrTokenAgent), errors.Is(err, ErrInvalidToken),
			errors.Is(err, ErrRevokedToken):
			return &Attribution{PolicyContext: PolicyContext{Present: true, Source: SourceToken, Chain: []HopState{}},
				TokenError: tokenErrorText(err)}, nil
		case err != nil:
			return nil, fmt.Errorf("verify delegation token: %w", err)
		}
		// The token adds to, never replaces, the open inbound hops: an
		// agent must not hide a stricter inbound chain behind an older,
		// more permissive token (its own self-delegation token included).
		att := &Attribution{
			PolicyContext: PolicyContext{Present: true, Source: SourceToken, DelegationID: c.DelegationID, Depth: c.Depth, Root: c.Root},
		}
		att.Lineage = slices.Clone(c.Chain[:len(c.Chain)-1])
		att.Roots = []string{c.Root}
		hops, err := e.inbound(ctx, a.AgentID)
		if err != nil {
			return nil, err
		}
		for _, h := range hops {
			if h.DelegationID != c.DelegationID {
				e.merge(att, h, a.AgentID)
			}
		}
		if len(att.Roots) > 1 {
			att.Root = ""
		}
		att.Lineage = append(att.Lineage, a.AgentID)
		if err := e.fill(ctx, att, a); err != nil {
			return nil, err
		}
		return att, nil
	}
	hops, err := e.inbound(ctx, a.AgentID)
	if err != nil {
		return nil, err
	}
	if len(hops) == 0 {
		return &Attribution{PolicyContext: PolicyContext{Chain: []HopState{}}}, nil
	}
	att := &Attribution{PolicyContext: PolicyContext{Present: true, Source: SourceInferred}}
	var relevant []Hop
	for _, h := range hops {
		if e.merge(att, h, a.AgentID) {
			relevant = append(relevant, h)
		}
	}
	if len(relevant) == 0 {
		return &Attribution{PolicyContext: PolicyContext{Chain: []HopState{}}}, nil
	}
	att.Lineage = append(att.Lineage, a.AgentID)
	if len(att.Roots) == 1 {
		att.Root = att.Roots[0]
	}
	if len(relevant) == 1 {
		att.DelegationID = relevant[0].DelegationID
	}
	if err := e.fill(ctx, att, a); err != nil {
		return nil, err
	}
	return att, nil
}

// merge adds hop h's upstream agents (other than agent) to att's lineage,
// its root to Roots and its depth to Depth. Hops whose upstream is only the
// agent itself (Task subagents) add nothing: its own level and profile are
// evaluated directly. It reports whether h added anything.
func (e *Enricher) merge(att *Attribution, h Hop, agent string) bool {
	added := false
	for _, ag := range h.Chain[:len(h.Chain)-1] {
		if ag == agent {
			continue
		}
		added = true
		if !slices.Contains(att.Lineage, ag) {
			att.Lineage = append(att.Lineage, ag)
		}
	}
	if !added {
		return false
	}
	if h.Root != agent && !slices.Contains(att.Roots, h.Root) {
		att.Roots = append(att.Roots, h.Root)
	}
	att.Depth = max(att.Depth, h.Depth)
	return true
}

func tokenErrorText(err error) string {
	switch {
	case errors.Is(err, ErrExpiredToken):
		return ErrExpiredToken.Error()
	case errors.Is(err, ErrTokenAgent):
		return ErrTokenAgent.Error()
	case errors.Is(err, ErrRevokedToken):
		return ErrRevokedToken.Error()
	default:
		return ErrInvalidToken.Error()
	}
}

// inbound returns the open, unexpired hops delegated to agent, only when
// the agent is registered with delegation_strict (the default).
func (e *Enricher) inbound(ctx context.Context, agent string) ([]Hop, error) {
	rows, err := e.pool.Query(ctx, `SELECT `+hopCols+` FROM delegations d
		WHERE d.to_agent = $1 AND d.status = 'open' AND d.expires_at > $2
		  AND EXISTS (SELECT 1 FROM agents ag WHERE ag.agent_id = d.to_agent AND ag.delegation_strict)
		ORDER BY d.created_at, d.delegation_id`, agent, e.now())
	if err != nil {
		return nil, fmt.Errorf("open inbound delegations for %s: %w", agent, err)
	}
	hops, err := collectHops(rows)
	if err != nil {
		return nil, fmt.Errorf("open inbound delegations for %s: %w", agent, err)
	}
	return hops, nil
}

// fill sets Chain: the upstream agents of the lineage (root first, each
// once, the executor excluded: its own level and profile are input.agent and
// input.access already), with their levels and their profiles for the
// action's system.
func (e *Enricher) fill(ctx context.Context, att *Attribution, a action.Action) error {
	var ids []string
	for _, ag := range att.Lineage {
		if ag != a.AgentID && !slices.Contains(ids, ag) {
			ids = append(ids, ag)
		}
	}
	att.Chain = []HopState{}
	if len(ids) == 0 {
		return nil
	}
	states, err := LoadHopStates(ctx, e.pool, ids, a.System)
	if err != nil {
		return err
	}
	att.Chain = states
	return nil
}

// LoadHopStates returns each agent's control state and access profile for
// system in one query, in the order given. Semantics match control.Get (an
// unknown agent is unregistered at ISOLATED) and access.PGStore.PolicyInput
// (version 0 and a null profile when none, or for systems without profiles).
func LoadHopStates(ctx context.Context, pool *pgxpool.Pool, agents []string, system string) ([]HopState, error) {
	rows, err := pool.Query(ctx, `
		SELECT ids.agent_id, ag.level, p.version, p.profile_json
		FROM unnest($1::text[]) WITH ORDINALITY AS ids(agent_id, ord)
		LEFT JOIN agents ag ON ag.agent_id = ids.agent_id
		LEFT JOIN LATERAL (
			SELECT ap.version, ap.profile_json FROM access_profiles ap
			WHERE $3 AND ap.agent_id = ids.agent_id AND ap.system = $2
			ORDER BY ap.version DESC LIMIT 1
		) p ON true
		ORDER BY ids.ord`, agents, system, access.KnownSystem(system))
	if err != nil {
		return nil, fmt.Errorf("delegation chain state: %w", err)
	}
	defer rows.Close()
	out := make([]HopState, 0, len(agents))
	for rows.Next() {
		var id string
		var lvl *int16
		var version *int
		var profile []byte
		if err := rows.Scan(&id, &lvl, &version, &profile); err != nil {
			return nil, fmt.Errorf("delegation chain state: %w", err)
		}
		st := HopState{AgentID: id, Registered: lvl != nil, Level: int(control.Isolated)}
		if lvl != nil {
			st.Level = int(*lvl)
		}
		st.LevelName = control.Level(st.Level).String()
		pi := access.PolicyInput{System: system, Version: 0, Profile: json.RawMessage("null")}
		if version != nil && len(profile) > 0 {
			pi.Version, pi.Profile = *version, json.RawMessage(profile)
		}
		st.Access = &pi
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("delegation chain state: %w", err)
	}
	if len(out) != len(agents) {
		return nil, fmt.Errorf("delegation chain state: got %d of %d agents", len(out), len(agents))
	}
	return out, nil
}
