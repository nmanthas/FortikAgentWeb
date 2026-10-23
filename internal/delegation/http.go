package delegation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

// Handler serves the read-only delegation view for the console:
//
//	GET /v1/agents/{id}/delegations?direction=inbound|outbound|all&status=&limit=
//
// Allowed for auditor or security, or the agent's owner (sponsor). It
// returns the hops (never tokens) and the recent refusals by the delegation
// rules (POL-601..604) in which the agent executed or appeared in the chain.
type Handler struct {
	store *PGStore
	log   *slog.Logger
}

// NewHandler returns the API handler; mount with api.Server.Mount(h.Register).
func NewHandler(store *PGStore, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{store: store, log: log}
}

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/agents/{id}/delegations", h.list)
}

// Blocked is one refusal by a delegation rule, as the console lists it.
type Blocked struct {
	ActionID string          `json:"action_id"`
	TS       time.Time       `json:"ts"`
	Executor string          `json:"executor"`
	System   string          `json:"system"`
	Verb     string          `json:"verb"`
	RuleID   string          `json:"rule_id"`
	Reason   string          `json:"reason"`
	Context  json.RawMessage `json:"delegation"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, ok := authz.From(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !agentIDPattern.MatchString(id) {
		httpx.WriteError(w, http.StatusNotFound, "agent not found")
		return
	}
	sponsor, exists, err := h.sponsor(r.Context(), id)
	if err != nil {
		h.internal(w, err)
		return
	}
	if !p.Has(authz.RoleSecurity) && !p.Has(authz.RoleAuditor) && !(exists && p.IsOwner(sponsor)) {
		httpx.WriteError(w, http.StatusForbidden, "auditor, security or the agent's owner required")
		return
	}
	if !exists {
		httpx.WriteError(w, http.StatusNotFound, "agent not found")
		return
	}
	q := r.URL.Query()
	dir := q.Get("direction")
	if dir == "" {
		dir = DirAll
	}
	if dir != DirInbound && dir != DirOutbound && dir != DirAll {
		httpx.WriteError(w, http.StatusBadRequest, "direction must be inbound, outbound or all")
		return
	}
	status := q.Get("status")
	switch status {
	case "", StatusOpen, StatusClosed, StatusExpired, StatusRefused:
	default:
		httpx.WriteError(w, http.StatusBadRequest, "status must be open, closed, expired or refused")
		return
	}
	limit := 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			httpx.WriteError(w, http.StatusBadRequest, "limit must be between 1 and 500")
			return
		}
		limit = n
	}
	hops, err := h.store.List(r.Context(), id, dir, status, limit)
	if err != nil {
		h.internal(w, err)
		return
	}
	// Owners without auditor/security see only the agent ids of a recorded
	// chain, not other owners' agents' levels and access profiles (which
	// GET /v1/agents/{id}/access refuses them).
	full := p.Has(authz.RoleSecurity) || p.Has(authz.RoleAuditor)
	blocked, err := h.blocked(r.Context(), id, limit, full)
	if err != nil {
		h.internal(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"agent_id": id, "hops": hops, "blocked": blocked})
}

func (h *Handler) sponsor(ctx context.Context, id string) (string, bool, error) {
	var s string
	err := h.store.pool.QueryRow(ctx, `SELECT sponsor FROM agents WHERE agent_id = $1`, id).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return s, err == nil, err
}

// blocked lists recent refusals by the delegation rules where the agent is
// the executor or an upstream agent of the recorded chain.
func (h *Handler) blocked(ctx context.Context, id string, limit int, full bool) ([]Blocked, error) {
	rows, err := h.store.pool.Query(ctx, `
		SELECT action_id, ts, agent_id, system, verb, rule_id, reason,
		       COALESCE(decision_json->'context'->'delegation', 'null'::jsonb)
		FROM actions
		WHERE rule_id IN ('POL-601', 'POL-602', 'POL-603', 'POL-604')
		  AND (agent_id = $1 OR decision_json->'context'->'delegation'->'chain' @> jsonb_build_array(jsonb_build_object('agent_id', $1::text)))
		ORDER BY ts DESC LIMIT $2`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Blocked{}
	for rows.Next() {
		var b Blocked
		var raw []byte
		if err := rows.Scan(&b.ActionID, &b.TS, &b.Executor, &b.System, &b.Verb, &b.RuleID, &b.Reason, &raw); err != nil {
			return nil, err
		}
		b.TS = b.TS.UTC()
		b.Context = json.RawMessage(raw)
		if !full {
			if b.Context, err = redactContext(raw); err != nil {
				return nil, err
			}
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// redactContext projects a recorded delegation context to fields that name
// no other agent's level or access profile: chain entries keep agent_id only.
func redactContext(raw []byte) (json.RawMessage, error) {
	var c map[string]any
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("decode delegation context: %w", err)
	}
	if c == nil {
		return json.RawMessage("null"), nil
	}
	out := map[string]any{}
	for _, k := range []string{"present", "source", "delegation_id", "depth", "root", "token_error", "max_depth"} {
		if v, ok := c[k]; ok {
			out[k] = v
		}
	}
	chain := []map[string]any{}
	if entries, ok := c["chain"].([]any); ok {
		for _, e := range entries {
			if m, ok := e.(map[string]any); ok {
				chain = append(chain, map[string]any{"agent_id": m["agent_id"]})
			}
		}
	}
	out["chain"] = chain
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (h *Handler) internal(w http.ResponseWriter, err error) {
	h.log.Error("delegation API failed", "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal error")
}
