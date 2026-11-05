package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"fortik/internal/authz"
	"fortik/internal/diary"
	"fortik/internal/policy"
)

// EventEnforcementChanged records a change of an agent's enforcement mode.
const EventEnforcementChanged = "enforcement.changed"

// mode is the deployment's enforcement mode ("enforce" unless configured).
func (s *Server) mode() string {
	if s.EnforcementMode == policy.ObserveMode {
		return policy.ObserveMode
	}
	return policy.EnforceMode
}

type enforcementRequest struct {
	Mode   string `json:"mode"` // default | observe | enforce
	Reason string `json:"reason"`
}

// setEnforcement: PUT /v1/agents/{id}/enforcement (security). Puts one agent
// in observe mode (Fortik records what it would enforce, and does not), in
// enforce mode, or back to the deployment default. Recorded in the Diary in
// the same transaction.
func (s *Server) setEnforcement(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	id := r.PathValue("id")
	var req enforcementRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch req.Mode {
	case "default", policy.ObserveMode, policy.EnforceMode:
	default:
		writeError(w, http.StatusBadRequest, "mode must be default, observe or enforce")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required")
		return
	}
	if err := plainText("reason", req.Reason, maxReason); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	var from string
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT enforcement FROM agents WHERE agent_id = $1 FOR UPDATE`, id).Scan(&from); err != nil {
			return err
		}
		if from == req.Mode {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE agents SET enforcement = $2, updated_at = now() WHERE agent_id = $1`, id, req.Mode); err != nil {
			return err
		}
		_, err := s.Diary.AppendTx(ctx, tx, diary.Event{AgentID: id, EventType: EventEnforcementChanged, Actor: p.Actor(),
			Data: map[string]any{"from": from, "to": req.Mode, "deployment_mode": s.mode(), "reason": req.Reason}})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	eff := req.Mode
	if eff == "default" {
		eff = s.mode()
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_id": id, "from": from, "enforcement": req.Mode, "effective_enforcement": eff})
}

// getEnforcement: GET /v1/enforcement (auditor or security): the deployment
// mode and the agents that override it, for the console banner.
func (s *Server) getEnforcement(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	var observe, enforce []string
	rows, err := s.Pool.Query(r.Context(), `SELECT agent_id, enforcement FROM agents WHERE enforcement <> 'default' ORDER BY agent_id LIMIT 1000`)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, m string
		if err := rows.Scan(&id, &m); err != nil {
			s.internal(w, err)
			return
		}
		if m == policy.ObserveMode {
			observe = append(observe, id)
		} else {
			enforce = append(enforce, id)
		}
	}
	if err := rows.Err(); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": s.mode(), "observe_agents": nonNilStrings(observe), "enforce_agents": nonNilStrings(enforce)})
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
