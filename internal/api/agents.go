package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"fortik/internal/population"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/authz"
	"fortik/internal/control"
	"fortik/internal/diary"
)

// Diary event types written by the agent management API (Phase 2).
const (
	EventAgentUpdated      = "agent.updated"
	EventAgentTokenIssued  = "agent.token_issued"
	EventAgentTokenRevoked = "agent.token_revoked"
)

// agentIDPattern mirrors the agents.agent_id CHECK constraint.
var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)

const maxReason = 1000

// --- views ------------------------------------------------------------------

// agentViewSQL selects one JSON object per agent with the console fields:
// registry data, level, owner, suspension, memory access, today's/24h
// activity and pending holds.
// $1 = start of the current UTC day, $2 = now - 24h.
const agentViewSQL = `
	SELECT jsonb_build_object('agent_id', g.agent_id, 'name', g.name, 'type', g.type, 'platform', g.platform,
		'sponsor', g.sponsor, 'owner', g.sponsor, 'business_unit', g.business_unit, 'workspace_user', g.workspace_user,
		'copy_cap', g.copy_cap, 'level', g.level,
		'level_name', (ARRAY['FULL','SUPERVISED','READ_ONLY','ISOLATED','QUARANTINED','KILLED'])[g.level + 1],
		'level_changed_at', g.level_changed_at, 'discovered', g.discovered,
		'created_at', g.created_at, 'updated_at', g.updated_at,
		'actions_today', COALESCE(t.n, 0),
		'worst_class_24h', d.worst,
		'systems_24h', COALESCE(d.systems, '[]'::jsonb),
		'held_pending', COALESCE(hp.n, 0),
		'suspended', g.suspended_at IS NOT NULL, 'suspended_at', g.suspended_at,
		'suspended_by', g.suspended_by, 'suspended_reason', g.suspended_reason,
		'memory_access', COALESCE(ma.mode, 'full'), 'memory_access_changed_by', ma.changed_by)
	FROM agents g
	LEFT JOIN memory_access ma ON ma.agent_id = g.agent_id
	LEFT JOIN LATERAL (SELECT count(*) AS n FROM actions a WHERE a.agent_id = g.agent_id AND a.ts >= $1) t ON true
	LEFT JOIN LATERAL (
		SELECT CASE WHEN bool_or(a.class = 'red') THEN 'red' WHEN bool_or(a.class = 'yellow') THEN 'yellow'
		            WHEN count(*) > 0 THEN 'green' END AS worst,
		       jsonb_agg(DISTINCT a.system) FILTER (WHERE a.system IS NOT NULL) AS systems
		FROM actions a WHERE a.agent_id = g.agent_id AND a.ts >= $2) d ON true
	LEFT JOIN LATERAL (SELECT count(*) AS n FROM held_actions h WHERE h.agent_id = g.agent_id AND h.outcome = 'pending') hp ON true`

func dayStart(now time.Time) time.Time {
	y, m, d := now.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	rows, err := s.Pool.Query(r.Context(), agentViewSQL+` ORDER BY g.agent_id`, dayStart(now), now.Add(-24*time.Hour))
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var j json.RawMessage
		if err := rows.Scan(&j); err != nil {
			s.internal(w, err)
			return
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"agents": out})
}

type profileVersion struct {
	Version   int       `json:"version"`
	ChangedBy string    `json:"changed_by"`
	ChangedAt time.Time `json:"changed_at"`
}

// getAgent: the agent, its level, 24h counts by class, pending holds,
// current access profile version per system and integration readiness.
func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	now := time.Now()
	var agent json.RawMessage
	err := s.Pool.QueryRow(ctx, agentViewSQL+` WHERE g.agent_id = $3`, dayStart(now), now.Add(-24*time.Hour), id).Scan(&agent)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}

	counts := map[string]int64{"green": 0, "yellow": 0, "red": 0}
	if err := s.groupCounts(ctx, counts, `SELECT class, count(*) FROM actions WHERE agent_id = $1 AND ts >= $2 GROUP BY class`,
		id, now.Add(-24*time.Hour)); err != nil {
		s.internal(w, err)
		return
	}

	held := []json.RawMessage{}
	rows, err := s.Pool.Query(ctx, `
		SELECT jsonb_build_object('action_id', h.action_id, 'rule_id', h.rule_id, 'reason', h.reason,
			'approver_role', h.approver_role, 'expires_at', h.expires_at, 'created_at', h.created_at,
			'class', a.class, 'decision', a.decision, 'system', a.system, 'verb', a.verb)
		FROM held_actions h JOIN actions a USING (action_id)
		WHERE h.agent_id = $1 AND h.outcome = 'pending' ORDER BY h.created_at DESC LIMIT 50`, id)
	if err != nil {
		s.internal(w, err)
		return
	}
	for rows.Next() {
		var j json.RawMessage
		if err := rows.Scan(&j); err != nil {
			rows.Close()
			s.internal(w, err)
			return
		}
		held = append(held, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.internal(w, err)
		return
	}

	profiles := map[string]profileVersion{}
	rows, err = s.Pool.Query(ctx, `
		SELECT DISTINCT ON (system) system, version, changed_by, changed_at
		FROM access_profiles WHERE agent_id = $1 ORDER BY system, version DESC`, id)
	if err != nil {
		s.internal(w, err)
		return
	}
	for rows.Next() {
		var sys string
		var pv profileVersion
		if err := rows.Scan(&sys, &pv.Version, &pv.ChangedBy, &pv.ChangedAt); err != nil {
			rows.Close()
			s.internal(w, err)
			return
		}
		profiles[sys] = pv
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.internal(w, err)
		return
	}

	integrations := map[string]string{}
	rows, err = s.Pool.Query(ctx, `SELECT key, status FROM integrations ORDER BY key`)
	if err != nil {
		s.internal(w, err)
		return
	}
	for rows.Next() {
		var k, st string
		if err := rows.Scan(&k, &st); err != nil {
			rows.Close()
			s.internal(w, err)
			return
		}
		integrations[k] = st
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.internal(w, err)
		return
	}

	writeJSON(w, 200, map[string]any{
		"agent": agent, "counts_24h": counts, "held_pending": len(held), "held": held,
		"access_profiles": profiles, "integrations": integrations, "token_issued": s.tokenIssued(ctx, id),
	})
}

// groupCounts runs a "SELECT key, count" query into m.
func (s *Server) groupCounts(ctx context.Context, m map[string]int64, sql string, args ...any) error {
	rows, err := s.Pool.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		m[k] = n
	}
	return rows.Err()
}

// --- registration -------------------------------------------------------------

type agentFields struct {
	Name          *string `json:"name"`
	Type          *string `json:"type"`
	Platform      *string `json:"platform"`
	Sponsor       *string `json:"sponsor"`
	BusinessUnit  *string `json:"business_unit"`
	WorkspaceUser *string `json:"workspace_user"`
	CopyCap       *int    `json:"copy_cap"`
}

type createAgentRequest struct {
	AgentID string `json:"agent_id"`
	agentFields
}

// validate checks every field that is present.
func (f agentFields) validate() error {
	for name, v := range map[string]*string{"name": f.Name, "type": f.Type, "platform": f.Platform, "business_unit": f.BusinessUnit} {
		if v != nil {
			if err := plainText(name, *v, 200); err != nil {
				return err
			}
		}
	}
	for name, v := range map[string]*string{"sponsor": f.Sponsor, "workspace_user": f.WorkspaceUser} {
		if v == nil || *v == "" {
			continue
		}
		if err := plainText(name, *v, 254); err != nil {
			return err
		}
		if !looksLikeEmail(*v) {
			return fmt.Errorf("%s must be an email address (owner matching and Workspace impersonation use it)", name)
		}
	}
	if f.CopyCap != nil && (*f.CopyCap < 0 || *f.CopyCap > 10000) {
		return errors.New("copy_cap must be between 0 and 10000")
	}
	return nil
}

func plainText(field, v string, max int) error {
	if len(v) > max {
		return fmt.Errorf("%s is longer than %d bytes", field, max)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains control characters", field)
		}
	}
	return nil
}

func looksLikeEmail(v string) bool {
	local, domain, ok := strings.Cut(v, "@")
	return ok && local != "" && domain != "" && !strings.ContainsAny(domain, "@ ") && !strings.Contains(local, " ")
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

func (s *Server) createAgent(w http.ResponseWriter, r *http.Request) {
	var req createAgentRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !agentIDPattern.MatchString(req.AgentID) {
		writeError(w, http.StatusBadRequest, "agent_id must match "+agentIDPattern.String())
		return
	}
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	copyCap := 1
	if req.CopyCap != nil {
		copyCap = *req.CopyCap
	}
	sponsor, wsUser := strings.ToLower(str(req.Sponsor)), strings.ToLower(str(req.WorkspaceUser))
	actor := principalFrom(r.Context()).Actor()
	ctx := r.Context()
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if s.AgentGuard != nil {
			if err := s.AgentGuard.CheckAgentRegistrationTx(ctx, tx, str(req.Type)); err != nil {
				return &guardError{err}
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO agents (agent_id, name, type, platform, sponsor, business_unit, workspace_user, copy_cap)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			req.AgentID, str(req.Name), str(req.Type), str(req.Platform), sponsor, str(req.BusinessUnit), wsUser, copyCap); err != nil {
			return err
		}
		_, err := s.Diary.AppendTx(ctx, tx, diary.Event{AgentID: req.AgentID, EventType: diary.EventAgentRegistered, Actor: actor,
			Data: map[string]any{"name": str(req.Name), "type": str(req.Type), "platform": str(req.Platform), "sponsor": sponsor,
				"business_unit": str(req.BusinessUnit), "workspace_user": wsUser, "copy_cap": copyCap, "new": true, "via": "api"}})
		return err
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		writeError(w, http.StatusConflict, "agent already registered")
		return
	}
	if s.writeGuardError(w, err) {
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.writeAgent(w, r, req.AgentID, http.StatusCreated)
}

func (s *Server) patchAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req agentFields
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error()+" (agent_id and level cannot be changed here)")
		return
	}
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := principalFrom(r.Context()).Actor()
	ctx := r.Context()
	found := true
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var cur struct {
			name, typ, platform, sponsor, bu, ws string
			copyCap                              int
		}
		err := tx.QueryRow(ctx, `SELECT name, type, platform, sponsor, business_unit, workspace_user, copy_cap
			FROM agents WHERE agent_id = $1 FOR UPDATE`, id).
			Scan(&cur.name, &cur.typ, &cur.platform, &cur.sponsor, &cur.bu, &cur.ws, &cur.copyCap)
		if errors.Is(err, pgx.ErrNoRows) {
			found = false
			return nil
		}
		if err != nil {
			return err
		}
		changes := map[string]any{}
		set := func(field string, p *string, cur *string, lower bool) {
			if p == nil {
				return
			}
			v := str(p)
			if lower {
				v = strings.ToLower(v)
			}
			if v != *cur {
				changes[field] = map[string]any{"old": *cur, "new": v}
				*cur = v
			}
		}
		set("name", req.Name, &cur.name, false)
		if req.Type != nil && str(req.Type) != cur.typ && s.AgentGuard != nil {
			// Check exactly the value that will be stored (trimmed).
			if err := s.AgentGuard.CheckAgentRegistrationTx(ctx, tx, str(req.Type)); err != nil {
				return &guardError{err}
			}
		}
		set("type", req.Type, &cur.typ, false)
		set("platform", req.Platform, &cur.platform, false)
		set("sponsor", req.Sponsor, &cur.sponsor, true)
		set("business_unit", req.BusinessUnit, &cur.bu, false)
		set("workspace_user", req.WorkspaceUser, &cur.ws, true)
		if req.CopyCap != nil && *req.CopyCap != cur.copyCap {
			changes["copy_cap"] = map[string]any{"old": cur.copyCap, "new": *req.CopyCap}
			cur.copyCap = *req.CopyCap
		}
		if len(changes) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE agents SET name = $2, type = $3, platform = $4, sponsor = $5, business_unit = $6,
			workspace_user = $7, copy_cap = $8, updated_at = now() WHERE agent_id = $1`,
			id, cur.name, cur.typ, cur.platform, cur.sponsor, cur.bu, cur.ws, cur.copyCap); err != nil {
			return err
		}
		_, err = s.Diary.AppendTx(ctx, tx, diary.Event{AgentID: id, EventType: EventAgentUpdated, Actor: actor,
			Data: map[string]any{"changes": changes}})
		return err
	})
	if s.writeGuardError(w, err) {
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	s.writeAgent(w, r, id, http.StatusOK)
}

func (s *Server) writeAgent(w http.ResponseWriter, r *http.Request, id string, code int) {
	now := time.Now()
	var agent json.RawMessage
	if err := s.Pool.QueryRow(r.Context(), agentViewSQL+` WHERE g.agent_id = $3`, dayStart(now), now.Add(-24*time.Hour), id).Scan(&agent); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, code, map[string]any{"agent": agent})
}

// --- control ladder -----------------------------------------------------------

type levelRequest struct {
	Level  string `json:"level"`
	Reason string `json:"reason"`
}

// errLevelRule is a refusal by the ladder rules (design §9).
type errLevelRule struct {
	code int
	msg  string
}

func (e errLevelRule) Error() string { return e.msg }

// checkLevelChange applies design §9 to a principal moving an agent from
// `from` to `to`:
//
//	step down to any level below KILLED: security or the owner
//	step up exactly one level:           security or the owner
//	set KILLED or leave KILLED:          security only
func checkLevelChange(p authz.Principal, sponsor string, from, to control.Level) error {
	isSec := p.Has(authz.RoleSecurity)
	if !isSec && !p.IsOwner(sponsor) {
		return errLevelRule{http.StatusForbidden, "changing an agent's level needs the security role or ownership of the agent"}
	}
	if (to == control.Killed || from == control.Killed) && from != to && !isSec {
		return errLevelRule{http.StatusForbidden, "only the security role may set or leave KILLED"}
	}
	if to < from && from-to != 1 {
		return errLevelRule{http.StatusForbidden, fmt.Sprintf("step up exactly one level at a time (from %s the next step up is %s)", from, from-1)}
	}
	return nil
}

// setLevel: PUT /v1/agents/{id}/level. The rule check and the update run in
// one transaction with the agent row locked, so a concurrent change (for
// example security killing the agent) cannot be undone by a stale owner
// decision. The Diary event is written in the same transaction.
func (s *Server) setLevel(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	var req levelRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
	to, err := control.ParseLevel(req.Level)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	actor := p.Actor()
	var from control.Level
	changed := false
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var lvl int16
		var sponsor string
		if err := tx.QueryRow(ctx, `SELECT level, sponsor FROM agents WHERE agent_id = $1 FOR UPDATE`, id).Scan(&lvl, &sponsor); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errLevelRule{http.StatusNotFound, "agent not found"}
			}
			return err
		}
		from = control.Level(lvl)
		if err := checkLevelChange(p, sponsor, from, to); err != nil {
			return err
		}
		if from == to {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE agents SET level = $2, level_changed_at = now(), updated_at = now() WHERE agent_id = $1`, id, int16(to)); err != nil {
			return err
		}
		dir := "down"
		if to < from {
			dir = "up"
		}
		// Same event shape as control.Store.SetLevel, plus how it was made.
		_, err := s.Diary.AppendTx(ctx, tx, diary.Event{AgentID: id, EventType: diary.EventLevelChanged, Actor: actor,
			Data: map[string]any{"from": from.String(), "to": to.String(), "direction": dir, "automatic": false,
				"reason": req.Reason, "via": "api", "as_owner": !p.Has(authz.RoleSecurity)}})
		changed = err == nil
		return err
	})
	var rule errLevelRule
	if errors.As(err, &rule) {
		writeError(w, rule.code, rule.msg)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	resp := map[string]any{"agent_id": id, "from": from.String(), "to": to.String(), "changed": changed}
	// Revoke on every request at QUARANTINED/KILLED, including a repeat of
	// the current level: that is how a failed revocation is retried.
	if to >= control.Quarantined {
		resp["revocation"], resp["revocation_error"] = s.revokeAll(ctx, id, actor, req.Reason)
	}
	writeJSON(w, http.StatusOK, resp)
}

// revokeAll calls the injected Revoker best effort (the level change is
// already committed and enforced by Decide); it returns the per-system
// result and an error summary ("" when none).
func (s *Server) revokeAll(ctx context.Context, agentID, actor, reason string) (map[string]string, string) {
	if s.Revoker == nil {
		s.Log.Warn("agent quarantined/killed but no credential broker is configured; nothing to revoke", "agent_id", agentID)
		return map[string]string{}, "no credential broker configured: issued credentials were not revoked"
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	res, err := s.Revoker.RevokeAll(rctx, agentID, actor, reason)
	if res == nil {
		res = map[string]string{}
	}
	if err != nil {
		s.Log.Error("credential revocation incomplete", "agent_id", agentID, "err", err)
		return res, "revocation incomplete: " + truncate(err.Error(), 300)
	}
	return res, ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// guardError marks a refusal by the AgentGuard (registration surge guard).
type guardError struct{ err error }

func (g *guardError) Error() string { return g.err.Error() }
func (g *guardError) Unwrap() error { return g.err }

// writeGuardError maps AgentGuard refusals: a surge (population.ErrAgentSurge)
// is 409 with the reason; any other guard failure refuses (503, fail closed).
func (s *Server) writeGuardError(w http.ResponseWriter, err error) bool {
	var g *guardError
	if !errors.As(err, &g) {
		return false
	}
	if errors.Is(err, population.ErrAgentSurge) {
		writeError(w, http.StatusConflict, err.Error())
	} else {
		s.Log.Error("agent registration guard failed; refusing", "err", err)
		writeError(w, http.StatusServiceUnavailable, "agent registration guard unavailable: refusing")
	}
	return true
}
