package shadow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/alerts"
	"fortik/internal/control"
	"fortik/internal/diary"
)

// AlertRaiser raises an alert inside a transaction. *alerts.PGStore satisfies it.
type AlertRaiser interface {
	RaiseTx(ctx context.Context, tx pgx.Tx, a alerts.Alert) (alerts.Alert, error)
}

const findingColumns = `finding_id, system, kind, credential_ref, holder, used_by_software, evidence,
	COALESCE(agent_id, ''), status, first_seen, last_seen, COALESCE(updated_by, '')`

func scanFinding(row pgx.Row) (Finding, error) {
	var f Finding
	var ev []byte
	err := row.Scan(&f.FindingID, &f.System, &f.Kind, &f.CredentialRef, &f.Holder, &f.UsedBySoftware, &ev,
		&f.AgentID, &f.Status, &f.FirstSeen, &f.LastSeen, &f.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return Finding{}, ErrNotFound
	}
	if err != nil {
		return Finding{}, err
	}
	f.Evidence = json.RawMessage(ev)
	if len(f.Evidence) == 0 {
		f.Evidence = json.RawMessage(`{}`)
	}
	return f, nil
}

// Filter selects findings for List.
type Filter struct {
	Status  string
	System  string
	Kind    string
	AgentID string
	Limit   int // default 100, max 1000
}

var validStatus = map[string]bool{StatusOpen: true, StatusFlagged: true, StatusRevoked: true, StatusDismissed: true, StatusRegistered: true}

var validSystem = map[string]bool{SystemPostgres: true, SystemGitHub: true, SystemAWS: true, SystemGoogle: true, SystemTraffic: true}

func listFindings(ctx context.Context, pool *pgxpool.Pool, f Filter) ([]Finding, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 1000 {
		f.Limit = 1000
	}
	var where []string
	var args []any
	add := func(col, v string) {
		if v == "" {
			return
		}
		args = append(args, v)
		where = append(where, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	add("status", f.Status)
	add("system", f.System)
	add("kind", f.Kind)
	add("agent_id", f.AgentID)
	q := `SELECT ` + findingColumns + ` FROM shadow_findings`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, f.Limit)
	q += fmt.Sprintf(" ORDER BY last_seen DESC, finding_id LIMIT $%d", len(args))
	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("shadow: list findings: %w", err)
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		fd, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, fd)
	}
	return out, rows.Err()
}

func getFinding(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id string, forUpdate bool) (Finding, error) {
	sql := `SELECT ` + findingColumns + ` FROM shadow_findings WHERE finding_id = $1`
	if forUpdate {
		sql += " FOR UPDATE"
	}
	return scanFinding(q.QueryRow(ctx, sql, id))
}

// ---- upsert ----

type upsertIn struct {
	system, kind, ref, holder string
	software                  bool
	integration, label        string
	// evidence replaces the stored evidence (scans); merge, when set,
	// computes it from the stored evidence instead (traffic counts).
	evidence map[string]any
	merge    func(old map[string]any) map[string]any
	// mayFlag decides, for a software credential whose finding is open (or
	// revoked and seen live again), whether to register the discovered
	// agent now. nil = always.
	mayFlag func(f Finding, ev map[string]any) bool
	// reactivate: the credential was seen LIVE in this scan, so a revoked
	// finding is reopened (the credential came back).
	reactivate bool
	actor      string
	// alertDedup overrides the alert dedup key (traffic floods bump one alert).
	alertDedup string
}

type upsertOut struct {
	finding Finding
	isNew   bool
	flagged bool
	agentIn bool // the discovered agent was created now
}

// boundEvidence keeps the evidence JSON under maxEvidenceBytes: list and
// object values are dropped first (scalars kept) and "truncated" is set.
func boundEvidence(ev map[string]any) []byte {
	if ev == nil {
		ev = map[string]any{}
	}
	b, err := json.Marshal(ev)
	if err == nil && len(b) <= maxEvidenceBytes {
		return b
	}
	small := map[string]any{"truncated": true}
	keys := make([]string, 0, len(ev))
	for k := range ev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := ev[k].(type) {
		case string:
			small[k] = Clean(v, 512)
		case bool, int, int64, float64, nil:
			small[k] = v
		}
	}
	b, err = json.Marshal(small)
	if err != nil || len(b) > maxEvidenceBytes {
		return []byte(`{"truncated": true}`)
	}
	return b
}

func decodeEvidence(raw json.RawMessage) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

func (s *Service) upsertTx(ctx context.Context, tx pgx.Tx, in upsertIn) (upsertOut, error) {
	var out upsertOut
	in.ref = Clean(in.ref, maxRefLen)
	in.holder = Clean(in.holder, maxHolderLen)
	if in.ref == "" || !validSystem[in.system] || in.kind == "" {
		return out, fmt.Errorf("%w: credential needs a system, kind and identifier", ErrInvalid)
	}
	id := FindingID(in.system, in.kind, in.ref)
	ev := in.evidence
	if in.merge != nil {
		ev = in.merge(nil)
	}
	if ev == nil {
		ev = map[string]any{}
	}
	if in.integration != "" {
		ev["integration"] = in.integration
	}
	var inserted string
	err := tx.QueryRow(ctx, `INSERT INTO shadow_findings (finding_id, system, kind, credential_ref, holder, used_by_software, evidence, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (system, kind, credential_ref) DO NOTHING RETURNING finding_id`,
		id, in.system, in.kind, in.ref, in.holder, in.software, boundEvidence(ev), in.actor).Scan(&inserted)
	switch {
	case err == nil:
		out.isNew = true
	case errors.Is(err, pgx.ErrNoRows):
	default:
		return out, fmt.Errorf("shadow: insert finding: %w", err)
	}
	f, err := scanFinding(tx.QueryRow(ctx, `SELECT `+findingColumns+` FROM shadow_findings
		WHERE system = $1 AND kind = $2 AND credential_ref = $3 FOR UPDATE`, in.system, in.kind, in.ref))
	if err != nil {
		return out, fmt.Errorf("shadow: lock finding: %w", err)
	}
	reopened := false
	if !out.isNew {
		if in.merge != nil {
			ev = in.merge(decodeEvidence(f.Evidence))
			if in.integration != "" {
				ev["integration"] = in.integration
			}
		}
		holder := f.Holder
		if in.holder != "" {
			holder = in.holder
		}
		status := f.Status
		if in.reactivate && f.Status == StatusRevoked {
			status, reopened = StatusOpen, true
		}
		f, err = scanFinding(tx.QueryRow(ctx, `UPDATE shadow_findings SET holder = $2, evidence = $3,
			used_by_software = used_by_software OR $4, last_seen = now(), status = $5
			WHERE finding_id = $1 RETURNING `+findingColumns, f.FindingID, holder, boundEvidence(ev), in.software, status))
		if err != nil {
			return out, fmt.Errorf("shadow: update finding: %w", err)
		}
	}
	flag := f.UsedBySoftware && f.Status == StatusOpen
	if flag && in.mayFlag != nil && !in.mayFlag(f, decodeEvidence(f.Evidence)) {
		flag = false
	}
	data := map[string]any{"finding_id": f.FindingID, "system": f.System, "kind": f.Kind, "credential_ref": f.CredentialRef,
		"holder": f.Holder, "used_by_software": f.UsedBySoftware, "new": out.isNew}
	if in.integration != "" {
		data["integration"] = in.integration
	}
	if reopened {
		data["reactivated"] = true
		data["note"] = "a credential recorded as revoked was seen live again"
	}
	if flag {
		agentID := f.AgentID
		if agentID == "" {
			agentID = AgentID(f.System, f.Kind, f.CredentialRef)
		}
		label := Clean(in.label, 200)
		if label == "" {
			label = Clean(f.System+" "+f.Kind+" "+f.CredentialRef, 200)
		}
		created, err := ensureDiscoveredAgent(ctx, tx, agentID, label, f.System)
		if err != nil {
			return out, err
		}
		f, err = scanFinding(tx.QueryRow(ctx, `UPDATE shadow_findings SET status = $2, agent_id = $3, updated_by = $4
			WHERE finding_id = $1 RETURNING `+findingColumns, f.FindingID, StatusFlagged, agentID, in.actor))
		if err != nil {
			return out, fmt.Errorf("shadow: flag finding: %w", err)
		}
		out.flagged, out.agentIn = true, created
		data["status"], data["agent_id"] = f.Status, agentID
		var events []diary.Event
		if created {
			events = append(events, diary.Event{AgentID: agentID, EventType: EventAgentFound, Actor: in.actor, Data: map[string]any{
				"finding_id": f.FindingID, "system": f.System, "kind": f.Kind, "credential_ref": f.CredentialRef, "holder": f.Holder,
				"name": label, "level": control.Isolated.String(), "sponsor": "", "discovered": true, "copy_cap": 0}})
		}
		events = append(events, diary.Event{AgentID: agentID, EventType: EventFound, Actor: in.actor, Data: data})
		if _, err := s.diary.AppendTx(ctx, tx, events...); err != nil {
			return out, err
		}
		dedup := in.alertDedup
		if dedup == "" {
			dedup = "shadow:" + f.FindingID
		}
		details, _ := json.Marshal(map[string]any{"finding_id": f.FindingID, "system": f.System, "kind": f.Kind,
			"credential_ref": f.CredentialRef, "holder": f.Holder, "integration": in.integration, "agent_id": agentID})
		if _, err := s.alerts.RaiseTx(ctx, tx, alerts.Alert{Kind: AlertKindShadow, Severity: alerts.SevHigh, AgentID: agentID,
			AgentType: AgentTypeShadow, DedupKey: dedup, Details: details,
			Summary: fmt.Sprintf("Shadow agent discovered: %s %s %q is used by software; agent %s registered ISOLATED with no owner, credential flagged for revocation",
				f.System, f.Kind, f.CredentialRef, agentID)}); err != nil {
			return out, fmt.Errorf("shadow: raise alert: %w", err)
		}
	} else if out.isNew || reopened {
		data["status"] = f.Status
		if _, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: f.AgentID, EventType: EventFound, Actor: in.actor, Data: data}); err != nil {
			return out, err
		}
	}
	out.finding = f
	return out, nil
}

// ensureDiscoveredAgent registers the discovered agent (ISOLATED, no owner,
// copy_cap 0) unless it exists. An existing agent with that id that was not
// discovered is never taken over.
func ensureDiscoveredAgent(ctx context.Context, tx pgx.Tx, agentID, name, system string) (bool, error) {
	var got string
	err := tx.QueryRow(ctx, `INSERT INTO agents (agent_id, name, type, platform, sponsor, business_unit, copy_cap, level, discovered)
		VALUES ($1, $2, $3, $4, '', '', 0, $5, true) ON CONFLICT (agent_id) DO NOTHING RETURNING agent_id`,
		agentID, name, AgentTypeShadow, system, int16(control.Isolated)).Scan(&got)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("shadow: register discovered agent: %w", err)
	}
	var discovered bool
	if err := tx.QueryRow(ctx, `SELECT discovered FROM agents WHERE agent_id = $1`, agentID).Scan(&discovered); err != nil {
		return false, fmt.Errorf("shadow: read agent %s: %w", agentID, err)
	}
	if !discovered {
		return false, fmt.Errorf("%w: %s", ErrAgentConflict, agentID)
	}
	return false, nil
}
