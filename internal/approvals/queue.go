package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"fortik/internal/authz"
	"fortik/internal/diary"
)

// Diary event types of the approval queue (docs/PHASE5_DESIGN.md §5).
const (
	EventActionAssigned = "action.assigned"  // a held action was (re)assigned or unassigned
	EventHeldBulkDenied = "held.bulk_denied" // summary of one bulk deny; each id also has its own action.denied
)

// Queue limits.
const (
	QueueDefaultLimit = 50
	QueueMaxLimit     = 500
	QueueMaxOffset    = 100000
	BulkDenyMax       = 200
	maxAssignee       = 320
)

// Sorts accepted by the queue.
const (
	SortExpiresAt = "expires_at" // default ascending: the most urgent first
	SortCreatedAt = "created_at" // default descending: the newest first
	SortClass     = "class"      // red first, then yellow; ties by expires_at
)

// Console aliases (sort=severity|newest|oldest|expires): each maps to a
// sort and its order.
var sortAliases = map[string][2]string{
	"severity": {SortClass, "asc"},
	"newest":   {SortCreatedAt, "desc"},
	"oldest":   {SortCreatedAt, "asc"},
	"expires":  {SortExpiresAt, "asc"},
}

// QueueFilter selects and orders held actions. Empty fields do not filter.
type QueueFilter struct {
	Status  string // pending (default) | approved | denied | expired | all
	AgentID string
	SwarmID string
	RuleID  string
	Class   string // green | yellow | red
	// AssignedTo: "none" (unassigned), "me" (the caller), an email address,
	// or a principal ("user:<email>", "token:<name>").
	AssignedTo string
	Sort       string // expires_at | created_at | class, or severity | newest | oldest | expires
	Order      string // asc | desc (default per sort)
	Limit      int
	Offset     int
}

// Vote is one recorded approve or deny vote.
type Vote struct {
	Approver string    `json:"approver"`
	Decision string    `json:"decision"`
	At       time.Time `json:"at"`
	Reason   string    `json:"reason"`
}

// QueueItem is one held action in the queue.
type QueueItem struct {
	ActionID          string          `json:"action_id"`
	AgentID           string          `json:"agent_id"`
	RuleID            string          `json:"rule_id"`
	Reason            string          `json:"reason"`
	Class             string          `json:"class"`
	Decision          string          `json:"decision"`
	System            string          `json:"system"`
	Verb              string          `json:"verb"`
	Target            json.RawMessage `json:"target"`
	Outcome           string          `json:"outcome"`
	Expired           bool            `json:"expired"` // past expires_at (the sweep may not have marked it yet)
	CreatedAt         time.Time       `json:"created_at"`
	ExpiresAt         time.Time       `json:"expires_at"`
	DecidedBy         *string         `json:"decided_by"`
	DecidedAt         *time.Time      `json:"decided_at"`
	ApproverRole      string          `json:"approver_role"`
	Approvals         int             `json:"approvals"`
	ApprovalsRequired int             `json:"approvals_required"`
	Progress          string          `json:"progress"` // e.g. "1 of 2 approvals"
	Votes             []Vote          `json:"votes"`
	AssignedTo        *string         `json:"assigned_to"`
	SwarmID           *string         `json:"swarm_id"`
	SafeForm          json.RawMessage `json:"safe_form"`
	// Same as GET /v1/held.
	LevelAtDecision json.RawMessage `json:"level_at_decision"`
	LevelAfter      json.RawMessage `json:"level_after"`
	UndoAvailable   bool            `json:"undo_available"`
}

// QueueGroup summarises the swarm-held calls of the filtered set.
type QueueGroup struct {
	SwarmID       string    `json:"swarm_id"`
	State         *string   `json:"state"` // swarms.state (null if the swarm row is gone)
	MemberCount   *int      `json:"member_count"`
	Held          int       `json:"held"`    // matching holds in the filtered set
	Pending       int       `json:"pending"` // of which pending
	NextExpiresAt time.Time `json:"next_expires_at"`
}

// QueueResult is the body of GET /v1/approvals/queue.
type QueueResult struct {
	Items      []QueueItem  `json:"items"`
	Total      int          `json:"total"`
	Limit      int          `json:"limit"`
	Offset     int          `json:"offset"`
	NextOffset *int         `json:"next_offset"`
	Sort       string       `json:"sort"`
	Order      string       `json:"order"`
	Groups     []QueueGroup `json:"groups"`
}

func validID(s string) bool { return s == "" || actionIDPattern.MatchString(s) }

func (f *QueueFilter) normalize(p authz.Principal) (assigned string, err error) {
	switch f.Status {
	case "":
		f.Status = OutcomePending
	case OutcomePending, OutcomeApproved, OutcomeDenied, OutcomeExpired, "all":
	default:
		return "", fmt.Errorf("%w: status must be pending, approved, denied, expired or all", ErrInvalid)
	}
	switch f.Class {
	case "", "green", "yellow", "red":
	default:
		return "", fmt.Errorf("%w: class must be green, yellow or red", ErrInvalid)
	}
	if !validID(f.AgentID) || !validID(f.SwarmID) || !validID(f.RuleID) {
		return "", fmt.Errorf("%w: agent_id, swarm_id and rule_id must be identifiers", ErrInvalid)
	}
	if a, ok := sortAliases[f.Sort]; ok {
		if f.Order != "" && f.Order != a[1] {
			return "", fmt.Errorf("%w: sort=%s implies order=%s", ErrInvalid, f.Sort, a[1])
		}
		f.Sort, f.Order = a[0], a[1]
	}
	switch f.Sort {
	case "":
		f.Sort = SortExpiresAt
	case SortExpiresAt, SortCreatedAt, SortClass:
	default:
		return "", fmt.Errorf("%w: sort must be expires_at, created_at, class, severity, newest, oldest or expires", ErrInvalid)
	}
	switch f.Order {
	case "":
		f.Order = "asc"
		if f.Sort == SortCreatedAt {
			f.Order = "desc"
		}
	case "asc", "desc":
	default:
		return "", fmt.Errorf("%w: order must be asc or desc", ErrInvalid)
	}
	switch {
	case f.Limit == 0:
		f.Limit = QueueDefaultLimit
	case f.Limit < 1 || f.Limit > QueueMaxLimit:
		return "", fmt.Errorf("%w: limit must be 1..%d", ErrInvalid, QueueMaxLimit)
	}
	if f.Offset < 0 || f.Offset > QueueMaxOffset {
		return "", fmt.Errorf("%w: offset must be 0..%d", ErrInvalid, QueueMaxOffset)
	}
	switch f.AssignedTo {
	case "", "none":
		return f.AssignedTo, nil
	case "me":
		return approverKey(p), nil
	default:
		a, err := normalizeAssignee(f.AssignedTo)
		if err != nil {
			return "", err
		}
		return a, nil
	}
}

// Queue lists held actions with their votes, approvals progress, assignment
// and swarm grouping. The caller must already have checked the role.
func (s *Service) Queue(ctx context.Context, p authz.Principal, f QueueFilter) (QueueResult, error) {
	assigned, err := f.normalize(p)
	if err != nil {
		return QueueResult{}, err
	}
	assignMode := ""
	switch {
	case f.AssignedTo == "none":
		assignMode = "none"
	case assigned != "":
		assignMode = "eq"
	}
	dir := "ASC"
	if f.Order == "desc" {
		dir = "DESC"
	}
	var order string
	switch f.Sort {
	case SortCreatedAt:
		order = "created_at " + dir + ", action_id " + dir
	case SortClass:
		order = "CASE class WHEN 'red' THEN 0 WHEN 'yellow' THEN 1 ELSE 2 END " + dir + ", expires_at ASC, action_id ASC"
	default:
		order = "expires_at " + dir + ", action_id " + dir
	}
	const base = `
		WITH q AS (
			SELECT h.action_id, h.agent_id, h.rule_id, h.reason, h.approvals_required, h.approver_role, h.safe_form,
			       h.expires_at, h.outcome, h.decided_by, h.decided_at, h.created_at, h.assigned_to,
			       COALESCE(h.swarm_id, a.swarm_id) AS swarm_id, a.class, a.system, a.verb, a.target,
			       a.decision, a.decision_json->'level_before' AS level_before, a.decision_json->'level_after' AS level_after
			FROM held_actions h JOIN actions a USING (action_id)
			WHERE ($1 = 'all' OR h.outcome = $1)
			  AND ($2 = '' OR h.agent_id = $2)
			  AND ($3 = '' OR COALESCE(h.swarm_id, a.swarm_id) = $3)
			  AND ($4 = '' OR h.rule_id = $4)
			  AND ($5 = '' OR a.class = $5)
			  AND ($6 = '' OR ($6 = 'none' AND h.assigned_to IS NULL) OR ($6 = 'eq' AND h.assigned_to = $7))
		)`
	args := []any{f.Status, f.AgentID, f.SwarmID, f.RuleID, f.Class, assignMode, assigned}
	res := QueueResult{Items: []QueueItem{}, Groups: []QueueGroup{}, Limit: f.Limit, Offset: f.Offset, Sort: f.Sort, Order: f.Order}
	now := s.now()
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, base+` SELECT count(*) FROM q`, args...).Scan(&res.Total); err != nil {
			return fmt.Errorf("queue count: %w", err)
		}
		rows, err := tx.Query(ctx, base+`
			SELECT action_id, agent_id, rule_id, reason, approvals_required, approver_role, safe_form, expires_at, outcome,
			       decided_by, decided_at, created_at, assigned_to, swarm_id, class, system, verb, target,
			       decision, level_before, level_after
			FROM q ORDER BY `+order+` LIMIT $8 OFFSET $9`, append(args, f.Limit, f.Offset)...)
		if err != nil {
			return fmt.Errorf("queue: %w", err)
		}
		index := map[string]int{}
		var ids []string
		for rows.Next() {
			var it QueueItem
			var safeForm, target, lvlBefore, lvlAfter []byte
			if err := rows.Scan(&it.ActionID, &it.AgentID, &it.RuleID, &it.Reason, &it.ApprovalsRequired, &it.ApproverRole, &safeForm,
				&it.ExpiresAt, &it.Outcome, &it.DecidedBy, &it.DecidedAt, &it.CreatedAt, &it.AssignedTo, &it.SwarmID,
				&it.Class, &it.System, &it.Verb, &target, &it.Decision, &lvlBefore, &lvlAfter); err != nil {
				rows.Close()
				return fmt.Errorf("queue: %w", err)
			}
			it.Target = json.RawMessage(target)
			it.LevelAtDecision, it.LevelAfter = jsonOrNull(lvlBefore), jsonOrNull(lvlAfter)
			if len(safeForm) > 0 {
				it.SafeForm = json.RawMessage(safeForm)
			}
			it.Expired = it.Outcome == OutcomeExpired || (it.Outcome == OutcomePending && !now.Before(it.ExpiresAt))
			it.Votes = []Vote{}
			index[it.ActionID] = len(res.Items)
			ids = append(ids, it.ActionID)
			res.Items = append(res.Items, it)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("queue: %w", err)
		}
		if len(ids) > 0 {
			vrows, err := tx.Query(ctx, `SELECT action_id, approver, decision, reason, created_at FROM held_approvals
				WHERE action_id = ANY($1) ORDER BY created_at, approver`, ids)
			if err != nil {
				return fmt.Errorf("queue votes: %w", err)
			}
			for vrows.Next() {
				var id string
				var v Vote
				if err := vrows.Scan(&id, &v.Approver, &v.Decision, &v.Reason, &v.At); err != nil {
					vrows.Close()
					return fmt.Errorf("queue votes: %w", err)
				}
				it := &res.Items[index[id]]
				it.Votes = append(it.Votes, v)
				if v.Decision == "approve" {
					it.Approvals++
				}
			}
			vrows.Close()
			if err := vrows.Err(); err != nil {
				return fmt.Errorf("queue votes: %w", err)
			}
		}
		grows, err := tx.Query(ctx, base+`
			SELECT g.swarm_id, s.state, s.member_count, g.held, g.pending, g.next_expires_at
			FROM (SELECT swarm_id, count(*) AS held, count(*) FILTER (WHERE outcome = 'pending') AS pending,
			             min(expires_at) AS next_expires_at
			      FROM q WHERE swarm_id IS NOT NULL GROUP BY swarm_id) g
			LEFT JOIN swarms s ON s.swarm_id = g.swarm_id
			ORDER BY g.next_expires_at, g.swarm_id`, args...)
		if err != nil {
			return fmt.Errorf("queue groups: %w", err)
		}
		defer grows.Close()
		for grows.Next() {
			var g QueueGroup
			if err := grows.Scan(&g.SwarmID, &g.State, &g.MemberCount, &g.Held, &g.Pending, &g.NextExpiresAt); err != nil {
				return fmt.Errorf("queue groups: %w", err)
			}
			res.Groups = append(res.Groups, g)
		}
		return grows.Err()
	})
	if err != nil {
		return QueueResult{}, err
	}
	for i := range res.Items {
		it := &res.Items[i]
		it.Progress = fmt.Sprintf("%d of %d approvals", it.Approvals, it.ApprovalsRequired)
	}
	if next := f.Offset + len(res.Items); len(res.Items) > 0 && next < res.Total {
		res.NextOffset = &next
	}
	return res, nil
}

// normalizeAssignee returns the canonical assignee: "user:<lower-case
// email>" for an email address or user principal, "token:<name>" for a
// service token; "" unassigns.
func normalizeAssignee(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	bad := fmt.Errorf("%w: assignee must be an email address or a principal (user:<email>, token:<name>)", ErrInvalid)
	if len(s) > maxAssignee || !utf8.ValidString(s) {
		return "", bad
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", bad
		}
	}
	email := func(e string) (string, error) {
		at := strings.IndexByte(e, '@')
		if at <= 0 || at == len(e)-1 || strings.Count(e, "@") != 1 || strings.Contains(e, ":") {
			return "", bad
		}
		return "user:" + strings.ToLower(e), nil
	}
	switch {
	case strings.HasPrefix(s, "user:"):
		return email(s[len("user:"):])
	case strings.HasPrefix(s, "token:"):
		name := s[len("token:"):]
		if name == "" || strings.Contains(name, ":") {
			return "", bad
		}
		return s, nil
	default:
		return email(s)
	}
}

// AssignRequest is the body of POST /v1/held/{id}/assign. An empty assignee
// removes the assignment.
type AssignRequest struct {
	Assignee string `json:"assignee"`
	Reason   string `json:"reason,omitempty"`
}

// Assignment is the result of an assign call.
type Assignment struct {
	ActionID   string  `json:"action_id"`
	AgentID    string  `json:"agent_id"`
	AssignedTo *string `json:"assigned_to"`
	Previous   *string `json:"previous"`
	AssignedBy string  `json:"assigned_by"`
	Changed    bool    `json:"changed"`
}

// Assign routes a pending, unexpired hold to an approver (security role is
// checked by the caller). Assigning to the agent's sponsor (now or since the
// hold was created) is refused unless owner approval is allowed: they could
// not decide it. A change is recorded in the Diary (action.assigned); a
// no-op assignment changes and records nothing.
func (s *Service) Assign(ctx context.Context, p authz.Principal, actionID string, req AssignRequest) (Assignment, error) {
	assignee, err := normalizeAssignee(req.Assignee)
	if err != nil {
		return Assignment{}, err
	}
	reason := strings.TrimSpace(req.Reason)
	if reason != "" {
		if reason, err = checkReason(reason); err != nil {
			return Assignment{}, err
		}
	}
	var out Assignment
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		h, err := lockHold(ctx, tx, actionID)
		if err != nil {
			return err
		}
		if h.outcome != OutcomePending {
			return fmt.Errorf("%w (outcome %s)", ErrNotPending, h.outcome)
		}
		if !s.now().Before(h.expiresAt) {
			return fmt.Errorf("%w at %s", ErrExpired, h.expiresAt.UTC().Format(time.RFC3339))
		}
		if assignee != "" && strings.HasPrefix(assignee, "user:") && !s.cfg.AllowOwnerApproval &&
			h.isOwner(authz.Principal{Kind: authz.KindUser, Email: strings.TrimPrefix(assignee, "user:")}) {
			return fmt.Errorf("%w: it cannot be assigned to them", ErrOwnerRefused)
		}
		var prev *string
		if err := tx.QueryRow(ctx, `SELECT assigned_to FROM held_actions WHERE action_id = $1`, actionID).Scan(&prev); err != nil {
			return fmt.Errorf("load assignment: %w", err)
		}
		var next *string
		if assignee != "" {
			next = &assignee
		}
		out = Assignment{ActionID: actionID, AgentID: h.agentID, AssignedTo: next, Previous: prev, AssignedBy: p.Actor()}
		if (prev == nil && next == nil) || (prev != nil && next != nil && *prev == *next) {
			return nil
		}
		tag, err := tx.Exec(ctx, `UPDATE held_actions SET assigned_to = $2 WHERE action_id = $1 AND outcome = 'pending'`, actionID, next)
		if err != nil {
			return fmt.Errorf("assign: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: held action changed concurrently", ErrNotPending)
		}
		out.Changed = true
		data := map[string]any{"action_id": actionID, "rule_id": h.ruleID, "class": string(h.class),
			"assigned_to": next, "previous": prev}
		if reason != "" {
			data["reason"] = reason
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: h.agentID, EventType: EventActionAssigned, Actor: p.Actor(), Data: data})
		return err
	})
	if err != nil {
		return Assignment{}, err
	}
	return out, nil
}

// BulkDenyRequest is the body of POST /v1/held/bulk-deny.
type BulkDenyRequest struct {
	ActionIDs []string `json:"action_ids"`
	Reason    string   `json:"reason"`
}

// BulkItem is the outcome for one id of a bulk deny.
type BulkItem struct {
	ActionID string `json:"action_id"`
	Outcome  string `json:"outcome"` // denied | error
	Status   int    `json:"status"`  // the HTTP status a single deny would have returned
	Error    string `json:"error,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
}

// BulkDenyResult reports every id honestly; Recorded says whether the
// summary Diary event was written (each denial has its own event either way).
type BulkDenyResult struct {
	Requested int        `json:"requested"`
	Denied    int        `json:"denied"`
	Failed    int        `json:"failed"`
	Results   []BulkItem `json:"results"`
	Recorded  bool       `json:"summary_recorded"`
}

// BulkDeny denies each id on its own (its own transaction, vote, checks and
// action.denied event, exactly like POST /v1/held/{id}/deny), then records a
// held.bulk_denied summary. Duplicate ids are decided once. The batch runs to
// completion even if the client goes away, so the summary matches what
// happened.
func (s *Service) BulkDeny(ctx context.Context, p authz.Principal, req BulkDenyRequest) (BulkDenyResult, error) {
	reason, err := checkReason(req.Reason)
	if err != nil {
		return BulkDenyResult{}, err
	}
	if len(req.ActionIDs) == 0 || len(req.ActionIDs) > BulkDenyMax {
		return BulkDenyResult{}, fmt.Errorf("%w: action_ids must hold 1..%d ids", ErrInvalid, BulkDenyMax)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	seen := map[string]bool{}
	res := BulkDenyResult{Results: []BulkItem{}}
	var denied []string
	var failed []map[string]any
	for _, id := range req.ActionIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		res.Requested++
		item := BulkItem{ActionID: id}
		var d Decision
		var err error
		if !actionIDPattern.MatchString(id) {
			err = ErrNotFound
		} else {
			d, err = s.Deny(ctx, p, id, DenyRequest{Reason: reason})
		}
		if err != nil {
			code, msg := errStatus(err)
			if code == http.StatusInternalServerError {
				s.log.Error("bulk deny: internal error", "action_id", id, "err", err)
			}
			item.Outcome, item.Status, item.Error = "error", code, msg
			res.Failed++
			failed = append(failed, map[string]any{"action_id": id, "status": code, "error": msg})
		} else {
			item.Outcome, item.Status, item.AgentID, item.RuleID = OutcomeDenied, http.StatusOK, d.AgentID, d.RuleID
			res.Denied++
			denied = append(denied, id)
		}
		res.Results = append(res.Results, item)
	}
	if denied == nil {
		denied = []string{}
	}
	if failed == nil {
		failed = []map[string]any{}
	}
	_, err = s.diary.Append(ctx, diary.Event{EventType: EventHeldBulkDenied, Actor: p.Actor(), Data: map[string]any{
		"reason": reason, "requested": res.Requested, "denied": denied, "failed": failed,
	}})
	if err != nil {
		s.log.Error("bulk deny: summary event not recorded (each denial is recorded on its own)", "err", err)
	} else {
		res.Recorded = true
	}
	return res, nil
}

// errStatus maps a service error to an HTTP status and a client-safe
// message (internal errors never leak detail).
func errStatus(err error) (int, string) {
	switch {
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, ErrInvalid):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, ErrOwnerRefused):
		return http.StatusForbidden, err.Error()
	case errors.Is(err, ErrNotPending), errors.Is(err, ErrExpired), errors.Is(err, ErrRedUnchanged),
		errors.Is(err, ErrAlreadyVoted), errors.Is(err, ErrTwoPerson), errors.Is(err, ErrAgentFrozen), errors.Is(err, ErrSafeFormState):
		return http.StatusConflict, err.Error()
	case errors.Is(err, ErrSafeFormRun), errors.Is(err, ErrOutcomeUnsure):
		return http.StatusBadGateway, err.Error()
	case errors.Is(err, ErrUnrecorded):
		return http.StatusInternalServerError, ErrUnrecorded.Error() + "; the undo handle is active, review manually"
	default:
		return http.StatusInternalServerError, "internal error"
	}
}

func jsonOrNull(b []byte) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return json.RawMessage(b)
}
