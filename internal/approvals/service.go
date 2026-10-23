package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/control"
	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/policy"
	"fortik/internal/undo"
)

// Diary event types written by this package.
const (
	EventActionApproved   = "action.approved"
	EventActionDenied     = "action.denied"
	EventApprovalVote     = "action.approval_vote" // an approve vote that did not yet reach approvals_required
	EventSafeFormExecuted = "safe_form.executed"
	EventSafeFormFailed   = "safe_form.failed"
	EventGrantIssued      = "grant.issued"
	EventGrantUsed        = "grant.used"
	EventHoldExpired      = "action.hold_expired"
)

// Outcomes of a held action (held_actions.outcome).
const (
	OutcomePending  = "pending"
	OutcomeApproved = "approved"
	OutcomeDenied   = "denied"
	OutcomeExpired  = "expired"
)

// SafeFormPGRename is the only safe-form kind Fortik executes itself.
const SafeFormPGRename = undo.KindPGRename

// Errors returned by Approve and Deny. The HTTP handler maps them to status
// codes; the wrapped message adds detail and never contains a secret.
var (
	ErrNotFound     = errors.New("held action not found")
	ErrInvalid      = errors.New("invalid request")
	ErrNotPending   = errors.New("held action is no longer pending")
	ErrExpired      = errors.New("held action expired")
	ErrRedUnchanged = errors.New("red actions are never run unchanged")
	ErrOwnerRefused = errors.New("the agent's sponsor may not decide its own agent's held actions")
	ErrAlreadyVoted = errors.New("this approver already voted on the held action")
	// ErrTwoPerson: a two-approver hold already has a vote from an API token
	// and this vote is from another token (see Config.AllowTokenPairs).
	ErrTwoPerson     = errors.New("two-person rule: this hold already has an approval from an API token; the second approval must come from a signed-in person, not another token")
	ErrAgentFrozen   = errors.New("the agent is quarantined or killed: its held actions cannot be approved")
	ErrSafeFormState = errors.New("the safe form cannot be executed")
	ErrSafeFormRun   = errors.New("the safe form failed on the upstream")
	ErrOutcomeUnsure = errors.New("safe form outcome unknown")
	// ErrUnrecorded: the safe form ran (and is undoable) but the approval
	// could not be recorded; the hold stays pending. Needs manual review.
	ErrUnrecorded = errors.New("safe form executed but the approval could not be recorded")
)

// Config tunes the approvals service.
type Config struct {
	// GrantTTL bounds how long the agent has to retry an approved yellow
	// action (config.ApprovalsConfig.GrantTTL; default 15m).
	GrantTTL time.Duration
	// AllowOwnerApproval lets the agent's sponsor approve or deny its own
	// agent's holds (they still need the security role). Default false.
	AllowOwnerApproval bool
	// TrashRetention is the lifetime of the pg_rename undo handle recorded
	// for an executed safe form (config.UndoConfig.TrashRetention; default 7 days).
	TrashRetention time.Duration
	// ExecTimeout bounds one safe-form execution on the upstream (default 2m).
	ExecTimeout time.Duration
	// LockTimeout bounds waiting for the upstream table lock (default 5s).
	LockTimeout time.Duration
	// AllowTokenPairs: two API tokens may supply both votes of a
	// multi-approver hold (config.ApprovalsConfig.AllowTokenPairs; dev only).
	AllowTokenPairs bool
}

// Service approves and denies held actions.
type Service struct {
	pool  *pgxpool.Pool
	diary *diary.Diary
	undo  undo.Store
	src   integrations.Source
	cfg   Config
	log   *slog.Logger
	// Now is the clock compared with held_actions.expires_at (the same clock
	// decide.Service uses to set it). Tests may replace it.
	Now func() time.Time
}

// New builds the service. undoStore records the pg_rename undo handle before
// a safe form runs; src resolves postgres:<upstream> integrations (the safe
// form runs as the integration's admin user). A nil src means red safe forms
// are refused (409); yellow approvals and denials still work.
func New(pool *pgxpool.Pool, d *diary.Diary, undoStore undo.Store, src integrations.Source, cfg Config, log *slog.Logger) *Service {
	if cfg.GrantTTL <= 0 {
		cfg.GrantTTL = 15 * time.Minute
	}
	if cfg.TrashRetention <= 0 {
		cfg.TrashRetention = 7 * 24 * time.Hour
	}
	if cfg.ExecTimeout <= 0 {
		cfg.ExecTimeout = 2 * time.Minute
	}
	if cfg.LockTimeout <= 0 {
		cfg.LockTimeout = 5 * time.Second
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{pool: pool, diary: d, undo: undoStore, src: src, cfg: cfg, log: log, Now: time.Now}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ApproveRequest is the body of POST /v1/held/{id}/approve.
type ApproveRequest struct {
	Reason      string `json:"reason"`
	UseSafeForm bool   `json:"use_safe_form"`
}

// DenyRequest is the body of POST /v1/held/{id}/deny.
type DenyRequest struct {
	Reason string `json:"reason"`
}

// SafeFormResult describes an executed safe form.
type SafeFormResult struct {
	Kind       string `json:"kind"`
	Op         string `json:"op"` // DROP | TRUNCATE
	Upstream   string `json:"upstream"`
	Database   string `json:"database"`
	Schema     string `json:"schema"`
	Table      string `json:"table"`
	TrashTable string `json:"trash_table"`
	Recreated  bool   `json:"recreated_empty_table"` // TRUNCATE: an empty copy was created
	UndoKind   string `json:"undo_kind"`
}

// Decision is the result of one approve or deny vote.
type Decision struct {
	ActionID          string          `json:"action_id"`
	AgentID           string          `json:"agent_id"`
	Class             string          `json:"class"`
	RuleID            string          `json:"rule_id"`
	Outcome           string          `json:"outcome"` // pending (more approvals needed) | approved | denied
	Approvals         int             `json:"approvals"`
	ApprovalsRequired int             `json:"approvals_required"`
	DecidedBy         string          `json:"decided_by,omitempty"`
	Grant             *Grant          `json:"grant,omitempty"`
	SafeForm          *SafeFormResult `json:"safe_form,omitempty"`
}

const maxReason = 2000

func checkReason(r string) (string, error) {
	r = strings.TrimSpace(r)
	switch {
	case r == "":
		return "", fmt.Errorf("%w: reason is required", ErrInvalid)
	case len(r) > maxReason:
		return "", fmt.Errorf("%w: reason must be at most %d bytes", ErrInvalid, maxReason)
	case !utf8.ValidString(r) || strings.ContainsRune(r, 0):
		return "", fmt.Errorf("%w: reason must be valid UTF-8 without NUL bytes", ErrInvalid)
	}
	return r, nil
}

// approverKey identifies a distinct approver: the principal's Diary actor,
// with user emails case-folded so one person cannot vote twice.
func approverKey(p authz.Principal) string {
	if p.Kind == authz.KindUser {
		return strings.ToLower(p.Actor())
	}
	return p.Actor()
}

// hold is a held action locked for a decision.
type hold struct {
	actionID          string
	agentID           string
	ruleID            string
	outcome           string
	expiresAt         time.Time
	approvalsRequired int
	safeForm          map[string]any
	class             policy.Class
	decision          string
	system            string
	actionHash        string
	target            map[string]any
	sponsor           string
	// pastSponsors are the sponsors the agent had at any point since the
	// hold was created (from agent.updated Diary events), so reassigning
	// the sponsor cannot launder the separation-of-duty rule.
	pastSponsors []string
	createdAt    time.Time
	registered   bool
	level        control.Level
}

// lockHold loads and row-locks a held action and reads its agent's level and
// sponsor.
func lockHold(ctx context.Context, tx pgx.Tx, actionID string) (*hold, error) {
	h := &hold{actionID: actionID}
	var safeForm, target []byte
	var class string
	err := tx.QueryRow(ctx, `
		SELECT h.agent_id, h.rule_id, h.outcome, h.expires_at, h.approvals_required, h.safe_form, h.created_at,
		       a.class, a.decision, a.system, a.action_hash, a.target
		FROM held_actions h JOIN actions a USING (action_id)
		WHERE h.action_id = $1
		FOR UPDATE OF h`, actionID).
		Scan(&h.agentID, &h.ruleID, &h.outcome, &h.expiresAt, &h.approvalsRequired, &safeForm, &h.createdAt,
			&class, &h.decision, &h.system, &h.actionHash, &target)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load held action: %w", err)
	}
	h.class = policy.Class(class)
	if len(safeForm) > 0 && string(safeForm) != "null" {
		if err := json.Unmarshal(safeForm, &h.safeForm); err != nil {
			return nil, fmt.Errorf("held action %s: safe_form is not a JSON object: %w", actionID, err)
		}
	}
	if err := json.Unmarshal(target, &h.target); err != nil {
		return nil, fmt.Errorf("held action %s: target is not a JSON object: %w", actionID, err)
	}
	var lvl int16
	// No lock on the agent row: the safe form runs while this transaction is
	// open, and decide (agents lock -> diary_head -> agents FOR UPDATE on a
	// step-down) must never wait on it while holding the diary head.
	err = tx.QueryRow(ctx, `SELECT level, sponsor FROM agents WHERE agent_id = $1`, h.agentID).Scan(&lvl, &h.sponsor)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		h.level = control.Isolated
	case err != nil:
		return nil, fmt.Errorf("load agent: %w", err)
	default:
		h.registered = true
		h.level = control.Level(lvl)
	}
	// Every sponsor the agent had over the hold's lifetime (a minute of
	// slack covers clock skew between the hold row and the Diary).
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT s FROM diary,
		  LATERAL (VALUES (body_json::jsonb #>> '{data,changes,sponsor,old}'),
		                  (body_json::jsonb #>> '{data,changes,sponsor,new}')) v(s)
		WHERE agent_id = $1 AND event_type = 'agent.updated' AND ts >= $2
		  AND s IS NOT NULL AND s <> ''`, h.agentID, h.createdAt.Add(-time.Minute))
	if err != nil {
		return nil, fmt.Errorf("load sponsor history: %w", err)
	}
	for rows.Next() {
		var sp string
		if err := rows.Scan(&sp); err != nil {
			rows.Close()
			return nil, fmt.Errorf("load sponsor history: %w", err)
		}
		h.pastSponsors = append(h.pastSponsors, sp)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load sponsor history: %w", err)
	}
	return h, nil
}

// checkDecidable enforces: pending, unexpired, and the sponsor rule.
func (s *Service) checkDecidable(h *hold, p authz.Principal) error {
	if h.outcome != OutcomePending {
		return fmt.Errorf("%w (outcome %s)", ErrNotPending, h.outcome)
	}
	if !s.now().Before(h.expiresAt) {
		return fmt.Errorf("%w at %s", ErrExpired, h.expiresAt.UTC().Format(time.RFC3339))
	}
	if !s.cfg.AllowOwnerApproval && h.isOwner(p) {
		return ErrOwnerRefused
	}
	return nil
}

// isOwner reports whether p is the agent's sponsor now or was at any point
// since the hold was created.
func (h *hold) isOwner(p authz.Principal) bool {
	if p.IsOwner(h.sponsor) {
		return true
	}
	for _, sp := range h.pastSponsors {
		if p.IsOwner(sp) {
			return true
		}
	}
	return false
}

func hasVoted(ctx context.Context, tx pgx.Tx, actionID, approver string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM held_approvals WHERE action_id = $1 AND approver = $2)`, actionID, approver).Scan(&ok)
	return ok, err
}

func insertVote(ctx context.Context, tx pgx.Tx, actionID, approver, decision, reason string) error {
	_, err := tx.Exec(ctx, `INSERT INTO held_approvals (action_id, approver, decision, reason) VALUES ($1, $2, $3, $4)`,
		actionID, approver, decision, reason)
	if err != nil {
		return fmt.Errorf("record vote: %w", err)
	}
	return nil
}

func (s *Service) closeHold(ctx context.Context, tx pgx.Tx, actionID, outcome, decidedBy string) error {
	tag, err := tx.Exec(ctx, `UPDATE held_actions SET outcome = $2, decided_by = $3, decided_at = $4
		WHERE action_id = $1 AND outcome = 'pending'`, actionID, outcome, decidedBy, s.now().UTC())
	if err != nil {
		return fmt.Errorf("update held action: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: held action changed concurrently", ErrNotPending)
	}
	return nil
}

func (h *hold) result(outcome string, approvals int) Decision {
	return Decision{ActionID: h.actionID, AgentID: h.agentID, Class: string(h.class), RuleID: h.ruleID,
		Outcome: outcome, Approvals: approvals, ApprovalsRequired: h.approvalsRequired}
}

// Approve records p's approve vote. When the vote brings the distinct
// approve votes to approvals_required the hold is approved:
//   - yellow: a one-time grant bound to (agent, action hash) is issued;
//   - red: only with use_safe_form and a pg_rename safe form, which Fortik
//     executes itself on the upstream after recording an undo handle.
//
// Red without a usable safe form is refused (ErrRedUnchanged) and no vote is
// recorded. The caller must already have checked the security role.
func (s *Service) Approve(ctx context.Context, p authz.Principal, actionID string, req ApproveRequest) (Decision, error) {
	reason, err := checkReason(req.Reason)
	if err != nil {
		return Decision{}, err
	}
	approver := approverKey(p)
	var out Decision
	// The safe form runs inside this transaction's row lock on the hold, so
	// concurrent approvals, denials and the expiry sweep serialise behind it.
	// It must finish even if the HTTP client goes away.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.ExecTimeout+30*time.Second)
	defer cancel()
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		h, err := lockHold(ctx, tx, actionID)
		if err != nil {
			return err
		}
		if err := s.checkDecidable(h, p); err != nil {
			return err
		}
		if h.registered && h.level >= control.Quarantined {
			return fmt.Errorf("%w (agent is %s)", ErrAgentFrozen, h.level)
		}
		var pgt *renameTarget
		switch h.class {
		case policy.Red:
			kind, _ := h.safeForm["kind"].(string)
			if !req.UseSafeForm || h.safeForm == nil {
				return fmt.Errorf("%w: approve it with use_safe_form=true when a safe form is offered, or deny it", ErrRedUnchanged)
			}
			if kind != SafeFormPGRename {
				return fmt.Errorf("%w: safe form kind %q cannot be executed by Fortik", ErrRedUnchanged, kind)
			}
			t, err := parseRenameTarget(h.system, h.target)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrRedUnchanged, err)
			}
			pgt = &t
		case policy.Yellow:
			if req.UseSafeForm {
				return fmt.Errorf("%w: use_safe_form applies only to red actions with a safe form", ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: held action has class %q", ErrNotPending, h.class)
		}
		if h.decision != string(policy.Hold) {
			return fmt.Errorf("%w: the action was not held (decision %s)", ErrNotPending, h.decision)
		}
		if voted, err := hasVoted(ctx, tx, actionID, approver); err != nil {
			return err
		} else if voted {
			return ErrAlreadyVoted
		}
		if h.approvalsRequired >= 2 && p.Kind != authz.KindUser && !s.cfg.AllowTokenPairs {
			var tokenVoted bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM held_approvals WHERE action_id = $1 AND decision = 'approve' AND approver NOT LIKE 'user:%')`,
				actionID).Scan(&tokenVoted); err != nil {
				return err
			}
			if tokenVoted {
				return ErrTwoPerson
			}
		}
		var approvals int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM held_approvals WHERE action_id = $1 AND decision = 'approve'`, actionID).Scan(&approvals); err != nil {
			return err
		}
		approvals++ // this vote
		asOwner := h.isOwner(p)
		voteData := map[string]any{
			"action_id": actionID, "rule_id": h.ruleID, "class": string(h.class), "approver": approver, "reason": reason,
			"approvals": approvals, "approvals_required": h.approvalsRequired, "use_safe_form": req.UseSafeForm, "as_owner": asOwner,
		}

		if approvals < h.approvalsRequired {
			if err := insertVote(ctx, tx, actionID, approver, "approve", reason); err != nil {
				return err
			}
			if _, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: h.agentID, EventType: EventApprovalVote, Actor: p.Actor(), Data: voteData}); err != nil {
				return err
			}
			out = h.result(OutcomePending, approvals)
			return nil
		}

		events := []diary.Event{{AgentID: h.agentID, EventType: EventActionApproved, Actor: p.Actor(), Data: voteData}}
		out = h.result(OutcomeApproved, approvals)
		out.DecidedBy = p.Actor()
		if pgt != nil {
			// Undo handle first (its own committed transaction), then the
			// upstream change. Nothing below may fail silently after this.
			res, err := s.executeRename(ctx, h, *pgt, p.Actor())
			if err != nil {
				return err
			}
			out.SafeForm = &res
			events = append(events, diary.Event{AgentID: h.agentID, EventType: EventSafeFormExecuted, Actor: p.Actor(), Data: map[string]any{
				"action_id": actionID, "kind": res.Kind, "op": res.Op, "upstream": res.Upstream, "database": res.Database,
				"schema": res.Schema, "table": res.Table, "trash_table": res.TrashTable,
				"recreated_empty_table": res.Recreated, "undo_kind": res.UndoKind, "executed_as": "integration_admin",
			}})
		} else {
			g, err := s.issueGrant(ctx, tx, h, p.Actor(), reason)
			if err != nil {
				return err
			}
			out.Grant = &g
			events = append(events, diary.Event{AgentID: h.agentID, EventType: EventGrantIssued, Actor: p.Actor(), Data: map[string]any{
				"grant_id": g.GrantID, "action_id": actionID, "action_hash": g.ActionHash, "uses": 1,
				"expires_at": g.ExpiresAt.UTC().Format(time.RFC3339),
			}})
		}
		if err := insertVote(ctx, tx, actionID, approver, "approve", reason); err != nil {
			return err
		}
		if err := s.closeHold(ctx, tx, actionID, OutcomeApproved, p.Actor()); err != nil {
			return err
		}
		_, err = s.diary.AppendTx(ctx, tx, events...)
		return err
	})
	if err != nil {
		if out.SafeForm != nil {
			// The upstream change is committed and undoable (handle active),
			// but the approval could not be recorded.
			s.log.Error("safe form EXECUTED but the approval could not be recorded; the hold stays pending",
				"action_id", actionID, "trash_table", out.SafeForm.TrashTable, "err", err)
			return Decision{}, fmt.Errorf("%w (undo handle active, trash table %s.%s): %v",
				ErrUnrecorded, out.SafeForm.Schema, out.SafeForm.TrashTable, err)
		}
		return Decision{}, err
	}
	return out, nil
}

// issueGrant creates the one-time grant for an approved yellow hold. Its
// expiry uses the database clock, like the grants enricher and observer.
func (s *Service) issueGrant(ctx context.Context, tx pgx.Tx, h *hold, approvedBy, reason string) (Grant, error) {
	g := Grant{GrantID: action.NewID("grt"), ActionID: h.actionID, AgentID: h.agentID, ActionHash: h.actionHash,
		ApprovedBy: approvedBy, Reason: reason}
	if h.actionHash == "" {
		return Grant{}, errors.New("held action has no action hash")
	}
	err := tx.QueryRow(ctx, `
		INSERT INTO approval_grants (grant_id, action_id, agent_id, action_hash, approved_by, reason, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))
		RETURNING expires_at`, g.GrantID, g.ActionID, g.AgentID, g.ActionHash, g.ApprovedBy, g.Reason, s.cfg.GrantTTL.Seconds()).
		Scan(&g.ExpiresAt)
	if err != nil {
		return Grant{}, fmt.Errorf("issue grant: %w", err)
	}
	return g, nil
}

// Deny records p's deny vote; one deny denies the hold.
func (s *Service) Deny(ctx context.Context, p authz.Principal, actionID string, req DenyRequest) (Decision, error) {
	reason, err := checkReason(req.Reason)
	if err != nil {
		return Decision{}, err
	}
	approver := approverKey(p)
	var out Decision
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		h, err := lockHold(ctx, tx, actionID)
		if err != nil {
			return err
		}
		if err := s.checkDecidable(h, p); err != nil {
			return err
		}
		// Denying is always the safe direction: an approver who already voted
		// to approve may still deny. Votes are append-only, so their approve
		// vote stays on record; the denial closes the hold and the Diary event
		// says the approver withdrew their approval.
		voted, err := hasVoted(ctx, tx, actionID, approver)
		if err != nil {
			return err
		}
		if !voted {
			if err := insertVote(ctx, tx, actionID, approver, "deny", reason); err != nil {
				return err
			}
		}
		var approvals int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM held_approvals WHERE action_id = $1 AND decision = 'approve'`, actionID).Scan(&approvals); err != nil {
			return err
		}
		if err := s.closeHold(ctx, tx, actionID, OutcomeDenied, p.Actor()); err != nil {
			return err
		}
		out = h.result(OutcomeDenied, approvals)
		out.DecidedBy = p.Actor()
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: h.agentID, EventType: EventActionDenied, Actor: p.Actor(), Data: map[string]any{
			"action_id": actionID, "rule_id": h.ruleID, "class": string(h.class), "approver": approver, "reason": reason,
			"as_owner": h.isOwner(p), "withdrew_approval": voted,
		}})
		return err
	})
	if err != nil {
		return Decision{}, err
	}
	return out, nil
}
