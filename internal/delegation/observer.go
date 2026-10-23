package delegation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/jackc/pgx/v5"

	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/metrics"
	"fortik/internal/policy"
)

// Rule ids the observer reacts to (policies/fortik/delegation).
const (
	RuleBypass     = "POL-601"
	RuleDepth      = "POL-602"
	RuleNotAllowed = "POL-603"
	RuleToken      = "POL-604"
)

// AlertRaiser raises an alert inside the caller's transaction so it commits
// (or rolls back) with the decision. Workstream D4's alerts store implements it.
type AlertRaiser interface {
	RaiseTx(ctx context.Context, tx pgx.Tx, a alerts.Alert) (alerts.Alert, error)
}

// Observer implements decide.Observer (docs/PHASE3_DESIGN.md §1.4). Inside
// the decision transaction it:
//
//   - POL-601 (delegation bypass): steps the ORIGINATING agent(s) down to
//     BypassOriginLevel (never loosening), raises a high delegation_bypass
//     alert and writes delegation.bypass_blocked. The executor is not
//     stepped down by this rule.
//   - POL-602/POL-603: raises a warning delegation_depth alert.
//   - an allowed a2a DELEGATE: records the hop (OpenTx) and places its
//     token in the request's Sink (WithTokenSink); the token never enters
//     the Outcome, the actions table or the Diary.
//
// Any error rolls the decision back, and Decide fails it closed.
type Observer struct {
	store  *PGStore
	ctl    *control.Store
	diary  *diary.Diary
	alerts AlertRaiser
	origin control.Level
	actor  string
}

var _ decide.Observer = (*Observer)(nil)

// NewObserver returns the delegation observer. bypassOriginLevel is
// config.DelegationConfig.BypassOriginLevel (e.g. "SUPERVISED"). All
// dependencies are required: without an alert raiser a blocked bypass could
// not be investigated, so construction fails rather than run degraded.
func NewObserver(store *PGStore, ctl *control.Store, d *diary.Diary, raiser AlertRaiser, bypassOriginLevel string) (*Observer, error) {
	if store == nil || ctl == nil || d == nil || raiser == nil {
		return nil, errors.New("delegation observer: store, control, diary and alert raiser are required")
	}
	lvl, err := control.ParseLevel(bypassOriginLevel)
	if err != nil {
		return nil, fmt.Errorf("delegation observer: bypass_origin_level: %w", err)
	}
	if lvl == control.Full {
		return nil, errors.New("delegation observer: bypass_origin_level FULL would never restrict the originating agent")
	}
	return &Observer{store: store, ctl: ctl, diary: d, alerts: raiser, origin: lvl, actor: "system:delegation"}, nil
}

// AttributionOf extracts the delegation attribution from a policy input
// (nil when the enricher did not run or found none).
func AttributionOf(in policy.Input) *Attribution {
	switch v := in.Context[Key].(type) {
	case *Attribution:
		return v
	case Attribution:
		return &v
	}
	return nil
}

// AfterDecide implements decide.Observer.
func (o *Observer) AfterDecide(ctx context.Context, tx pgx.Tx, out *decide.Outcome, in policy.Input) error {
	att := AttributionOf(in)
	a := out.Action
	switch out.Result.RuleID {
	case RuleBypass:
		return o.bypass(ctx, tx, out, att)
	case RuleDepth, RuleNotAllowed:
		return o.depth(ctx, tx, out, att)
	}
	if out.Result.Decision.Executes() && a.System == action.SystemA2A && a.Verb == action.VerbDelegate {
		return o.open(ctx, tx, out, att)
	}
	return nil
}

func chainIDs(att *Attribution) []string {
	if att == nil {
		return []string{}
	}
	ids := make([]string, 0, len(att.Chain))
	for _, h := range att.Chain {
		ids = append(ids, h.AgentID)
	}
	return ids
}

// origins are the originating agents a POL-601 refusal steps down: every
// root of the attribution except the executor, sorted so agent rows are
// always locked in the same order.
func origins(att *Attribution, executor string) []string {
	roots := []string{}
	if att != nil {
		for _, r := range att.Roots {
			if r != executor && !slices.Contains(roots, r) {
				roots = append(roots, r)
			}
		}
	}
	sort.Strings(roots)
	return roots
}

// PreLock takes the row locks of the agents a POL-601 refusal will step
// down. decide.Service.persist locks agents row -> diary_head, but observers
// run after the decision's Diary append, so stepping another agent down
// there inverts that order and can deadlock with a concurrent decision of
// the originating agent (Postgres then aborts one of them). Called right
// after the executor's row lock and before any Diary write, this restores
// the order. It is not part of decide.Observer today (see the contract
// change request in the D1 report); without it the observer is still
// correct, and a deadlock fails the decision closed (the refusal is kept).
func (o *Observer) PreLock(ctx context.Context, tx pgx.Tx, res policy.Result, in policy.Input) error {
	if res.RuleID != RuleBypass {
		return nil
	}
	for _, r := range origins(AttributionOf(in), in.Action.AgentID) {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM agents WHERE agent_id = $1 FOR UPDATE`, r); err != nil {
			return fmt.Errorf("lock originating agent %s: %w", r, err)
		}
	}
	return nil
}

func (o *Observer) bypass(ctx context.Context, tx pgx.Tx, out *decide.Outcome, att *Attribution) error {
	a := out.Action
	roots := origins(att, a.AgentID)
	chain := chainIDs(att)
	source, did, root := "", "", ""
	if att != nil {
		source, did, root = att.Source, att.DelegationID, att.Root
	}
	stepped := []string{}
	for _, r := range roots {
		_, changed, err := o.ctl.StepDownTx(ctx, tx, r, o.origin,
			fmt.Sprintf("%s: delegation bypass attempt through %s", RuleBypass, a.AgentID), o.actor,
			map[string]any{"action_id": a.ActionID, "rule_id": RuleBypass, "executor": a.AgentID, "chain": chain})
		if err != nil {
			return fmt.Errorf("step down originating agent %s: %w", r, err)
		}
		if changed {
			stepped = append(stepped, r)
			metrics.StepDowns.WithLabelValues(o.origin.String(), RuleBypass).Inc()
		}
	}
	details := map[string]any{
		"rule_id":       RuleBypass,
		"reason":        out.Result.Reason,
		"executor":      a.AgentID,
		"root":          root,
		"roots":         roots,
		"chain":         chain,
		"source":        source,
		"delegation_id": did,
		"system":        a.System,
		"verb":          string(a.Verb),
		"stepped_down":  stepped,
		"origin_level":  o.origin.String(),
	}
	alertAgent := root
	if alertAgent == "" && len(roots) > 0 {
		alertAgent = roots[0]
	}
	if alertAgent == "" {
		alertAgent = a.AgentID
	}
	if err := o.raise(ctx, tx, alerts.Alert{
		Kind:     alerts.KindDelegationBypass,
		Severity: alerts.SevHigh,
		AgentID:  alertAgent,
		ActionID: a.ActionID,
		Summary:  fmt.Sprintf("delegation bypass blocked: %s acted for %v on %s %s", a.AgentID, chain, a.System, a.Verb),
		DedupKey: "delegation_bypass:" + alertAgent + ">" + a.AgentID,
	}, details); err != nil {
		return err
	}
	_, err := o.diary.AppendTx(ctx, tx, diary.Event{AgentID: alertAgent, EventType: EventBypassBlocked, Actor: o.actor, Data: map[string]any{
		"action_id":     a.ActionID,
		"rule_id":       RuleBypass,
		"reason":        out.Result.Reason,
		"executor":      a.AgentID,
		"root":          root,
		"roots":         roots,
		"chain":         chain,
		"source":        source,
		"delegation_id": did,
		"system":        a.System,
		"verb":          string(a.Verb),
		"stepped_down":  stepped,
		"origin_level":  o.origin.String(),
	}})
	return err
}

func (o *Observer) depth(ctx context.Context, tx pgx.Tx, out *decide.Outcome, att *Attribution) error {
	a := out.Action
	details := map[string]any{
		"rule_id":  out.Result.RuleID,
		"reason":   out.Result.Reason,
		"executor": a.AgentID,
		"chain":    chainIDs(att),
		"system":   a.System,
		"verb":     string(a.Verb),
		"to_agent": a.Target["to_agent"],
	}
	if att != nil {
		details["depth"] = att.Depth
		details["root"] = att.Root
	}
	return o.raise(ctx, tx, alerts.Alert{
		Kind:     alerts.KindDelegationDepth,
		Severity: alerts.SevWarning,
		AgentID:  a.AgentID,
		ActionID: a.ActionID,
		Summary:  fmt.Sprintf("delegation refused for %s: %s", a.AgentID, out.Result.Reason),
		DedupKey: "delegation_depth:" + a.AgentID,
	}, details)
}

func (o *Observer) raise(ctx context.Context, tx pgx.Tx, al alerts.Alert, details map[string]any) error {
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	al.Details = b
	al.Status = "open"
	al.Count = 1
	if _, err := o.alerts.RaiseTx(ctx, tx, al); err != nil {
		return fmt.Errorf("raise %s alert: %w", al.Kind, err)
	}
	return nil
}

// open records the hop of an allowed DELEGATE and hands its token to the sink.
func (o *Observer) open(ctx context.Context, tx pgx.Tx, out *decide.Outcome, att *Attribution) error {
	a := out.Action
	to, _ := a.Target["to_agent"].(string)
	if to == "" {
		return errors.New("allowed DELEGATE without target.to_agent")
	}
	channel := ChannelA2A
	if c, ok := a.Target["channel"]; ok {
		s, isStr := c.(string)
		if !isStr || !slices.Contains(channels, s) {
			return fmt.Errorf("allowed DELEGATE with unknown channel %v", c)
		}
		channel = s
	}
	task := ""
	if t, ok := a.Target["task_id"]; ok && t != nil {
		s, isStr := t.(string)
		if !isStr {
			return errors.New("allowed DELEGATE with a non-string task_id")
		}
		task = s
	}
	lineage := []string{a.AgentID}
	depth := 1
	parent := ""
	if att != nil && att.Present && att.TokenError == "" && len(att.Lineage) > 0 {
		lineage = slices.Clone(att.Lineage)
		depth = att.Depth + 1
		parent = att.DelegationID
	}
	hop, tok, err := o.store.OpenTx(ctx, tx, Hop{
		ParentID: parent,
		From:     a.AgentID,
		To:       to,
		Chain:    append(lineage, to),
		Depth:    depth,
		TaskID:   task,
		Channel:  channel,
		ActionID: a.ActionID,
	}, o.actor)
	if err != nil {
		return fmt.Errorf("record delegation hop: %w", err)
	}
	if s := sinkFrom(ctx); s != nil {
		s.put(tok, hop)
	}
	return nil
}
