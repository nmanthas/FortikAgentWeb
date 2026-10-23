package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/policy"
)

// Diary event types written by the broker.
const (
	EventIssued  = "credential.issued"
	EventRefused = "credential.refused"
	EventRevoked = "credential.revoked"
)

// RuleBrokerScope names a refusal by the broker's own profile re-check (the
// decision allowed the issuance but the current profile does not).
const RuleBrokerScope = "BROKER-SCOPE"

// DefaultMaxLifetime caps any credential the broker records (the AWS STS maximum).
const DefaultMaxLifetime = 12 * time.Hour

// Service implements Broker: decide, narrow to the access profile, mint via
// the system's adapter, record (never the secret).
type Service struct {
	decider  decide.Decider
	pool     *pgxpool.Pool
	diary    *diary.Diary
	access   access.Store
	adapters map[string]Adapter
	log      *slog.Logger

	// TTL is the requested credential lifetime per system; 0 lets the adapter
	// use its configured default (e.g. broker.aws_session_ttl).
	TTL map[string]time.Duration
	// MaxLifetime rejects (and never returns) a minted credential that lives
	// longer than this (default DefaultMaxLifetime).
	MaxLifetime time.Duration
	Now         func() time.Time
}

var _ Broker = (*Service)(nil)

// New builds the broker. adapters is keyed by system ("aws", "github"); a
// system without an adapter answers ErrNotConfigured after its decision is
// recorded.
func New(dec decide.Decider, pool *pgxpool.Pool, d *diary.Diary, acc access.Store, adapters map[string]Adapter, log *slog.Logger) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{decider: dec, pool: pool, diary: d, access: acc, adapters: maps.Clone(adapters), log: log,
		TTL: map[string]time.Duration{}}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) maxLifetime() time.Duration {
	if s.MaxLifetime > 0 {
		return s.MaxLifetime
	}
	return DefaultMaxLifetime
}

// request is a validated IssueRequest.
type request struct {
	IssueRequest
	repos []string          // github, normalised
	perms map[string]string // github
}

// buildAction validates req and maps it to the Action that is decided.
func buildAction(req IssueRequest) (action.Action, request, error) {
	r := request{IssueRequest: req}
	a := action.Action{
		AgentID:    req.AgentID,
		InstanceID: req.InstanceID,
		System:     req.System,
		Source:     action.SourceAppGateway,
	}
	if req.AgentID == "" {
		return a, r, fmt.Errorf("%w: agent identity is required", ErrInvalidRequest)
	}
	switch req.System {
	case action.SystemAWS:
		if req.GitHub != nil {
			return a, r, fmt.Errorf("%w: github fields on an aws request", ErrInvalidRequest)
		}
		if err := validateAWS(req.AWS); err != nil {
			return a, r, err
		}
		target := map[string]any{
			"iam_action":         req.AWS.Service + ":" + req.AWS.Action,
			"resource":           req.AWS.Resource,
			"credential_request": true,
		}
		if req.AWS.Region != "" {
			target["region"] = req.AWS.Region
		}
		a.Verb = AWSVerb(req.AWS.Action, req.AWS.EstCostUSD)
		a.Target = target
		a.EstCostUSD = req.AWS.EstCostUSD
	case action.SystemGitHub:
		if req.AWS != nil {
			return a, r, fmt.Errorf("%w: aws fields on a github request", ErrInvalidRequest)
		}
		repos, perms, err := normGitHub(req.GitHub)
		if err != nil {
			return a, r, err
		}
		r.repos, r.perms = repos, perms
		a.Verb = action.VerbRead
		for _, v := range perms {
			if v != access.PermRead {
				a.Verb = action.VerbWrite
			}
		}
		a.Target = map[string]any{
			"repos":              repos,
			"permissions":        perms,
			"operation":          "credential",
			"credential_request": true,
		}
	case action.SystemPostgres:
		return a, r, ErrUnsupported
	default:
		return a, r, fmt.Errorf("%w: system must be aws or github (got %q)", ErrInvalidRequest, req.System)
	}
	return a, r, nil
}

// Issue decides, narrows, mints and records one credential. Refusals are
// *Refusal; a missing integration is *NotConfiguredError (errors.Is
// ErrNotConfigured), both after the decision is recorded.
func (s *Service) Issue(ctx context.Context, req IssueRequest) (Credential, error) {
	a, r, err := buildAction(req)
	if err != nil {
		return Credential{}, err
	}
	out, err := s.decider.Decide(ctx, a)
	if errors.Is(err, action.ErrInvalid) {
		return Credential{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if err != nil {
		return Credential{}, fmt.Errorf("decide: %w", err)
	}
	actionID := out.Action.ActionID
	if !out.Result.Decision.Executes() {
		s.refused(ctx, req, actionID, "decision", out.Result)
		return Credential{}, &Refusal{Outcome: out}
	}
	// A fail-closed outcome may still allow a green read (the configured
	// allowlist), but a credential outlives the request: never mint one
	// while Fortik itself is degraded.
	if out.FailClosed {
		ref := out
		ref.Result.Decision = policy.Deny
		ref.Result.Reason = out.Result.Reason + " (decided fail-closed: no credential is issued while Fortik is degraded)"
		ref.Result.ReducedForm = nil
		s.refused(ctx, req, actionID, "fail_closed", ref.Result)
		return Credential{}, &Refusal{Outcome: ref}
	}
	adapter, configured := s.adapters[req.System]
	if out.Result.Decision == policy.AllowReduced {
		rf, ok := adapter.(ReducedFormSupporter)
		if !configured || !ok || !rf.SupportsReducedForm(out.Result.ReducedForm) {
			ref := out
			ref.Result.Reason = out.Result.Reason + " (no reduced form is meaningful for a credential: refused)"
			s.refused(ctx, req, actionID, "reduced_form", ref.Result)
			return Credential{}, &Refusal{Outcome: ref}
		}
	}
	if !configured {
		s.refused(ctx, req, actionID, "not_configured", policy.Result{Decision: out.Result.Decision, RuleID: out.Result.RuleID,
			Reason: "integration not configured"})
		return Credential{}, &NotConfiguredError{System: req.System, ActionID: actionID}
	}

	scope, err := s.scope(ctx, r)
	if err != nil {
		return Credential{}, s.scopeRefusal(ctx, req, out, err)
	}
	cred, err := adapter.Mint(ctx, req.AgentID, scope, s.TTL[req.System])
	switch {
	case err == nil:
	case errors.Is(err, ErrNotConfigured), errors.Is(err, integrations.ErrNotConfigured):
		s.refused(ctx, req, actionID, "not_configured", policy.Result{Decision: out.Result.Decision, RuleID: out.Result.RuleID,
			Reason: "integration not configured"})
		return Credential{}, &NotConfiguredError{System: req.System, ActionID: actionID}
	case errors.Is(err, ErrScopeDenied):
		return Credential{}, s.scopeRefusal(ctx, req, out, err)
	default:
		s.log.Error("credential mint failed", "system", req.System, "agent_id", req.AgentID, "action_id", actionID, "err", err)
		s.refused(ctx, req, actionID, "mint", policy.Result{Decision: out.Result.Decision, RuleID: out.Result.RuleID,
			Reason: "credential issuance failed upstream"})
		return Credential{}, fmt.Errorf("%w: %s", ErrMintFailed, req.System)
	}
	cred.ActionID = actionID
	cred.System = req.System
	if err := s.checkMinted(cred); err != nil {
		s.log.Error("adapter returned an unacceptable credential; discarded", "system", req.System, "action_id", actionID, "err", err)
		s.refused(ctx, req, actionID, "mint", policy.Result{Decision: out.Result.Decision, RuleID: out.Result.RuleID, Reason: err.Error()})
		return Credential{}, fmt.Errorf("%w: %v", ErrMintFailed, err)
	}
	if err := s.record(ctx, &cred, req.AgentID, req.InstanceID); err != nil {
		// Never hand out a credential that is not on record.
		s.log.Error("credential minted but not recorded; discarded unreturned", "system", req.System,
			"agent_id", req.AgentID, "action_id", actionID, "expires_at", cred.ExpiresAt, "err", err)
		return Credential{}, fmt.Errorf("record credential issuance: %w", err)
	}
	return cred, nil
}

// scope builds the Mint scope from the request intersected with the
// agent's current access profile.
func (s *Service) scope(ctx context.Context, r request) (map[string]any, error) {
	prof, err := s.access.Current(ctx, r.AgentID, r.System)
	if errors.Is(err, access.ErrNotFound) {
		return nil, fmt.Errorf("%w: no access profile", ErrScopeDenied)
	}
	if err != nil {
		return nil, err
	}
	parsed, err := access.Parse(r.System, prof.Profile)
	if err != nil {
		return nil, fmt.Errorf("%w: stored profile: %v", ErrScopeDenied, err)
	}
	scope := map[string]any{ScopeProfile: prof.Profile, ScopeProfileVersion: prof.Version}
	switch p := parsed.(type) {
	case access.AWSProfile:
		if err := CheckAWSProfile(p, r.AWS.Service, r.AWS.Action); err != nil {
			return nil, err
		}
		scope["service"] = r.AWS.Service
		scope["action"] = r.AWS.Action
		scope["iam_action"] = r.AWS.Service + ":" + r.AWS.Action
		scope["resource"] = r.AWS.Resource
		scope["region"] = r.AWS.Region
	case access.GitHubProfile:
		repos, perms, err := intersectGitHub(p, r.repos, r.perms)
		if err != nil {
			return nil, err
		}
		scope["repos"] = repos
		scope["permissions"] = perms
	default:
		return nil, ErrUnsupported
	}
	return scope, nil
}

// scopeRefusal converts a profile re-check failure into a Refusal (or
// passes a store error through so the caller fails closed with 500).
func (s *Service) scopeRefusal(ctx context.Context, req IssueRequest, out decide.Outcome, err error) error {
	if !errors.Is(err, ErrScopeDenied) {
		if errors.Is(err, ErrUnsupported) {
			return err
		}
		s.log.Error("credential scope check failed", "system", req.System, "action_id", out.Action.ActionID, "err", err)
		s.refused(ctx, req, out.Action.ActionID, "profile", policy.Result{Decision: out.Result.Decision, RuleID: RuleBrokerScope,
			Reason: "access profile unavailable: fail closed"})
		return fmt.Errorf("credential scope: %w", err)
	}
	ref := out
	ref.Result.Decision = policy.Deny
	ref.Result.RuleID = RuleBrokerScope
	ref.Result.Reason = err.Error()
	ref.Result.ReducedForm = nil
	s.refused(ctx, req, out.Action.ActionID, "profile", ref.Result)
	return &Refusal{Outcome: ref}
}

// checkMinted enforces that the adapter returned a usable, short-lived credential.
func (s *Service) checkMinted(c Credential) error {
	now := s.now()
	if c.ExpiresAt.IsZero() || !c.ExpiresAt.After(now) {
		return errors.New("credential has no future expiry")
	}
	if c.ExpiresAt.After(now.Add(s.maxLifetime() + time.Minute)) {
		return fmt.Errorf("credential lives longer than %s", s.maxLifetime())
	}
	if len(c.Secret) == 0 {
		return errors.New("credential has no secret material")
	}
	return nil
}

// RecordIssuance stores a credential issued in-process (gateway, pgproxy)
// and writes credential.issued. The secret is never stored.
func (s *Service) RecordIssuance(ctx context.Context, c Credential, agentID, instanceID string) error {
	if agentID == "" || c.System == "" {
		return fmt.Errorf("%w: agent and system are required", ErrInvalidRequest)
	}
	now := s.now()
	if c.ExpiresAt.IsZero() || !c.ExpiresAt.After(now) || c.ExpiresAt.After(now.Add(s.maxLifetime()+time.Minute)) {
		return fmt.Errorf("%w: expires_at must be in the future and within %s", ErrInvalidRequest, s.maxLifetime())
	}
	return s.record(ctx, &c, agentID, instanceID)
}

// record inserts the issuance row and the Diary event in one transaction,
// assigning an issuance id when the adapter did not.
func (s *Service) record(ctx context.Context, c *Credential, agentID, instanceID string) error {
	if c.IssuanceID == "" {
		c.IssuanceID = action.NewID("iss")
	}
	scope := map[string]any{}
	for k, v := range c.Scope {
		if k != ScopeProfile {
			scope[k] = v
		}
	}
	c.Scope = scope
	scopeJSON, err := json.Marshal(scope)
	if err != nil {
		return fmt.Errorf("encode scope: %w", err)
	}
	exp := c.ExpiresAt.UTC()
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO credential_issuances (issuance_id, action_id, agent_id, instance_id, system, scope_json, expires_at)
			VALUES ($1, NULLIF($2, ''), $3, NULLIF($4, ''), $5, $6, $7)`,
			c.IssuanceID, c.ActionID, agentID, instanceID, c.System, scopeJSON, exp); err != nil {
			return fmt.Errorf("insert credential issuance: %w", err)
		}
		_, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: EventIssued, Actor: "agent:" + agentID,
			Data: map[string]any{
				"issuance_id": c.IssuanceID,
				"action_id":   c.ActionID,
				"instance_id": instanceID,
				"system":      c.System,
				"scope":       scope,
				"expires_at":  exp.Format(time.RFC3339),
			}})
		return err
	})
}

// refused writes credential.refused (best effort, own transaction): the
// decision itself is already recorded by Decide.
func (s *Service) refused(ctx context.Context, req IssueRequest, actionID, stage string, res policy.Result) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	data := map[string]any{
		"action_id": actionID,
		"system":    req.System,
		"stage":     stage,
		"decision":  string(res.Decision),
		"rule_id":   res.RuleID,
		"reason":    res.Reason,
	}
	if req.InstanceID != "" {
		data["instance_id"] = req.InstanceID
	}
	if _, err := s.diary.Append(rctx, diary.Event{AgentID: req.AgentID, EventType: EventRefused, Actor: "agent:" + req.AgentID, Data: data}); err != nil {
		s.log.Error("could not record credential refusal", "action_id", actionID, "err", err)
	}
}

// RevokeAll revokes every live credential of the agent on every system
// (best effort: each adapter is tried even if another fails). For each
// system it records what was actually achieved: live issuances are marked
// revoked only when the adapter succeeded, and one credential.revoked Diary
// event per system carries the adapter's own description. Systems with live
// issuances but no adapter are recorded honestly as expiring naturally.
// The returned map is system -> description; the error joins failures.
// liveIssuances counts unexpired, unrevoked credentials recorded for the
// agent on one system.
func (s *Service) liveIssuances(ctx context.Context, agentID, system string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM credential_issuances
		WHERE agent_id = $1 AND system = $2 AND revoked_at IS NULL AND expires_at > now()`, agentID, system).Scan(&n)
	return n, err
}

func (s *Service) RevokeAll(ctx context.Context, agentID, actor, reason string) (map[string]string, error) {
	if agentID == "" || actor == "" {
		return nil, fmt.Errorf("%w: agent and actor are required", ErrInvalidRequest)
	}
	results := map[string]string{}
	var errs []error
	for _, sys := range slices.Sorted(maps.Keys(s.adapters)) {
		desc, err := s.adapters[sys].RevokeAgent(ctx, agentID)
		if err != nil && (errors.Is(err, ErrNotConfigured) || errors.Is(err, integrations.ErrNotConfigured)) {
			// An unconfigured system can only hold credentials Fortik issued
			// before the integration was removed: if none are live, there is
			// honestly nothing to revoke; if some are, it stays a failure.
			if live, lerr := s.liveIssuances(ctx, agentID, sys); lerr == nil && live == 0 {
				desc, err = sys+": integration not configured and no live credentials issued: nothing to revoke", nil
			}
		}
		ok := err == nil
		if !ok {
			s.log.Error("credential revocation failed", "system", sys, "agent_id", agentID, "err", err)
			desc = "revocation FAILED: " + sanitize(err.Error())
			errs = append(errs, fmt.Errorf("%s: %w", sys, err))
		}
		results[sys] = desc
		if err := s.recordRevocation(ctx, agentID, sys, actor, reason, desc, ok); err != nil {
			errs = append(errs, fmt.Errorf("%s: record revocation: %w", sys, err))
		}
	}
	// Live issuances on systems no adapter here can revoke (e.g. recorded by
	// an in-process issuer): say so rather than claim a revocation.
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT system FROM credential_issuances
		WHERE agent_id = $1 AND revoked_at IS NULL AND expires_at > now()`, agentID)
	if err != nil {
		errs = append(errs, err)
	} else {
		systems, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			errs = append(errs, err)
		}
		for _, sys := range systems {
			if _, handled := s.adapters[sys]; handled {
				continue
			}
			desc := "no revocation adapter registered: live credentials stay valid until they expire; Fortik stops issuing new ones"
			results[sys] = desc
			if err := s.recordRevocation(ctx, agentID, sys, actor, reason, desc, false); err != nil {
				errs = append(errs, fmt.Errorf("%s: record revocation: %w", sys, err))
			}
		}
	}
	return results, errors.Join(errs...)
}

func (s *Service) recordRevocation(ctx context.Context, agentID, system, actor, reason, desc string, revoked bool) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return pgx.BeginFunc(rctx, s.pool, func(tx pgx.Tx) error {
		var marked int64
		if revoked {
			tag, err := tx.Exec(rctx, `UPDATE credential_issuances SET revoked_at = now(), revoke_method = $3
				WHERE agent_id = $1 AND system = $2 AND revoked_at IS NULL AND expires_at > now()`, agentID, system, desc)
			if err != nil {
				return err
			}
			marked = tag.RowsAffected()
		}
		_, err := s.diary.AppendTx(rctx, tx, diary.Event{AgentID: agentID, EventType: EventRevoked, Actor: actor, Data: map[string]any{
			"system":           system,
			"succeeded":        revoked,
			"method":           desc,
			"issuances_marked": marked,
			"reason":           reason,
		}})
		return err
	})
}

// sanitize keeps an adapter error short and single-line for the Diary.
func sanitize(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
