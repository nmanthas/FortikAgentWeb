package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/broker"
	"fortik/internal/integrations"
)

// Errors returned by Mint. Each wraps broker.ErrScopeDenied, so the broker
// core records and returns a refusal (rule BROKER-SCOPE).
var (
	ErrDirectTokenNotAllowed = fmt.Errorf("%w: github: direct tokens are not allowed for this agent (allow_direct_token is false); use the gateway /gw/github/", broker.ErrScopeDenied)
	ErrEmptyScope            = fmt.Errorf("%w: github: nothing grantable: the requested repositories/permissions do not intersect the access profile", broker.ErrScopeDenied)
	ErrBadScope              = fmt.Errorf("%w: github: invalid credential scope", broker.ErrScopeDenied)
)

// RevokeHook is called by RevokeAgent so in-process token holders (the
// gateway's token cache) drop and revoke their tokens for the agent. It
// returns a human description of what it did.
type RevokeHook func(ctx context.Context, agentID string) (string, error)

// Adapter is the broker.Adapter for GitHub direct tokens
// (POST /v1/credentials/issue with system "github"). It mints only when the
// agent's profile has allow_direct_token, narrowed to profile ∩ request, and
// keeps every token it minted in an in-process registry so RevokeAgent can
// revoke them with DELETE /installation/token.
type Adapter struct {
	client   *Client
	source   integrations.Source
	profiles ProfileSource
	log      *slog.Logger

	mu     sync.Mutex
	live   map[string][]*liveToken // agent id -> tokens minted by this process
	hooks  []RevokeHook
	closed bool
}

type liveToken struct {
	issuanceID string
	secret     string
	baseURL    string
	expiresAt  time.Time
	timer      *time.Timer // early revocation when the requested ttl < GitHub's 1h
}

var _ broker.Adapter = (*Adapter)(nil)

// AdapterConfig wires the adapter. Source is required.
type AdapterConfig struct {
	Client *Client             // shared with the gateway adapter; nil = new client
	Source integrations.Source // the "github" integration (config + private key)
	// Profiles is used when a Mint scope carries no access_profile (the
	// broker core always passes one); nil then means refuse.
	Profiles ProfileSource
	Log      *slog.Logger
}

// NewAdapter builds the direct-token adapter.
func NewAdapter(cfg AdapterConfig) (*Adapter, error) {
	if cfg.Source == nil {
		return nil, errors.New("github broker adapter: Source is required")
	}
	if cfg.Client == nil {
		cfg.Client = NewClient(nil)
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	return &Adapter{client: cfg.Client, source: cfg.Source, profiles: cfg.Profiles, log: cfg.Log, live: map[string][]*liveToken{}}, nil
}

func (a *Adapter) System() string { return System }

// OnRevokeAgent registers a hook run by RevokeAgent (e.g. the gateway's
// DropAgent so its cached tokens are revoked and dropped too).
func (a *Adapter) OnRevokeAgent(h RevokeHook) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hooks = append(a.hooks, h)
}

// Scope is the scope Mint accepts: {"repos":["org/repo"],"permissions":{"contents":"read"}}
// (the shape of broker.GHRequest). Any JSON-equivalent map works.
type Scope = broker.GHRequest

func parseScope(scope map[string]any) (Scope, error) {
	b, err := json.Marshal(scope)
	if err != nil {
		return Scope{}, fmt.Errorf("%w: %v", ErrBadScope, err)
	}
	var s Scope
	if err := json.Unmarshal(b, &s); err != nil {
		return Scope{}, fmt.Errorf("%w: %v", ErrBadScope, err)
	}
	if len(s.Repos) == 0 || len(s.Permissions) == 0 {
		return Scope{}, fmt.Errorf("%w: repos and permissions are required (GitHub would otherwise grant every repository/permission of the installation)", ErrBadScope)
	}
	return s, nil
}

// Narrow intersects a requested scope with the profile: repositories not in
// the profile are dropped, each permission is lowered to the profile's level
// (or dropped). Malformed input is an error, never silently widened.
func Narrow(req Scope, prof Profile) (repos []string, perms map[string]string, err error) {
	seen := map[string]bool{}
	for _, r := range req.Repos {
		owner, name, err := SplitRepo(r)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrBadScope, err)
		}
		full := strings.ToLower(owner + "/" + name)
		if prof.HasRepo(full) && !seen[full] {
			seen[full] = true
			repos = append(repos, full)
		}
	}
	perms = map[string]string{}
	for k, v := range req.Permissions {
		if !validPermName.MatchString(k) || levelRank(v) == 0 {
			return nil, nil, fmt.Errorf("%w: permission %q:%q", ErrBadScope, k, v)
		}
		switch {
		case prof.Allows(k, v):
			perms[k] = v
		case v != "read" && prof.Allows(k, "read"):
			perms[k] = "read"
		}
	}
	if len(repos) == 0 || len(perms) == 0 {
		return nil, nil, ErrEmptyScope
	}
	sort.Strings(repos)
	return repos, perms, nil
}

// Mint issues a direct installation token. GitHub fixes the lifetime at 1h;
// when ttl is shorter the token is revoked by this process at ttl (best
// effort: ExpiresAt stays GitHub's hard expiry, the honest upper bound).
func (a *Adapter) Mint(ctx context.Context, agentID string, scope map[string]any, ttl time.Duration) (broker.Credential, error) {
	prof, err := a.profile(ctx, agentID, scope)
	if err != nil {
		return broker.Credential{}, err
	}
	if !prof.AllowDirectToken {
		return broker.Credential{}, ErrDirectTokenNotAllowed
	}
	req, err := parseScope(scope)
	if err != nil {
		return broker.Credential{}, err
	}
	repos, perms, err := Narrow(req, prof)
	if err != nil {
		return broker.Credential{}, err
	}
	res, err := a.source.Get(ctx, IntegrationKey)
	if err != nil {
		if errors.Is(err, integrations.ErrNotConfigured) {
			return broker.Credential{}, notConfigured{}
		}
		return broker.Credential{}, fmt.Errorf("github: load integration: %w", err)
	}
	s, err := a.client.Settings(res)
	if err != nil {
		return broker.Credential{}, err
	}
	names := make([]string, 0, len(repos))
	for _, r := range repos {
		owner, name, _ := SplitRepo(r)
		if err := a.client.CheckOwner(ctx, s, owner); err != nil {
			return broker.Credential{}, err
		}
		names = append(names, name)
	}
	tok, err := a.client.MintToken(ctx, s, names, perms)
	if err != nil {
		return broker.Credential{}, err
	}

	lt := &liveToken{issuanceID: action.NewID("iss"), secret: tok.Secret, baseURL: s.BaseURL, expiresAt: tok.ExpiresAt}
	credScope := map[string]any{
		"mode":            "direct",
		"repos":           repos,
		"permissions":     tok.Permissions,
		"installation_id": s.InstallationID,
		"profile_version": prof.Version,
		"hard_expiry":     "GitHub installation tokens live at most 1h; revocation: DELETE /installation/token",
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		a.revokeBestEffort(lt)
		return broker.Credential{}, errors.New("github broker adapter is shut down")
	}
	if ttl > 0 && time.Until(tok.ExpiresAt) > ttl {
		at := time.Now().Add(ttl)
		credScope["revoke_scheduled_at"] = at.UTC().Format(time.RFC3339)
		lt.timer = time.AfterFunc(ttl, func() { a.expire(agentID, lt) })
	}
	a.pruneLocked(agentID)
	a.live[agentID] = append(a.live[agentID], lt)
	a.mu.Unlock()

	return broker.Credential{
		IssuanceID: lt.issuanceID,
		System:     System,
		ExpiresAt:  tok.ExpiresAt,
		Scope:      credScope,
		Secret:     map[string]string{"token": tok.Secret},
	}, nil
}

// profile returns the profile to narrow against: the one the broker core
// decided and intersected with (scope access_profile), else the current one
// from Profiles. Errors (no profile, invalid profile) are scope refusals.
func (a *Adapter) profile(ctx context.Context, agentID string, scope map[string]any) (Profile, error) {
	if raw, ok := scope[broker.ScopeProfile]; ok {
		var b []byte
		switch v := raw.(type) {
		case json.RawMessage:
			b = v
		case []byte:
			b = v
		default:
			var err error
			if b, err = json.Marshal(v); err != nil {
				return Profile{}, fmt.Errorf("%w: access_profile: %v", ErrBadScope, err)
			}
		}
		prof, err := ParseProfile(b)
		if err != nil {
			return Profile{}, fmt.Errorf("%w: %v", broker.ErrScopeDenied, err)
		}
		if v, ok := scope[broker.ScopeProfileVersion].(int); ok {
			prof.Version = v
		}
		return prof, nil
	}
	if a.profiles == nil {
		return Profile{}, fmt.Errorf("%w: no access profile available", broker.ErrScopeDenied)
	}
	prof, err := LoadProfile(ctx, a.profiles, agentID)
	if errors.Is(err, access.ErrInvalidProfile) {
		return Profile{}, fmt.Errorf("%w: %v", broker.ErrScopeDenied, err)
	}
	return prof, err
}

// expire revokes a token whose requested ttl elapsed.
func (a *Adapter) expire(agentID string, lt *liveToken) {
	a.mu.Lock()
	removed := a.removeLocked(agentID, lt)
	a.mu.Unlock()
	if removed {
		a.revokeBestEffort(lt)
	}
}

func (a *Adapter) revokeBestEffort(lt *liveToken) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.client.RevokeToken(ctx, lt.baseURL, lt.secret); err != nil {
		a.log.Warn("github: scheduled token revocation failed; the token expires on its own", "issuance_id", lt.issuanceID,
			"expires_at", lt.expiresAt, "err", err)
	}
}

func (a *Adapter) removeLocked(agentID string, lt *liveToken) bool {
	list := a.live[agentID]
	for i, x := range list {
		if x == lt {
			a.live[agentID] = append(list[:i:i], list[i+1:]...)
			if len(a.live[agentID]) == 0 {
				delete(a.live, agentID)
			}
			return true
		}
	}
	return false
}

// pruneLocked forgets tokens GitHub has already expired.
func (a *Adapter) pruneLocked(agentID string) {
	now := time.Now()
	list := a.live[agentID][:0]
	for _, lt := range a.live[agentID] {
		if lt.expiresAt.After(now) {
			list = append(list, lt)
		} else if lt.timer != nil {
			lt.timer.Stop()
		}
	}
	if len(list) == 0 {
		delete(a.live, agentID)
	} else {
		a.live[agentID] = list
	}
}

// LiveTokens reports how many unexpired direct tokens this process holds for
// the agent (no secrets).
func (a *Adapter) LiveTokens(agentID string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(agentID)
	return len(a.live[agentID])
}

// RevokeAgent revokes every live direct token this process minted for the
// agent (DELETE /installation/token), then runs the registered hooks (the
// gateway drops and revokes its cached tokens). The description states the
// real semantics, including what this process cannot reach.
func (a *Adapter) RevokeAgent(ctx context.Context, agentID string) (string, error) {
	a.mu.Lock()
	a.pruneLocked(agentID)
	toks := a.live[agentID]
	delete(a.live, agentID)
	hooks := append([]RevokeHook(nil), a.hooks...)
	a.mu.Unlock()

	var errs []error
	revoked, failed := 0, 0
	for _, lt := range toks {
		if lt.timer != nil {
			lt.timer.Stop()
		}
		if err := a.client.RevokeToken(ctx, lt.baseURL, lt.secret); err != nil {
			failed++
			errs = append(errs, fmt.Errorf("issuance %s: %w", lt.issuanceID, err))
			continue
		}
		revoked++
	}
	parts := []string{fmt.Sprintf("github: revoked %d direct token(s) minted by this process via DELETE /installation/token", revoked)}
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%d revocation(s) FAILED (those tokens stay valid until they expire, at most 1h)", failed))
	}
	for _, h := range hooks {
		desc, err := h(ctx, agentID)
		if desc != "" {
			parts = append(parts, desc)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	parts = append(parts, "tokens minted by other Fortik processes/instances are not tracked here and expire within 1h; new requests are refused by Decide")
	return strings.Join(parts, "; "), errors.Join(errs...)
}

// Close stops scheduled revocations, first revoking every token whose
// requested ttl is shorter than GitHub's expiry (revoking early is always
// safe; leaving it would outlive the promised ttl).
func (a *Adapter) Close() {
	a.mu.Lock()
	a.closed = true
	var early []*liveToken
	for _, list := range a.live {
		for _, lt := range list {
			if lt.timer != nil && lt.timer.Stop() {
				early = append(early, lt)
			}
		}
	}
	a.live = map[string][]*liveToken{}
	a.mu.Unlock()
	for _, lt := range early {
		a.revokeBestEffort(lt)
	}
}
