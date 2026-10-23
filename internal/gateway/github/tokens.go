package github

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"fortik/internal/action"
	"fortik/internal/broker"
	ghbroker "fortik/internal/broker/github"
)

// tokenRefreshMargin: a cached token is used until 5 minutes before expiry.
const tokenRefreshMargin = 5 * time.Minute

// internalAgent keys Fortik's own read-only lookup tokens (branch
// protection, default branch, PR base). They are never used for agent
// requests and never leave the process.
const internalAgent = "\x00fortik-lookup"

type cacheKey struct {
	agent, settings, repo, perms string
}

func (k cacheKey) String() string {
	return k.agent + "\x00" + k.settings + "\x00" + k.repo + "\x00" + k.perms
}

type tokenCache struct {
	mu sync.Mutex
	m  map[cacheKey]ghbroker.Token
}

func newTokenCache() *tokenCache { return &tokenCache{m: map[cacheKey]ghbroker.Token{}} }

func (c *tokenCache) get(k cacheKey, now time.Time) (ghbroker.Token, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.m[k]
	if !ok {
		return ghbroker.Token{}, false
	}
	if now.Add(tokenRefreshMargin).After(t.ExpiresAt) {
		delete(c.m, k)
		return ghbroker.Token{}, false
	}
	return t, true
}

// put stores a token and forgets every entry that is no longer usable, so
// the cache stays bounded by live (agent, repo, permission set) triples.
func (c *tokenCache) put(k cacheKey, t ghbroker.Token, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, old := range c.m {
		if now.Add(tokenRefreshMargin).After(old.ExpiresAt) {
			delete(c.m, key)
		}
	}
	c.m[k] = t
}

// drop removes one entry if it still holds token secret.
func (c *tokenCache) drop(k cacheKey, secret string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.m[k]; ok && t.Secret == secret {
		delete(c.m, k)
	}
}

// takeAgent removes and returns every cached token of an agent.
func (c *tokenCache) takeAgent(agent string) []ghbroker.Token {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []ghbroker.Token
	for k, t := range c.m {
		if k.agent == agent {
			out = append(out, t)
			delete(c.m, k)
		}
	}
	return out
}

// mintRequest describes the token an agent request needs.
type mintRequest struct {
	agentID, instanceID, actionID string
	owner, name, repo             string
	perms                         map[string]string
	profileVersion                int
}

// agentToken returns a cached or freshly minted installation token for one
// agent, repository and permission set. A fresh token is recorded with the
// IssuanceRecorder before use; if recording fails the token is revoked and
// the request refused (no unrecorded credential is ever used).
func (a *Adapter) agentToken(ctx context.Context, s ghbroker.Settings, req mintRequest) (ghbroker.Token, cacheKey, error) {
	key := cacheKey{agent: req.agentID, settings: s.Fingerprint, repo: req.repo, perms: ghbroker.PermKey(req.perms)}
	if t, ok := a.tokens.get(key, a.cfg.Now()); ok {
		return t, key, nil
	}
	v, err, _ := a.flight.Do(key.String(), func() (any, error) {
		if t, ok := a.tokens.get(key, a.cfg.Now()); ok {
			return t, nil
		}
		// Detached from the caller so one cancelled request cannot fail the
		// others waiting on the same mint.
		mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		t, err := a.client.MintToken(mctx, s, []string{req.name}, req.perms)
		if err != nil {
			return nil, err
		}
		cred := broker.Credential{
			IssuanceID: action.NewID("iss"),
			ActionID:   req.actionID,
			System:     ghbroker.System,
			ExpiresAt:  t.ExpiresAt,
			Scope: map[string]any{
				"mode":            "gateway",
				"repos":           []string{req.repo},
				"permissions":     t.Permissions,
				"installation_id": s.InstallationID,
				"profile_version": req.profileVersion,
				"note":            "held by the Fortik gateway; never returned to the agent",
			},
		}
		if err := a.cfg.Recorder.RecordIssuance(mctx, cred, req.agentID, req.instanceID); err != nil {
			if rerr := a.client.RevokeToken(mctx, s.BaseURL, t.Secret); rerr != nil {
				a.log.Error("github: revoking an unrecorded token failed; it expires on its own", "agent_id", req.agentID, "err", rerr)
			}
			return nil, fmt.Errorf("github: credential issuance could not be recorded; refused: %w", err)
		}
		a.tokens.put(key, t, a.cfg.Now())
		return t, nil
	})
	if err != nil {
		return ghbroker.Token{}, key, err
	}
	return v.(ghbroker.Token), key, nil
}

// lookupToken returns Fortik's own read-only token for pre-decision lookups.
func (a *Adapter) lookupToken(ctx context.Context, s ghbroker.Settings, name, perm string) (ghbroker.Token, error) {
	perms := map[string]string{perm: "read"}
	key := cacheKey{agent: internalAgent, settings: s.Fingerprint, repo: strings.ToLower(name), perms: ghbroker.PermKey(perms)}
	if t, ok := a.tokens.get(key, a.cfg.Now()); ok {
		return t, nil
	}
	v, err, _ := a.flight.Do(key.String(), func() (any, error) {
		if t, ok := a.tokens.get(key, a.cfg.Now()); ok {
			return t, nil
		}
		mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		t, err := a.client.MintToken(mctx, s, []string{name}, perms)
		if err != nil {
			return nil, err
		}
		a.tokens.put(key, t, a.cfg.Now())
		return t, nil
	})
	if err != nil {
		return ghbroker.Token{}, err
	}
	return v.(ghbroker.Token), nil
}

// DropAgent removes every cached gateway token of the agent and revokes each
// with DELETE /installation/token. Register it with the broker adapter
// (ghbroker.Adapter.OnRevokeAgent) so RevokeAll covers gateway tokens too.
// Requests after this mint a fresh token only if Decide allows them.
func (a *Adapter) DropAgent(ctx context.Context, agentID string) (string, error) {
	toks := a.tokens.takeAgent(agentID)
	var errs []error
	revoked := 0
	for _, t := range toks {
		if err := a.client.RevokeToken(ctx, t.BaseURL, t.Secret); err != nil {
			errs = append(errs, err)
			continue
		}
		revoked++
	}
	desc := fmt.Sprintf("github gateway: dropped %d cached token(s) and revoked %d", len(toks), revoked)
	if len(errs) > 0 {
		desc += fmt.Sprintf(" (%d revocation(s) failed; those tokens are no longer used by the gateway and expire within 1h)", len(errs))
	}
	return desc, errors.Join(errs...)
}

// CachedTokens reports how many gateway tokens are cached for the agent.
func (a *Adapter) CachedTokens(agentID string) int {
	a.tokens.mu.Lock()
	defer a.tokens.mu.Unlock()
	n := 0
	for k := range a.tokens.m {
		if k.agent == agentID {
			n++
		}
	}
	return n
}
