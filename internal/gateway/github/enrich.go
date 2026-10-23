package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"fortik/internal/authz"
	ghbroker "fortik/internal/broker/github"
	"fortik/internal/gateway"
)

// Enrich runs the pre-decision lookups: the repository's default branch
// (contents API without "branch"), the PR base (merge_pr) and branch
// protection (target.protected, cached 60 s). Lookups use Fortik's own
// read-only token, never the agent's.
//
// It deliberately skips lookups that cannot matter (repo outside the agent's
// profile, repo not owned by the installation account: the decision and/or
// Forward refuse those). A missing integration is remembered and answered
// by Forward with 503 after the decision is recorded. Any other lookup
// failure is returned: the gateway must refuse rather than decide on a
// guess (fail closed).
func (a *Adapter) Enrich(ctx context.Context, p authz.Principal, op *gateway.Op) error {
	st, ok := op.State.(*opState)
	if !ok || st == nil {
		return errors.New("github: op has no adapter state")
	}
	if st.unknown || st.repo == "" || !(st.branchFromDefault || st.needProtection || st.operation == OpMergePR) {
		return nil
	}
	prof, err := ghbroker.LoadProfile(ctx, a.cfg.Profiles, p.Name)
	if err != nil || !prof.HasRepo(st.repo) {
		return nil // denied by policy (POL-020/024) and refused by Forward
	}
	s, err := a.settings(ctx)
	if errors.Is(err, ghbroker.ErrNotConfigured) {
		st.notConfigured = err
		return nil
	}
	if err != nil {
		return err
	}
	if err := a.client.CheckOwner(ctx, s, st.owner); errors.Is(err, ghbroker.ErrWrongOwner) {
		return nil // Forward refuses
	} else if err != nil {
		return fmt.Errorf("github: installation lookup: %w", err)
	}
	if st.branchFromDefault {
		b, err := a.defaultBranch(ctx, s, st)
		if err != nil {
			return err
		}
		st.branch, st.ref = b, "heads/"+b
		op.Action.Target["branch"] = b
	}
	if st.operation == OpMergePR {
		base, err := a.prBase(ctx, s, st)
		if err != nil {
			return err
		}
		st.branch, st.ref = base, "heads/"+base
		op.Action.Target["branch"] = base
	}
	if st.needProtection && st.branch != "" && !strings.HasPrefix(st.branch, "refs/") {
		prot, err := a.branchProtected(ctx, s, st)
		if err != nil {
			return err
		}
		op.Action.Target["protected"] = prot
	}
	return nil
}

func (a *Adapter) defaultBranch(ctx context.Context, s ghbroker.Settings, st *opState) (string, error) {
	key := s.Fingerprint + "|" + st.repo
	a.lookupMu.Lock()
	c, ok := a.defaults[key]
	a.lookupMu.Unlock()
	if ok && a.cfg.Now().Sub(c.at) < lookupTTL {
		return c.v, nil
	}
	tok, err := a.lookupToken(ctx, s, st.name, "metadata")
	if err != nil {
		return "", fmt.Errorf("github: default branch lookup: %w", err)
	}
	var repo struct {
		DefaultBranch string `json:"default_branch"`
	}
	if _, err := a.client.JSON(ctx, s.BaseURL, tok.Secret, http.MethodGet, repoPath(st), nil, &repo, "get repository", http.StatusOK); err != nil {
		return "", fmt.Errorf("github: default branch lookup: %w", err)
	}
	if !validBranch(repo.DefaultBranch) {
		return "", errors.New("github: default branch lookup returned an invalid branch name")
	}
	a.lookupMu.Lock()
	a.pruneLookupsLocked()
	a.defaults[key] = cachedString{v: repo.DefaultBranch, at: a.cfg.Now()}
	a.lookupMu.Unlock()
	return repo.DefaultBranch, nil
}

// prBase is never cached: a PR's base can be changed at any time.
func (a *Adapter) prBase(ctx context.Context, s ghbroker.Settings, st *opState) (string, error) {
	tok, err := a.lookupToken(ctx, s, st.name, "pull_requests")
	if err != nil {
		return "", fmt.Errorf("github: pull request lookup: %w", err)
	}
	pr, err := a.getPull(ctx, s, tok.Secret, st)
	if err != nil {
		return "", err
	}
	return pr.Base.Ref, nil
}

type pullInfo struct {
	State  string `json:"state"`
	Merged bool   `json:"merged"`
	Base   struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

func (a *Adapter) getPull(ctx context.Context, s ghbroker.Settings, token string, st *opState) (pullInfo, error) {
	var pr pullInfo
	if _, err := a.client.JSON(ctx, s.BaseURL, token, http.MethodGet, repoPath(st)+"/pulls/"+strconv.Itoa(st.pr), nil, &pr,
		"get pull request", http.StatusOK); err != nil {
		return pullInfo{}, fmt.Errorf("github: pull request lookup: %w", err)
	}
	if !validBranch(pr.Base.Ref) || (pr.State != "open" && pr.State != "closed") {
		return pullInfo{}, errors.New("github: pull request lookup returned an unexpected base or state")
	}
	return pr, nil
}

// branchProtected reports GitHub's "protected" flag; a branch that does not
// exist yet (404, e.g. a new branch) is not protected. Name-based protection
// (policy config github_protected_branches) applies regardless.
func (a *Adapter) branchProtected(ctx context.Context, s ghbroker.Settings, st *opState) (bool, error) {
	key := s.Fingerprint + "|" + st.repo + "|" + st.branch
	a.lookupMu.Lock()
	c, ok := a.protection[key]
	a.lookupMu.Unlock()
	if ok && a.cfg.Now().Sub(c.at) < lookupTTL {
		return c.v, nil
	}
	tok, err := a.lookupToken(ctx, s, st.name, "contents")
	if err != nil {
		return false, fmt.Errorf("github: branch protection lookup: %w", err)
	}
	var br struct {
		Protected *bool `json:"protected"`
	}
	status, err := a.client.JSON(ctx, s.BaseURL, tok.Secret, http.MethodGet, repoPath(st)+"/branches/"+escapeRef(st.branch), nil, &br,
		"get branch", http.StatusOK, http.StatusNotFound)
	if err != nil {
		return false, fmt.Errorf("github: branch protection lookup: %w", err)
	}
	prot := false
	if status == http.StatusOK {
		if br.Protected == nil {
			return false, errors.New("github: branch protection lookup returned no protected flag")
		}
		prot = *br.Protected
	}
	a.lookupMu.Lock()
	a.pruneLookupsLocked()
	a.protection[key] = cachedBool{v: prot, at: a.cfg.Now()}
	a.lookupMu.Unlock()
	return prot, nil
}

func repoPath(st *opState) string {
	return "/repos/" + escapeSeg(st.owner) + "/" + escapeSeg(st.name)
}

// maxLookupEntries bounds the lookup caches: branch names come from agents,
// so an agent must not be able to grow them without limit.
const maxLookupEntries = 4096

// pruneLookupsLocked drops expired lookups once the caches are large, and
// everything if they are still over the limit (a cache miss only costs a lookup).
func (a *Adapter) pruneLookupsLocked() {
	if len(a.protection)+len(a.defaults) < maxLookupEntries {
		return
	}
	now := a.cfg.Now()
	for k, v := range a.protection {
		if now.Sub(v.at) >= lookupTTL {
			delete(a.protection, k)
		}
	}
	for k, v := range a.defaults {
		if now.Sub(v.at) >= lookupTTL {
			delete(a.defaults, k)
		}
	}
	if len(a.protection)+len(a.defaults) >= maxLookupEntries {
		a.protection = map[string]cachedBool{}
		a.defaults = map[string]cachedString{}
	}
}
