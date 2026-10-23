package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	ghbroker "fortik/internal/broker/github"
	"fortik/internal/integrations"
	"fortik/internal/undo"
)

// UndoExecutor reverses KindRef and KindPR handles (POST /v1/undo/{id}). It
// uses its own single-repository token (contents:write or
// pull_requests:write), revoked as soon as the undo finishes.
type UndoExecutor struct {
	client *ghbroker.Client
	source integrations.Source
	log    *slog.Logger
}

var _ undo.Executor = (*UndoExecutor)(nil)

// NewUndoExecutor builds the executor (nil client = new client).
func NewUndoExecutor(c *ghbroker.Client, src integrations.Source, log *slog.Logger) *UndoExecutor {
	if c == nil {
		c = ghbroker.NewClient(nil)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &UndoExecutor{client: c, source: src, log: log}
}

func (e *UndoExecutor) Kinds() []string { return []string{KindRef, KindPR} }

// Undo reverses one handle. Both reversals are idempotent (restoring a ref to
// a sha, reopening a PR), so a failed attempt can safely be retried.
func (e *UndoExecutor) Undo(ctx context.Context, h undo.Handle) (map[string]any, error) {
	switch h.Kind {
	case KindRef:
		var d RefUndoData
		if err := json.Unmarshal(h.Data, &d); err != nil {
			return nil, fmt.Errorf("github undo: bad handle_json: %w", err)
		}
		return e.undoRef(ctx, d)
	case KindPR:
		var d PRUndoData
		if err := json.Unmarshal(h.Data, &d); err != nil {
			return nil, fmt.Errorf("github undo: bad handle_json: %w", err)
		}
		return e.undoPR(ctx, d)
	}
	return nil, fmt.Errorf("%w: %s", undo.ErrUnsupported, h.Kind)
}

// token mints a single-repository token for the undo and returns a func that
// revokes it.
func (e *UndoExecutor) token(ctx context.Context, repo string, perms map[string]string) (ghbroker.Settings, ghbroker.Token, string, func(), error) {
	owner, name, err := ghbroker.SplitRepo(repo)
	if err != nil {
		return ghbroker.Settings{}, ghbroker.Token{}, "", nil, fmt.Errorf("github undo: %w", err)
	}
	if e.source == nil {
		return ghbroker.Settings{}, ghbroker.Token{}, "", nil, ghbroker.ErrNotConfigured
	}
	res, err := e.source.Get(ctx, ghbroker.IntegrationKey)
	if errors.Is(err, integrations.ErrNotConfigured) {
		return ghbroker.Settings{}, ghbroker.Token{}, "", nil, fmt.Errorf("github undo: %w", ghbroker.ErrNotConfigured)
	}
	if err != nil {
		return ghbroker.Settings{}, ghbroker.Token{}, "", nil, fmt.Errorf("github undo: load integration: %w", err)
	}
	s, err := e.client.Settings(res)
	if err != nil {
		return ghbroker.Settings{}, ghbroker.Token{}, "", nil, fmt.Errorf("github undo: %w", err)
	}
	if err := e.client.CheckOwner(ctx, s, owner); err != nil {
		return ghbroker.Settings{}, ghbroker.Token{}, "", nil, fmt.Errorf("github undo: %w", err)
	}
	tok, err := e.client.MintToken(ctx, s, []string{name}, perms)
	if err != nil {
		return ghbroker.Settings{}, ghbroker.Token{}, "", nil, fmt.Errorf("github undo: %w", err)
	}
	revoke := func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := e.client.RevokeToken(rctx, s.BaseURL, tok.Secret); err != nil {
			e.log.Warn("github undo: revoking the undo token failed; it expires within 1h", "repo", repo, "err", err)
		}
	}
	return s, tok, "/repos/" + escapeSeg(owner) + "/" + escapeSeg(name), revoke, nil
}

func (e *UndoExecutor) undoRef(ctx context.Context, d RefUndoData) (map[string]any, error) {
	if !validRef(d.Ref) {
		return nil, fmt.Errorf("github undo: invalid ref %q in handle", d.Ref)
	}
	if d.PreviousSHA != "" && !shaPattern.MatchString(d.PreviousSHA) {
		return nil, errors.New("github undo: invalid previous_sha in handle")
	}
	s, tok, rp, revoke, err := e.token(ctx, d.Repo, map[string]string{"contents": "write"})
	if err != nil {
		return nil, err
	}
	defer revoke()
	cur, err := currentRefSHA(ctx, e.client, s, tok.Secret, rp, d.Ref)
	if err != nil {
		return nil, fmt.Errorf("github undo: %w", err)
	}
	result := map[string]any{"repo": d.Repo, "ref": d.Ref, "previous_sha": d.PreviousSHA, "sha_before_undo": cur}
	refURL := rp + "/git/refs/" + escapeRef(d.Ref)
	switch {
	case d.PreviousSHA == "" && cur == "":
		result["action"] = "none: the ref does not exist, as before the action"
	case d.PreviousSHA == "":
		if err := e.checkUnchangedSince(ctx, s, tok.Secret, rp, d, cur); err != nil {
			return nil, err
		}
		if _, err := e.client.JSON(ctx, s.BaseURL, tok.Secret, http.MethodDelete, refURL, nil, nil, "delete ref", http.StatusNoContent); err != nil {
			return nil, fmt.Errorf("github undo: %w", err)
		}
		result["action"] = "deleted the ref created by the action"
	case cur == d.PreviousSHA:
		result["action"] = "none: the ref already points at the previous sha"
	case cur == "":
		body := map[string]any{"ref": "refs/" + d.Ref, "sha": d.PreviousSHA}
		if _, err := e.client.JSON(ctx, s.BaseURL, tok.Secret, http.MethodPost, rp+"/git/refs", body, nil, "recreate ref", http.StatusCreated); err != nil {
			return nil, fmt.Errorf("github undo: %w", err)
		}
		result["action"] = "recreated the deleted ref at the previous sha"
	default:
		if err := e.checkUnchangedSince(ctx, s, tok.Secret, rp, d, cur); err != nil {
			return nil, err
		}
		body := map[string]any{"sha": d.PreviousSHA, "force": true}
		if _, err := e.client.JSON(ctx, s.BaseURL, tok.Secret, http.MethodPatch, refURL, body, nil, "restore ref", http.StatusOK); err != nil {
			return nil, fmt.Errorf("github undo: %w", err)
		}
		result["action"] = "force-updated the ref back to the previous sha"
	}
	return result, nil
}

// checkUnchangedSince refuses to rewind (or delete) a ref unless it still
// points at what the action itself produced; otherwise later commits pushed
// by people or CI would be silently discarded by a forced update.
//   - ResultSHA known (git refs create/update): cur must equal it.
//   - delete_branch: the ref existing again means someone recreated it.
//   - otherwise (contents API, merge_pr): the action made exactly one commit
//     on top of the previous sha, so cur's first parent must be PreviousSHA.
func (e *UndoExecutor) checkUnchangedSince(ctx context.Context, s ghbroker.Settings, token, rp string, d RefUndoData, cur string) error {
	moved := func() error {
		return fmt.Errorf("%w: %s moved to %s after the action (changes by someone else); refusing to discard them, restore %s manually if intended",
			undo.ErrNothingToUndo, d.Ref, cur, d.Ref)
	}
	switch {
	case d.ResultSHA != "":
		if !strings.EqualFold(cur, d.ResultSHA) {
			return moved()
		}
		return nil
	case d.Operation == OpDeleteBranch, d.PreviousSHA == "":
		return moved()
	}
	var c struct {
		SHA     string `json:"sha"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	status, err := e.client.JSON(ctx, s.BaseURL, token, http.MethodGet, rp+"/git/commits/"+url.PathEscape(cur), nil, &c, "get commit",
		http.StatusOK, http.StatusNotFound)
	if err != nil {
		return fmt.Errorf("github undo: %w", err)
	}
	if status != http.StatusOK || !strings.EqualFold(c.SHA, cur) || len(c.Parents) == 0 || !strings.EqualFold(c.Parents[0].SHA, d.PreviousSHA) {
		return moved()
	}
	return nil
}

func (e *UndoExecutor) undoPR(ctx context.Context, d PRUndoData) (map[string]any, error) {
	if d.PR <= 0 {
		return nil, errors.New("github undo: invalid pr in handle")
	}
	result := map[string]any{"repo": d.Repo, "pr": d.PR, "previous_state": d.PreviousState}
	if d.PreviousState != "open" {
		result["action"] = "none: the pull request was not open before the action"
		return result, nil
	}
	s, tok, rp, revoke, err := e.token(ctx, d.Repo, map[string]string{"pull_requests": "write"})
	if err != nil {
		return nil, err
	}
	defer revoke()
	var pr pullInfo
	if _, err := e.client.JSON(ctx, s.BaseURL, tok.Secret, http.MethodGet, rp+"/pulls/"+strconv.Itoa(d.PR), nil, &pr, "get pull request", http.StatusOK); err != nil {
		return nil, fmt.Errorf("github undo: %w", err)
	}
	switch {
	case pr.State == "open":
		result["action"] = "none: the pull request is already open"
	case pr.Merged:
		return nil, fmt.Errorf("%w: pull request #%d was merged after it was closed; it cannot be reopened", undo.ErrNothingToUndo, d.PR)
	default:
		if _, err := e.client.JSON(ctx, s.BaseURL, tok.Secret, http.MethodPatch, rp+"/pulls/"+strconv.Itoa(d.PR),
			map[string]any{"state": "open"}, nil, "reopen pull request", http.StatusOK); err != nil {
			return nil, fmt.Errorf("github undo: %w", err)
		}
		result["action"] = "reopened the pull request"
	}
	return result, nil
}

// validRef accepts "heads/<branch>" and "tags/<tag>".
func validRef(ref string) bool {
	return validFullRef("refs/" + ref)
}

// escapeRef escapes each "/"-separated part of a ref or branch.
func escapeRef(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = escapeSeg(p)
	}
	return strings.Join(parts, "/")
}

func escapeSeg(s string) string { return url.PathEscape(s) }
