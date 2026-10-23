package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"fortik/internal/authz"
	ghbroker "fortik/internal/broker/github"
	"fortik/internal/decide"
	"fortik/internal/gateway"
	"fortik/internal/undo"
)

// redacted replaces any echo of the installation token in an upstream response.
const redacted = "[redacted-by-fortik]"

// Request headers forwarded from the agent. Everything else, above all the
// agent's own Authorization (its Fortik token), is dropped. Content-Type and
// X-GitHub-Api-Version are always Fortik's (application/json, APIVersion):
// the body GitHub parses must be the JSON Fortik classified, under the API
// version Fortik's mapping was written for.
var forwardRequestHeaders = []string{
	"Accept", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since",
}

// Response headers returned to the agent. Location is deliberately absent:
// GitHub redirects (tarball/zipball, archive downloads) can embed a
// short-lived credential in the URL.
var forwardResponseHeaders = []string{
	"Content-Type", "ETag", "Last-Modified", "Link", "Retry-After", "X-GitHub-Request-Id", "X-GitHub-Media-Type",
	"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-RateLimit-Used", "X-RateLimit-Resource",
	"X-Accepted-GitHub-Permissions",
}

// Forward executes an allowed (or allow_reduced) Op: it re-checks the access
// profile, mints or reuses the narrowed installation token, applies
// record_ref (undo handle prepared BEFORE the request is sent), forwards the
// request and writes GitHub's response (token redacted) to w.
//
// Every error is returned before anything is written to w.
func (a *Adapter) Forward(ctx context.Context, p authz.Principal, op *gateway.Op, out decide.Outcome, w http.ResponseWriter, r *http.Request) error {
	st, ok := op.State.(*opState)
	if !ok || st == nil {
		return refuse(RuleRefused, "github: request state missing")
	}
	if p.Kind != authz.KindAgent || p.Name == "" || p.Name != op.Action.AgentID || out.Action.AgentID != p.Name {
		return refuse(RuleRefused, "github: caller is not the agent the action was decided for")
	}
	if !out.Result.Decision.Executes() || out.Action.ActionID == "" {
		return refuse(RuleRefused, "github: decision %q does not permit execution", out.Result.Decision)
	}
	wantRecord, err := reducedForm(out.Result.ReducedForm)
	if err != nil {
		return err
	}
	if st.unknown {
		return refuse(RuleUnknown, "github: unclassified request refused")
	}
	if wantRecord && st.record == recordNone {
		return gateway.ErrReducedFormUnsupported{Key: "record_ref"}
	}
	if st.notConfigured != nil {
		return st.notConfigured
	}
	if st.repo == "" {
		return refuse(RuleScope, "github: only repository-scoped requests (/repos/{owner}/{repo}/...) are brokered")
	}
	s, err := a.settings(ctx)
	if err != nil {
		return err
	}
	prof, err := ghbroker.LoadProfile(ctx, a.cfg.Profiles, p.Name)
	if errors.Is(err, ghbroker.ErrNoProfile) {
		return refuse(RuleProfile, "github: the agent has no github access profile")
	}
	if err != nil {
		return err
	}
	if !prof.HasRepo(st.repo) {
		return refuse(RuleProfile, "github: repository %s is not in the agent's access profile (v%d)", st.repo, prof.Version)
	}
	if missing := prof.Missing(st.perms); len(missing) > 0 {
		sort.Strings(missing)
		return refuse(RuleProfile, "github: %s needs %s, which the access profile (v%d) does not grant", st.operation, strings.Join(missing, ", "), prof.Version)
	}
	if err := a.client.CheckOwner(ctx, s, st.owner); errors.Is(err, ghbroker.ErrWrongOwner) {
		return refuse(RuleScope, "github: repository owner %s is not the account of the configured app installation", st.owner)
	} else if err != nil {
		return err
	}
	tok, key, err := a.agentToken(ctx, s, mintRequest{
		agentID: p.Name, instanceID: p.InstanceID, actionID: out.Action.ActionID,
		owner: st.owner, name: st.name, repo: st.repo, perms: st.perms, profileVersion: prof.Version,
	})
	if err != nil {
		return err
	}

	prepared := false
	if wantRecord {
		if err := a.prepareRecord(ctx, s, tok, st, out, p); err != nil {
			return err
		}
		prepared = true
	}

	resp, err := a.send(ctx, s, tok, st, op.Body, r)
	if err != nil {
		if prepared {
			// The request may have reached GitHub. Restoring a ref (or
			// reopening a PR) is idempotent, so keep the undo available.
			a.finishRecord(ctx, out.Action.ActionID, true, "upstream outcome unknown: "+err.Error())
		}
		return fmt.Errorf("github: upstream request failed: %w", err)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, a.cfg.MaxResponseBytes+1))
	ok2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	if prepared {
		a.finishRecord(ctx, out.Action.ActionID, ok2xx, fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode))
	}
	if resp.StatusCode == http.StatusUnauthorized {
		a.tokens.drop(key, tok.Secret) // revoked or expired elsewhere: mint afresh next time
	}
	if rerr != nil {
		return fmt.Errorf("github: read upstream response (HTTP %d): %w", resp.StatusCode, rerr)
	}
	if int64(len(body)) > a.cfg.MaxResponseBytes {
		return fmt.Errorf("%w (HTTP %d, more than %d bytes)", ErrResponseTooLarge, resp.StatusCode, a.cfg.MaxResponseBytes)
	}
	a.writeResponse(w, r, resp, body, tok.Secret, s.BaseURL, out.Action.ActionID)
	return nil
}

// reducedForm returns whether record_ref is requested; any other key (or a
// non-boolean record_ref) is unsupported, so the gateway refuses.
func reducedForm(rf map[string]any) (bool, error) {
	keys := make([]string, 0, len(rf))
	for k := range rf {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	record := false
	for _, k := range keys {
		if k != "record_ref" {
			return false, gateway.ErrReducedFormUnsupported{Key: k}
		}
		b, ok := rf[k].(bool)
		if !ok {
			return false, gateway.ErrReducedFormUnsupported{Key: k}
		}
		record = b
	}
	return record, nil
}

// RefUndoData is handle_json for KindRef. PreviousSHA "" means the ref did
// not exist before the action (undo deletes it).
type RefUndoData struct {
	Repo        string `json:"repo"`
	Ref         string `json:"ref"` // "heads/<branch>" or "tags/<tag>"
	PreviousSHA string `json:"previous_sha"`
	Operation   string `json:"operation,omitempty"`
	PR          int    `json:"pr,omitempty"` // merge_pr: the merged PR
	// ResultSHA is the sha the action set the ref to, when the request named
	// it (git refs create/update). Undo only rewinds a ref still pointing
	// there, so later commits by others are never discarded.
	ResultSHA string `json:"result_sha,omitempty"`
}

// PRUndoData is handle_json for KindPR.
type PRUndoData struct {
	Repo          string `json:"repo"`
	PR            int    `json:"pr"`
	PreviousState string `json:"previous_state"`
}

// prepareRecord captures the previous state and writes the undo handle
// (status "prepared", with its Diary event) before the request is sent.
func (a *Adapter) prepareRecord(ctx context.Context, s ghbroker.Settings, tok ghbroker.Token, st *opState, out decide.Outcome, p authz.Principal) error {
	var kind string
	var data any
	switch st.record {
	case recordRef:
		if st.ref == "" {
			return gateway.ErrReducedFormUnsupported{Key: "record_ref"} // branch unresolved: cannot record
		}
		sha, err := a.currentRef(ctx, s, tok.Secret, st, st.ref)
		if err != nil {
			return err
		}
		kind, data = KindRef, RefUndoData{Repo: st.repo, Ref: st.ref, PreviousSHA: sha, Operation: st.operation, ResultSHA: strings.ToLower(st.resultSHA)}
	case recordMerge:
		pr, err := a.getPull(ctx, s, tok.Secret, st)
		if err != nil {
			return err
		}
		if pr.Base.Ref != st.branch {
			return refuse(RuleRefused, "github: pull request base changed since the decision (%s → %s); retry", st.branch, pr.Base.Ref)
		}
		sha, err := a.currentRef(ctx, s, tok.Secret, st, "heads/"+pr.Base.Ref)
		if err != nil {
			return err
		}
		if sha == "" {
			return refuse(RuleRefused, "github: base branch %s does not exist", pr.Base.Ref)
		}
		kind, data = KindRef, RefUndoData{Repo: st.repo, Ref: "heads/" + pr.Base.Ref, PreviousSHA: sha, Operation: st.operation, PR: st.pr}
	case recordPR:
		pr, err := a.getPull(ctx, s, tok.Secret, st)
		if err != nil {
			return err
		}
		kind, data = KindPR, PRUndoData{Repo: st.repo, PR: st.pr, PreviousState: pr.State}
	default:
		return gateway.ErrReducedFormUnsupported{Key: "record_ref"}
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	h := undo.Handle{ActionID: out.Action.ActionID, AgentID: p.Name, Kind: kind, Data: raw, ExpiresAt: a.cfg.Now().Add(a.cfg.UndoRetention)}
	if err := a.cfg.Undo.Prepare(ctx, h, p.Actor()); err != nil {
		return fmt.Errorf("github: could not prepare the undo handle; refused: %w", err)
	}
	return nil
}

// finishRecord activates (the action may have happened) or fails the handle.
func (a *Adapter) finishRecord(ctx context.Context, actionID string, activate bool, note string) {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	var err error
	if activate {
		err = a.cfg.Undo.Activate(sctx, actionID)
	} else {
		err = a.cfg.Undo.Fail(sctx, actionID, note)
	}
	if err != nil {
		a.log.Error("github: undo handle state change failed; review manually", "action_id", actionID, "activate", activate, "note", note, "err", err)
	}
}

var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// currentRef returns the ref's sha, or "" if it does not exist.
func (a *Adapter) currentRef(ctx context.Context, s ghbroker.Settings, token string, st *opState, ref string) (string, error) {
	return currentRefSHA(ctx, a.client, s, token, repoPath(st), ref)
}

func currentRefSHA(ctx context.Context, c *ghbroker.Client, s ghbroker.Settings, token, repoPath, ref string) (string, error) {
	var out struct {
		Ref    string `json:"ref"`
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	status, err := c.JSON(ctx, s.BaseURL, token, http.MethodGet, repoPath+"/git/ref/"+escapeRef(ref), nil, &out, "get ref",
		http.StatusOK, http.StatusNotFound)
	if err != nil {
		return "", fmt.Errorf("github: record previous ref: %w", err)
	}
	if status == http.StatusNotFound {
		return "", nil
	}
	if out.Ref != "refs/"+ref || !shaPattern.MatchString(out.Object.SHA) {
		// GitHub answers a prefix match with an array; anything but the exact
		// ref is not something Fortik can restore.
		return "", fmt.Errorf("github: record previous ref: unexpected answer for %s", ref)
	}
	return out.Object.SHA, nil
}

// send forwards the agent's request with the installation token.
func (a *Adapter) send(ctx context.Context, s ghbroker.Settings, tok ghbroker.Token, st *opState, body []byte, r *http.Request) (*http.Response, error) {
	u := s.BaseURL + st.upPath
	if st.rawQuery != "" {
		u += "?" + st.rawQuery
	}
	var rd io.Reader
	if st.method != http.MethodGet && st.method != http.MethodHead && len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, st.method, u, rd)
	if err != nil {
		return nil, err
	}
	ghbroker.SetAPIHeaders(req.Header, tok.Secret)
	for _, k := range forwardRequestHeaders {
		if v := r.Header.Get(k); v != "" {
			req.Header.Set(k, v)
		}
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return a.client.HTTP.Do(req)
}

func (a *Adapter) writeResponse(w http.ResponseWriter, r *http.Request, resp *http.Response, body []byte, secret, baseURL, actionID string) {
	h := w.Header()
	for _, k := range forwardResponseHeaders {
		for _, v := range resp.Header.Values(k) {
			v = strings.ReplaceAll(v, secret, redacted)
			if k == "Link" {
				v = rewriteLink(v, baseURL, r)
			}
			h.Add(k, v)
		}
	}
	h.Set("Cache-Control", "no-store")
	h.Set("X-Fortik-Action-Id", actionID)
	w.WriteHeader(resp.StatusCode)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(bytes.ReplaceAll(body, []byte(secret), []byte(redacted)))
}

// rewriteLink points pagination links at the gateway instead of GitHub.
func rewriteLink(v, baseURL string, r *http.Request) string {
	if r.Host == "" {
		return v
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return strings.ReplaceAll(v, baseURL+"/", scheme+"://"+r.Host+gatewayPrefix+"/")
}
