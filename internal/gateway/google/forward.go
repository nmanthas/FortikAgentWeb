package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"fortik/internal/authz"
	"fortik/internal/decide"
	"fortik/internal/gateway"
	"fortik/internal/policy"
)

// plan is the set of reduced forms Forward must apply.
type plan struct {
	delay  time.Duration
	narrow bool
	record bool
}

const maxDelay = 7 * 24 * time.Hour

// reducedPlan validates every reduced-form key against the request. A key
// this adapter does not understand, or one that does not fit the request
// (e.g. narrow_share on a send), refuses the action.
func reducedPlan(st *opState, out decide.Outcome) (plan, error) {
	var pl plan
	rf := out.Result.ReducedForm
	if out.Result.Decision == policy.AllowReduced && len(rf) == 0 {
		return pl, gateway.ErrReducedFormUnsupported{Key: "(empty reduced form)"}
	}
	keys := make([]string, 0, len(rf))
	for k := range rf {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := rf[k]
		switch k {
		case "delay_send_seconds":
			secs, ok := number(v)
			if st.send == nil || !ok || secs <= 0 || time.Duration(secs*float64(time.Second)) > maxDelay {
				return pl, gateway.ErrReducedFormUnsupported{Key: k}
			}
			pl.delay = time.Duration(math.Ceil(secs)) * time.Second
		case "narrow_share":
			if st.share == nil || !st.share.create || v != "domain" {
				return pl, gateway.ErrReducedFormUnsupported{Key: k}
			}
			pl.narrow = true
		case "record_permission":
			if st.share == nil || !st.share.create || v != true {
				return pl, gateway.ErrReducedFormUnsupported{Key: k}
			}
			pl.record = true
		default:
			return pl, gateway.ErrReducedFormUnsupported{Key: k}
		}
	}
	return pl, nil
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// Forward executes an allowed or allow_reduced request.
func (a *Adapter) Forward(ctx context.Context, p authz.Principal, op *gateway.Op, out decide.Outcome, w http.ResponseWriter, r *http.Request) error {
	st, ok := op.State.(*opState)
	if !ok || st == nil || st.unknown {
		return &gateway.RefusedError{RuleID: "GW-UNMAPPED", Reason: "request was not classified by the Google adapter: refused"}
	}
	pl, err := reducedPlan(st, out)
	if err != nil {
		return err
	}
	s, err := a.settings(ctx)
	if err != nil {
		return err
	}
	subject, err := a.subject(ctx, p.Name)
	if err != nil {
		return err
	}
	if subject == "" {
		return &gateway.RefusedError{RuleID: "GW-IDENTITY",
			Reason: "agent has no workspace_user: Fortik cannot act on Google Workspace for it (set workspace_user on the agent in the console)"}
	}
	mreq := mintRequest{agentID: p.Name, instanceID: p.InstanceID, actionID: out.Action.ActionID, subject: subject, system: st.api, scopes: st.scopes}

	if st.send != nil {
		if st.send.msg == nil {
			return &gateway.RefusedError{RuleID: "GW-UNCLASSIFIED", Reason: "message content could not be classified: refused"}
		}
		if pl.delay > 0 {
			return a.enqueueDelayed(ctx, p, out, st, subject, pl.delay, w)
		}
		return a.sendNow(ctx, s, mreq, st, w)
	}

	body := op.Body
	set := http.Header{}
	if st.share != nil {
		b, err := st.share.body(pl.narrow, s.primaryDomain)
		if err != nil {
			return err
		}
		body = b
		set.Set("Content-Type", "application/json; charset=UTF-8")
		if pl.narrow {
			// Notification/ownership parameters do not apply to a domain permission.
			for _, k := range []string{"emailMessage", "sendNotificationEmail", "transferOwnership", "moveToNewOwnersRoot"} {
				st.query.Del(k)
			}
		}
		if pl.record {
			ensureField(st.query, "id")
		}
	}
	tok, err := a.tokens.token(ctx, s, mreq)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		body = nil
	}
	req := gateway.ProxyRequest{Client: a.client, Method: st.method, URL: st.url(), Body: body, Header: r.Header,
		SetHeader: set, Authorization: "Bearer " + tok}
	if !pl.record {
		_, err := gateway.Proxy(ctx, w, req)
		return err
	}
	// record_permission: the undo handle is written before the agent sees the result.
	resp, err := gateway.Do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, gateway.MaxCaptureBytes+1))
	if err != nil || len(respBody) > gateway.MaxCaptureBytes {
		a.log.Error("drive permission created but response unreadable; undo handle NOT recorded", "action_id", out.Action.ActionID)
		return fmt.Errorf("%w: reading permissions.create response", gateway.ErrUpstream)
	}
	if resp.StatusCode/100 == 2 {
		if err := a.recordPermission(ctx, p, out, st, subject, respBody); err != nil {
			// The share exists; say so loudly rather than pretend it is undoable.
			a.log.Error("drive permission created but its undo handle could not be recorded: NOT undoable",
				"action_id", out.Action.ActionID, "err", err)
		}
	}
	gateway.CopyResponseHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
	return nil
}

// body is the permission body to forward: the canonical parsed fields, or
// the narrowed domain permission.
func (sh *shareState) body(narrow bool, primaryDomain string) ([]byte, error) {
	if narrow {
		if primaryDomain == "" {
			return nil, &gateway.NotConfiguredError{System: IntegrationKey}
		}
		return json.Marshal(map[string]any{"type": "domain", "domain": primaryDomain, "role": sh.role})
	}
	return json.Marshal(sh.fields)
}

// ensureField makes sure a partial-response "fields" parameter includes f.
func ensureField(q url.Values, f string) {
	fields := q.Get("fields")
	if fields == "" || fields == "*" {
		return
	}
	for _, x := range strings.Split(fields, ",") {
		if strings.TrimSpace(x) == f {
			return
		}
	}
	q.Set("fields", fields+","+f)
}

// sendNow sends the classified message via messages.send (multipart upload),
// then deletes the draft for drafts.send.
func (a *Adapter) sendNow(ctx context.Context, s settings, mreq mintRequest, st *opState, w http.ResponseWriter) error {
	tok, err := a.tokens.token(ctx, s, mreq)
	if err != nil {
		return err
	}
	req, err := a.sendRequest(tok, st.send.msg.raw, st.send.threadID)
	if err != nil {
		return err
	}
	resp, err := gateway.Do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, gateway.MaxCaptureBytes))
	if err != nil {
		// The message may have been sent; report the transport failure.
		return fmt.Errorf("%w: reading messages.send response: %v", gateway.ErrUpstream, err)
	}
	if st.send.draftID != "" && resp.StatusCode/100 == 2 {
		a.deleteDraft(ctx, tok, st.send.draftID)
	}
	gateway.CopyResponseHeader(w.Header(), resp.Header)
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
	return nil
}

// sendRequest builds users.messages.send (uploadType=multipart) for raw.
func (a *Adapter) sendRequest(tok string, raw []byte, threadID string) (gateway.ProxyRequest, error) {
	meta := map[string]any{}
	if threadID != "" {
		meta["threadId"] = threadID
	}
	mb, err := json.Marshal(meta)
	if err != nil {
		return gateway.ProxyRequest{}, err
	}
	body, ct, err := buildRelated(mb, "message/rfc822", raw)
	if err != nil {
		return gateway.ProxyRequest{}, err
	}
	return gateway.ProxyRequest{
		Client: a.client, Method: http.MethodPost,
		URL:  a.gmailBase + "/upload/gmail/v1/users/me/messages/send?uploadType=multipart",
		Body: body, ForwardHeaders: []string{},
		SetHeader:     http.Header{"Content-Type": {ct}, "Accept": {"application/json"}},
		Authorization: "Bearer " + tok,
	}, nil
}

// deleteDraft removes a sent draft (best effort: the message has gone).
func (a *Adapter) deleteDraft(ctx context.Context, tok, draftID string) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	resp, err := gateway.Do(dctx, gateway.ProxyRequest{Client: a.client, Method: http.MethodDelete,
		URL: a.gmailBase + "/gmail/v1/users/me/drafts/" + url.PathEscape(draftID), ForwardHeaders: []string{}, Authorization: "Bearer " + tok})
	if err != nil {
		a.log.Warn("sent draft could not be deleted", "err", err)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		a.log.Warn("sent draft could not be deleted", "status", resp.StatusCode)
	}
}

// getJSON performs an authenticated GET used by pre-decision lookups.
func (a *Adapter) getJSON(ctx context.Context, tok, u string, v any) (int, error) {
	resp, err := gateway.Do(ctx, gateway.ProxyRequest{Client: a.client, Method: http.MethodGet, URL: u,
		ForwardHeaders: []string{}, SetHeader: http.Header{"Accept": {"application/json"}}, Authorization: "Bearer " + tok})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	limit := a.cfg.MaxBodyBytes
	if limit <= 0 {
		limit = 25 << 20
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2*limit))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%w: reading response: %v", gateway.ErrUpstream, err)
	}
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("google returned HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return resp.StatusCode, fmt.Errorf("google response not understood: %w", err)
	}
	return resp.StatusCode, nil
}

// fetchDraft loads a stored draft for drafts.send so Fortik classifies (and
// later sends) exactly its content. No subject: left unknown; Forward refuses.
func (a *Adapter) fetchDraft(ctx context.Context, p authz.Principal, op *gateway.Op, st *opState, s settings) error {
	subject, err := a.subject(ctx, p.Name)
	if err != nil || subject == "" {
		return err
	}
	tok, err := a.tokens.token(ctx, s, mintRequest{agentID: p.Name, instanceID: p.InstanceID, subject: subject, system: "gmail",
		scopes: []string{ScopeGmailCompose}})
	if err != nil {
		return err
	}
	var d struct {
		Message struct {
			ThreadID string `json:"threadId"`
			Raw      string `json:"raw"`
		} `json:"message"`
	}
	if _, err := a.getJSON(ctx, tok, a.gmailBase+"/gmail/v1/users/me/drafts/"+url.PathEscape(st.send.draftID)+"?format=raw", &d); err != nil {
		return fmt.Errorf("drafts.get: %w", err)
	}
	raw, err := decodeRaw(d.Message.Raw)
	if err != nil {
		return fmt.Errorf("drafts.get: %w", err)
	}
	msg, err := parseMessage(raw)
	if err != nil {
		return fmt.Errorf("drafts.get: %w", err)
	}
	st.send.msg = msg
	if st.send.threadID == "" && segPattern.MatchString(d.Message.ThreadID) {
		st.send.threadID = d.Message.ThreadID
	}
	return nil
}

// fetchGrantee reads the existing permission for permissions.update (the
// grantee is not in the update body).
func (a *Adapter) fetchGrantee(ctx context.Context, p authz.Principal, op *gateway.Op, st *opState, s settings) error {
	subject, err := a.subject(ctx, p.Name)
	if err != nil || subject == "" {
		return err
	}
	tok, err := a.tokens.token(ctx, s, mintRequest{agentID: p.Name, instanceID: p.InstanceID, subject: subject, system: "drive",
		scopes: []string{ScopeDriveReadonly}})
	if err != nil {
		return err
	}
	var perm struct {
		Type         string `json:"type"`
		Role         string `json:"role"`
		EmailAddress string `json:"emailAddress"`
		Domain       string `json:"domain"`
	}
	u := a.driveBase + "/drive/v3/files/" + url.PathEscape(st.share.fileID) + "/permissions/" + url.PathEscape(st.share.permissionID) +
		"?fields=id,type,role,emailAddress,domain&supportsAllDrives=true"
	if _, err := a.getJSON(ctx, tok, u, &perm); err != nil {
		return fmt.Errorf("permissions.get: %w", err)
	}
	if !shareTypes[perm.Type] {
		return errors.New("permissions.get: unknown permission type")
	}
	st.share.shareType = perm.Type
	st.share.email = strings.ToLower(strings.TrimSpace(perm.EmailAddress))
	st.share.domain = normDomain(perm.Domain)
	if st.share.role == "" {
		st.share.role = perm.Role
	}
	return nil
}
