package saasrest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/decide"
	"fortik/internal/gateway"
	"fortik/internal/integrations"
)

// HeaderIntegration selects the tenant (logical integration id, e.g.
// salesforce:acme) when several are connected. Without it the only
// connection is used; with several the call is refused, never guessed.
const HeaderIntegration = "X-Fortik-Integration"

// RuleRefused is the adapter's own refusal (after policy allowed).
const RuleRefused = "GW-SAAS"

// Request is what Map learned; Forward re-checks it against the decision.
type Request struct {
	Key, IntegrationID string
	Method, Path       string // path below the API base, e.g. /services/data/v62.0/sobjects/Account/001
	RawQuery           string
	Operation, Object  string
	RecordID           string
}

// Adapter is the gateway adapter of one provider (/gw/<system>/...).
type Adapter struct {
	s      *Service
	system string
}

var _ gateway.Adapter = (*Adapter)(nil)

// Adapters returns one gateway adapter per provider.
func (s *Service) Adapters() []gateway.Adapter {
	out := make([]gateway.Adapter, 0, len(Systems))
	for _, sys := range Systems {
		out = append(out, &Adapter{s: s, system: sys})
	}
	return out
}

func (a *Adapter) Prefix() string { return a.system }

func (a *Adapter) Enrich(context.Context, authz.Principal, *gateway.Op) error { return nil }

func verbOf(method, op string) action.Verb {
	switch {
	case op == "action":
		return action.VerbExecute
	case method == http.MethodGet || method == http.MethodHead:
		return action.VerbRead
	case method == http.MethodDelete:
		return action.VerbDelete
	case method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut:
		return action.VerbWrite
	}
	return "UNKNOWN"
}

// Map decides nothing: it names the operation for policy. A path outside
// the provider's API, or a tenant it cannot resolve, is UNKNOWN (denied).
func (a *Adapter) Map(ctx context.Context, p authz.Principal, r *http.Request, body []byte) (gateway.Op, error) {
	path := strings.TrimPrefix(r.URL.Path, "/gw/"+a.system)
	op := gateway.Op{Body: body}
	op.Action.System = a.system
	op.Action.PayloadSummary.Bytes = int64(len(body))
	conn, reason := a.resolve(ctx, r.Header.Get(HeaderIntegration))
	var (
		m     Request
		ok    bool
		extra map[string]any // Agent API target fields
	)
	if a.system == integrations.SystemSalesforce && IsAgentAPIPath(path) {
		if reason == "" {
			var why string
			m, extra, why = a.mapAgentAPI(p, r.Method, path, body, conn)
			ok, reason = why == "", why
		}
	} else {
		m, ok = mapPath(a.system, r.Method, path, r.URL.RawQuery)
	}
	if reason == "" && !ok {
		reason = "path is outside the " + a.system + " API Fortik governs"
	}
	if reason != "" {
		op.Action.Verb = "UNKNOWN"
		op.Action.Target = map[string]any{"transport": integrations.TransportREST, "operation": "unknown", "path": clip(path, 300), "reason": reason}
		if conn.integrationID != "" {
			op.Action.Target["integration_id"] = conn.integrationID
		}
		op.State = Request{Path: path}
		return op, nil
	}
	m.Key, m.IntegrationID, m.Method, m.Path, m.RawQuery = conn.key, conn.integrationID, r.Method, path, r.URL.RawQuery
	op.State = m
	op.Action.Verb = verbOf(r.Method, m.Operation)
	t := map[string]any{"transport": integrations.TransportREST, "integration_id": conn.integrationID, "connection": conn.key,
		"operation": m.Operation, "object": m.Object, "path": clip(path, 300)}
	if conn.tenant != "" {
		t["tenant"] = conn.tenant
	}
	if m.RecordID != "" {
		t["record_id"] = m.RecordID
	}
	for k, v := range extra {
		t[k] = v
	}
	if extra != nil {
		delete(t, "record_id") // the agent or session id is named on its own
		if m.Operation == opAgentMessage {
			op.Action.Verb = action.VerbExecute
		} else {
			op.Action.Verb = action.VerbRead // session start and end change no org data
		}
	}
	op.Action.Target = t
	return op, nil
}

type restConn struct{ key, integrationID, tenant string }

func (a *Adapter) resolve(ctx context.Context, want string) (restConn, string) {
	want = strings.TrimSpace(want)
	list, err := a.s.store.List(ctx, a.system)
	if err != nil {
		return restConn{}, "could not read the " + a.system + " connections"
	}
	conn := func(r integrations.Resolved) restConn {
		st, _ := settingsFrom(r)
		u, _ := url.Parse(st.Base)
		host := ""
		if u != nil {
			host = u.Host
		}
		return restConn{key: r.Key, integrationID: r.IntegrationID, tenant: host}
	}
	if want != "" {
		for _, r := range list {
			if r.IntegrationID == want {
				return conn(r), ""
			}
		}
		return restConn{integrationID: clip(want, 80)}, "no " + a.system + " REST connection for integration " + clip(want, 80)
	}
	switch len(list) {
	case 0:
		_, id, _ := integrations.LogicalID(a.system)
		return restConn{key: a.system, integrationID: id}, ""
	case 1:
		return conn(list[0]), ""
	}
	return restConn{}, fmt.Sprintf("%d %s tenants are connected: name one with the %s header (e.g. %s)", len(list), a.system, HeaderIntegration, list[0].IntegrationID)
}

var (
	sfVersioned = regexp.MustCompile(`^/services/data/v[0-9]{2,3}\.0(/.*)?$`)
	soqlFrom    = regexp.MustCompile(`(?i)\bfrom\s+([A-Za-z0-9_]+)`)
	odataRoot   = regexp.MustCompile(`^(/sap/opu/odata4?/[A-Za-z0-9_/]*?/[A-Z0-9_][A-Za-z0-9_]*(?:;[^/]*)?)(/.*)?$`)
)

// mapPath names the operation and object of a call; ok=false for paths
// outside the API Fortik governs.
func mapPath(system, method, path, rawQuery string) (Request, bool) {
	segs := func(p string) []string { return strings.Split(strings.Trim(p, "/"), "/") }
	read := method == http.MethodGet || method == http.MethodHead
	crud := func(hasID bool) string {
		switch method {
		case http.MethodGet, http.MethodHead:
			if hasID {
				return "get"
			}
			return "list"
		case http.MethodPost:
			return "create"
		case http.MethodPatch:
			return "update"
		case http.MethodPut:
			return "upsert"
		case http.MethodDelete:
			return "delete"
		}
		return "unknown"
	}
	switch system {
	case integrations.SystemSalesforce:
		if path == "/services/data" || path == "/services/data/" {
			return Request{Operation: "describe", Object: "versions"}, read
		}
		m := sfVersioned.FindStringSubmatch(path)
		if m == nil {
			return Request{}, false
		}
		s := segs(m[1])
		switch {
		case len(s) == 0 || s[0] == "":
			return Request{Operation: "describe", Object: "resources"}, read
		case s[0] == "sobjects" && len(s) == 1:
			return Request{Operation: "describe", Object: "sobjects"}, read
		case s[0] == "sobjects" && len(s) >= 2 && len(s) <= 3 && (len(s) < 3 || s[2] != "describe"):
			r := Request{Object: s[1], Operation: crud(len(s) == 3)}
			if len(s) == 3 {
				r.RecordID = s[2]
			}
			return r, r.Operation != "unknown"
		case s[0] == "sobjects" && len(s) == 3 && s[2] == "describe":
			return Request{Operation: "describe", Object: s[1]}, read
		case s[0] == "query" || s[0] == "queryAll":
			q, _ := url.ParseQuery(rawQuery)
			obj := ""
			if f := soqlFrom.FindStringSubmatch(q.Get("q")); f != nil {
				obj = f[1]
			}
			return Request{Operation: "query", Object: obj}, read
		case s[0] == "limits":
			return Request{Operation: "describe", Object: "limits"}, read
		case s[0] == "actions" && read:
			return Request{Operation: "describe", Object: strings.Join(s, "/")}, true
		case s[0] == "actions" && method == http.MethodPost:
			return Request{Operation: "action", Object: strings.Join(s, "/")}, true
		case s[0] == "composite":
			return Request{Operation: crud(false), Object: "composite"}, true
		}
		return Request{}, false
	case integrations.SystemServiceNow:
		if !strings.HasPrefix(path, "/api/now/") {
			return Request{}, false
		}
		s := segs(strings.TrimPrefix(path, "/api/now/"))
		switch {
		case s[0] == "table" && len(s) >= 2 && len(s) <= 3:
			r := Request{Object: s[1], Operation: crud(len(s) == 3)}
			if len(s) == 3 {
				r.RecordID = s[2]
			}
			return r, r.Operation != "unknown"
		case s[0] == "attachment":
			return Request{Object: "attachment", Operation: crud(len(s) >= 2)}, true
		}
		return Request{Object: s[0], Operation: crud(false)}, true
	case integrations.SystemSAP:
		m := odataRoot.FindStringSubmatch(path)
		if m == nil {
			return Request{}, false
		}
		service := m[1][strings.LastIndex(m[1], "/")+1:]
		rest := strings.Trim(m[2], "/")
		switch {
		case rest == "" || rest == "$metadata":
			return Request{Operation: "describe", Object: service}, read
		case rest == "$batch":
			return Request{Operation: "batch", Object: service + "/$batch"}, method == http.MethodPost
		}
		set := rest
		if i := strings.IndexAny(set, "(/"); i >= 0 {
			set = set[:i]
		}
		hasKey := strings.Contains(rest, "(")
		r := Request{Object: service + "/" + set, Operation: crud(hasKey)}
		if hasKey {
			open, end := strings.Index(rest, "("), strings.LastIndex(rest, ")")
			if end < open {
				end = len(rest)
			}
			r.RecordID = clip(rest[open+1:end], 120)
		}
		// A POST to a function import is not told apart from a create: both
		// are writes and held alike.
		return r, r.Operation != "unknown"
	}
	return Request{}, false
}

// Forward runs an allowed call with Fortik's token. No reduced form is
// supported: an allowed-with-constraints decision is refused.
func (a *Adapter) Forward(ctx context.Context, p authz.Principal, op *gateway.Op, out decide.Outcome, w http.ResponseWriter, r *http.Request) error {
	m, ok := op.State.(Request)
	if !ok || m.Key == "" || out.Action.AgentID != p.Name {
		return &gateway.RefusedError{RuleID: RuleRefused, Reason: "request state or identity does not match the decision"}
	}
	for k := range out.Result.ReducedForm {
		return gateway.ErrReducedFormUnsupported{Key: k}
	}
	res, err := a.s.store.Get(ctx, m.Key)
	if errors.Is(err, integrations.ErrNotConfigured) {
		return &gateway.NotConfiguredError{System: m.Key}
	}
	if err != nil {
		return err
	}
	st, err := settingsFrom(res)
	if err != nil {
		return &gateway.NotConfiguredError{System: m.Key}
	}
	if a.system == integrations.SystemSalesforce && IsAgentAPIPath(m.Path) {
		return a.forwardAgentAPI(ctx, p, m, st, op.Body, w, r)
	}
	target := st.Base + m.Path
	if m.RawQuery != "" {
		target += "?" + m.RawQuery
	}
	if why := a.s.guard.Refused(a.system, target); why != "" {
		return &gateway.RefusedError{RuleID: RuleRefused, Reason: "upstream URL not permitted: " + why}
	}
	auth, err := a.s.Token(ctx, st)
	if err != nil {
		return &gateway.RefusedError{RuleID: RuleRefused, Reason: "Fortik could not authenticate to " + a.system + ": " + clip(err.Error(), 160)}
	}
	hdr := http.Header{}
	for _, h := range []string{"Content-Type", "Accept", "If-Match", "Sforce-Query-Options"} {
		if v := r.Header.Get(h); v != "" {
			hdr.Set(h, v)
		}
	}
	if a.system == integrations.SystemSAP && m.Method != http.MethodGet && m.Method != http.MethodHead {
		// SAP Gateway refuses changes without a CSRF token fetched in the
		// same session (a GET with X-CSRF-Token: Fetch).
		if err := a.s.sapCSRF(ctx, st, auth, m, hdr); err != nil {
			return &gateway.RefusedError{RuleID: RuleRefused, Reason: "could not obtain SAP's CSRF token: " + clip(err.Error(), 160)}
		}
	}
	resp, err := a.s.send(ctx, auth, m.Method, target, op.Body, hdr)
	if err != nil {
		return fmt.Errorf("%s forward: %w", a.system, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		a.s.Drop(m.Key) // the next call fetches a new token
	}
	for _, h := range []string{"Content-Type", "Location", "ETag", "Sforce-Limit-Info"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 32<<20))
	return nil
}

func (s *Service) send(ctx context.Context, auth, method, target string, body []byte, hdr http.Header) (*http.Response, error) {
	var rd io.Reader
	if len(body) > 0 {
		rd = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("Authorization", auth)
	return s.http.Do(req)
}

// sapCSRF fetches a CSRF token (and its session cookies) for a change.
func (s *Service) sapCSRF(ctx context.Context, st Settings, auth string, m Request, hdr http.Header) error {
	root := odataRoot.FindStringSubmatch(m.Path)
	if root == nil {
		return errors.New("not an OData path")
	}
	u := st.Base + root[1] + "/"
	if st.SAPClient != "" {
		u += "?sap-client=" + url.QueryEscape(st.SAPClient)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("X-CSRF-Token", "Fetch")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	tok := resp.Header.Get("X-CSRF-Token")
	if resp.StatusCode != http.StatusOK || tok == "" || strings.EqualFold(tok, "Required") {
		return fmt.Errorf("HTTP %d without a token", resp.StatusCode)
	}
	hdr.Set("X-CSRF-Token", tok)
	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, c.Name+"="+c.Value)
	}
	if len(cookies) > 0 {
		hdr.Set("Cookie", strings.Join(cookies, "; "))
	}
	return nil
}
