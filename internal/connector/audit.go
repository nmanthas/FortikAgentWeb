package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/action"
	"fortik/internal/diary"
)

// Vendor audit logs (plan: "vendor audit logs pulled for visibility"). What a
// copilot did with the tokens Fortik issued is not decided by Fortik (the
// copilot calls Google / GitHub directly), but it is seen: each event from
// the upstream's audit log that belongs to Fortik's OAuth client is recorded
// as an observed action (source vendor_audit) so it appears on the
// communication map and in the Diary.

// VendorEvent is one audit-log entry attributed to a connector.
type VendorEvent struct {
	ID     string         `json:"id"`
	Time   time.Time      `json:"time"`
	Actor  string         `json:"actor"`  // the upstream user
	Action string         `json:"action"` // e.g. gmail.users.messages.send, git.push
	System string         `json:"system"` // gmail | drive | github | other
	Verb   action.Verb    `json:"verb"`
	Detail map[string]any `json:"detail,omitempty"`
}

// AuditFetcher reads an upstream's audit log for Fortik's client since t.
type AuditFetcher interface {
	Fetch(ctx context.Context, since time.Time) ([]VendorEvent, error)
}

// TokenFunc returns an admin access token for the audit API.
type TokenFunc func(ctx context.Context) (string, error)

// GoogleAudit reads the Admin SDK Reports API "token" activities (OAuth API
// requests, authorizations and revocations) of Fortik's OAuth client.
type GoogleAudit struct {
	Up    *Upstream
	Token TokenFunc
}

// Fetch implements AuditFetcher.
func (g GoogleAudit) Fetch(ctx context.Context, since time.Time) ([]VendorEvent, error) {
	tok, err := g.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("google audit: %w", err)
	}
	q := url.Values{"startTime": {since.UTC().Format(time.RFC3339)}, "maxResults": {"1000"},
		"filters": {"client_id==" + g.Up.ClientID}}
	var page struct {
		Items []struct {
			ID struct {
				Time            time.Time `json:"time"`
				UniqueQualifier string    `json:"uniqueQualifier"`
			} `json:"id"`
			Actor struct {
				Email string `json:"email"`
			} `json:"actor"`
			Events []struct {
				Name       string `json:"name"`
				Parameters []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"parameters"`
			} `json:"events"`
		} `json:"items"`
	}
	if err := getJSON(ctx, g.Up.HTTP, strings.TrimRight(g.Up.APIBaseURL, "/")+"/admin/reports/v1/activity/users/all/applications/token?"+q.Encode(),
		"Bearer "+tok, &page); err != nil {
		return nil, fmt.Errorf("google audit: %w", err)
	}
	var out []VendorEvent
	for _, it := range page.Items {
		for i, ev := range it.Events {
			p := map[string]string{}
			for _, x := range ev.Parameters {
				p[x.Name] = x.Value
			}
			if p["client_id"] != "" && p["client_id"] != g.Up.ClientID {
				continue // not Fortik's client
			}
			api, method := strings.ToLower(p["api_name"]), strings.ToLower(p["method_name"])
			sys := "other"
			switch {
			case strings.Contains(api, "gmail"):
				sys = "gmail"
			case strings.Contains(api, "drive"):
				sys = "drive"
			}
			out = append(out, VendorEvent{ID: fmt.Sprintf("%s:%d", it.ID.UniqueQualifier, i), Time: it.ID.Time, Actor: it.Actor.Email,
				Action: firstNonEmpty(method, ev.Name), System: sys, Verb: googleVerb(ev.Name, method),
				Detail: map[string]any{"event": ev.Name, "api": api, "method": method}})
		}
	}
	return out, nil
}

func googleVerb(event, method string) action.Verb {
	switch {
	case event == "authorize":
		return action.VerbGrant
	case strings.Contains(method, "send"):
		return action.VerbSend
	case strings.Contains(method, "delete") || strings.Contains(method, "trash"):
		return action.VerbDelete
	case strings.Contains(method, "insert") || strings.Contains(method, "create") || strings.Contains(method, "update") ||
		strings.Contains(method, "modify") || strings.Contains(method, "patch") || strings.Contains(method, "copy"):
		return action.VerbWrite
	}
	return action.VerbRead
}

// GitHubAudit reads the organization audit log for events made through
// Fortik's GitHub App user tokens.
type GitHubAudit struct {
	Up    *Upstream
	Token TokenFunc
	AppID string // oauth_application_id to match ("" = client id)
}

// Fetch implements AuditFetcher.
func (g GitHubAudit) Fetch(ctx context.Context, since time.Time) ([]VendorEvent, error) {
	if g.Up.AuditOrg == "" {
		return nil, errors.New("github audit: connectors.github.audit_org is not set")
	}
	tok, err := g.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("github audit: %w", err)
	}
	q := url.Values{"phrase": {"created:>=" + since.UTC().Format("2006-01-02T15:04:05Z")}, "per_page": {"100"}, "order": {"asc"}}
	var events []map[string]any
	if err := getJSON(ctx, g.Up.HTTP, strings.TrimRight(g.Up.APIBaseURL, "/")+"/orgs/"+url.PathEscape(g.Up.AuditOrg)+"/audit-log?"+q.Encode(),
		"Bearer "+tok, &events); err != nil {
		return nil, fmt.Errorf("github audit: %w", err)
	}
	want := g.AppID
	var out []VendorEvent
	for _, e := range events {
		app := fmt.Sprint(e["oauth_application_id"])
		if want == "" || app != want {
			continue
		}
		id := fmt.Sprint(e["_document_id"])
		act := fmt.Sprint(e["action"])
		ts := time.UnixMilli(int64(num(e["@timestamp"])))
		out = append(out, VendorEvent{ID: id, Time: ts, Actor: fmt.Sprint(e["actor"]), Action: act, System: "github", Verb: githubVerb(act),
			Detail: map[string]any{"repo": e["repo"], "action": act}})
	}
	return out, nil
}

func githubVerb(act string) action.Verb {
	switch {
	case strings.HasPrefix(act, "git.clone"), strings.HasPrefix(act, "git.fetch"):
		return action.VerbRead
	case strings.Contains(act, "destroy") || strings.Contains(act, "delete"):
		return action.VerbDelete
	case strings.Contains(act, "permission") || strings.Contains(act, "add_member") || strings.Contains(act, "invite"):
		return action.VerbGrant
	}
	return action.VerbWrite
}

// PullAudit fetches each connector upstream's audit log and records new
// events for the connectors of that upstream (one connector per upstream
// client in the MVP: every connector shares Fortik's client, so events are
// attributed to the upstream user's grant's connector when known, else to
// every active connector of that upstream as "unattributed").
func (s *Service) PullAudit(ctx context.Context, fetchers map[string]AuditFetcher, since time.Time) (int, error) {
	var total int
	var errs []error
	for ups, f := range fetchers {
		evs, err := f.Fetch(ctx, since)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rows, err := s.pool.Query(ctx, `SELECT connector_id, agent_id, vendor FROM connectors WHERE upstream = $1 AND status = 'active' ORDER BY created_at`, ups)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		type conn struct{ id, agent, vendor string }
		cs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (conn, error) {
			var c conn
			return c, r.Scan(&c.id, &c.agent, &c.vendor)
		})
		if err != nil || len(cs) == 0 {
			continue
		}
		for _, ev := range evs {
			for _, c := range cs {
				n, err := s.recordVendorEvent(ctx, c.id, c.agent, c.vendor, ups, ev, len(cs) > 1)
				if err != nil {
					errs = append(errs, err)
					break
				}
				total += n
			}
		}
	}
	return total, errors.Join(errs...)
}

func (s *Service) recordVendorEvent(ctx context.Context, connectorID, agentID, vendor, upstream string, ev VendorEvent, ambiguous bool) (int, error) {
	if ev.ID == "" {
		return 0, nil
	}
	added := 0
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO connector_audit_seen (connector_id, event_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, connectorID, ev.ID)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		a := action.Action{ActionID: action.NewID("act"), AgentID: agentID, System: ev.System, Verb: ev.Verb, Source: action.SourceVendorAudit,
			Target: map[string]any{"vendor_action": clip(ev.Action, 120), "upstream_user": clip(ev.Actor, 200), "connector_id": connectorID}}
		target, _ := json.Marshal(a.Target)
		dj, _ := json.Marshal(map[string]any{"vendor_audit": map[string]any{"event_id": ev.ID, "vendor": vendor, "upstream": upstream,
			"detail": ev.Detail, "unattributed": ambiguous}})
		ts := ev.Time
		if ts.IsZero() {
			ts = s.now()
		}
		if _, err := tx.Exec(ctx, `INSERT INTO actions (action_id, agent_id, system, verb, action_hash, class, decision, rule_id, reason,
			reversible, source, target, payload_summary, decision_json, fail_closed, latency_us, ts)
			VALUES ($1,$2,$3,$4,$5,'green','allow','VENDOR-AUDIT',$6,false,$7,$8,'{}',$9,false,0,$10)`,
			a.ActionID, agentID, a.System, string(a.Verb), a.Hash(), fmt.Sprintf("seen in the %s audit log (made by the copilot directly; not decided by Fortik)", vendorName(upstream)),
			a.Source, target, dj, ts); err != nil {
			return err
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: EventVendorActivity, Actor: "system:connector-audit",
			Data: map[string]any{"connector_id": connectorID, "action_id": a.ActionID, "event_id": ev.ID, "system": ev.System,
				"verb": string(ev.Verb), "vendor_action": clip(ev.Action, 120), "upstream_user": clip(ev.Actor, 200), "unattributed": ambiguous}})
		added = 1
		return err
	})
	return added, err
}

// AuditWorker pulls the audit logs every interval (looking back 2 intervals;
// duplicates are skipped).
func (s *Service) AuditWorker(ctx context.Context, fetchers map[string]AuditFetcher, every time.Duration) {
	if len(fetchers) == 0 || every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if n, err := s.PullAudit(ctx, fetchers, s.now().Add(-2*every)); err != nil {
			s.log.Warn("connector: vendor audit pull failed", "err", err)
		} else if n > 0 {
			s.log.Info("connector: vendor audit events recorded", "events", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func vendorName(upstream string) string {
	if upstream == UpstreamGitHub {
		return "GitHub"
	}
	return "Google Workspace"
}

func getJSON(ctx context.Context, hc *http.Client, u, auth string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return json.Unmarshal(b, out)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func num(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}
