package memory_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/memory"
	"fortik/internal/undo"
)

func TestGatewayWriteIsDecidedStagedAndUndoable(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()

	r := e.agentCall(t, supportAgent, http.MethodPost, writePath("kb"), map[string]any{
		"content": "refunds are processed within 5 business days", "embedding": []float32{1, 0, 0},
		"metadata": map[string]string{"labels": "faq", "source": "ticket-42"}})
	if r.code != http.StatusCreated {
		t.Fatalf("write: %d %s", r.code, r.raw)
	}
	actionID := r.body["action_id"].(string)
	item := r.body["item"].(map[string]any)
	id := item["id"].(string)
	if item["staged"] != true {
		t.Fatalf("write not staged: %s", r.raw)
	}
	if u := r.body["undo"].(map[string]any); u["undoable"] != true || u["kind"] != undo.KindMemoryStaging {
		t.Fatalf("undo info: %s", r.raw)
	}
	// The decision: POL-903 allow_reduced {memory_staging: true}, recorded
	// with the action (target and payload summary, never the content).
	var decision, rule, target, summary string
	if err := e.pool.QueryRow(ctx, `SELECT decision, rule_id, target::text, payload_summary::text FROM actions WHERE action_id = $1`, actionID).
		Scan(&decision, &rule, &target, &summary); err != nil {
		t.Fatal(err)
	}
	if decision != "allow_reduced" || rule != "POL-903" {
		t.Fatalf("decision %s %s", decision, rule)
	}
	var tg map[string]any
	_ = json.Unmarshal([]byte(target), &tg)
	if tg["store"] != "support" || tg["namespace"] != "kb" || tg["item_id"] != id {
		t.Fatalf("target: %s", target)
	}
	var ps action.PayloadSummary
	_ = json.Unmarshal([]byte(summary), &ps)
	if ps.Bytes != int64(len("refunds are processed within 5 business days")) || len(ps.DataLabels) != 1 || ps.DataLabels[0] != "faq" {
		t.Fatalf("payload summary: %s", summary)
	}
	if n := e.count(t, `SELECT count(*) FROM diary WHERE body_json LIKE '%refunds are processed%'`); n != 0 {
		t.Fatal("memory content leaked into the Diary")
	}
	h, err := e.undo.Get(ctx, actionID)
	if err != nil || h.Status != undo.StatusActive || h.Kind != undo.KindMemoryStaging {
		t.Fatalf("undo handle: %+v %v", h, err)
	}
	if a := undo.Undoability(h); !a.Undoable {
		t.Fatalf("handle not undoable: %+v", a)
	}

	// The writer sees its staged item; another agent does not.
	if got := ids(itemsOf(t, e.agentCall(t, supportAgent, http.MethodPost, queryPath("kb"), map[string]any{"embedding": []float32{1, 0, 0}}))); !got[id] {
		t.Fatal("writer does not see its own staged item")
	}
	if got := itemsOf(t, e.agentCall(t, otherAgent, http.MethodPost, queryPath("kb"), map[string]any{"text": "refunds"})); len(got) != 0 {
		t.Fatalf("other agent sees a staged item: %v", got)
	}
	if got := itemsOf(t, e.agentCall(t, supportAgent, http.MethodPost, queryPath("kb"), map[string]any{"include_own_staged": false})); len(got) != 0 {
		t.Fatalf("include_own_staged=false still returned staged items: %v", got)
	}

	// Undo drops the staged item.
	res, err := e.runUndo(t, actionID)
	if err != nil || res["dropped"] != true {
		t.Fatalf("undo: %v %v", res, err)
	}
	if _, err := e.store(t).Get(ctx, "kb", id); !errors.Is(err, memory.ErrItemNotFound) {
		t.Fatalf("staged item survived the undo: %v", err)
	}
	if _, err := e.runUndo(t, actionID); !errors.Is(err, undo.ErrNotUndoable) {
		t.Fatalf("second undo: %v", err)
	}
	e.verifyDiary(t)
}

func TestGatewayPromotedWriteIsNotUndoable(t *testing.T) {
	e := newEnv(t, envOpts{delay: 50 * time.Millisecond})
	ctx := context.Background()
	id, actionID := e.mustWrite(t, supportAgent, "kb", "promote me", nil)
	time.Sleep(100 * time.Millisecond)
	res, err := e.svc.PromoteDue(ctx)
	if err != nil || res.Promoted != 1 {
		t.Fatalf("promotion: %+v %v", res, err)
	}
	h, err := e.undo.Get(ctx, actionID)
	if err != nil || h.Status != undo.StatusExpired || h.Error == "" {
		t.Fatalf("promoted write's undo handle not closed: %+v %v", h, err)
	}
	if a := undo.Undoability(h); a.Undoable {
		t.Fatalf("promoted write still reported undoable: %+v", a)
	}
	if n := e.count(t, `SELECT count(*) FROM diary WHERE event_type = 'undo.expired' AND body_json LIKE '%`+actionID+`%'`); n != 1 {
		t.Fatalf("undo.expired events: %d", n)
	}
	// The executor refuses honestly even when called directly.
	h.Status = undo.StatusUndoing
	if _, err := e.exec.Undo(ctx, h); !errors.Is(err, undo.ErrNothingToUndo) {
		t.Fatalf("executor on a promoted item: %v", err)
	}
	if it, err := e.store(t).Get(ctx, "kb", id); err != nil || it.Staged {
		t.Fatalf("promoted item: %+v %v", it, err)
	}
	// Other agents now see it.
	if got := ids(itemsOf(t, e.agentCall(t, otherAgent, http.MethodPost, queryPath("kb"), map[string]any{}))); !got[id] {
		t.Fatal("promoted item not visible to other agents")
	}
	e.verifyDiary(t)
}

func TestGatewayPolicyRefusals(t *testing.T) {
	e := newEnv(t, envOpts{})
	id, _ := e.mustWrite(t, supportAgent, "kb", "keep", nil)

	// DELETE is not undoable: held for a human (POL-005), nothing deleted.
	r := e.agentCall(t, supportAgent, http.MethodDelete, writePath("kb")+"/"+id, nil)
	if f := refusal(t, r); r.code != http.StatusForbidden || f["decision"] != "hold" || f["rule_id"] != "POL-005" {
		t.Fatalf("delete: %d %s", r.code, r.raw)
	}
	if _, err := e.store(t).Get(context.Background(), "kb", id); err != nil {
		t.Fatalf("held delete removed the item: %v", err)
	}
	// Sensitive labels: held (POL-904), nothing written.
	r = e.agentCall(t, supportAgent, http.MethodPost, writePath("kb"), map[string]any{"content": "card 4111", "metadata": map[string]string{"labels": "customer_pii"}})
	if f := refusal(t, r); f["decision"] != "hold" {
		t.Fatalf("sensitive write: %d %s", r.code, r.raw)
	}
	if n := e.custCount(t, `SELECT count(*) FROM fortik_memory.items WHERE content = 'card 4111'`); n != 0 {
		t.Fatal("held write reached the store")
	}
	// Unknown endpoint and malformed bodies: decided as UNKNOWN and denied.
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/gw/memory/support/kb/items", nil},
		{http.MethodPost, writePath("kb"), `{"content": "x", "extra": 1}`},
		{http.MethodPost, writePath("kb"), `{"content": ""}`},
		{http.MethodPost, "/gw/memory/support/bad%2Fns/items", map[string]any{"content": "x"}},
		{http.MethodPost, queryPath("kb"), `{"embedding": [1, "a"]}`},
	} {
		r := e.agentCall(t, supportAgent, c.method, c.path, c.body)
		if f := refusal(t, r); r.code != http.StatusForbidden || f["decision"] != "deny" || f["rule_id"] != "POL-002" {
			t.Fatalf("%s %s: %d %s", c.method, c.path, r.code, r.raw)
		}
	}
	// Unauthenticated: 401, nothing decided.
	if r := do(t, e.gw, http.MethodPost, queryPath("kb"), map[string]any{}, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", r.code)
	}
	// Unconfigured store: decided, then 503.
	r = e.agentCall(t, supportAgent, http.MethodPost, "/gw/memory/nostore/kb/query", map[string]any{})
	if r.code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured store: %d %s", r.code, r.raw)
	}
	// Embedding size mismatch: refused by the store, nothing written.
	e.mustWrite(t, supportAgent, "kb", "sized", []float32{1, 2, 3})
	r = e.agentCall(t, supportAgent, http.MethodPost, writePath("kb"), map[string]any{"content": "wrong", "embedding": []float32{1, 2}})
	if f := refusal(t, r); f["rule_id"] != memory.RuleInvalid {
		t.Fatalf("size mismatch: %d %s", r.code, r.raw)
	}
	var failed int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM undo_handles WHERE status = 'failed'`).Scan(&failed); err != nil || failed != 1 {
		t.Fatalf("failed write's undo handle not marked failed: %d %v", failed, err)
	}
	e.verifyDiary(t)
}

func TestGatewayKilledAgentDenied(t *testing.T) {
	e := newEnv(t, envOpts{})
	if _, err := e.ctl.SetLevel(context.Background(), supportAgent, control.Killed, "kill", "test"); err != nil {
		t.Fatal(err)
	}
	r := e.agentCall(t, supportAgent, http.MethodPost, queryPath("kb"), map[string]any{})
	if f := refusal(t, r); f["decision"] != "deny" {
		t.Fatalf("killed agent: %s", r.raw)
	}
}

func TestEnricher(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	en := memory.NewEnricher(e.svc)
	if en.Key() != "memory" {
		t.Fatal(en.Key())
	}
	v, err := en.Enrich(ctx, action.Action{AgentID: supportAgent, System: "memory"}, control.State{})
	if err != nil || v.(memory.PolicyContext).Access != memory.AccessFull {
		t.Fatalf("default access: %v %v", v, err)
	}
	if _, err := e.svc.ChangeAccess(ctx, supportAgent, memory.AccessStagingOnly, "user:sec", "investigating"); err != nil {
		t.Fatal(err)
	}
	v, err = en.Enrich(ctx, action.Action{AgentID: supportAgent, System: "mcp"}, control.State{})
	if err != nil || v.(memory.PolicyContext).Access != memory.AccessStagingOnly {
		t.Fatalf("mcp access: %v %v", v, err)
	}
	if v, err := en.Enrich(ctx, action.Action{AgentID: supportAgent, System: "postgres"}, control.State{}); v != nil || err != nil {
		t.Fatalf("other system enriched: %v %v", v, err)
	}
}

func TestWriteRequestMetadataLabels(t *testing.T) {
	for in, want := range map[string]string{
		`{"content":"x","metadata":{"labels":["PII","finance"],"src":"chat"}}`: "PII,finance",
		`{"content":"x","metadata":{"labels":"pii, finance"}}`:                 "pii, finance",
	} {
		var w memory.WriteRequest
		if err := json.Unmarshal([]byte(in), &w); err != nil || w.Metadata["labels"] != want {
			t.Fatalf("%s: %v %v", in, w.Metadata, err)
		}
		if got := memory.Labels(w.Metadata); len(got) != 2 || got[0] != "finance" || got[1] != "pii" {
			t.Fatalf("labels %v", got)
		}
	}
	for _, in := range []string{`{"metadata":{"n":1}}`, `{"metadata":{"labels":[1]}}`, `{"metadata":["x"]}`} {
		var w memory.WriteRequest
		if err := json.Unmarshal([]byte(in), &w); err == nil {
			t.Fatalf("%s accepted", in)
		}
	}
}
