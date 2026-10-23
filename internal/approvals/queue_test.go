package approvals_test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fortik/internal/approvals"
	"fortik/internal/authz"
	"fortik/internal/policy"
)

func (e *env) get(p *authz.Principal, path string) (int, map[string]any) {
	e.t.Helper()
	e.mu.Lock()
	e.who = p
	e.mu.Unlock()
	resp, err := http.Get(e.srv.URL + path)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func itemIDs(body map[string]any) []string {
	var out []string
	for _, it := range body["items"].([]any) {
		out = append(out, it.(map[string]any)["action_id"].(string))
	}
	return out
}

func (e *env) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.pool.Exec(bg, q, args...); err != nil {
		e.t.Fatal(err)
	}
}

var agentPrincipal = authz.Principal{Kind: authz.KindAgent, Name: analyst}

// The queue: filters, sorts, pagination, votes, progress, assignment and
// swarm groups; strict query parsing; roles.
func TestQueueFiltersSortAndPagination(t *testing.T) {
	e := setup(t, approvals.Config{})
	yA := e.decideCopy(e.pgAct(analyst, "COPY orders TO STDOUT")).Action.ActionID    // yellow POL-105
	yB := e.decideCopy(e.pgAct(other, "COPY customers TO STDOUT")).Action.ActionID   // yellow POL-105
	yC := e.decideCopy(e.pgAct(analyst, "COPY customers TO STDOUT")).Action.ActionID // yellow, denied below
	red := e.decideCopy(e.pgAct(coder, "DROP TABLE orders")).Action.ActionID         // red POL-101
	base := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	for i, id := range []string{red, yB, yA, yC} { // expires_at order: red, yB, yA, yC
		e.exec(`UPDATE held_actions SET expires_at = $2, created_at = $3 WHERE action_id = $1`, id,
			base.Add(time.Duration(i)*time.Minute), base.Add(-time.Duration(10-i)*time.Minute))
	}
	// yB is held as part of a swarm; it needs two approvers and has one vote.
	e.exec(`INSERT INTO swarms (swarm_id, detected_by, member_count, state) VALUES ('swm_test', 'manual', 7, 'breaker_tripped')`)
	e.exec(`UPDATE held_actions SET swarm_id = 'swm_test', approvals_required = 2 WHERE action_id = $1`, yB)
	if code, body := e.do(&security, path(yB, "approve"), `{"reason":"looks fine"}`); code != 202 || body["outcome"] != "pending" {
		t.Fatalf("first vote: %d %v", code, body)
	}
	if code, _ := e.do(&security, path(yA, "assign"), `{"assignee":"Sec2@Acme.com"}`); code != 200 {
		t.Fatalf("assign: %d", code)
	}
	if code, _ := e.do(&security, path(yC, "deny"), `{"reason":"no"}`); code != 200 {
		t.Fatalf("deny: %d", code)
	}

	// Roles.
	if code, _ := e.get(nil, "/v1/approvals/queue"); code != 401 {
		t.Fatalf("anonymous %d", code)
	}
	if code, _ := e.get(&agentPrincipal, "/v1/approvals/queue"); code != 403 {
		t.Fatalf("agent %d", code)
	}
	if code, _ := e.get(&security, "/v1/approvals/queue"); code != 200 {
		t.Fatalf("security %d", code)
	}

	// Default: pending, most urgent first.
	code, body := e.get(&auditor, "/v1/approvals/queue")
	if code != 200 || strings.Join(itemIDs(body), ",") != strings.Join([]string{red, yB, yA}, ",") || body["total"] != float64(3) {
		t.Fatalf("default: %d %v", code, itemIDs(body))
	}
	if body["sort"] != "expires_at" || body["order"] != "asc" || body["next_offset"] != nil {
		t.Fatalf("meta: %v", body)
	}
	items := body["items"].([]any)
	b := items[1].(map[string]any)
	if b["swarm_id"] != "swm_test" || b["approvals"] != float64(1) || b["approvals_required"] != float64(2) || b["progress"] != "1 of 2 approvals" {
		t.Fatalf("swarm item: %v", b)
	}
	votes := b["votes"].([]any)
	if len(votes) != 1 {
		t.Fatalf("votes %v", votes)
	}
	v := votes[0].(map[string]any)
	if v["approver"] != "user:sec@acme.com" || v["decision"] != "approve" || v["at"] == nil || v["reason"] != "looks fine" {
		t.Fatalf("vote %v", v)
	}
	if a := items[2].(map[string]any); a["assigned_to"] != "user:sec2@acme.com" || a["progress"] != "0 of 1 approvals" || len(a["votes"].([]any)) != 0 {
		t.Fatalf("assigned item %v", a)
	}
	if r := items[0].(map[string]any); r["class"] != "red" || r["safe_form"] == nil || r["rule_id"] != "POL-101" || r["expired"] != false ||
		r["decision"] != "hold" || r["level_at_decision"] != "FULL" || r["undo_available"] != false || r["system"] != "postgres" {
		t.Fatalf("red item %v", r)
	}
	groups := body["groups"].([]any)
	if len(groups) != 1 {
		t.Fatalf("groups %v", groups)
	}
	g := groups[0].(map[string]any)
	if g["swarm_id"] != "swm_test" || g["state"] != "breaker_tripped" || g["member_count"] != float64(7) || g["held"] != float64(1) || g["pending"] != float64(1) {
		t.Fatalf("group %v", g)
	}

	cases := map[string][]string{
		"?status=all":                     {red, yB, yA, yC},
		"?status=denied":                  {yC},
		"?status=all&agent_id=" + analyst: {yA, yC},
		"?class=red":                      {red},
		"?class=yellow&sort=expires_at&order=desc": {yA, yB},
		"?rule_id=POL-101":                         {red},
		"?swarm_id=swm_test":                       {yB},
		"?assigned_to=none":                        {red, yB},
		"?assigned_to=sec2@acme.com":               {yA},
		"?assigned_to=user:SEC2@acme.com":          {yA},
		"?sort=created_at":                         {yA, yB, red},
		"?sort=created_at&order=asc":               {red, yB, yA},
		"?sort=class":                              {red, yB, yA},
		"?status=all&sort=class&order=desc":        {yB, yA, yC, red},
		"?agent_id=nobody":                         {},
		"?sort=severity":                           {red, yB, yA},
		"?sort=newest":                             {yA, yB, red},
		"?sort=oldest":                             {red, yB, yA},
		"?sort=expires":                            {red, yB, yA},
	}
	for q, want := range cases {
		code, body := e.get(&auditor, "/v1/approvals/queue"+q)
		if code != 200 || strings.Join(itemIDs(body), ",") != strings.Join(want, ",") || body["total"] != float64(len(want)) {
			t.Fatalf("%s: %d %v want %v", q, code, itemIDs(body), want)
		}
	}
	// assigned_to=me is the caller.
	sec2Assigned := authz.Principal{Kind: authz.KindUser, Email: "SEC2@acme.com", Roles: map[string]bool{authz.RoleAuditor: true}}
	if _, body := e.get(&sec2Assigned, "/v1/approvals/queue?assigned_to=me"); strings.Join(itemIDs(body), ",") != yA {
		t.Fatalf("me: %v", itemIDs(body))
	}

	// Pagination.
	code, body = e.get(&auditor, "/v1/approvals/queue?limit=2")
	if code != 200 || strings.Join(itemIDs(body), ",") != red+","+yB || body["next_offset"] != float64(2) || body["total"] != float64(3) {
		t.Fatalf("page 1: %v %v", itemIDs(body), body["next_offset"])
	}
	_, body = e.get(&auditor, "/v1/approvals/queue?limit=2&offset=2")
	if strings.Join(itemIDs(body), ",") != yA || body["next_offset"] != nil {
		t.Fatalf("page 2: %v %v", itemIDs(body), body["next_offset"])
	}
	_, body = e.get(&auditor, "/v1/approvals/queue?offset=10")
	if len(itemIDs(body)) != 0 || body["total"] != float64(3) {
		t.Fatalf("past the end: %v", body)
	}

	// Strict parsing.
	for _, q := range []string{"?status=open", "?class=blue", "?sort=agent", "?order=up", "?limit=0", "?limit=501", "?limit=x",
		"?offset=-1", "?bogus=1", "?sort=newest&order=asc", "?status=pending&status=all", "?agent_id=a%20b", "?assigned_to=not%20an%20email", "?assigned_to=bob"} {
		if code, _ := e.get(&auditor, "/v1/approvals/queue"+q); code != 400 {
			t.Fatalf("%s: %d", q, code)
		}
	}

	// A pending hold past its expiry (not yet swept) is flagged.
	e.exec(`UPDATE held_actions SET expires_at = now() - interval '1 minute' WHERE action_id = $1`, yA)
	_, body = e.get(&auditor, "/v1/approvals/queue?agent_id="+analyst)
	if it := body["items"].([]any)[0].(map[string]any); it["expired"] != true || it["outcome"] != "pending" {
		t.Fatalf("expired flag %v", it)
	}
}

// Assignment: security only, canonical assignee, sponsor refused, no-op not
// recorded, unassign, closed holds refused; each change in the Diary.
func TestAssign(t *testing.T) {
	e := setup(t, approvals.Config{})
	id := e.decideCopy(e.pgAct(analyst, "COPY orders TO STDOUT")).Action.ActionID
	if code, _ := e.do(&auditor, path(id, "assign"), `{"assignee":"sec2@acme.com"}`); code != 403 {
		t.Fatalf("auditor %d", code)
	}
	if code, _ := e.do(nil, path(id, "assign"), `{"assignee":"sec2@acme.com"}`); code != 401 {
		t.Fatalf("anonymous %d", code)
	}
	for _, body := range []string{`{"assignee":"x y@acme.com"}`, `{"assignee":"bob"}`, `{"assignee":"user:"}`, `{"assignee":"token:"}`,
		`{"assignee":"a@b@c"}`, `{"assignee":"sec2@acme.com","extra":1}`, `{"assignee":"sec2@acme.com"} {}`, `[]`} {
		if code, _ := e.do(&security, path(id, "assign"), body); code != 400 {
			t.Fatalf("%s: %d", body, code)
		}
	}
	if code, _ := e.do(&security, path("act_missing", "assign"), `{"assignee":"sec2@acme.com"}`); code != 404 {
		t.Fatalf("missing %d", code)
	}
	// The sponsor cannot decide the hold, so it cannot be routed to them.
	if code, _ := e.do(&security, path(id, "assign"), `{"assignee":"JANE@acme.com"}`); code != 403 {
		t.Fatalf("assign to sponsor %d", code)
	}
	code, body := e.do(&security, path(id, "assign"), `{"assignee":"Sec2@Acme.com","reason":"on call"}`)
	if code != 200 || body["assigned_to"] != "user:sec2@acme.com" || body["previous"] != nil || body["changed"] != true || body["assigned_by"] != "user:sec@acme.com" {
		t.Fatalf("assign: %d %v", code, body)
	}
	if code, body := e.do(&security, path(id, "assign"), `{"assignee":"user:sec2@ACME.com"}`); code != 200 || body["changed"] != false {
		t.Fatalf("no-op: %d %v", code, body)
	}
	if code, body := e.do(&security, path(id, "assign"), `{"assignee":"token:oncall-bot"}`); code != 200 || body["previous"] != "user:sec2@acme.com" || body["assigned_to"] != "token:oncall-bot" {
		t.Fatalf("reassign: %d %v", code, body)
	}
	if code, body := e.do(&security, path(id, "assign"), `{"assignee":""}`); code != 200 || body["assigned_to"] != nil || body["changed"] != true {
		t.Fatalf("unassign: %d %v", code, body)
	}
	if n := e.events(approvals.EventActionAssigned, id); n != 3 {
		t.Fatalf("assigned events %d", n)
	}
	var reason string
	if err := e.pool.QueryRow(bg, `SELECT body_json::jsonb->'data'->>'reason' FROM diary WHERE event_type = 'action.assigned' ORDER BY seq LIMIT 1`).Scan(&reason); err != nil || reason != "on call" {
		t.Fatalf("reason %q %v", reason, err)
	}
	// Closed or expired holds cannot be assigned.
	exp := e.decideCopy(e.pgAct(other, "COPY orders TO STDOUT")).Action.ActionID
	e.exec(`UPDATE held_actions SET expires_at = now() - interval '1 second' WHERE action_id = $1`, exp)
	if code, _ := e.do(&security, path(exp, "assign"), `{"assignee":"sec2@acme.com"}`); code != 409 {
		t.Fatalf("expired %d", code)
	}
	if code, _ := e.do(&security, path(id, "deny"), `{"reason":"no"}`); code != 200 {
		t.Fatal("deny")
	}
	if code, _ := e.do(&security, path(id, "assign"), `{"assignee":"sec2@acme.com"}`); code != 409 {
		t.Fatalf("closed %d", code)
	}
	e.verifyDiary()

	// With owner approval allowed, the sponsor may be assigned.
	e2 := setup(t, approvals.Config{AllowOwnerApproval: true})
	id2 := e2.decideCopy(e2.pgAct(analyst, "COPY orders TO STDOUT")).Action.ActionID
	if code, _ := e2.do(&security, path(id2, "assign"), `{"assignee":"jane@acme.com"}`); code != 200 {
		t.Fatalf("assign to sponsor when allowed %d", code)
	}
}

// Bulk deny: each id decided and recorded on its own, honest per-id results,
// the owner rule applied per id, and one summary event.
func TestBulkDeny(t *testing.T) {
	e := setup(t, approvals.Config{})
	a := e.decideCopy(e.pgAct(analyst, "COPY orders TO STDOUT")).Action.ActionID // sponsor jane
	o := e.decideCopy(e.pgAct(other, "COPY orders TO STDOUT")).Action.ActionID   // sponsor bob
	o2 := e.decideCopy(e.pgAct(other, "COPY customers TO STDOUT")).Action.ActionID
	if code, _ := e.do(&security, path(o2, "deny"), `{"reason":"already"}`); code != 200 {
		t.Fatal("deny")
	}
	for _, body := range []string{`{"action_ids":[]}`, `{"action_ids":["x"]}`, `{"action_ids":[],"reason":"r"}`, `{"action_ids":["x"],"reason":"r","more":1}`,
		`{"action_ids":"x","reason":"r"}`, fmt.Sprintf(`{"action_ids":[%s"x"],"reason":"r"}`, strings.Repeat(`"x",`, approvals.BulkDenyMax))} {
		if code, _ := e.do(&security, "/v1/held/bulk-deny", body); code != 400 {
			t.Fatalf("%.80s: %d", body, code)
		}
	}
	if code, _ := e.do(&auditor, "/v1/held/bulk-deny", `{"action_ids":["x"],"reason":"r"}`); code != 403 {
		t.Fatalf("auditor %d", code)
	}
	// ownerSec (Jane) sponsors analyst: refused for a, allowed for o.
	req := fmt.Sprintf(`{"action_ids":[%q,%q,%q,%q,"act_missing","bad id",%q],"reason":"incident 42"}`, a, o, o2, o, a)
	code, body := e.do(&ownerSec, "/v1/held/bulk-deny", req)
	if code != 200 || body["requested"] != float64(5) || body["denied"] != float64(1) || body["failed"] != float64(4) || body["summary_recorded"] != true {
		t.Fatalf("bulk: %d %v", code, body)
	}
	want := map[string]float64{a: 403, o: 200, o2: 409, "act_missing": 404, "bad id": 404}
	for _, r := range body["results"].([]any) {
		m := r.(map[string]any)
		id := m["action_id"].(string)
		if m["status"] != want[id] {
			t.Fatalf("%s: %v", id, m)
		}
		if (m["outcome"] == "denied") != (want[id] == 200) || (want[id] != 200 && m["error"] == "") {
			t.Fatalf("%s: %v", id, m)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("missing results %v", want)
	}
	if e.outcome(o) != "denied" || e.outcome(a) != "pending" {
		t.Fatal("outcomes")
	}
	if e.events(approvals.EventActionDenied, o) != 1 || e.events(approvals.EventActionDenied, a) != 0 {
		t.Fatal("per-id deny events")
	}
	var summary map[string]any
	var raw []byte
	if err := e.pool.QueryRow(bg, `SELECT body_json::jsonb->'data' FROM diary WHERE event_type = $1`, approvals.EventHeldBulkDenied).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &summary)
	if summary["reason"] != "incident 42" || len(summary["denied"].([]any)) != 1 || len(summary["failed"].([]any)) != 4 || summary["requested"] != float64(5) {
		t.Fatalf("summary %v", summary)
	}
	// Security (not the sponsor) denies the rest.
	code, body = e.do(&security, "/v1/held/bulk-deny", fmt.Sprintf(`{"action_ids":[%q],"reason":"incident 42"}`, a))
	if code != 200 || body["denied"] != float64(1) || e.outcome(a) != "denied" {
		t.Fatalf("second bulk: %d %v", code, body)
	}
	e.verifyDiary()
}

// copyPolicies copies the repo bundle to a temp dir and adds extra files.
func copyPolicies(t *testing.T, extra map[string]string) string {
	t.Helper()
	dst := t.TempDir()
	src := policyDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel, body := range extra {
		if err := os.WriteFile(filepath.Join(dst, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// A test-only rule asking for two approvers on an otherwise green action.
const twoApproverRule = `package fortik.rules

findings contains {
	"rule_id": "POL-998",
	"class": "yellow",
	"reason": "test: two approvers",
	"hold": true,
	"approvals_required": 2,
} if {
	input.action.target.test_two_approvers == true
}
`

// Two-approver hold end to end through decide: the hold stores
// approvals_required 2, the first approver gets pending 1 of 2, the same
// approver (any case) is refused, the sponsor is refused, the second
// distinct approver approves and the one-time grant releases the retry.
func TestTwoApproverHoldEndToEnd(t *testing.T) {
	e := setup(t, approvals.Config{})
	eng, err := policy.NewEngine(bg, copyPolicies(t, map[string]string{"fortik/zz_two_approvers_test_rule.rego": twoApproverRule}), e.quiet)
	if err != nil {
		t.Fatal(err)
	}
	e.dec.Policy = eng
	act := e.pgAct(analyst, "SELECT * FROM orders")
	if plain := e.decideCopy(act); plain.Result.Decision != policy.Allow {
		t.Fatalf("plain SELECT should be allowed: %+v", plain.Result)
	}
	act.Target["test_two_approvers"] = true
	out := e.decideCopy(act)
	if out.Result.Decision != policy.Hold || out.Result.Class != policy.Yellow || out.Result.ApprovalsRequired != 2 || out.Result.RuleID != "POL-998" {
		t.Fatalf("hold: %+v", out.Result)
	}
	id := out.Action.ActionID
	_, body := e.get(&auditor, "/v1/approvals/queue?rule_id=POL-998")
	if it := body["items"].([]any)[0].(map[string]any); it["approvals_required"] != float64(2) || it["progress"] != "0 of 2 approvals" {
		t.Fatalf("queue before votes: %v", it)
	}
	code, body := e.do(&security, path(id, "approve"), `{"reason":"first"}`)
	if code != 202 || body["outcome"] != "pending" || body["approvals"] != float64(1) || body["approvals_required"] != float64(2) {
		t.Fatalf("first: %d %v", code, body)
	}
	if code, _ := e.do(&securityUpper, path(id, "approve"), `{"reason":"again"}`); code != 409 {
		t.Fatalf("same approver: %d", code)
	}
	if code, _ := e.do(&ownerSec, path(id, "approve"), `{"reason":"mine"}`); code != 403 {
		t.Fatalf("sponsor: %d", code)
	}
	if o := e.decideCopy(act); o.Result.Decision != policy.Hold {
		t.Fatalf("retry before the second approval: %+v", o.Result)
	}
	_, body = e.get(&auditor, "/v1/approvals/queue?status=all&rule_id=POL-998&sort=created_at&order=asc")
	if it := body["items"].([]any)[0].(map[string]any); it["progress"] != "1 of 2 approvals" || len(it["votes"].([]any)) != 1 {
		t.Fatalf("queue after one vote: %v", it)
	}
	code, body = e.do(&security2, path(id, "approve"), `{"reason":"second"}`)
	if code != 200 || body["outcome"] != "approved" || body["approvals"] != float64(2) || body["grant"] == nil {
		t.Fatalf("second: %d %v", code, body)
	}
	grant := body["grant"].(map[string]any)["grant_id"].(string)
	if o := e.decideCopy(act); o.Result.Decision != policy.Allow || o.Result.GrantID != grant {
		t.Fatalf("retry with grant: %+v", o.Result)
	}
	if o := e.decideCopy(act); o.Result.Decision != policy.Hold {
		t.Fatalf("grant reused: %+v", o.Result)
	}
	if e.events(approvals.EventApprovalVote, id) != 1 || e.events(approvals.EventActionApproved, id) != 1 || e.events(approvals.EventGrantIssued, id) != 1 {
		t.Fatal("diary events")
	}
	e.verifyDiary()
}
