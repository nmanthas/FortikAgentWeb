package shadow_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"fortik/internal/control"
	"fortik/internal/shadow"
)

func TestNilRecorderIsSafe(t *testing.T) {
	var r *shadow.Recorder
	r.RecordTraffic(shadow.TrafficEvent{Source: shadow.SourceGateway, Kind: shadow.KindUnknownToken, TokenRef: "0123456789ab"})
	if err := r.Flush(bg); err != nil || r.Stats() != (shadow.RecorderStats{}) {
		t.Fatal("nil recorder")
	}
	var tr shadow.TrafficRecorder = r
	tr.RecordTraffic(shadow.TrafficEvent{})
	if _, err := shadow.NewRecorder(shadow.RecorderConfig{}); err == nil {
		t.Fatal("empty recorder config accepted")
	}
}

func TestTrafficRecorder(t *testing.T) {
	e := newEnv(t)
	rec, err := shadow.NewRecorder(shadow.RecorderConfig{Pool: e.pool, Diary: e.diary, Alerts: e.alerts, MaxPending: 5, MaxNewPerHour: 3})
	if err != nil {
		t.Fatal(err)
	}
	const tok = "agt_old_script_token"
	ev := shadow.TrafficEvent{Source: shadow.SourceGateway, Kind: shadow.KindUnknownToken, TokenRef: shadow.TokenRef(tok),
		Host: "10.0.0.7", UserAgent: "python-requests/2.31\x00", Detail: "path=/gw/gmail"}
	// Invalid events are dropped, never recorded.
	for _, bad := range []shadow.TrafficEvent{
		{Source: "nope", Kind: shadow.KindUnknownToken, TokenRef: shadow.TokenRef(tok)},
		{Source: shadow.SourceGateway, Kind: shadow.KindUnknownToken, TokenRef: tok}, // a raw token is not a ref
		{Source: shadow.SourceGateway, Kind: "other"},
		{Source: shadow.SourcePGProxy, Kind: shadow.KindUnknownAgent},
	} {
		rec.RecordTraffic(bad)
	}
	if st := rec.Stats(); st.Dropped != 4 || st.Pending != 0 {
		t.Fatalf("stats: %+v", st)
	}
	rec.RecordTraffic(ev)
	if err := rec.Flush(bg); err != nil {
		t.Fatal(err)
	}
	ref := "token:" + shadow.TokenRef(tok)
	fid := shadow.FindingID(shadow.SystemTraffic, shadow.KindUnknownToken, ref)
	f, err := e.svc.Get(bg, fid)
	if err != nil || f.Status != shadow.StatusOpen || f.AgentID != "" || !f.UsedBySoftware {
		t.Fatalf("one attempt: %v %+v", err, f)
	}
	if strings.Contains(string(f.Evidence)+f.CredentialRef+f.Holder, tok) {
		t.Fatal("token stored")
	}
	// Two more attempts (deduplicated in memory) cross RegisterAfter=3.
	rec.RecordTraffic(ev)
	rec.RecordTraffic(ev)
	if st := rec.Stats(); st.Pending != 1 {
		t.Fatalf("dedup: %+v", st)
	}
	if err := rec.Flush(bg); err != nil {
		t.Fatal(err)
	}
	f, _ = e.svc.Get(bg, fid)
	var evd map[string]any
	_ = json.Unmarshal(f.Evidence, &evd)
	if f.Status != shadow.StatusFlagged || f.AgentID == "" || evd["attempts"] != float64(3) {
		t.Fatalf("after 3 attempts: %+v %v", f, evd)
	}
	if uas, _ := evd["user_agents"].([]any); len(uas) != 1 || uas[0] != "python-requests/2.31" {
		t.Fatalf("user agents: %v", evd["user_agents"])
	}
	st, _ := control.Get(bg, e.pool, f.AgentID)
	if !st.Discovered || st.Level != control.Isolated || st.Sponsor != "" {
		t.Fatalf("traffic agent: %+v", st)
	}
	// Revoking a traffic finding is honest: Fortik did not issue it.
	_, res, err := e.svc.Revoke(bg, fid, "user:sec", "unknown caller")
	if err != nil || res.Outcome != shadow.OutcomeManualRequired {
		t.Fatalf("traffic revoke: %v %+v", err, res)
	}

	// Bounded: MaxPending distinct callers per flush, MaxNewPerHour new findings.
	for i := 0; i < 8; i++ {
		rec.RecordTraffic(shadow.TrafficEvent{Source: shadow.SourcePGProxy, Kind: shadow.KindUnknownAgent, AgentID: "ghost" + string(rune('a'+i)), Host: "10.0.0.8"})
	}
	if st := rec.Stats(); st.Pending != 5 {
		t.Fatalf("pending cap: %+v", st)
	}
	if err := rec.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM shadow_findings WHERE system = 'traffic'`); n != 3 { // 1 token + 2 more under the hourly cap of 3
		t.Fatalf("new-findings cap: %d traffic findings", n)
	}
	// A claimed id that is not a valid agent id is hashed, never stored raw.
	rec2, _ := shadow.NewRecorder(shadow.RecorderConfig{Pool: e.pool, Diary: e.diary, Alerts: e.alerts})
	rec2.RecordTraffic(shadow.TrafficEvent{Source: shadow.SourcePGProxy, Kind: shadow.KindUnknownAgent, AgentID: "bad name; drop table"})
	if err := rec2.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM shadow_findings WHERE credential_ref LIKE 'agent-hash:%'`); n != 1 {
		t.Fatalf("hashed claimed id: %d", n)
	}

	// Phase 5 review L5: a restarted recorder (or another process) takes its
	// hourly budget from the database, not a fresh one: 4 traffic findings
	// this hour already exceed a budget of 3, so a new caller is not recorded.
	rec3, _ := shadow.NewRecorder(shadow.RecorderConfig{Pool: e.pool, Diary: e.diary, Alerts: e.alerts, MaxNewPerHour: 3})
	rec3.RecordTraffic(shadow.TrafficEvent{Source: shadow.SourcePGProxy, Kind: shadow.KindUnknownAgent, AgentID: "after-restart", Host: "10.0.0.9"})
	if err := rec3.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM shadow_findings WHERE credential_ref = 'agent:after-restart'`); n != 0 {
		t.Fatal("a restart handed out a fresh hourly budget")
	}
	// Agents minted by unauthenticated callers through one interception point
	// bump one open alert instead of one alert each.
	rec4, _ := shadow.NewRecorder(shadow.RecorderConfig{Pool: e.pool, Diary: e.diary, Alerts: e.alerts, RegisterAfter: 1})
	for _, id := range []string{"flood-a", "flood-b", "flood-c"} {
		rec4.RecordTraffic(shadow.TrafficEvent{Source: shadow.SourceHook, Kind: shadow.KindUnknownAgent, AgentID: id, Host: "10.0.0.10"})
	}
	if err := rec4.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM shadow_findings WHERE credential_ref LIKE 'agent:flood-%' AND agent_id IS NOT NULL`); n != 3 {
		t.Fatalf("flood agents: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM alerts WHERE dedup_key = 'shadow-traffic:hook'`); n != 1 {
		t.Fatalf("flood alerts: %d", n)
	}
}

// Phase 5 review L6: the unknown-token ref is keyed. Without the server key
// the stored prefix cannot be checked against a guessed password; with the
// same key it is stable (repeat use is still recognised across restarts).
func TestTokenRefIsKeyed(t *testing.T) {
	const guess = "Summer2026!"
	unkeyed := sha256.Sum256([]byte("fortik/shadow/token-ref/v1\x00" + guess))
	shadow.SetTokenRefKey([]byte("server-secret-one"))
	a := shadow.TokenRef(guess)
	if a == hex.EncodeToString(unkeyed[:6]) || len(a) != 12 {
		t.Fatalf("ref %q is the unkeyed hash", a)
	}
	if shadow.TokenRef(guess) != a {
		t.Fatal("not stable under one key")
	}
	shadow.SetTokenRefKey([]byte("server-secret-two"))
	if shadow.TokenRef(guess) == a {
		t.Fatal("ref does not depend on the key")
	}
}
