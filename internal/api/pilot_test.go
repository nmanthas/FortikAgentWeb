package api_test

import (
	"context"
	"testing"
	"time"

	"fortik/internal/api"
	"fortik/internal/diary"
	"fortik/internal/testutil"
)

// Each pilot metric over a controlled window.
func TestPilotMetrics(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	now := time.Now().UTC()
	act := func(id, agent, class, decision, rule string, latency int, ladder bool, ts time.Time) {
		t.Helper()
		dj := `{}`
		if ladder {
			dj = `{"ladder_change":{"to":"READ_ONLY"}}`
		}
		if _, err := pool.Exec(ctx, `INSERT INTO actions (action_id, agent_id, system, verb, action_hash, class, decision, rule_id, reason,
			reversible, source, target, payload_summary, decision_json, fail_closed, latency_us, ts)
			VALUES ($1,$2,'postgres','DELETE','h',$3,$4,$5,'r',false,'pgproxy','{}','{}',$6::jsonb,false,$7,$8)`,
			id, agent, class, decision, rule, dj, latency, ts); err != nil {
			t.Fatal(err)
		}
	}
	ev := func(agent, typ string, data map[string]any) {
		t.Helper()
		if _, err := d.Append(ctx, diary.Event{AgentID: agent, EventType: typ, Actor: "test", Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	// 20 green decisions, 2 to 40 ms.
	for i := 1; i <= 20; i++ {
		act("g"+string(rune('a'+i)), "a1", "green", "allow", "POL-000", i*2000, false, now.Add(-time.Hour))
	}
	// Red: r1 stepped down by itself 300 ms later and stays down; r2 stepped
	// down and a person raised it back (overturned); r3 on an agent later killed.
	ts := time.Now().UTC().Add(-300 * time.Millisecond)
	act("r1", "a1", "red", "hold", "POL-101", 3000, true, ts)
	act("r2", "a2", "red", "hold", "POL-101", 3000, true, ts)
	act("r3", "a3", "red", "hold", "POL-101", 3000, true, ts)
	act("y1", "a1", "yellow", "hold", "POL-102", 3000, false, ts)
	for _, x := range []struct{ a, id string }{{"a1", "r1"}, {"a2", "r2"}, {"a3", "r3"}} {
		ev(x.a, "agent.level_changed", map[string]any{"from": "FULL", "to": "READ_ONLY", "direction": "down", "automatic": true, "action_id": x.id})
	}
	ev("a2", "agent.level_changed", map[string]any{"from": "READ_ONLY", "to": "FULL", "direction": "up", "automatic": false})
	ev("a3", "agent.level_changed", map[string]any{"from": "READ_ONLY", "to": "KILLED", "direction": "down", "automatic": false})
	m, err := api.ComputePilotMetrics(ctx, pool, now.Add(-2*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// 4 risky (r1 r2 r3 y1); a3 killed -> 3 of 4.
	if m.RiskyWithoutKill.N != 4 || *m.RiskyWithoutKill.Value != 75 || *m.RiskyWithoutKill.Met {
		t.Fatalf("risky: %+v", m.RiskyWithoutKill)
	}
	// 3 red, 1 overturned (r2).
	if m.RedOverturned.N != 3 || int(*m.RedOverturned.Value) != 33 || *m.RedOverturned.Met {
		t.Fatalf("red overturned: %+v", m.RedOverturned)
	}
	// Step-down recorded after each red: the median is the lag, well under 1 s.
	if m.RedToStepDownP50.N != 3 || m.RedToStepDownP50.Value == nil || !*m.RedToStepDownP50.Met {
		t.Fatalf("red to step-down: %+v", m.RedToStepDownP50)
	}
	// Green p95: 20 values 2..40 ms -> 38.1 ms, met.
	if m.GreenOverheadP95.N != 20 || *m.GreenOverheadP95.Value < 37 || *m.GreenOverheadP95.Value > 40 || !*m.GreenOverheadP95.Met {
		t.Fatalf("green p95: %+v", m.GreenOverheadP95)
	}
	if m.UndoSuccess.Value != nil || m.UndoSuccess.N != 0 {
		t.Fatalf("undo with no runs: %+v", m.UndoSuccess)
	}
}
