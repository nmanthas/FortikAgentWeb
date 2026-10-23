package google

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/control"
	"fortik/internal/gateway"
)

func (e *env) setSuspended(agentID string, suspend bool) {
	e.t.Helper()
	reason := ""
	if suspend {
		reason = "containment test"
	}
	err := pgx.BeginFunc(context.Background(), e.pool, func(tx pgx.Tx) error {
		_, err := e.ctl.SetSuspendedTx(context.Background(), tx, agentID, suspend, reason, "user:security@acme.test", nil)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// F16 (decision D5): a suspended agent's delayed emails are not sent while
// it is suspended; they stay pending (still undoable) and go out after
// Resume.
func TestWorkerKeepsSuspendedAgentsSendsPending(t *testing.T) {
	e := newEnv(t)
	r := e.call("POST", sendPath, mailToken, sendBody(rfc822("alice@external.test", "held by suspend")), nil)
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	actionID := r.header.Get(gateway.ActionIDHeader)
	ctx := context.Background()
	e.setSuspended(mailAgent, true)
	e.clock.add(5 * time.Minute)
	w := e.worker()
	for i := 0; i < 2; i++ {
		if n, err := w.RunOnce(ctx); err != nil || n != 0 {
			t.Fatalf("suspended run %d: n=%d err=%v", i, n, err)
		}
	}
	if sent, _, _, _ := e.google.snapshot(); len(sent) != 0 {
		t.Fatal("delayed email sent while the agent is suspended")
	}
	if s := e.str(`SELECT status FROM delayed_sends WHERE action_id = $1`, actionID); s != "pending" {
		t.Fatalf("status while suspended: %s", s)
	}
	if s := e.str(`SELECT status FROM undo_handles WHERE action_id = $1`, actionID); s != "active" {
		t.Fatalf("handle while suspended: %s", s)
	}

	// Resume: the kept email goes out.
	e.setSuspended(mailAgent, false)
	if n, err := w.RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("after resume: n=%d err=%v", n, err)
	}
	if sent, _, _, _ := e.google.snapshot(); len(sent) != 1 {
		t.Fatalf("after resume sent %d", len(sent))
	}
	if s := e.str(`SELECT status FROM delayed_sends WHERE action_id = $1`, actionID); s != "sent" {
		t.Fatalf("status after resume: %s", s)
	}
}

// A suspended agent that is also READ_ONLY or stricter keeps the existing
// behaviour: its delayed email is cancelled.
func TestWorkerCancelsSuspendedReadOnlyAgentsSends(t *testing.T) {
	e := newEnv(t)
	r := e.call("POST", sendPath, mailToken, sendBody(rfc822("alice@external.test", "suspended and stepped down")), nil)
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	actionID := r.header.Get(gateway.ActionIDHeader)
	ctx := context.Background()
	e.setSuspended(mailAgent, true)
	if _, err := e.ctl.SetLevel(ctx, mailAgent, control.Quarantined, "quarantine", "user:security@acme.test"); err != nil {
		t.Fatal(err)
	}
	e.clock.add(5 * time.Minute)
	if n, err := e.worker().RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if sent, _, _, _ := e.google.snapshot(); len(sent) != 0 {
		t.Fatal("sent although the agent is QUARANTINED")
	}
	if s := e.str(`SELECT status FROM delayed_sends WHERE action_id = $1`, actionID); s != "cancelled" {
		t.Fatalf("status %s", s)
	}
}
