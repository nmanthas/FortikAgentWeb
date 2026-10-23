package api_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/api"
	"fortik/internal/diary"
	"fortik/internal/undo"
)

type fakeGmailExec struct{}

func (fakeGmailExec) Kinds() []string { return []string{undo.KindGmailDelayedSend} }
func (fakeGmailExec) Undo(context.Context, undo.Handle) (map[string]any, error) {
	return map[string]any{"cancelled": true}, nil
}

// F19: GET /v1/undo assesses a delayed email against its delayed_sends row.
// A retried email is still pending (and cancellable) after the send time
// recorded in its handle; the list must not say "already sent".
func TestUndoListDelayedSendUsesLiveRow(t *testing.T) {
	e := setupWith(t, fakeExec{}, setupOpts{configure: func(s *api.Server, _ *pgxpool.Pool, _ *diary.Diary) {
		s.Executors[undo.KindGmailDelayedSend] = fakeGmailExec{}
	}})
	ctx := context.Background()
	out, err := e.svc.Decide(ctx, action.Action{AgentID: "claude_code_01", System: "gmail", Verb: "SEND",
		Target: map[string]any{"recipients": 1, "external_domains": 1}})
	if err != nil {
		t.Fatal(err)
	}
	id := out.Action.ActionID
	queuedFor := time.Now().Add(-time.Minute).UTC() // the handle's send time has passed
	h := undo.Handle{ActionID: id, AgentID: "claude_code_01", Kind: undo.KindGmailDelayedSend, ExpiresAt: time.Now().Add(time.Hour),
		Data: json.RawMessage(`{"action_id":"` + id + `","send_at":"` + queuedFor.Format(time.RFC3339Nano) + `","mailbox":"ops@example.com"}`)}
	if err := e.store.Prepare(ctx, h, "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.store.Activate(ctx, id); err != nil {
		t.Fatal(err)
	}
	// Gmail answered 429 once: the sender put the row back to pending with
	// a later send time (the handle keeps the original one).
	retryAt := time.Now().Add(4 * time.Minute).UTC()
	if _, err := e.pool.Exec(ctx, `INSERT INTO delayed_sends (action_id, agent_id, send_at, status, payload_enc, nonce, key_id)
		VALUES ($1, 'claude_code_01', $2, 'pending', '\x00', '\x00', 'k')`, id, retryAt); err != nil {
		t.Fatal(err)
	}
	find := func() map[string]any {
		t.Helper()
		c, l := call(t, e, "GET", "/v1/undo", tokAuditor, nil)
		if c != 200 {
			t.Fatalf("list: %d %v", c, l)
		}
		for _, x := range l["undo"].([]any) {
			if m := x.(map[string]any); m["action_id"] == id {
				return m
			}
		}
		t.Fatal("handle not listed")
		return nil
	}
	got := find()
	if got["undoable"] != true || got["why_not"] != nil || !strings.Contains(got["description"].(string), "not sent yet; it goes out at "+retryAt.Format(time.RFC3339)) {
		t.Fatalf("pending (retried) delayed send: %v", got)
	}
	// Once the row is really sent, the list says so.
	if _, err := e.pool.Exec(ctx, `UPDATE delayed_sends SET status = 'sent', sent_at = now() WHERE action_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if got := find(); got["undoable"] != false || got["why_not"] != undo.WhyNotSent {
		t.Fatalf("sent delayed send: %v", got)
	}
	// Without a row (e.g. not readable), the handle alone keeps Undo offered
	// with honest wording; the executor decides.
	if _, err := e.pool.Exec(ctx, `DELETE FROM delayed_sends WHERE action_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if got := find(); got["undoable"] != true || !strings.Contains(got["description"].(string), undo.NoteSendTimeReached) {
		t.Fatalf("handle-only delayed send: %v", got)
	}
}
