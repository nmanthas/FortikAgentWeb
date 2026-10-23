package undo_test

import (
	"encoding/json"
	"testing"
	"time"

	"fortik/internal/undo"
)

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUndoability(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	future, past := now.Add(time.Hour), now.Add(-time.Second)
	rows := func(op string, extra map[string]any) json.RawMessage {
		m := map[string]any{"upstream": "acme", "database": "acme", "schema": "public", "table": "orders",
			"snapshot_schema": "fortik_undo", "snapshot_table": "orders_01jabc", "op": op, "pk_columns": []string{"id"}}
		for k, v := range extra {
			m[k] = v
		}
		return mustJSON(t, m)
	}
	rename := func(op string) json.RawMessage {
		return mustJSON(t, undo.PGRenameData{Upstream: "acme", Schema: "public", Table: "orders",
			TrashTable: "fortik_trash_orders_20261018110000", Op: op})
	}
	h := func(kind, status string, exp time.Time, data json.RawMessage) undo.Handle {
		return undo.Handle{ActionID: "act_1", AgentID: "a1", Kind: kind, Status: status, ExpiresAt: exp, Data: data}
	}
	sendSoon := mustJSON(t, map[string]any{"action_id": "act_1", "send_at": now.Add(5 * time.Minute).Format(time.RFC3339Nano), "mailbox": "ops@example.com"})
	sentAlready := mustJSON(t, map[string]any{"action_id": "act_1", "send_at": now.Add(-time.Minute).Format(time.RFC3339Nano)})

	cases := []struct {
		name     string
		h        undo.Handle
		undoable bool
		whyNot   string
		desc     string
	}{
		{"no handle", undo.Handle{}, false, undo.WhyNotNoUndo, ""},
		{"rows delete with count", h(undo.KindPGRows, undo.StatusActive, future, rows("DELETE", map[string]any{"rows": 335})),
			true, "", "Restore 335 deleted rows into public.orders"},
		{"rows delete one row", h(undo.KindPGRows, undo.StatusActive, future, rows("DELETE", map[string]any{"rows": 1})),
			true, "", "Restore 1 deleted row into public.orders"},
		{"rows delete without count", h(undo.KindPGRows, undo.StatusActive, future, rows("DELETE", nil)),
			true, "", "Restore the deleted rows into public.orders"},
		{"rows update", h(undo.KindPGRows, undo.StatusActive, future, rows("UPDATE", map[string]any{"rows": 12})),
			true, "", "Put back the previous values of 12 updated rows in public.orders"},
		{"rows used", h(undo.KindPGRows, undo.StatusUsed, future, rows("DELETE", nil)),
			false, undo.WhyNotUsed, "Restore the deleted rows into public.orders"},
		{"rows expired status", h(undo.KindPGRows, undo.StatusExpired, past, rows("DELETE", nil)),
			false, undo.WhyNotExpired, "Restore the deleted rows into public.orders"},
		{"rows active past expiry", h(undo.KindPGRows, undo.StatusActive, past, rows("DELETE", nil)),
			false, undo.WhyNotExpired, "Restore the deleted rows into public.orders"},
		{"rows active at exact expiry", h(undo.KindPGRows, undo.StatusActive, now, rows("DELETE", nil)),
			false, undo.WhyNotExpired, "Restore the deleted rows into public.orders"},
		{"rows prepared", h(undo.KindPGRows, undo.StatusPrepared, future, rows("DELETE", nil)),
			false, undo.WhyNotIncomplete, "Restore the deleted rows into public.orders"},
		{"rows failed", h(undo.KindPGRows, undo.StatusFailed, future, rows("DELETE", nil)),
			false, undo.WhyNotIncomplete, "Restore the deleted rows into public.orders"},
		{"rows undoing", h(undo.KindPGRows, undo.StatusUndoing, future, rows("DELETE", nil)),
			false, undo.WhyNotInProgress, "Restore the deleted rows into public.orders"},
		{"rows malformed", h(undo.KindPGRows, undo.StatusActive, future, json.RawMessage(`{"op":"DELETE"}`)),
			false, undo.WhyNotMalformed, "Restore the rows changed by this statement"},
		{"rows unknown op", h(undo.KindPGRows, undo.StatusActive, future, rows("MERGE", nil)),
			false, undo.WhyNotMalformed, "Restore the rows changed in public.orders"},
		{"rename drop", h(undo.KindPGRename, undo.StatusActive, future, rename("DROP")),
			true, "", "Restore the dropped table public.orders (from public.fortik_trash_orders_20261018110000)"},
		{"rename truncate", h(undo.KindPGRename, undo.StatusActive, future, rename("TRUNCATE")),
			true, "", "Restore the truncated rows of public.orders (from public.fortik_trash_orders_20261018110000)"},
		{"delayed send pending", h(undo.KindGmailDelayedSend, undo.StatusActive, future, sendSoon),
			true, "", "Cancel the delayed email (only before it is sent, at 2026-10-18T12:05:00Z)"},
		// F19: from the handle alone a past send time does not mean "sent"
		// (retries and a late or paused sender keep the row pending): Undo
		// stays offered, worded honestly, and the executor decides.
		{"delayed send time reached (handle only)", h(undo.KindGmailDelayedSend, undo.StatusActive, future, sentAlready),
			true, "", "Cancel the delayed email if it has not gone out yet (send time reached: may already be sent, at 2026-10-18T11:59:00Z)"},
		{"delayed send expired wins", h(undo.KindGmailDelayedSend, undo.StatusActive, past, sentAlready),
			false, undo.WhyNotExpired, "Cancel the delayed email if it has not gone out yet (send time reached: may already be sent, at 2026-10-18T11:59:00Z)"},
		{"delayed send no time", h(undo.KindGmailDelayedSend, undo.StatusActive, future, json.RawMessage(`{}`)),
			false, undo.WhyNotMalformed, "Cancel the delayed email (only before it is sent)"},
		{"drive permission", h(undo.KindDrivePermission, undo.StatusActive, future,
			mustJSON(t, map[string]any{"file_id": "f1", "permission_id": "p9", "subject": "u@example.com"})),
			true, "", "Remove the sharing permission p9 from Drive file f1"},
		{"github ref rewind", h(undo.KindGitHubRef, undo.StatusActive, future,
			mustJSON(t, map[string]any{"repo": "acme/api", "ref": "heads/main", "previous_sha": "0123456789abcdef0123456789abcdef01234567", "operation": "force_push"})),
			true, "", "Move heads/main in acme/api back to 0123456789ab (only if nobody pushed since)"},
		{"github ref created", h(undo.KindGitHubRef, undo.StatusActive, future,
			mustJSON(t, map[string]any{"repo": "acme/api", "ref": "heads/feature", "previous_sha": ""})),
			true, "", "Delete heads/feature in acme/api, which this action created (only if nobody pushed since)"},
		{"github merge", h(undo.KindGitHubRef, undo.StatusActive, future,
			mustJSON(t, map[string]any{"repo": "acme/api", "ref": "heads/main", "previous_sha": "abc123", "pr": 12})),
			true, "", "Revert the merge of pull request #12: move heads/main in acme/api back to abc123 (only if nobody pushed since)"},
		{"github pr", h(undo.KindGitHubPR, undo.StatusActive, future,
			mustJSON(t, map[string]any{"repo": "acme/api", "pr": 7, "previous_state": "open"})),
			true, "", "Reopen pull request #7 in acme/api"},
		{"github pr used", h(undo.KindGitHubPR, undo.StatusUsed, future,
			mustJSON(t, map[string]any{"repo": "acme/api", "pr": 7, "previous_state": "open"})),
			false, undo.WhyNotUsed, "Reopen pull request #7 in acme/api"},
		{"memory staging", h(undo.KindMemoryStaging, undo.StatusActive, future,
			mustJSON(t, map[string]any{"store": "memory:support", "namespace": "kb", "item_id": "mem_1"})),
			true, "", "Drop the staged memory item mem_1 from memory:support/kb (only while it is still staged)"},
		{"memory staging alt keys", h(undo.KindMemoryStaging, undo.StatusActive, future,
			mustJSON(t, map[string]any{"store_key": "memory:support", "namespace": "kb", "id": "mem_2"})),
			true, "", "Drop the staged memory item mem_2 from memory:support/kb (only while it is still staged)"},
		{"memory staging malformed", h(undo.KindMemoryStaging, undo.StatusActive, future, json.RawMessage(`{"namespace":"kb"}`)),
			false, undo.WhyNotMalformed, "Drop the staged memory write (only while it is still staged)"},
		{"unknown kind", h("aws_iam", undo.StatusActive, future, json.RawMessage(`{}`)),
			false, undo.WhyNotUnsupported, "Undo is not available for aws_iam"},
		{"unknown status", h(undo.KindPGRows, "weird", future, rows("DELETE", nil)),
			false, undo.WhyNotUnsupported, "Restore the deleted rows into public.orders"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := undo.UndoabilityAt(c.h, now)
			if got.Undoable != c.undoable || got.WhyNot != c.whyNot || got.Description != c.desc {
				t.Fatalf("got %+v\nwant undoable=%v why_not=%q description=%q", got, c.undoable, c.whyNot, c.desc)
			}
			if got.Undoable != (got.WhyNot == "") {
				t.Fatalf("undoable and why_not disagree: %+v", got)
			}
		})
	}
}

func TestUndoabilityJSONShape(t *testing.T) {
	b, err := json.Marshal(undo.NoUndo())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"undoable":false,"why_not":"no undo was prepared for this action: NOT undoable","description":""}` {
		t.Fatalf("json %s", b)
	}
	// Undoability uses the wall clock.
	h := undo.Handle{ActionID: "a", Kind: undo.KindDrivePermission, Status: undo.StatusActive, ExpiresAt: time.Now().Add(-time.Minute),
		Data: json.RawMessage(`{"file_id":"f","permission_id":"p"}`)}
	if a := undo.Undoability(h); a.Undoable || a.WhyNot != undo.WhyNotExpired {
		t.Fatalf("%+v", a)
	}
}

type delayedCase struct {
	name     string
	h        undo.Handle
	row      *undo.DelayedSendState
	undoable bool
	whyNot   string
	desc     string
}

// F19: with the live delayed_sends row, the list reports the row's real
// state instead of guessing from the send time recorded in the handle.
func TestAssessDelayedSendAgainstRow(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	queuedFor := now.Add(-time.Minute) // the handle's (stale) send time has passed
	h := undo.Handle{ActionID: "act_1", Kind: undo.KindGmailDelayedSend, Status: undo.StatusActive, ExpiresAt: now.Add(time.Hour),
		Data: mustJSON(t, map[string]any{"action_id": "act_1", "send_at": queuedFor.Format(time.RFC3339Nano)})}
	row := func(status string, at time.Time) *undo.DelayedSendState {
		return &undo.DelayedSendState{Status: status, SendAt: at}
	}
	cases := []delayedCase{
		{"retried: pending with a later send time", h, row("pending", now.Add(4*time.Minute)), true, "",
			"Cancel the delayed email (not sent yet; it goes out at 2026-10-18T12:04:00Z)"},
		{"late sender: pending past its send time", h, row("pending", queuedFor), true, "",
			"Cancel the delayed email (not sent yet: still queued although its send time 2026-10-18T11:59:00Z has passed; the sender may pick it up at any moment)"},
		{"being sent", h, row("sending", queuedFor), false, undo.WhyNotSending, "Cancel the delayed email (only before it is sent)"},
		{"sent", h, row("sent", queuedFor), false, undo.WhyNotSent, "Cancel the delayed email (only before it is sent)"},
		{"cancelled", h, row("cancelled", queuedFor), false, undo.WhyNotSendCancelled, "Cancel the delayed email (only before it is sent)"},
		{"failed", h, row("failed", queuedFor), false, undo.WhyNotSendIncomplete, "Cancel the delayed email (only before it is sent)"},
		{"no row: handle only", h, nil, true, "",
			"Cancel the delayed email if it has not gone out yet (send time reached: may already be sent, at 2026-10-18T11:59:00Z)"},
	}
	used := h
	used.Status = undo.StatusUsed
	expired := h
	expired.ExpiresAt = now.Add(-time.Second)
	cases = append(cases,
		delayedCase{"used handle wins", used, row("pending", now.Add(time.Minute)), false, undo.WhyNotUsed,
			"Cancel the delayed email if it has not gone out yet (send time reached: may already be sent, at 2026-10-18T11:59:00Z)"},
		delayedCase{"expired handle wins", expired, row("pending", now.Add(time.Minute)), false, undo.WhyNotExpired,
			"Cancel the delayed email if it has not gone out yet (send time reached: may already be sent, at 2026-10-18T11:59:00Z)"},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := undo.AssessDelayedSendAt(c.h, c.row, now)
			if got.Undoable != c.undoable || got.WhyNot != c.whyNot || got.Description != c.desc {
				t.Fatalf("got %+v\nwant undoable=%v why_not=%q description=%q", got, c.undoable, c.whyNot, c.desc)
			}
		})
	}
}
