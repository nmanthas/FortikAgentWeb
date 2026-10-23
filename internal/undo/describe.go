package undo

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Handle kinds prepared outside this package (the gateway adapters and the
// memory gateway own their handle_json). The values are the kinds stored in
// undo_handles.kind; they are repeated here so the Undo list can describe
// every kind without importing the adapters.
const (
	KindGmailDelayedSend = "gmail_delayed_send" // {action_id, send_at, mailbox}: cancel before the send
	KindDrivePermission  = "drive_permission"   // {file_id, permission_id, subject}: delete the permission
	KindGitHubRef        = "github_ref"         // {repo, ref, previous_sha, operation, pr, result_sha}
	KindGitHubPR         = "github_pr"          // {repo, pr, previous_state}: reopen the PR
	KindMemoryStaging    = "memory_staging"     // {store, namespace, item_id}: drop the staged memory item
)

// WhyNot values of the Undo list. They are shown to people verbatim.
const (
	WhyNotUsed        = "already used"
	WhyNotExpired     = "expired"
	WhyNotSent        = "already sent: NOT undoable"
	WhyNotIncomplete  = "prepared but the action did not complete"
	WhyNotNoUndo      = "no undo was prepared for this action: NOT undoable"
	WhyNotInProgress  = "an undo is already in progress"
	WhyNotUnsupported = "Fortik cannot undo this kind of action: NOT undoable"
	WhyNotMalformed   = "the undo record is incomplete: NOT undoable"

	// Delayed email states read from the live delayed_sends row.
	WhyNotSending        = "being sent right now: NOT undoable"
	WhyNotSendCancelled  = "already cancelled before sending: nothing was sent"
	WhyNotSendIncomplete = "the send failed or its outcome is unknown: nothing left to cancel, NOT undoable"

	// NoteSendTimeReached is shown when only the handle is known and its
	// send time has passed: the email may or may not be out (retries and a
	// late or paused sender keep it pending), so Undo stays offered and the
	// executor gives the authoritative answer.
	NoteSendTimeReached = "send time reached: may already be sent"
)

// Assessment says whether a handle can be undone right now and what Undo
// would do. It is computed from the handle alone (no calls to the real
// system; AssessDelayedSendAt adds the live delayed_sends row for delayed
// emails), so it is advisory: the executor re-checks when Undo runs and may
// still refuse (e.g. the rows were changed again since).
type Assessment struct {
	Undoable    bool   `json:"undoable"`
	WhyNot      string `json:"why_not,omitempty"`
	Description string `json:"description"`
}

// NoUndo is the assessment of an action for which no handle exists.
func NoUndo() Assessment { return Assessment{WhyNot: WhyNotNoUndo} }

// Undoability assesses h at the current time.
func Undoability(h Handle) Assessment { return UndoabilityAt(h, time.Now()) }

// UndoabilityAt assesses h at now. A zero handle (no action id or kind)
// means no undo was prepared.
func UndoabilityAt(h Handle, now time.Time) Assessment {
	if h.ActionID == "" || h.Kind == "" {
		return NoUndo()
	}
	desc, ok := describe(h, now)
	a := Assessment{Description: desc}
	switch h.Status {
	case StatusUsed:
		a.WhyNot = WhyNotUsed
	case StatusExpired:
		a.WhyNot = WhyNotExpired
	case StatusPrepared, StatusFailed:
		a.WhyNot = WhyNotIncomplete
	case StatusUndoing:
		a.WhyNot = WhyNotInProgress
	case StatusActive:
		switch {
		case !h.ExpiresAt.IsZero() && !now.Before(h.ExpiresAt):
			a.WhyNot = WhyNotExpired
		case desc == "":
			a.WhyNot = WhyNotUnsupported
		case !ok:
			a.WhyNot = WhyNotMalformed
		}
	default:
		// Unknown status: never offer an undo Fortik cannot vouch for.
		a.WhyNot = WhyNotUnsupported
	}
	a.Undoable = a.WhyNot == ""
	if a.Description == "" {
		a.Description = "Undo is not available for " + h.Kind
	}
	return a
}

// describe returns the human description of what Undo does for h at now and
// whether handle_json was complete. An empty description means the kind is
// unknown.
func describe(h Handle, now time.Time) (string, bool) {
	switch h.Kind {
	case KindPGRows:
		var d struct {
			PGRowsData
			Rows *int64 `json:"rows,omitempty"` // optional: affected row count, when recorded
		}
		if err := json.Unmarshal(h.Data, &d); err != nil || d.Schema == "" || d.Table == "" || d.SnapshotTable == "" {
			return "Restore the rows changed by this statement", false
		}
		table := d.Schema + "." + d.Table
		switch strings.ToUpper(d.Op) {
		case "DELETE":
			return fmt.Sprintf("Restore %s into %s", rowCount(d.Rows, "deleted"), table), true
		case "UPDATE":
			return fmt.Sprintf("Put back the previous values of %s in %s", rowCount(d.Rows, "updated"), table), true
		}
		return fmt.Sprintf("Restore the rows changed in %s", table), false
	case KindPGRename:
		var d PGRenameData
		if err := json.Unmarshal(h.Data, &d); err != nil || d.Schema == "" || d.Table == "" || d.TrashTable == "" {
			return "Restore the dropped or truncated table", false
		}
		table := d.Schema + "." + d.Table
		switch strings.ToUpper(d.Op) {
		case "TRUNCATE":
			return fmt.Sprintf("Restore the truncated rows of %s (from %s.%s)", table, d.Schema, d.TrashTable), true
		case "DROP":
			return fmt.Sprintf("Restore the dropped table %s (from %s.%s)", table, d.Schema, d.TrashTable), true
		}
		return fmt.Sprintf("Restore %s from %s.%s", table, d.Schema, d.TrashTable), false
	case KindGmailDelayedSend:
		var d struct {
			SendAt string `json:"send_at"`
		}
		_ = json.Unmarshal(h.Data, &d)
		sendAt, err := time.Parse(time.RFC3339Nano, d.SendAt)
		if err != nil {
			// Without the send time Fortik cannot tell whether it was sent.
			return "Cancel the delayed email (only before it is sent)", false
		}
		// The handle's send_at is the time recorded when the email was
		// queued. The row can stay pending past it (Gmail retries move
		// send_at, a late or stopped sender, a suspended agent), so a past
		// send time never means "sent": AssessDelayedSendAt reads the row.
		if !now.Before(sendAt) {
			return fmt.Sprintf("Cancel the delayed email if it has not gone out yet (%s, at %s)", NoteSendTimeReached, sendAt.UTC().Format(time.RFC3339)), true
		}
		return fmt.Sprintf("Cancel the delayed email (only before it is sent, at %s)", sendAt.UTC().Format(time.RFC3339)), true
	case KindDrivePermission:
		var d struct {
			FileID       string `json:"file_id"`
			PermissionID string `json:"permission_id"`
		}
		if err := json.Unmarshal(h.Data, &d); err != nil || d.FileID == "" || d.PermissionID == "" {
			return "Remove the Drive sharing permission this action added", false
		}
		return fmt.Sprintf("Remove the sharing permission %s from Drive file %s", d.PermissionID, d.FileID), true
	case KindGitHubRef:
		var d struct {
			Repo        string `json:"repo"`
			Ref         string `json:"ref"`
			PreviousSHA string `json:"previous_sha"`
			PR          int    `json:"pr"`
		}
		if err := json.Unmarshal(h.Data, &d); err != nil || d.Repo == "" || d.Ref == "" {
			return "Move the GitHub ref back to where it was before this action", false
		}
		var desc string
		if d.PreviousSHA == "" {
			desc = fmt.Sprintf("Delete %s in %s, which this action created", d.Ref, d.Repo)
		} else {
			desc = fmt.Sprintf("Move %s in %s back to %s", d.Ref, d.Repo, shortSHA(d.PreviousSHA))
		}
		if d.PR > 0 {
			desc = fmt.Sprintf("Revert the merge of pull request #%d: %s", d.PR, lowerFirst(desc))
		}
		return desc + " (only if nobody pushed since)", true
	case KindGitHubPR:
		var d struct {
			Repo          string `json:"repo"`
			PR            int    `json:"pr"`
			PreviousState string `json:"previous_state"`
		}
		if err := json.Unmarshal(h.Data, &d); err != nil || d.Repo == "" || d.PR <= 0 {
			return "Reopen the pull request this action closed", false
		}
		if d.PreviousState != "" && d.PreviousState != "open" {
			return fmt.Sprintf("Nothing to reopen: pull request #%d in %s was %s before this action", d.PR, d.Repo, d.PreviousState), true
		}
		return fmt.Sprintf("Reopen pull request #%d in %s", d.PR, d.Repo), true
	case KindMemoryStaging:
		var d map[string]any
		_ = json.Unmarshal(h.Data, &d)
		store := firstString(d, "store", "store_key")
		ns := firstString(d, "namespace")
		item := firstString(d, "item_id", "id")
		if item == "" {
			return "Drop the staged memory write (only while it is still staged)", false
		}
		where := ""
		switch {
		case store != "" && ns != "":
			where = " from " + store + "/" + ns
		case ns != "":
			where = " from namespace " + ns
		}
		return fmt.Sprintf("Drop the staged memory item %s%s (only while it is still staged)", item, where), true
	}
	return "", false
}

func rowCount(n *int64, verb string) string {
	switch {
	case n == nil:
		return "the " + verb + " rows"
	case *n == 1:
		return "1 " + verb + " row"
	default:
		return fmt.Sprintf("%d %s rows", *n, verb)
	}
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
