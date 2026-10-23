package google

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/authz"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/gateway"
	"fortik/internal/httpx"
	"fortik/internal/secrets"
	"fortik/internal/undo"
)

// DelayedSendKeySecret names the AES-256 data key (base64) that encrypts
// queued messages. It is created on first use when the store is writable.
const DelayedSendKeySecret = "gateway/delayed_send_key"

const actorGateway = "system:gateway"

// dataKey loads (and if needed creates) the delayed-send data key.
type dataKey struct {
	sec  secrets.Provider
	name string

	mu  sync.Mutex
	key []byte
	id  string
}

func keyID(k []byte) string {
	sum := sha256.Sum256(k)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func (d *dataKey) get(ctx context.Context, create bool) ([]byte, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.key != nil {
		return d.key, d.id, nil
	}
	raw, err := d.sec.Get(ctx, d.name)
	if errors.Is(err, secrets.ErrNotFound) && create {
		st, ok := d.sec.(secrets.Store)
		if !ok {
			return nil, "", errors.New("delayed-send data key missing and the secret provider is read-only")
		}
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, "", err
		}
		if err := st.Put(ctx, d.name, []byte(base64.StdEncoding.EncodeToString(k))); err != nil {
			return nil, "", fmt.Errorf("create delayed-send data key: %w", err)
		}
		// Re-read: if another writer raced us, use the value that persisted.
		raw, err = d.sec.Get(ctx, d.name)
	}
	if err != nil {
		return nil, "", fmt.Errorf("load delayed-send data key: %w", err)
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(k) != 32 {
		return nil, "", errors.New("delayed-send data key is not 32 bytes of base64")
	}
	d.key, d.id = k, keyID(k)
	return d.key, d.id, nil
}

// forID returns the key whose id is id, re-reading the secret once if the
// cached key differs (e.g. it was replaced).
func (d *dataKey) forID(ctx context.Context, id string) ([]byte, error) {
	if k, kid, err := d.get(ctx, false); err == nil && kid == id {
		return k, nil
	}
	d.mu.Lock()
	d.key, d.id = nil, ""
	d.mu.Unlock()
	k, kid, err := d.get(ctx, false)
	if err != nil {
		return nil, err
	}
	if kid != id {
		return nil, errors.New("delayed-send data key changed since the message was queued: it cannot be decrypted")
	}
	return k, nil
}

func seal(key, plaintext []byte, aad string) (ct, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, []byte(aad)), nonce, nil
}

func unseal(key, ct, nonce []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("bad nonce")
	}
	return gcm.Open(nil, nonce, ct, []byte(aad))
}

// delayedMeta is delayed_sends.meta_json: counts and routing, never content.
type delayedMeta struct {
	Recipients      int    `json:"recipients"`
	ExternalDomains int    `json:"external_domains"`
	Attachments     int    `json:"attachments"`
	Bytes           int64  `json:"bytes"`
	Mailbox         string `json:"mailbox"` // the impersonated workspace user at decision time
	ThreadID        string `json:"thread_id,omitempty"`
	DraftID         string `json:"draft_id,omitempty"`
	InstanceID      string `json:"instance_id,omitempty"`
	Attempts        int    `json:"attempts"`
	ClaimedAt       string `json:"claimed_at,omitempty"`
}

// enqueueDelayed stores the encrypted message, its undo handle and the Diary
// events in one transaction, then answers like Gmail would (200 + a message
// resource marked FORTIK_DELAYED).
func (a *Adapter) enqueueDelayed(ctx context.Context, p authz.Principal, out decide.Outcome, st *opState, subject string, delay time.Duration, w http.ResponseWriter) error {
	actionID := out.Action.ActionID
	key, kid, err := a.keys.get(ctx, true)
	if err != nil {
		a.log.Error("delayed send unavailable", "action_id", actionID, "err", err)
		return &gateway.RefusedError{RuleID: "GW-DELAY-UNAVAILABLE", Reason: "this send must be delayed but the delayed-send queue is unavailable: refused"}
	}
	m := st.send.msg
	ct, nonce, err := seal(key, m.raw, actionID)
	if err != nil {
		return err
	}
	extF, _ := number(out.Action.Target["external_domains"])
	ext := int(extF)
	meta := delayedMeta{Recipients: len(m.recipients()), ExternalDomains: ext, Attachments: m.attachments, Bytes: int64(len(m.raw)),
		Mailbox: subject, ThreadID: st.send.threadID, DraftID: st.send.draftID, InstanceID: p.InstanceID}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	sendAt := a.now().UTC().Add(delay).Truncate(time.Microsecond)
	expires := sendAt.Add(a.undoGrace)
	handle := map[string]any{"action_id": actionID, "send_at": sendAt.Format(time.RFC3339Nano), "mailbox": subject}
	err = pgx.BeginFunc(ctx, a.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO delayed_sends (action_id, agent_id, send_at, status, payload_enc, nonce, key_id, meta_json)
			VALUES ($1, $2, $3, 'pending', $4, $5, $6, $7)`, actionID, p.Name, sendAt, ct, nonce, kid, metaJSON); err != nil {
			return fmt.Errorf("insert delayed send: %w", err)
		}
		if err := insertActiveHandle(ctx, tx, a.diary, actionID, p.Name, KindGmailDelayedSend, handle, expires); err != nil {
			return err
		}
		_, err := a.diary.AppendTx(ctx, tx, diary.Event{AgentID: p.Name, EventType: EventDelayedQueued, Actor: actorGateway, Data: map[string]any{
			"action_id": actionID, "send_at": sendAt.Format(time.RFC3339Nano), "delay_seconds": int(delay / time.Second),
			"recipients": meta.Recipients, "external_domains": meta.ExternalDomains, "attachments": meta.Attachments, "bytes": meta.Bytes,
		}})
		return err
	})
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id":       "fortik-delayed-" + actionID,
		"labelIds": []string{"FORTIK_DELAYED"},
		"fortik":   map[string]any{"status": "delayed", "send_at": sendAt.Format(time.RFC3339), "action_id": actionID},
	})
	return nil
}

// insertActiveHandle records an undo handle that is undoable immediately
// (the action it reverses has already been made safe), with the same Diary
// events undo.PGStore writes for prepare + activate, in the caller's tx.
func insertActiveHandle(ctx context.Context, tx pgx.Tx, d *diary.Diary, actionID, agentID, kind string, data map[string]any, expires time.Time) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO undo_handles (action_id, agent_id, kind, handle_json, status, expires_at)
		VALUES ($1, $2, $3, $4, 'active', $5)`, actionID, agentID, kind, b, expires); err != nil {
		return fmt.Errorf("insert undo handle: %w", err)
	}
	_, err = d.AppendTx(ctx, tx,
		diary.Event{AgentID: agentID, EventType: diary.EventUndoPrepared, Actor: actorGateway, Data: map[string]any{
			"action_id": actionID, "kind": kind, "handle": data, "expires_at": expires.UTC().Format(time.RFC3339)}},
		diary.Event{AgentID: agentID, EventType: diary.EventUndoActivated, Actor: actorGateway, Data: map[string]any{
			"action_id": actionID, "from": undo.StatusPrepared, "to": undo.StatusActive}})
	return err
}

// recordPermission writes the drive_permission undo handle for a created share.
func (a *Adapter) recordPermission(ctx context.Context, p authz.Principal, out decide.Outcome, st *opState, subject string, respBody []byte) error {
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &created); err != nil || !segPattern.MatchString(created.ID) {
		return errors.New("permissions.create response has no usable permission id")
	}
	data := map[string]any{"file_id": st.share.fileID, "permission_id": created.ID, "subject": subject}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return pgx.BeginFunc(rctx, a.pool, func(tx pgx.Tx) error {
		return insertActiveHandle(rctx, tx, a.diary, out.Action.ActionID, p.Name, KindDrivePermission, data, a.now().Add(a.permTTL))
	})
}

// --- worker -----------------------------------------------------------------

// DelayedSender sends queued messages once their delay has elapsed. Before
// sending it re-checks the agent's control level: READ_ONLY or stricter (or
// an agent no longer registered) cancels the send. A suspended agent's sends
// stay pending (not claimed, still undoable) until it is resumed.
type DelayedSender struct {
	a          *Adapter
	Poll       time.Duration
	Batch      int
	MaxRetries int
	StuckAfter time.Duration    // a "sending" row older than this is failed as outcome-unknown
	Now        func() time.Time // defaults to the adapter's clock
}

// NewDelayedSender builds the worker (poll interval from config.GatewayConfig.DelayedSendPoll).
func (a *Adapter) NewDelayedSender() *DelayedSender {
	poll := a.cfg.DelayedSendPoll
	if poll <= 0 {
		poll = time.Second
	}
	return &DelayedSender{a: a, Poll: poll, Batch: 20, MaxRetries: 5, StuckAfter: 10 * time.Minute}
}

func (d *DelayedSender) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return d.a.now().UTC()
}

// Run polls until ctx ends.
func (d *DelayedSender) Run(ctx context.Context) {
	t := time.NewTicker(d.Poll)
	defer t.Stop()
	for {
		if _, err := d.RunOnce(ctx); err != nil && ctx.Err() == nil {
			d.a.log.Error("delayed send poll failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type dueSend struct {
	actionID, agentID, keyID string
	payload, nonce           []byte
	meta                     delayedMeta
}

// RunOnce processes every due send once and returns how many it handled.
func (d *DelayedSender) RunOnce(ctx context.Context) (int, error) {
	if err := d.sweepStuck(ctx); err != nil {
		return 0, err
	}
	claimed, n, err := d.claim(ctx)
	if err != nil {
		return n, err
	}
	for _, s := range claimed {
		d.send(ctx, s)
	}
	return n, nil
}

// claim locks due rows (SKIP LOCKED, so several workers never share one),
// cancels those whose agent is now READ_ONLY or stricter, leaves those of a
// suspended agent pending, and marks the rest "sending" — after which an
// undo can no longer cancel them.
func (d *DelayedSender) claim(ctx context.Context) ([]dueSend, int, error) {
	var claimed []dueSend
	handled := 0
	now := d.now()
	err := pgx.BeginFunc(ctx, d.a.pool, func(tx pgx.Tx) error {
		claimed, handled = nil, 0
		// Rows of a suspended agent stay pending and are not even locked
		// (so they never crowd other agents' sends out of the batch); they
		// go out after Resume. A suspended agent that is also READ_ONLY or
		// stricter is still selected, and cancelled below.
		rows, err := tx.Query(ctx, `
			SELECT d.action_id, d.agent_id, d.payload_enc, d.nonce, d.key_id, d.meta_json FROM delayed_sends d
			WHERE d.status = 'pending' AND d.send_at <= $1
			  AND NOT EXISTS (SELECT 1 FROM agents ag WHERE ag.agent_id = d.agent_id AND ag.suspended_at IS NOT NULL AND ag.level < $3)
			ORDER BY d.send_at LIMIT $2 FOR UPDATE OF d SKIP LOCKED`, now, d.Batch, int16(control.ReadOnly))
		if err != nil {
			return err
		}
		var due []dueSend
		for rows.Next() {
			var s dueSend
			var meta []byte
			if err := rows.Scan(&s.actionID, &s.agentID, &s.payload, &s.nonce, &s.keyID, &meta); err != nil {
				rows.Close()
				return err
			}
			_ = json.Unmarshal(meta, &s.meta)
			due = append(due, s)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, s := range due {
			handled++
			st, err := control.Get(ctx, tx, s.agentID)
			if err != nil {
				return err
			}
			if !st.Registered || st.Level >= control.ReadOnly {
				reason := fmt.Sprintf("agent is %s: delayed send cancelled before sending", st.Level)
				if !st.Registered {
					reason = "agent is no longer registered: delayed send cancelled before sending"
				}
				if err := d.finishTx(ctx, tx, s, "pending", "cancelled", reason, undo.StatusFailed, "cancelled before sending: nothing was sent",
					EventDelayedCancelled, map[string]any{"by": "worker", "level": st.Level.String()}); err != nil {
					return err
				}
				continue
			}
			if st.Suspended {
				// Suspended since the query ran: keep it pending (state kept;
				// it is sent after Resume, or cancelled if the agent steps
				// down meanwhile). Never claimed, so an undo can still cancel it.
				handled--
				continue
			}
			s.meta.ClaimedAt = now.Format(time.RFC3339Nano)
			if _, err := tx.Exec(ctx, `UPDATE delayed_sends SET status = 'sending', meta_json = meta_json || jsonb_build_object('claimed_at', $2::text)
				WHERE action_id = $1`, s.actionID, s.meta.ClaimedAt); err != nil {
				return err
			}
			claimed = append(claimed, s)
		}
		return nil
	})
	return claimed, handled, err
}

var errAlreadyFinal = errors.New("delayed send already finalised")

// finishTx moves a delayed send (and its undo handle) to a final state and
// records it, inside tx.
// The row must still be in status from; otherwise errAlreadyFinal is
// returned and nothing is changed.
func (d *DelayedSender) finishTx(ctx context.Context, tx pgx.Tx, s dueSend, from, status, errText, handleStatus, handleNote, event string, extra map[string]any) error {
	q := `UPDATE delayed_sends SET status = $2, error = NULLIF($3, '') WHERE action_id = $1 AND status = $4`
	if status == "sent" {
		q = `UPDATE delayed_sends SET status = $2, error = NULLIF($3, ''), sent_at = now() WHERE action_id = $1 AND status = $4`
	}
	rct, err := tx.Exec(ctx, q, s.actionID, status, errText, from)
	if err != nil {
		return err
	}
	if rct.RowsAffected() != 1 {
		return errAlreadyFinal
	}
	ct, err := tx.Exec(ctx, `UPDATE undo_handles SET status = $2, error = $3,
			used_at = CASE WHEN $2 = 'used' THEN now() ELSE used_at END,
			used_by = CASE WHEN $2 = 'used' THEN $4 ELSE used_by END
		WHERE action_id = $1 AND status IN ('prepared', 'active')`, s.actionID, handleStatus, handleNote, actorGateway)
	if err != nil {
		return err
	}
	data := map[string]any{"action_id": s.actionID, "status": status, "undo_handle": handleStatus, "undo_note": handleNote,
		"handle_updated": ct.RowsAffected() == 1, "recipients": s.meta.Recipients}
	if errText != "" {
		data["reason"] = errText
	}
	for k, v := range extra {
		data[k] = v
	}
	_, err = d.a.diary.AppendTx(ctx, tx, diary.Event{AgentID: s.agentID, EventType: event, Actor: actorGateway, Data: data})
	return err
}

func (d *DelayedSender) finish(ctx context.Context, s dueSend, status, errText, handleStatus, handleNote, event string, extra map[string]any) {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err := pgx.BeginFunc(fctx, d.a.pool, func(tx pgx.Tx) error {
		return d.finishTx(fctx, tx, s, "sending", status, errText, handleStatus, handleNote, event, extra)
	})
	if errors.Is(err, errAlreadyFinal) {
		// Finalised by someone else (the stuck sweep) while in flight. Keep
		// that final state, but record what actually happened.
		d.a.log.Error("delayed send finished after its row was finalised", "action_id", s.actionID, "outcome", status)
		err = pgx.BeginFunc(fctx, d.a.pool, func(tx pgx.Tx) error {
			var cur string
			if err := tx.QueryRow(fctx, `SELECT status FROM delayed_sends WHERE action_id = $1`, s.actionID).Scan(&cur); err != nil {
				return err
			}
			data := map[string]any{"action_id": s.actionID, "outcome": status, "recorded_status": cur, "recipients": s.meta.Recipients}
			if errText != "" {
				data["reason"] = errText
			}
			_, err := d.a.diary.AppendTx(fctx, tx, diary.Event{AgentID: s.agentID, EventType: EventDelayedLate, Actor: actorGateway, Data: data})
			return err
		})
	}
	if err != nil {
		d.a.log.Error("delayed send state could not be recorded", "action_id", s.actionID, "status", status, "err", err)
	}
}

// send delivers one claimed message.
func (d *DelayedSender) send(ctx context.Context, s dueSend) {
	a := d.a
	log := a.log.With("action_id", s.actionID, "agent_id", s.agentID)
	key, err := a.keys.forID(ctx, s.keyID)
	var raw []byte
	if err == nil {
		raw, err = unseal(key, s.payload, s.nonce, s.actionID)
	}
	if err != nil {
		log.Error("delayed send cannot be decrypted", "err", err)
		d.finish(ctx, s, "failed", "message could not be decrypted: nothing was sent", undo.StatusFailed,
			"send failed: nothing was sent", EventDelayedFailed, nil)
		return
	}
	st, err := a.settings(ctx)
	if err != nil {
		d.retry(ctx, s, "integration unavailable")
		return
	}
	scopes := []string{ScopeGmailSend}
	if s.meta.DraftID != "" {
		scopes = []string{ScopeGmailCompose}
	}
	tok, err := a.tokens.token(ctx, st, mintRequest{agentID: s.agentID, instanceID: s.meta.InstanceID, actionID: s.actionID,
		subject: s.meta.Mailbox, system: "gmail", scopes: scopes})
	if err != nil {
		log.Warn("delayed send: no token", "err", err)
		d.retry(ctx, s, "could not obtain a Google token")
		return
	}
	req, err := a.sendRequest(tok, raw, s.meta.ThreadID)
	if err != nil {
		d.finish(ctx, s, "failed", "request could not be built: nothing was sent", undo.StatusFailed, "send failed: nothing was sent", EventDelayedFailed, nil)
		return
	}
	resp, err := gateway.Do(ctx, req)
	if err != nil {
		// The request may have reached Gmail: never resend automatically.
		log.Error("delayed send outcome unknown", "err", err)
		d.finish(ctx, s, "failed", "outcome unknown: transport error while sending", undo.StatusExpired,
			"send outcome unknown: not undoable", EventDelayedFailed, map[string]any{"outcome_unknown": true})
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	switch {
	case resp.StatusCode/100 == 2:
		var sent struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(body, &sent)
		extra := map[string]any{}
		if segPattern.MatchString(sent.ID) {
			extra["gmail_message_id"] = sent.ID
		}
		d.finish(ctx, s, "sent", "", undo.StatusUsed, "sent: not undoable", EventDelayedSent, extra)
		if s.meta.DraftID != "" {
			a.deleteDraft(ctx, tok, s.meta.DraftID)
		}
		log.Info("delayed send sent")
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		d.retry(ctx, s, fmt.Sprintf("gmail returned HTTP %d", resp.StatusCode))
	default:
		d.finish(ctx, s, "failed", fmt.Sprintf("gmail rejected the message (HTTP %d): nothing was sent", resp.StatusCode),
			undo.StatusFailed, "send failed: nothing was sent", EventDelayedFailed, nil)
	}
}

// retry puts a definitely-unsent message back in the queue with backoff, or
// fails it after MaxRetries. The level check runs again on the next claim.
func (d *DelayedSender) retry(ctx context.Context, s dueSend, reason string) {
	attempt := s.meta.Attempts + 1
	if attempt > d.MaxRetries {
		d.finish(ctx, s, "failed", reason+": retries exhausted, nothing was sent", undo.StatusFailed,
			"send failed: nothing was sent", EventDelayedFailed, map[string]any{"attempts": attempt - 1})
		return
	}
	backoff := time.Duration(1<<min(attempt, 5)) * 15 * time.Second
	next := d.now().Add(backoff)
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err := pgx.BeginFunc(rctx, d.a.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(rctx, `UPDATE delayed_sends SET status = 'pending', send_at = $2, error = $3,
			meta_json = (meta_json - 'claimed_at') || jsonb_build_object('attempts', $4::int) WHERE action_id = $1 AND status = 'sending'`,
			s.actionID, next, reason, attempt); err != nil {
			return err
		}
		_, err := d.a.diary.AppendTx(rctx, tx, diary.Event{AgentID: s.agentID, EventType: EventDelayedRetry, Actor: actorGateway, Data: map[string]any{
			"action_id": s.actionID, "attempt": attempt, "reason": reason, "next_send_at": next.Format(time.RFC3339)}})
		return err
	})
	if err != nil {
		d.a.log.Error("delayed send retry could not be recorded", "action_id", s.actionID, "err", err)
	}
}

// sweepStuck fails rows left in "sending" by a stopped worker. Whether they
// went out is unknown, so they are never resent.
func (d *DelayedSender) sweepStuck(ctx context.Context) error {
	cutoff := d.now().Add(-d.StuckAfter)
	return pgx.BeginFunc(ctx, d.a.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT action_id, agent_id, meta_json FROM delayed_sends
			WHERE status = 'sending' AND COALESCE((meta_json->>'claimed_at')::timestamptz, created_at) < $1 FOR UPDATE SKIP LOCKED`, cutoff)
		if err != nil {
			return err
		}
		var stuck []dueSend
		for rows.Next() {
			var s dueSend
			var meta []byte
			if err := rows.Scan(&s.actionID, &s.agentID, &meta); err != nil {
				rows.Close()
				return err
			}
			_ = json.Unmarshal(meta, &s.meta)
			stuck = append(stuck, s)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, s := range stuck {
			if err := d.finishTx(ctx, tx, s, "sending", "failed", "outcome unknown: the worker stopped while sending", undo.StatusExpired,
				"send outcome unknown: not undoable", EventDelayedFailed, map[string]any{"outcome_unknown": true}); err != nil {
				return err
			}
		}
		return nil
	})
}
