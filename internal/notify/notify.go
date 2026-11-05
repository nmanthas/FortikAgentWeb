// Package notify sends Fortik's security alerts to a Slack-compatible
// incoming webhook (integration notify_slack), naming the agent's owner. It
// is how an owner hears that a suspension was restored, or that its restore
// was blocked (the plan: "notifies the owner (console, plus Slack or email)"),
// and how security hears about bypass attempts, swarms and shadow agents.
//
// Each alert is sent at most once (alerts.notified_at), by whichever Fortik
// process locks it first (FOR UPDATE SKIP LOCKED). A failed post is retried
// on the next passes, up to maxAttempts, then recorded as failed. Alerts
// raised before the integration was configured are never sent (no flood of
// history). The console keeps showing every alert whatever happens here.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/integrations"
)

// System is the integration key.
const System = integrations.SystemNotifySlack

const (
	maxAttempts = 3
	batch       = 20
	postTimeout = 5 * time.Second
	maxText     = 3000
)

var sevRank = map[string]int{"info": 0, "warning": 1, "high": 2, "critical": 3}

// Worker posts pending alerts every interval.
type Worker struct {
	pool     *pgxpool.Pool
	src      integrations.Source
	client   *http.Client
	interval time.Duration
	log      *slog.Logger
}

// NewWorker returns the notifier; Run starts it.
func NewWorker(pool *pgxpool.Pool, src integrations.Source, interval time.Duration, log *slog.Logger) *Worker {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Worker{pool: pool, src: src, interval: interval, log: log,
		client: &http.Client{Timeout: postTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// System and Test make the worker the integration's "Test connection".
func (w *Worker) System() string { return System }

// Test posts a test message.
func (w *Worker) Test(ctx context.Context, r integrations.Resolved) error {
	return w.post(ctx, r, "Fortik: connection test. Security alerts and owner notifications will be posted here.")
}

// Run sends pending alerts until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		if _, err := w.Pass(ctx); err != nil && ctx.Err() == nil {
			w.log.Warn("notify: pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type pending struct {
	id, kind, severity, agentID, summary, owner, actionID string
	count, attempts                                       int
}

// Pass sends up to one batch of pending alerts; it returns how many were
// posted. Not configured: nothing to do.
func (w *Worker) Pass(ctx context.Context) (int, error) {
	r, err := w.src.Get(ctx, System)
	if errors.Is(err, integrations.ErrNotConfigured) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	minRank := sevRank[r.Text("min_severity")]
	kinds := r.Strings("kinds")
	consoleURL := strings.TrimRight(r.Text("console_url"), "/")
	sent := 0
	err = pgx.BeginFunc(ctx, w.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT a.alert_id, a.kind, a.severity, COALESCE(a.agent_id, ''), a.summary, COALESCE(g.sponsor, ''),
			COALESCE(a.action_id, ''), a.count, a.notify_attempts
			FROM alerts a LEFT JOIN agents g ON g.agent_id = a.agent_id
			WHERE a.notified_at IS NULL AND a.created_at >= $1
			ORDER BY a.created_at LIMIT $2 FOR UPDATE OF a SKIP LOCKED`, r.UpdatedAt, batch)
		if err != nil {
			return err
		}
		var list []pending
		for rows.Next() {
			var p pending
			if err := rows.Scan(&p.id, &p.kind, &p.severity, &p.agentID, &p.summary, &p.owner, &p.actionID, &p.count, &p.attempts); err != nil {
				rows.Close()
				return err
			}
			list = append(list, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, p := range list {
			status, done := "", true
			switch {
			case sevRank[p.severity] < minRank:
				status = "skipped: below min_severity"
			case len(kinds) > 0 && !slices.Contains(kinds, p.kind):
				status = "skipped: kind not selected"
			default:
				if perr := w.post(ctx, r, message(p, consoleURL)); perr != nil {
					status = "failed: " + clip(perr.Error(), 200)
					done = p.attempts+1 >= maxAttempts
				} else {
					status = "sent"
					sent++
				}
			}
			q := `UPDATE alerts SET notify_attempts = notify_attempts + 1, notify_status = $2 WHERE alert_id = $1`
			if done {
				q = `UPDATE alerts SET notify_attempts = notify_attempts + 1, notify_status = $2, notified_at = now() WHERE alert_id = $1`
			}
			if _, err := tx.Exec(ctx, q, p.id, status); err != nil {
				return err
			}
		}
		return nil
	})
	return sent, err
}

// message is the Slack text: severity, kind, summary, agent and owner, and
// where to look. Alert summaries never contain secrets or payloads.
func message(p pending, consoleURL string) string {
	owner := p.owner
	if owner == "" {
		owner = "none"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*Fortik %s* · %s\n%s", strings.ToUpper(p.severity), p.kind, p.summary)
	if p.count > 1 {
		fmt.Fprintf(&b, " (x%d)", p.count)
	}
	if p.agentID != "" {
		fmt.Fprintf(&b, "\nAgent: %s · Owner: %s", p.agentID, owner)
	}
	if consoleURL != "" {
		if p.agentID != "" {
			fmt.Fprintf(&b, "\n%s/agents/%s", consoleURL, url.PathEscape(p.agentID))
		} else {
			fmt.Fprintf(&b, "\n%s/alerts", consoleURL)
		}
	}
	return clip(b.String(), maxText)
}

func (w *Worker) post(ctx context.Context, r integrations.Resolved, text string) error {
	hook := r.Secret("webhook_url")
	u, err := url.Parse(hook)
	if hook == "" || err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("notify_slack: webhook URL not set or invalid (re-enter it in Integrations)")
	}
	body, _ := json.Marshal(map[string]string{"text": text})
	ctx, cancel := context.WithTimeout(ctx, postTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("notify_slack: cannot build request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fortik-Notify/1")
	resp, err := w.client.Do(req)
	if err != nil {
		// Never echo the URL: a Slack webhook URL is itself the secret.
		return fmt.Errorf("notify_slack: post to %s failed", u.Host)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notify_slack: %s replied HTTP %d", u.Host, resp.StatusCode)
	}
	return nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
