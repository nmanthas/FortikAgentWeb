package queues

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fortik/internal/integrations"
)

// Webhook request headers and limits.
const (
	SignatureHeader = "X-Fortik-Signature" // "sha256=" + hex(HMAC-SHA256(secret, body))
	DeliveryHeader  = "X-Fortik-Delivery"  // random id per request (receivers may de-duplicate)
	signaturePrefix = "sha256="

	// WebhookTimeout bounds one webhook call.
	WebhookTimeout = 10 * time.Second

	webhookTestAction = "test"
	maxWebhookReply   = 64 << 10
)

// WebhookPayload is the JSON body Fortik POSTs to the queue webhook.
type WebhookPayload struct {
	Action  string `json:"action"`   // pause | resume | cancel | test
	AgentID string `json:"agent_id"` // empty for "test"
	Reason  string `json:"reason"`
	TS      string `json:"ts"` // RFC 3339, UTC
}

// SignWebhook returns the X-Fortik-Signature value for body.
func SignWebhook(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return signaturePrefix + hex.EncodeToString(m.Sum(nil))
}

// VerifyWebhook reports whether header is the valid signature of body
// (constant time). Receivers written in Go can use it directly.
func VerifyWebhook(secret string, body []byte, header string) bool {
	got, ok := strings.CutPrefix(strings.TrimSpace(header), signaturePrefix)
	if !ok {
		return false
	}
	sig, err := hex.DecodeString(got)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hmac.Equal(sig, m.Sum(nil))
}

// Webhook is the generic queue adapter: it tells the customer's endpoint to
// pause, resume or cancel an agent's work. A 2xx reply is done; anything
// else, a redirect, a timeout or a network error is a failed step. What the
// receiver really did is up to the receiver; a JSON reply {"affected": n}
// is reported as the count.
type Webhook struct {
	src    integrations.Source
	client *http.Client
	now    func() time.Time
}

var (
	_ Adapter             = (*Webhook)(nil)
	_ integrations.Tester = (*Webhook)(nil)
)

// NewWebhook builds the adapter. Redirects are never followed (the signed
// request must reach exactly the configured endpoint).
func NewWebhook(src integrations.Source) *Webhook {
	return &Webhook{
		src: src,
		client: &http.Client{
			Timeout:       WebhookTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (*Webhook) System() string { return SystemWebhook }

func (w *Webhook) Pause(ctx context.Context, agentID, reason string) (Result, error) {
	return w.run(ctx, "pause", agentID, reason)
}

func (w *Webhook) Resume(ctx context.Context, agentID, reason string) (Result, error) {
	return w.run(ctx, "resume", agentID, reason)
}

func (w *Webhook) Cancel(ctx context.Context, agentID, reason string) (Result, error) {
	return w.run(ctx, "cancel", agentID, reason)
}

// Test sends a signed {"action":"test"} request; receivers should reply
// 2xx without acting on any agent.
func (w *Webhook) Test(ctx context.Context, r integrations.Resolved) error {
	_, err := w.post(ctx, r, WebhookPayload{Action: webhookTestAction, Reason: "Fortik connection test"})
	return err
}

func (w *Webhook) run(ctx context.Context, action, agentID, reason string) (Result, error) {
	res := Result{System: SystemWebhook}
	if err := checkAgentID(agentID); err != nil {
		return res, err
	}
	r, err := resolve(ctx, w.src, SystemWebhook)
	if err != nil {
		return res, err
	}
	reply, err := w.post(ctx, r, WebhookPayload{Action: action, AgentID: agentID, Reason: cleanReason(reason)})
	if err != nil {
		res.Detail = fmt.Sprintf("queue webhook did not confirm %s: %v", action, err)
		return res, err
	}
	res.Affected = reply.affected
	res.Detail = fmt.Sprintf("queue webhook acknowledged %s (HTTP %d)", action, reply.status)
	if reply.hasCount {
		res.Detail += fmt.Sprintf("; receiver reported %s affected", plural(reply.affected, "job", "jobs"))
	} else {
		res.Detail += "; what was affected is up to the receiver (it reported no count)"
	}
	if action == "cancel" {
		res.Detail += "; cancellation is not reversible"
	}
	return res, nil
}

type webhookReply struct {
	status   int
	affected int
	hasCount bool
}

func (w *Webhook) post(ctx context.Context, r integrations.Resolved, p WebhookPayload) (webhookReply, error) {
	endpoint := r.Text("url")
	secret := r.Secret("secret")
	if secret == "" {
		return webhookReply{}, fmt.Errorf("%w: queue_webhook: signing secret not set", ErrNotConfigured)
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		// Validated when saved; refuse anything else rather than send.
		return webhookReply{}, errors.New("queue_webhook: configured URL is not a valid http(s) URL")
	}
	p.TS = w.now().Format(time.RFC3339)
	body, err := json.Marshal(p)
	if err != nil {
		return webhookReply{}, fmt.Errorf("queue_webhook: encode: %w", err)
	}
	var id [12]byte
	_, _ = rand.Read(id[:])

	ctx, cancel := context.WithTimeout(ctx, WebhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return webhookReply{}, errors.New("queue_webhook: cannot build request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Fortik-Queue-Webhook/1")
	req.Header.Set(SignatureHeader, SignWebhook(secret, body))
	req.Header.Set(DeliveryHeader, hex.EncodeToString(id[:]))
	resp, err := w.client.Do(req)
	if err != nil {
		return webhookReply{}, fmt.Errorf("request to %s failed: %s", redactURL(u), describeHTTPError(err))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxWebhookReply))
	out := webhookReply{status: resp.StatusCode}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return out, fmt.Errorf("%s replied HTTP %d (want 2xx)", redactURL(u), resp.StatusCode)
	}
	var reply struct {
		Affected *int `json:"affected"`
	}
	if json.Unmarshal(raw, &reply) == nil && reply.Affected != nil && *reply.Affected >= 0 {
		out.affected, out.hasCount = *reply.Affected, true
	}
	return out, nil
}

// redactURL is scheme://host/path (no query; the URL never has userinfo).
func redactURL(u *url.URL) string {
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
}

func describeHTTPError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("no reply within %s", WebhookTimeout)
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return fmt.Sprintf("no reply within %s", WebhookTimeout)
		}
		return ue.Err.Error()
	}
	return err.Error()
}
