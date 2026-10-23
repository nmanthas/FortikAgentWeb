package queues

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"fortik/internal/integrations"
)

// System names (integration keys).
const (
	SystemTemporal = integrations.SystemTemporal
	SystemCelery   = integrations.SystemCelery
	SystemWebhook  = integrations.SystemQueueWebhook
)

// maxReasonLen caps the reason text sent to queue systems (it is a human
// summary; queue systems store it in notes, memos and webhook bodies).
const maxReasonLen = 500

// agentIDPattern matches Fortik agent ids (same pattern as the API). Agent
// ids are interpolated into Temporal visibility queries and Redis keys, so
// anything else is refused before any call is made.
var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)

func checkAgentID(agentID string) error {
	if !agentIDPattern.MatchString(agentID) {
		return fmt.Errorf("queues: invalid agent id")
	}
	return nil
}

// cleanReason flattens control characters and caps the length.
func cleanReason(reason string) string {
	reason = strings.Join(strings.FieldsFunc(reason, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}), " ")
	if len(reason) > maxReasonLen {
		cut := maxReasonLen
		for cut > 0 && reason[cut]&0xC0 == 0x80 {
			cut--
		}
		reason = reason[:cut] + "..."
	}
	return reason
}

// resolve reads the settings of one queue integration. Only a missing or
// unconfigured integration is ErrNotConfigured (containment records the
// step as skipped). A configured integration whose required secret is
// missing is ErrSecretMissing, which containment records as failed: the
// customer uses that queue system and nothing was done to it.
func resolve(ctx context.Context, src integrations.Source, key string) (integrations.Resolved, error) {
	if src == nil {
		return integrations.Resolved{}, fmt.Errorf("%w: %s", ErrNotConfigured, key)
	}
	r, err := src.Get(ctx, key)
	if errors.Is(err, integrations.ErrSecretMissing) {
		// Checked first: it also wraps integrations.ErrNotConfigured. The
		// message names the system only (never secret values).
		return integrations.Resolved{}, fmt.Errorf("%s: %w (re-enter it in Integrations); nothing was done", key, ErrSecretMissing)
	}
	if errors.Is(err, integrations.ErrNotConfigured) {
		return integrations.Resolved{}, fmt.Errorf("%w: %s", ErrNotConfigured, key)
	}
	if err != nil {
		return integrations.Resolved{}, fmt.Errorf("queues: read %s settings: %w", key, err)
	}
	return r, nil
}

// forEach runs fn over items with at most n in flight and returns the
// per-item errors (nil where fn succeeded), in item order.
func forEach[T any](ctx context.Context, n int, items []T, fn func(context.Context, T) error) []error {
	errs := make([]error, len(items))
	sem := make(chan struct{}, max(n, 1))
	var wg sync.WaitGroup
	for i, it := range items {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			for j := i; j < len(items); j++ {
				errs[j] = ctx.Err()
			}
			wg.Wait()
			return errs
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			errs[i] = fn(ctx, it)
		}()
	}
	wg.Wait()
	return errs
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Set is the three queue adapters sharing one settings source.
type Set struct {
	Temporal *Temporal
	Celery   *Celery
	Webhook  *Webhook
}

// New builds every queue adapter. Each reads its integration on every call,
// so settings changed in the console apply without a restart; an absent
// integration makes its operations return ErrNotConfigured.
func New(src integrations.Source, log *slog.Logger) Set {
	return Set{
		Temporal: NewTemporal(src, log),
		Celery:   NewCelery(src),
		Webhook:  NewWebhook(src),
	}
}

// Adapters returns the adapters in the order containment runs them.
func (s Set) Adapters() []Adapter {
	return []Adapter{s.Temporal, s.Celery, s.Webhook}
}

// RegisterTesters adds the three connection testers to the integrations
// registry (the console's "Test connection").
func (s Set) RegisterTesters(reg *integrations.Registry) error {
	for _, t := range []integrations.Tester{s.Temporal, s.Celery, s.Webhook} {
		if err := reg.Register(t); err != nil {
			return err
		}
	}
	return nil
}
