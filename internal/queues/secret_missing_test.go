package queues

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
)

func cfgRaw(m map[string]any) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for k, v := range m {
		b, _ := json.Marshal(v)
		out[k] = b
	}
	return out
}

// F20: through the real integrations store, a configured queue integration
// whose required secret was lost from the secret store fails (a distinct
// error that is NOT ErrNotConfigured, so containment records the step as
// failed instead of "not configured: nothing to cancel"). Only a missing row
// is ErrNotConfigured.
func TestQueueSecretMissingIsNotNotConfigured(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	sec, err := secrets.NewEncFile(filepath.Join(t.TempDir(), "secrets"), k)
	if err != nil {
		t.Fatal(err)
	}
	store := integrations.NewPGStore(pool, diary.New(pool), sec)
	ctx := context.Background()
	set := New(store, nil)

	// No rows at all: honest "not configured" (skipped) for every adapter.
	for _, a := range set.Adapters() {
		if _, err := a.Cancel(ctx, "agent-1", "r"); !errors.Is(err, ErrNotConfigured) || errors.Is(err, ErrSecretMissing) {
			t.Errorf("%s without a row: %v", a.System(), err)
		}
	}

	const redisURL = "redis://:f20-redis-password@127.0.0.1:1/0"
	const hookSecret = "f20-webhook-signing-secret-0123456789"
	str := func(s string) *string { return &s }
	for key, in := range map[string]integrations.ConfigureInput{
		SystemCelery:  {Config: cfgRaw(map[string]any{"queues": []string{"celery"}}), Secrets: map[string]*string{"redis_url": str(redisURL)}},
		SystemWebhook: {Config: cfgRaw(map[string]any{"url": "https://jobs.example.com/hook"}), Secrets: map[string]*string{"secret": str(hookSecret)}},
	} {
		if _, err := store.Configure(ctx, key, in, "sec@example.com"); err != nil {
			t.Fatalf("configure %s: %v", key, err)
		}
	}
	// The secrets disappear behind Fortik's back (secret-store loss).
	for _, n := range []string{integrations.SecretName(SystemCelery, "redis_url"), integrations.SecretName(SystemWebhook, "secret")} {
		if err := sec.Delete(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []Adapter{set.Celery, set.Webhook} {
		for name, op := range map[string]func(context.Context, string, string) (Result, error){"pause": a.Pause, "resume": a.Resume, "cancel": a.Cancel} {
			_, err := op(ctx, "agent-1", "r")
			if err == nil || errors.Is(err, ErrNotConfigured) || !errors.Is(err, ErrSecretMissing) {
				t.Errorf("%s %s with its secret lost: %v", a.System(), name, err)
				continue
			}
			if msg := err.Error(); strings.Contains(msg, "f20-redis-password") || strings.Contains(msg, hookSecret) {
				t.Errorf("%s %s error leaks a secret: %s", a.System(), name, msg)
			}
		}
	}
}
