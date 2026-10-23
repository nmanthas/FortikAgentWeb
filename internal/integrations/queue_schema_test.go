package integrations

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestQueueKeys(t *testing.T) {
	for _, key := range []string{SystemTemporal, SystemCelery, SystemQueueWebhook} {
		sys, err := ParseKey(key)
		if err != nil || sys != key {
			t.Errorf("ParseKey(%q) = %q, %v", key, sys, err)
		}
		if _, ok := SchemaFor(key); !ok {
			t.Errorf("no schema for %s", key)
		}
	}
	for _, key := range []string{"temporal:x", "celery:a", "queue_webhook:a", "Temporal", "queue-webhook", "webhook"} {
		if _, err := ParseKey(key); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseKey(%q) accepted", key)
		}
	}
	if n := SecretName(SystemCelery, "redis_url"); n != "integration/celery/redis_url" {
		t.Error(n)
	}
}

func TestQueueSchemaDefaults(t *testing.T) {
	tmp, _ := SchemaFor(SystemTemporal)
	out, err := normalizeConfig(tmp, raw(map[string]any{"host_port": " temporal.internal:7233 "}))
	if err != nil {
		t.Fatal(err)
	}
	if out["host_port"] != "temporal.internal:7233" || out["namespace"] != "default" || out["tls"] != false {
		t.Errorf("temporal defaults: %v", out)
	}
	out, err = normalizeConfig(tmp, raw(map[string]any{"host_port": "[::1]:7233", "namespace": "acme.prod-1", "tls": true}))
	if err != nil || out["tls"] != true || out["namespace"] != "acme.prod-1" {
		t.Errorf("temporal: %v %v", out, err)
	}

	cel, _ := SchemaFor(SystemCelery)
	out, err = normalizeConfig(cel, raw(map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	q, _ := out["queues"].([]string)
	if !slices.Equal(q, []string{"celery"}) {
		t.Errorf("celery default queues: %v", out)
	}
	// The default is copied: changing one result must not change the next.
	q[0] = "mutated"
	out, _ = normalizeConfig(cel, raw(map[string]any{}))
	if got := out["queues"].([]string); got[0] != "celery" {
		t.Fatal("default list shared between calls")
	}
	s := Schemas()
	for i := range s {
		if s[i].System == SystemCelery {
			s[i].Fields[0].Default.([]string)[0] = "mutated"
		}
	}
	if f, _ := fieldByKey(mustSchema(t, SystemCelery), "queues"); f.Default.([]string)[0] != "celery" {
		t.Fatal("Schemas returned a shared default list")
	}
	out, err = normalizeConfig(cel, raw(map[string]any{"queues": []string{"emails", " reports ", "emails", "agents:high"}}))
	if err != nil || !slices.Equal(out["queues"].([]string), []string{"emails", "reports", "agents:high"}) {
		t.Errorf("celery queues: %v %v", out, err)
	}

	wh, _ := SchemaFor(SystemQueueWebhook)
	out, err = normalizeConfig(wh, raw(map[string]any{"url": "https://jobs.example.com/fortik/queue"}))
	if err != nil || out["url"] != "https://jobs.example.com/fortik/queue" {
		t.Errorf("webhook: %v %v", out, err)
	}
}

func mustSchema(t *testing.T, sys string) Schema {
	t.Helper()
	s, ok := SchemaFor(sys)
	if !ok {
		t.Fatalf("no schema %s", sys)
	}
	return s
}

func TestQueueSchemaRejects(t *testing.T) {
	cases := []struct {
		sys  string
		cfg  map[string]any
		want string
	}{
		{SystemTemporal, map[string]any{}, "required"},
		{SystemTemporal, map[string]any{"host_port": "temporal.internal"}, "host:port"},
		{SystemTemporal, map[string]any{"host_port": "temporal.internal:0"}, "port"},
		{SystemTemporal, map[string]any{"host_port": "temporal.internal:99999"}, "port"},
		{SystemTemporal, map[string]any{"host_port": "bad host:7233"}, "hostname"},
		{SystemTemporal, map[string]any{"host_port": "t:7233", "namespace": "bad ns"}, "namespace"},
		{SystemTemporal, map[string]any{"host_port": "t:7233", "tls": "yes"}, "true or false"},
		{SystemTemporal, map[string]any{"host_port": "t:7233", "api_key": "k"}, "secret field"},
		{SystemCelery, map[string]any{"queues": []string{}}, "at least one queue"},
		{SystemCelery, map[string]any{"queues": []string{"ok", "bad queue"}}, "queue names"},
		{SystemCelery, map[string]any{"queues": []string{"pri\x06\x163"}}, "queue names"},
		{SystemCelery, map[string]any{"queues": "celery"}, "list"},
		{SystemCelery, map[string]any{"redis_url": "redis://x"}, "secret field"},
		{SystemQueueWebhook, map[string]any{}, "required"},
		{SystemQueueWebhook, map[string]any{"url": "http://jobs.example.com/hook"}, "https"},
		{SystemQueueWebhook, map[string]any{"url": "https://user:pw@jobs.example.com/hook"}, "credentials"},
		{SystemQueueWebhook, map[string]any{"url": "https://jobs.example.com/hook?token=x"}, "query"},
		{SystemQueueWebhook, map[string]any{"url": "https://jobs.example.com", "secret": "x"}, "secret field"},
	}
	for _, c := range cases {
		_, err := normalizeConfig(mustSchema(t, c.sys), raw(c.cfg))
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v: err = %v, want %q", c.sys, c.cfg, err, c.want)
		}
	}
	// Loopback http is accepted for local receivers and tests.
	if _, err := normalizeConfig(mustSchema(t, SystemQueueWebhook), raw(map[string]any{"url": "http://127.0.0.1:8081/hook"})); err != nil {
		t.Error(err)
	}
}

func TestQueueSecrets(t *testing.T) {
	const pw = "s3cr3t-Redis-pass"
	ok := []struct {
		sys, field, val, want string
	}{
		{SystemCelery, "redis_url", " redis://:" + pw + "@redis.internal:6379/2 ", "redis://:" + pw + "@redis.internal:6379/2"},
		{SystemCelery, "redis_url", "rediss://default:" + pw + "@10.0.0.5", ""},
		{SystemCelery, "redis_url", "redis://127.0.0.1:6379", ""},
		{SystemTemporal, "api_key", "  eyJhbGciOiJFUzI1NiJ9.payload.sig  ", "eyJhbGciOiJFUzI1NiJ9.payload.sig"},
		{SystemQueueWebhook, "secret", "0123456789abcdef-long-enough", ""},
	}
	for _, c := range ok {
		set, _, err := validateSecrets(mustSchema(t, c.sys), map[string]*string{c.field: strp(c.val)})
		if err != nil {
			t.Errorf("%s.%s: %v", c.sys, c.field, err)
			continue
		}
		if c.want != "" && set[c.field] != c.want {
			t.Errorf("%s.%s normalised to %q", c.sys, c.field, set[c.field])
		}
	}
	bad := []struct {
		sys, field, val, want string
	}{
		{SystemCelery, "redis_url", "http://:" + pw + "@redis:6379/0", "redis://"},
		{SystemCelery, "redis_url", "redis://:" + pw + "@redis:6379/0?dial_timeout=1s", "query"},
		{SystemCelery, "redis_url", "redis://:" + pw + "@redis:6379/zero", "database number"},
		{SystemCelery, "redis_url", "redis://:" + pw + "@redis:70000/0", "port"},
		{SystemCelery, "redis_url", "redis://:" + pw + "@/0", "Redis URL"},
		{SystemCelery, "redis_url", "unix:///tmp/" + pw + ".sock", "Redis URL"},
		{SystemCelery, "redis_url", "redis://:" + pw + "@bad host:6379", "Redis URL"},
		{SystemTemporal, "api_key", "short", "API key"},
		{SystemTemporal, "api_key", "has spaces " + pw, "API key"},
		{SystemQueueWebhook, "secret", "too-short", "16-1024"},
		{SystemQueueWebhook, "secret", pw + "\x01control", "16-1024"},
	}
	for _, c := range bad {
		_, _, err := validateSecrets(mustSchema(t, c.sys), map[string]*string{c.field: strp(c.val)})
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s.%s %q: err = %v, want %q", c.sys, c.field, c.val, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), pw) {
			t.Errorf("%s.%s: error echoes the secret: %v", c.sys, c.field, err)
		}
	}
	// api_key is optional (removable); the others are required.
	if _, rm, err := validateSecrets(mustSchema(t, SystemTemporal), map[string]*string{"api_key": nil}); err != nil || len(rm) != 1 {
		t.Errorf("remove api_key: %v %v", rm, err)
	}
	for _, c := range [][2]string{{SystemCelery, "redis_url"}, {SystemQueueWebhook, "secret"}} {
		if _, _, err := validateSecrets(mustSchema(t, c[0]), map[string]*string{c[1]: nil}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s.%s removable", c[0], c[1])
		}
	}
}

// TestQueueIntegrationsStore configures each queue integration through the
// real store and reads it back the way adapters do.
func TestQueueIntegrationsStore(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const redisURL = "redis://:queue-test-password@127.0.0.1:6379/3"
	const hookSecret = "webhook-signing-secret-0123456789"
	const apiKey = "temporal-api-key-0123456789"
	steps := []struct {
		key string
		in  ConfigureInput
	}{
		{SystemTemporal, ConfigureInput{Config: raw(map[string]any{"host_port": "temporal.internal:7233", "tls": true}), Secrets: map[string]*string{"api_key": strp(apiKey)}}},
		{SystemCelery, ConfigureInput{Config: raw(map[string]any{"queues": []string{"celery", "agents"}}), Secrets: map[string]*string{"redis_url": strp(redisURL)}}},
		{SystemQueueWebhook, ConfigureInput{Config: raw(map[string]any{"url": "https://jobs.example.com/hook"}), Secrets: map[string]*string{"secret": strp(hookSecret)}}},
	}
	for _, s := range steps {
		if _, err := f.store.Configure(ctx, s.key, s.in, "sec@example.com"); err != nil {
			t.Fatalf("configure %s: %v", s.key, err)
		}
	}
	tr, err := f.store.Get(ctx, SystemTemporal)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Text("host_port") != "temporal.internal:7233" || tr.Text("namespace") != "default" || !tr.Bool("tls") || tr.Secret("api_key") != apiKey {
		t.Errorf("temporal resolved: %v %v", tr.ConfigMap, tr.SecretFields)
	}
	cr, err := f.store.Get(ctx, SystemCelery)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cr.Strings("queues"), []string{"celery", "agents"}) || cr.Secret("redis_url") != redisURL {
		t.Errorf("celery resolved: %v", cr.ConfigMap)
	}
	wr, err := f.store.Get(ctx, SystemQueueWebhook)
	if err != nil {
		t.Fatal(err)
	}
	if wr.Text("url") != "https://jobs.example.com/hook" || wr.Secret("secret") != hookSecret {
		t.Errorf("webhook resolved: %v", wr.ConfigMap)
	}
	text := allDBText(t, f.pool)
	for _, secret := range []string{"queue-test-password", hookSecret, apiKey} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q stored in the database", secret)
		}
	}
	if len(diaryBodies(t, f.diary, EventConfigured)) != 3 {
		t.Error("each configure must write a Diary event")
	}
	// Deleting returns them to "not configured" for the adapters.
	if err := f.store.Delete(ctx, SystemCelery, "sec@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Resolve(ctx, SystemCelery); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("after delete: %v", err)
	}
}

// F20: a configured integration whose required secret is gone from the
// secret store is ErrSecretMissing (distinct, so queue containment can fail
// the step), while a missing row is plain ErrNotConfigured.
func TestResolveSecretMissingIsDistinctFromNotConfigured(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.store.Resolve(ctx, SystemCelery); !errors.Is(err, ErrNotConfigured) || errors.Is(err, ErrSecretMissing) {
		t.Fatalf("no row: %v", err)
	}
	in := ConfigureInput{Config: raw(map[string]any{"queues": []string{"celery"}}), Secrets: map[string]*string{"redis_url": strp("redis://:pw-f20@127.0.0.1:6379/0")}}
	if _, err := f.store.Configure(ctx, SystemCelery, in, "sec@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Get(ctx, SystemCelery); err != nil {
		t.Fatal(err)
	}
	if err := f.sec.Delete(ctx, SecretName(SystemCelery, "redis_url")); err != nil {
		t.Fatal(err)
	}
	f.store.invalidate()
	for name, get := range map[string]func(context.Context, string) (Resolved, error){"resolve": f.store.Resolve, "get": f.store.Get} {
		_, err := get(ctx, SystemCelery)
		if !errors.Is(err, ErrSecretMissing) || !strings.Contains(err.Error(), "redis_url") || strings.Contains(err.Error(), "pw-f20") {
			t.Errorf("%s with the secret lost: %v", name, err)
		}
		// Still "not usable" for callers that only check ErrNotConfigured.
		if !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%s: ErrSecretMissing must wrap ErrNotConfigured: %v", name, err)
		}
	}
}

func TestBrokenReportsConfiguredIntegrationsWithMissingSecrets(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if b, err := f.store.Broken(ctx, SystemCelery); err != nil || len(b) != 0 {
		t.Fatalf("no row: %v %v", b, err)
	}
	in := ConfigureInput{Config: raw(map[string]any{"queues": []string{"celery"}}), Secrets: map[string]*string{"redis_url": strp("redis://:pw@127.0.0.1:6379/0")}}
	if _, err := f.store.Configure(ctx, SystemCelery, in, "sec@example.com"); err != nil {
		t.Fatal(err)
	}
	if b, err := f.store.Broken(ctx, SystemCelery); err != nil || len(b) != 0 {
		t.Fatalf("healthy: %v %v", b, err)
	}
	if err := f.sec.Delete(ctx, SecretName(SystemCelery, "redis_url")); err != nil {
		t.Fatal(err)
	}
	f.store.invalidate()
	b, err := f.store.Broken(ctx, SystemCelery)
	if err != nil || len(b) != 1 || b[0] != SystemCelery {
		t.Fatalf("secret lost: %v %v", b, err)
	}
	if l, err := f.store.List(ctx, SystemCelery); err != nil || len(l) != 0 {
		t.Fatalf("List still skips it: %v %v", l, err)
	}
}
