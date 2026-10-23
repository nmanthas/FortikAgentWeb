package integrations

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"fortik/internal/diary"
	"fortik/internal/secrets"
)

const actor = "user:sec@example.com"

func awsInput(secret string) ConfigureInput {
	return ConfigureInput{
		Config: raw(map[string]any{"region": "eu-west-1", "role_arn": "arn:aws:iam::123456789012:role/fortik-agents"}),
		Secrets: map[string]*string{
			"access_key_id":     strp("AKIAIOSFODNN7EXAMPLE"),
			"secret_access_key": strp(secret),
		},
	}
}

func TestConfigureResolveDelete(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const secret1 = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	if _, err := f.store.Get(ctx, "aws"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("unconfigured: %v", err)
	}
	in, err := f.store.Configure(ctx, "aws", awsInput(secret1), actor)
	if err != nil {
		t.Fatal(err)
	}
	if in.Status != StatusConfigured || in.UpdatedBy != actor || strings.Join(in.SecretFields, ",") != "access_key_id,secret_access_key" {
		t.Fatalf("row: %+v", in)
	}
	// Secrets live only in the store.
	v, err := f.sec.Get(ctx, "integration/aws/secret_access_key")
	if err != nil || string(v) != secret1 {
		t.Fatalf("store: %q %v", v, err)
	}
	if strings.Contains(allDBText(t, f.pool), secret1) || strings.Contains(allDBText(t, f.pool), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("secret value found in Postgres")
	}

	r, err := f.store.Get(ctx, "aws")
	if err != nil {
		t.Fatal(err)
	}
	if r.Secrets["secret_access_key"] != secret1 || r.Text("region") != "eu-west-1" || r.System != SystemAWS {
		t.Fatalf("resolved: %v %v", r, r.ConfigMap)
	}
	// Callers cannot corrupt the cache.
	r.Secrets["secret_access_key"] = "mutated"
	r.ConfigMap["region"] = "mutated"
	if r2, _ := f.store.Get(ctx, "aws"); r2.Secrets["secret_access_key"] != secret1 || r2.Text("region") != "eu-west-1" {
		t.Fatal("cache shared with caller")
	}

	// Diary: config, field names and fingerprints only.
	ev := diaryBodies(t, f.diary, EventConfigured)
	if len(ev) != 1 {
		t.Fatalf("%d configured events", len(ev))
	}
	changed := ev[0]["secrets_changed"].(map[string]any)
	if changed["secret_access_key"] != Fingerprint(secret1) || ev[0]["created"] != true {
		t.Fatalf("diary event: %v", ev[0])
	}

	// Update config only: secrets kept, fingerprint list empty, previous config recorded.
	upd := awsInput("")
	upd.Secrets = nil
	upd.Config = raw(map[string]any{"region": "us-west-2", "role_arn": "arn:aws:iam::123456789012:role/fortik-agents"})
	if _, err := f.store.Configure(ctx, "aws", upd, actor); err != nil {
		t.Fatal(err)
	}
	r, _ = f.store.Get(ctx, "aws") // same instance: invalidated immediately
	if r.Text("region") != "us-west-2" || r.Secrets["secret_access_key"] != secret1 {
		t.Fatalf("after config-only update: %v", r.ConfigMap)
	}
	ev = diaryBodies(t, f.diary, EventConfigured)
	if kept := fmt.Sprint(ev[1]["secrets_kept"]); kept != "[access_key_id secret_access_key]" || len(ev[1]["secrets_changed"].(map[string]any)) != 0 {
		t.Fatalf("second event: %v", ev[1])
	}
	if ev[1]["previous_config"].(map[string]any)["region"] != "eu-west-1" {
		t.Fatalf("previous config: %v", ev[1])
	}

	// Optional secret set, then removed with null.
	withExt := upd
	withExt.Secrets = map[string]*string{"external_id": strp("ext-id-123")}
	if _, err := f.store.Configure(ctx, "aws", withExt, actor); err != nil {
		t.Fatal(err)
	}
	if r, _ := f.store.Get(ctx, "aws"); r.Secrets["external_id"] != "ext-id-123" {
		t.Fatal("external_id not set")
	}
	withExt.Secrets = map[string]*string{"external_id": nil}
	in, err = f.store.Configure(ctx, "aws", withExt, actor)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(in.SecretFields, ","), "external_id") {
		t.Fatal("external_id still listed")
	}
	if _, err := f.sec.Get(ctx, "integration/aws/external_id"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("external_id not deleted from the store: %v", err)
	}

	// Validation failures change nothing.
	bad := awsInput("")
	if _, err := f.store.Configure(ctx, "aws", bad, actor); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty secret: %v", err)
	}
	if _, err := f.store.Configure(ctx, "github", ConfigureInput{Config: raw(map[string]any{"app_id": "1", "installation_id": "2"})}, actor); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "private_key_pem") {
		t.Fatalf("new integration without its required secret: %v", err)
	}

	// Delete removes secrets, row, and records it.
	if err := f.store.Delete(ctx, "aws", actor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Get(ctx, "aws"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("after delete: %v", err)
	}
	for _, field := range []string{"access_key_id", "secret_access_key", "external_id"} {
		if _, err := f.sec.Get(ctx, SecretName("aws", field)); !errors.Is(err, secrets.ErrNotFound) {
			t.Fatalf("%s survived delete: %v", field, err)
		}
	}
	if err := f.store.Delete(ctx, "aws", actor); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("second delete: %v", err)
	}
	if ev := diaryBodies(t, f.diary, EventDeleted); len(ev) != 1 || ev[0]["key"] != "aws" {
		t.Fatalf("deleted events: %v", ev)
	}
	if strings.Contains(allDBText(t, f.pool), secret1) || strings.Contains(allDBText(t, f.pool), "ext-id-123") {
		t.Fatal("secret value found in Postgres")
	}
	rep, err := f.diary.VerifyChain(ctx)
	if err != nil || !rep.OK {
		t.Fatalf("diary chain: %+v %v", rep, err)
	}
}

func TestMissingSecretIsNotConfigured(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	in := ConfigureInput{
		Config:  raw(map[string]any{"host": "127.0.0.1", "database": "acme", "environment": "staging", "admin_user": "fortik_admin", "read_role": "r", "write_role": "w"}),
		Secrets: map[string]*string{"admin_password": strp("pw-123456")},
	}
	if _, err := f.store.Configure(ctx, "postgres:acme_staging", in, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Configure(ctx, "postgres:acme_prod", in, actor); err != nil {
		t.Fatal(err)
	}
	list, err := f.store.List(ctx, SystemPostgres)
	if err != nil || len(list) != 2 || list[0].Name() != "acme_prod" || list[0].Int("port") != 5432 {
		t.Fatalf("list: %v %v", list, err)
	}
	// Someone removes a secret behind Fortik's back: fail closed.
	if err := f.sec.Delete(ctx, "integration/postgres/acme_prod/admin_password"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Resolve(ctx, "postgres:acme_prod"); !errors.Is(err, ErrNotConfigured) || !strings.Contains(err.Error(), "admin_password") {
		t.Fatalf("missing secret: %v", err)
	}
	f.store.invalidate()
	list, err = f.store.List(ctx, SystemPostgres)
	if err != nil || len(list) != 1 || list[0].Key != "postgres:acme_staging" {
		t.Fatalf("list must skip the incomplete upstream: %v %v", list, err)
	}
	// Re-saving without the secret refuses (it would claim a secret it lacks).
	in.Secrets = nil
	if _, err := f.store.Configure(ctx, "postgres:acme_prod", in, actor); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "missing from the secret store") {
		t.Fatalf("configure with a lost secret: %v", err)
	}
	if _, err := f.store.List(ctx, "gmail"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown system: %v", err)
	}
	// A secret the master key cannot decrypt is an error, not "not configured".
	wrongKey := NewPGStore(f.pool, f.diary, newEncStore(t, f.secDir))
	if _, err := wrongKey.Resolve(ctx, "postgres:acme_staging"); err == nil || errors.Is(err, ErrNotConfigured) || !errors.Is(err, secrets.ErrDecrypt) {
		t.Fatalf("wrong master key: %v", err)
	}
}

func TestCacheAcrossProcesses(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	other := NewPGStore(f.pool, f.diary, f.sec) // a second Fortik process
	if _, err := f.store.Configure(ctx, "aws", awsInput("first-secret-value-123"), actor); err != nil {
		t.Fatal(err)
	}
	if r, err := other.Get(ctx, "aws"); err != nil || r.Secrets["secret_access_key"] != "first-secret-value-123" {
		t.Fatalf("other: %v", err)
	}
	if _, err := f.store.Configure(ctx, "aws", awsInput("second-secret-value-456"), actor); err != nil {
		t.Fatal(err)
	}
	if r, _ := f.store.Get(ctx, "aws"); r.Secrets["secret_access_key"] != "second-secret-value-456" {
		t.Fatal("writer's own cache not invalidated")
	}
	// The other process may serve the old value for at most CacheTTL.
	deadline := time.Now().Add(CacheTTL + 2*time.Second)
	for {
		r, err := other.Get(ctx, "aws")
		if err != nil {
			t.Fatal(err)
		}
		if r.Secrets["secret_access_key"] == "second-secret-value-456" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stale beyond CacheTTL")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// A cached "not configured" also expires.
	if _, err := other.Get(ctx, "github"); !errors.Is(err, ErrNotConfigured) {
		t.Fatal(err)
	}
}

// TestDBFailureRestoresSecrets makes the row write fail (a trigger raises)
// after the secrets were written, and checks the previous values are back.
func TestDBFailureRestoresSecrets(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.store.Configure(ctx, "aws", awsInput("original-secret-value"), actor); err != nil {
		t.Fatal(err)
	}
	_, err := f.pool.Exec(ctx, `
		CREATE FUNCTION fail_integration_write() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected failure'; END $$;
		CREATE TRIGGER fail_integration_write BEFORE INSERT OR UPDATE OR DELETE ON integrations
			FOR EACH ROW EXECUTE FUNCTION fail_integration_write();`)
	if err != nil {
		t.Fatal(err)
	}
	seq0, _, _ := f.diary.Head(ctx)

	in := awsInput("replacement-secret-value")
	in.Secrets["external_id"] = strp("new-external-id")
	if _, err := f.store.Configure(ctx, "aws", in, actor); err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("want injected failure, got %v", err)
	} else if strings.Contains(err.Error(), "replacement-secret-value") {
		t.Fatal("error leaks a secret")
	}
	if v, _ := f.sec.Get(ctx, "integration/aws/secret_access_key"); string(v) != "original-secret-value" {
		t.Fatalf("secret not restored: %q", v)
	}
	if _, err := f.sec.Get(ctx, "integration/aws/external_id"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("new optional secret not removed: %v", err)
	}
	// A new integration's secrets are removed again.
	gh := ConfigureInput{Config: raw(map[string]any{"app_id": "1", "installation_id": "2"}), Secrets: map[string]*string{"private_key_pem": strp(testPEM(t))}}
	if _, err := f.store.Configure(ctx, "github", gh, actor); err == nil {
		t.Fatal("want failure")
	}
	if _, err := f.sec.Get(ctx, "integration/github/private_key_pem"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("orphan secret left: %v", err)
	}
	// Delete failing in the DB restores the deleted secrets.
	if err := f.store.Delete(ctx, "aws", actor); err == nil {
		t.Fatal("want failure")
	}
	if v, _ := f.sec.Get(ctx, "integration/aws/secret_access_key"); string(v) != "original-secret-value" {
		t.Fatalf("secret not restored after failed delete: %q", v)
	}
	// Nothing reached the Diary (same transaction as the row).
	if seq1, _, _ := f.diary.Head(ctx); seq1 != seq0 {
		t.Fatalf("diary advanced on failure: %d -> %d", seq0, seq1)
	}
}

// failingStore is a secrets.Store that fails Put for one name (a fake for
// a secret backend error midway through a save).
type failingStore struct {
	secrets.Store
	failName string
}

func (f failingStore) Put(ctx context.Context, name string, v []byte) error {
	if name == f.failName {
		return errors.New("backend unavailable")
	}
	return f.Store.Put(ctx, name, v)
}

func TestSecretStoreFailureRollsBack(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.store.Configure(ctx, "aws", awsInput("original-secret-value"), actor); err != nil {
		t.Fatal(err)
	}
	s := NewPGStore(f.pool, f.diary, failingStore{Store: f.sec, failName: "integration/aws/secret_access_key"})
	in := awsInput("replacement-secret-value")
	in.Secrets["access_key_id"] = strp("AKIANEWKEYEXAMPLE000")
	if _, err := s.Configure(ctx, "aws", in, actor); err == nil || !strings.Contains(err.Error(), "backend unavailable") {
		t.Fatalf("want backend error, got %v", err)
	}
	// access_key_id (written first, alphabetically) was put back.
	if v, _ := f.sec.Get(ctx, "integration/aws/access_key_id"); string(v) != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("access_key_id not restored: %q", v)
	}
	if n := len(diaryBodies(t, f.diary, EventConfigured)); n != 1 {
		t.Fatalf("%d configured events", n)
	}
	// Read-only providers refuse cleanly.
	ro := NewPGStore(f.pool, f.diary, secrets.AsStore(secrets.Env{}))
	if _, err := ro.Configure(ctx, "github", ConfigureInput{Config: raw(map[string]any{"app_id": "1", "installation_id": "2"}), Secrets: map[string]*string{"private_key_pem": strp(testPEM(t))}}, actor); !errors.Is(err, secrets.ErrReadOnly) {
		t.Fatalf("read-only: %v", err)
	}
}

func TestRecordTest(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	in, err := f.store.Configure(ctx, "aws", awsInput("original-secret-value"), actor)
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.store.RecordTest(ctx, "aws", in.UpdatedAt, TestResult{OK: false, Error: "AccessDenied", Duration: 1500 * time.Millisecond}, actor)
	if err != nil || out.Status != StatusError || out.LastError != "AccessDenied" || out.LastTestedAt == nil {
		t.Fatalf("record failure: %+v %v", out, err)
	}
	out, err = f.store.RecordTest(ctx, "aws", in.UpdatedAt, TestResult{OK: true}, actor)
	if err != nil || out.Status != StatusOK || out.LastError != "" {
		t.Fatalf("record ok: %+v %v", out, err)
	}
	// Settings changed while testing: not applied to the new settings.
	in2, _ := f.store.Configure(ctx, "aws", awsInput("another-secret-value"), actor)
	out, err = f.store.RecordTest(ctx, "aws", in.UpdatedAt, TestResult{OK: true}, actor)
	if !errors.Is(err, ErrChanged) || out.Status != StatusConfigured {
		t.Fatalf("stale result: %+v %v", out, err)
	}
	if _, err := f.store.RecordTest(ctx, "github", in2.UpdatedAt, TestResult{OK: true}, actor); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("missing: %v", err)
	}
	ev := diaryBodies(t, f.diary, EventTested)
	if len(ev) != 3 || ev[0]["ok"] != false || ev[0]["error"] != "AccessDenied" || ev[0]["duration_ms"] != float64(1500) || ev[2]["stale"] != true {
		t.Fatalf("tested events: %v", ev)
	}
}

func TestConcurrentConfigure(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := f.store.Configure(ctx, "aws", awsInput(fmt.Sprintf("concurrent-secret-%02d-xxxx", i)), actor); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	// The row's last event fingerprint must match the secret in the store
	// (writers were serialised end to end).
	ev := diaryBodies(t, f.diary, EventConfigured)
	if len(ev) != 8 {
		t.Fatalf("%d events", len(ev))
	}
	last := ev[len(ev)-1]["secrets_changed"].(map[string]any)["secret_access_key"]
	v, _ := f.sec.Get(ctx, "integration/aws/secret_access_key")
	if Fingerprint(string(v)) != last {
		t.Fatal("secret store and last Diary event disagree: writers interleaved")
	}
	rep, err := diary.New(f.pool).VerifyChain(ctx)
	if err != nil || !rep.OK {
		t.Fatalf("chain: %+v %v", rep, err)
	}
}
