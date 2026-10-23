package integrations

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/diary"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
)

var (
	keyOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaKey = k
	})
	return rsaKey
}

// testPEM is a GitHub-style (PKCS#1) private key.
func testPEM(t *testing.T) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testRSAKey(t))}))
}

// testSAJSON is a Google-style service account key file (PKCS#8 key).
func testSAJSON(t *testing.T) string {
	der, err := x509.MarshalPKCS8PrivateKey(testRSAKey(t))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "fortik-test",
		"private_key_id": "0123456789abcdef0123456789abcdef01234567",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   "fortik@fortik-test.iam.gserviceaccount.com",
		"client_id":      "123456789012345678901",
		"token_uri":      "https://oauth2.googleapis.com/token",
	})
	return string(b)
}

func newEncStore(t *testing.T, dir string) *secrets.EncFile {
	t.Helper()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	s, err := secrets.NewEncFile(dir, k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type fixture struct {
	pool   *pgxpool.Pool
	diary  *diary.Diary
	sec    *secrets.EncFile
	secDir string
	store  *PGStore
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	dir := filepath.Join(t.TempDir(), "secrets")
	sec := newEncStore(t, dir)
	return fixture{pool: pool, diary: d, sec: sec, secDir: dir, store: NewPGStore(pool, d, sec)}
}

func raw(m map[string]any) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for k, v := range m {
		b, _ := json.Marshal(v)
		out[k] = b
	}
	return out
}

func strp(s string) *string { return &s }

// diaryBodies returns every Diary body of the given type.
func diaryBodies(t *testing.T, d *diary.Diary, eventType string) []map[string]any {
	t.Helper()
	entries, err := d.Query(context.Background(), diary.Filter{Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, e := range entries {
		if e.EventType != eventType {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(e.Body, &body); err != nil {
			t.Fatal(err)
		}
		data, _ := body["data"].(map[string]any)
		out = append(out, data)
	}
	return out
}

// allDBText concatenates every row of the tables that could plausibly hold
// a leaked secret.
func allDBText(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var s string
	err := pool.QueryRow(context.Background(), `
		SELECT COALESCE((SELECT string_agg(i::text, E'\n') FROM integrations i), '') ||
		       COALESCE((SELECT string_agg(d::text, E'\n') FROM diary d), '')`).Scan(&s)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
