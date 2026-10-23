package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"fortik/internal/authz"
	"fortik/internal/secrets"
)

// fakeTester is a test double for a system's live connection tester.
type fakeTester struct {
	system string
	mu     sync.Mutex
	calls  []Resolved
	fn     func(ctx context.Context, r Resolved) error
}

func (f *fakeTester) System() string { return f.system }

func (f *fakeTester) Test(ctx context.Context, r Resolved) error {
	f.mu.Lock()
	f.calls = append(f.calls, r)
	fn := f.fn
	f.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(ctx, r)
}

func (f *fakeTester) setFn(fn func(ctx context.Context, r Resolved) error) {
	f.mu.Lock()
	f.fn = fn
	f.mu.Unlock()
}

// withTestPrincipal stands in for the API's auth middleware: the roles come
// from a test header; no header means unauthenticated.
func withTestPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if roles := r.Header.Get("X-Test-Roles"); roles != "" {
			p := authz.Principal{Kind: authz.KindUser, Name: "Test", Email: "sec@example.com", AuthMethod: "dev", Roles: map[string]bool{}}
			for _, role := range strings.Split(roles, ",") {
				p.Roles[role] = true
			}
			r = r.WithContext(authz.With(r.Context(), p))
		}
		next.ServeHTTP(w, r)
	})
}

type apiClient struct {
	t   *testing.T
	url string
}

func (c apiClient) do(method, path, roles string, body any) (int, string) {
	c.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		buf, _ := json.Marshal(b)
		rd = bytes.NewReader(buf)
	}
	req, _ := http.NewRequest(method, c.url+path, rd)
	if roles != "" {
		req.Header.Set("X-Test-Roles", roles)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func TestHandler(t *testing.T) {
	f := newFixture(t)
	reg := NewRegistry()
	awsT := &fakeTester{system: SystemAWS}
	ghT := &fakeTester{system: SystemGitHub}
	if err := reg.Register(awsT); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(ghT); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(&fakeTester{system: SystemAWS}); err == nil {
		t.Fatal("duplicate tester accepted")
	}
	if err := reg.Register(&fakeTester{system: "gmail"}); err == nil {
		t.Fatal("unknown-system tester accepted")
	}
	h := NewHandler(f.store, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.testTimeout = 300 * time.Millisecond
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(withTestPrincipal(mux))
	defer srv.Close()
	c := apiClient{t: t, url: srv.URL}

	const awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	awsBody := map[string]any{
		"config":  map[string]any{"region": "us-east-1", "role_arn": "arn:aws:iam::123456789012:role/fortik-agents"},
		"secrets": map[string]any{"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": awsSecret},
	}

	// Authentication and roles.
	routes := []struct{ method, path string }{
		{"GET", "/v1/integrations/schema"}, {"GET", "/v1/integrations"}, {"GET", "/v1/integrations/aws"},
		{"PUT", "/v1/integrations/aws"}, {"POST", "/v1/integrations/aws/test"}, {"DELETE", "/v1/integrations/aws"},
	}
	for _, r := range routes {
		if code, _ := c.do(r.method, r.path, "", awsBody); code != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated: %d", r.method, r.path, code)
		}
	}
	for _, r := range routes[3:] {
		if code, _ := c.do(r.method, r.path, "auditor", awsBody); code != http.StatusForbidden {
			t.Errorf("%s %s as auditor: %d", r.method, r.path, code)
		}
		if code, _ := c.do(r.method, r.path, "interceptor", awsBody); code != http.StatusForbidden {
			t.Errorf("%s %s as interceptor: %d", r.method, r.path, code)
		}
	}
	if code, _ := c.do("GET", "/v1/integrations", "interceptor", nil); code != http.StatusForbidden {
		t.Errorf("list as interceptor: %d", code)
	}

	// Schema.
	code, body := c.do("GET", "/v1/integrations/schema", "auditor", nil)
	var schemaResp struct{ Schemas []Schema }
	if code != 200 || json.Unmarshal([]byte(body), &schemaResp) != nil || len(schemaResp.Schemas) != len(Schemas()) || len(schemaResp.Schemas) < 7 {
		t.Fatalf("schema: %d %s", code, body)
	}

	// Configure.
	code, body = c.do("PUT", "/v1/integrations/aws", "security", awsBody)
	if code != 200 {
		t.Fatalf("configure: %d %s", code, body)
	}
	if strings.Contains(body, awsSecret) || strings.Contains(body, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("configure response contains a secret")
	}
	var v View
	_ = json.Unmarshal([]byte(body), &v)
	if !v.Secrets["access_key_id"].Set || !v.Secrets["secret_access_key"].Set || v.Secrets["external_id"].Set || !v.TestAvailable || v.Status != StatusConfigured {
		t.Fatalf("view: %s", body)
	}
	if v.UpdatedBy != "user:sec@example.com" {
		t.Fatalf("actor: %s", v.UpdatedBy)
	}
	// admin implies security.
	if code, body := c.do("PUT", "/v1/integrations/aws", "admin", awsBody); code != 200 {
		t.Fatalf("admin configure: %d %s", code, body)
	}

	// Bad requests never echo secret material.
	for _, b := range []any{
		map[string]any{"config": awsBody["config"], "secrets": map[string]any{"secret_access_key": ""}},
		map[string]any{"config": awsBody["config"], "secrets": map[string]any{"access_key_id": "not-a-key " + awsSecret}},
		map[string]any{"config": awsBody["config"], "extra": 1},
		`{"config": {}, "secrets": {"secret_access_key": "` + awsSecret + `"`,
		`{"config":{"region":"us-east-1"}} {"trailing": "` + awsSecret + `"}`,
	} {
		code, body := c.do("PUT", "/v1/integrations/aws", "security", b)
		if code != http.StatusBadRequest {
			t.Errorf("bad body %v: %d %s", b, code, body)
		}
		if strings.Contains(body, awsSecret) {
			t.Errorf("400 response echoes a secret: %s", body)
		}
	}
	if code, _ := c.do("PUT", "/v1/integrations/gmail", "security", awsBody); code != http.StatusBadRequest {
		t.Errorf("unknown key: %d", code)
	}
	if code, _ := c.do("PUT", "/v1/integrations/aws", "security", strings.Repeat(" ", maxConfigureBody+10)+"{}"); code != http.StatusBadRequest {
		t.Errorf("oversized body: %d", code)
	}

	// List: secrets only as {"set": ...}.
	code, body = c.do("GET", "/v1/integrations", "auditor", nil)
	if code != 200 || strings.Contains(body, awsSecret) || !strings.Contains(body, `"secret_access_key":{"set":true}`) {
		t.Fatalf("list: %d %s", code, body)
	}
	if code, _ := c.do("GET", "/v1/integrations/github", "auditor", nil); code != http.StatusNotFound {
		t.Errorf("get unconfigured: %d", code)
	}

	// Test: failure whose message contains the secret is sanitised.
	awsT.setFn(func(ctx context.Context, r Resolved) error {
		if _, ok := ctx.Deadline(); !ok {
			return errors.New("no deadline")
		}
		return errors.New("InvalidClientTokenId: key " + r.Secrets["access_key_id"] + " secret " + r.Secrets["secret_access_key"] + " rejected")
	})
	code, body = c.do("POST", "/v1/integrations/aws/test", "security", nil)
	var tr TestResponse
	_ = json.Unmarshal([]byte(body), &tr)
	if code != 200 || tr.OK || tr.Error != "InvalidClientTokenId: key *** secret *** rejected" || tr.Integration.Status != StatusError || tr.Integration.LastError != tr.Error {
		t.Fatalf("failed test: %d %s", code, body)
	}
	awsT.mu.Lock()
	got := awsT.calls[len(awsT.calls)-1]
	awsT.mu.Unlock()
	if got.Secrets["secret_access_key"] != awsSecret || got.Text("region") != "us-east-1" {
		t.Fatal("tester did not receive resolved settings")
	}
	// Success.
	awsT.setFn(nil)
	code, body = c.do("POST", "/v1/integrations/aws/test", "security", nil)
	_ = json.Unmarshal([]byte(body), &tr)
	if code != 200 || !tr.OK || tr.Integration.Status != StatusOK || tr.Integration.LastTestedAt == nil {
		t.Fatalf("ok test: %d %s", code, body)
	}

	// A tester that ignores its context is cut off at the timeout; a panic is a failure.
	ghBody := map[string]any{"config": map[string]any{"app_id": 1, "installation_id": 2}, "secrets": map[string]any{"private_key_pem": testPEM(t)}}
	if code, body := c.do("PUT", "/v1/integrations/github", "security", ghBody); code != 200 {
		t.Fatalf("github configure: %d %s", code, body)
	}
	release := make(chan struct{})
	defer close(release)
	ghT.setFn(func(context.Context, Resolved) error { <-release; return nil })
	start := time.Now()
	code, body = c.do("POST", "/v1/integrations/github/test", "security", nil)
	_ = json.Unmarshal([]byte(body), &tr)
	if code != 200 || tr.OK || !strings.Contains(tr.Error, "timed out") || time.Since(start) > 5*time.Second {
		t.Fatalf("timeout test: %d %s", code, body)
	}
	pemStr := testPEM(t)
	ghT.setFn(func(context.Context, Resolved) error { panic("boom " + pemStr) })
	code, body = c.do("POST", "/v1/integrations/github/test", "security", nil)
	_ = json.Unmarshal([]byte(body), &tr)
	if code != 200 || tr.OK || !strings.Contains(tr.Error, "crashed") || strings.Contains(body, "PRIVATE KEY") {
		t.Fatalf("panic test: %d %s", code, body)
	}

	// No tester for postgres in this build; unconfigured key; missing secret.
	pgBody := map[string]any{
		"config":  map[string]any{"host": "127.0.0.1", "database": "acme", "environment": "dev", "admin_user": "fortik_admin", "read_role": "r", "write_role": "w", "sslmode": "disable"},
		"secrets": map[string]any{"admin_password": "pg-admin-password"},
	}
	if code, body := c.do("PUT", "/v1/integrations/postgres:acme_dev", "security", pgBody); code != 200 {
		t.Fatalf("postgres configure: %d %s", code, body)
	}
	if code, _ := c.do("POST", "/v1/integrations/postgres:acme_dev/test", "security", nil); code != http.StatusNotImplemented {
		t.Errorf("no tester: %d", code)
	}
	if code, _ := c.do("DELETE", "/v1/integrations/google_workspace", "security", nil); code != http.StatusNotFound {
		t.Errorf("delete unconfigured: %d", code)
	}
	if err := f.sec.Delete(context.Background(), "integration/github/private_key_pem"); err != nil {
		t.Fatal(err)
	}
	code, body = c.do("POST", "/v1/integrations/github/test", "security", nil)
	_ = json.Unmarshal([]byte(body), &tr)
	if code != 200 || tr.OK || !strings.Contains(tr.Error, "private_key_pem missing") {
		t.Fatalf("missing secret test: %d %s", code, body)
	}

	// Delete.
	if code, body := c.do("DELETE", "/v1/integrations/aws", "security", nil); code != 200 || !strings.Contains(body, `"deleted":"aws"`) {
		t.Fatalf("delete: %d %s", code, body)
	}
	if code, _ := c.do("DELETE", "/v1/integrations/aws", "security", nil); code != http.StatusNotFound {
		t.Errorf("second delete: %d", code)
	}
	if code, _ := c.do("POST", "/v1/integrations/aws/test", "security", nil); code != http.StatusNotFound {
		t.Errorf("test deleted: %d", code)
	}

	// The Diary and Postgres never saw a secret value.
	all := allDBText(t, f.pool)
	for _, s := range []string{awsSecret, "AKIAIOSFODNN7EXAMPLE", "pg-admin-password", "PRIVATE KEY"} {
		if strings.Contains(all, s) {
			t.Fatalf("Postgres contains secret material %q", s)
		}
	}
	tested := diaryBodies(t, f.diary, EventTested)
	if len(tested) < 4 || tested[0]["error"] != "InvalidClientTokenId: key *** secret *** rejected" {
		t.Fatalf("tested events: %v", tested)
	}
	rep, err := f.diary.VerifyChain(context.Background())
	if err != nil || !rep.OK {
		t.Fatalf("chain: %+v %v", rep, err)
	}
}

func TestHandlerReadOnlyProvider(t *testing.T) {
	f := newFixture(t)
	store := NewPGStore(f.pool, f.diary, secrets.AsStore(secrets.File{Dir: t.TempDir()}))
	mux := http.NewServeMux()
	NewHandler(store, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).Register(mux)
	srv := httptest.NewServer(withTestPrincipal(mux))
	defer srv.Close()
	c := apiClient{t: t, url: srv.URL}
	code, body := c.do("PUT", "/v1/integrations/github", "security", map[string]any{
		"config": map[string]any{"app_id": "1", "installation_id": "2"}, "secrets": map[string]any{"private_key_pem": testPEM(t)}})
	if code != http.StatusConflict || !strings.Contains(body, "read-only") {
		t.Fatalf("read-only provider: %d %s", code, body)
	}
	if code, _ := c.do("GET", "/v1/integrations", "auditor", nil); code != 200 {
		t.Fatalf("list: %d", code)
	}
}
