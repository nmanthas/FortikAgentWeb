package discoverers_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"fortik/internal/broker/pgroles/pgrolestest"
	"fortik/internal/integrations"
	"fortik/internal/shadow"
	"fortik/internal/shadow/discoverers"
)

// fakeAdminSDK is a LOCAL FAKE of Google's OAuth token endpoint (JWT bearer
// grant, RS256 verified against the test key) and the Admin SDK Directory
// users.list / tokens.list / tokens.delete. It is not Google.
type fakeAdminSDK struct {
	srv *httptest.Server
	pub *rsa.PublicKey
	sa  string

	mu       sync.Mutex
	admin    string
	tokens   map[string][]string // access token -> scopes
	grants   map[string][]map[string]any
	deleted  []string
	failUser string
}

func newFakeAdminSDK(t *testing.T) *fakeAdminSDK {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAdminSDK{pub: &key.PublicKey, admin: "admin@acme.test", tokens: map[string][]string{}, grants: map[string][]map[string]any{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "fortik@proj.iam.gserviceaccount.com",
		"private_key_id": "k1", "token_uri": "http://127.0.0.1:1/never-used",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))})
	f.sa = string(sa)
	return f
}

func (f *fakeAdminSDK) resolved() integrations.Resolved {
	cm := map[string]any{"primary_domain": "acme.test", "test_user": "admin@acme.test"}
	raw, _ := json.Marshal(cm)
	return integrations.Resolved{Integration: integrations.Integration{Key: "google_workspace", System: "google_workspace", Config: raw, Status: "configured"},
		ConfigMap: cm, Secrets: map[string]string{"service_account_json": f.sa}}
}

func (f *fakeAdminSDK) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		_ = r.ParseForm()
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(r.PostForm.Get("assertion"), claims, func(*jwt.Token) (any, error) { return f.pub, nil },
			jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(f.srv.URL+"/token"))
		f.mu.Lock()
		defer f.mu.Unlock()
		if err != nil || claims["sub"] != f.admin {
			writeJSON(w, 401, map[string]string{"error": "unauthorized_client"})
			return
		}
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		tok := "ya29.fake" + hex.EncodeToString(b)
		f.tokens[tok] = strings.Fields(claims["scope"].(string))
		writeJSON(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600})
		return
	}
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	defer f.mu.Unlock()
	scopes, ok := f.tokens[tok]
	has := func(s string) bool {
		for _, x := range scopes {
			if x == s {
				return true
			}
		}
		return false
	}
	if !ok {
		writeJSON(w, 401, map[string]any{"error": map[string]any{"message": "Invalid Credentials"}})
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/admin/directory/v1/users")
	switch {
	case p == "" && r.Method == "GET":
		if r.URL.Query().Get("customer") != "my_customer" || !has(discoverers.ScopeAdminUsersRead) {
			writeJSON(w, 403, map[string]any{"error": map[string]any{"message": "Not Authorized"}})
			return
		}
		var users []map[string]string
		for _, u := range []string{"admin@acme.test", "jdoe@acme.test", "alice@acme.test"} {
			users = append(users, map[string]string{"primaryEmail": u})
		}
		writeJSON(w, 200, map[string]any{"users": users})
	case strings.HasSuffix(p, "/tokens") && r.Method == "GET":
		u := strings.TrimSuffix(strings.TrimPrefix(p, "/"), "/tokens")
		if !has(discoverers.ScopeAdminSecurity) || u == f.failUser {
			writeJSON(w, 403, map[string]any{"error": map[string]any{"message": "Not Authorized"}})
			return
		}
		writeJSON(w, 200, map[string]any{"items": f.grants[u]})
	case strings.Contains(p, "/tokens/") && r.Method == "DELETE":
		if !has(discoverers.ScopeAdminSecurity) {
			writeJSON(w, 403, map[string]any{"error": map[string]any{"message": "Not Authorized"}})
			return
		}
		f.deleted = append(f.deleted, strings.TrimPrefix(p, "/"))
		w.WriteHeader(204)
	default:
		writeJSON(w, 404, map[string]any{"error": map[string]any{"message": "not found"}})
	}
}

func TestGoogleOAuthGrants(t *testing.T) {
	g := newFakeAdminSDK(t)
	script := map[string]any{"clientId": "1234-script.apps.googleusercontent.com", "displayText": "", "anonymous": true, "nativeApp": false,
		"scopes": []string{"https://www.googleapis.com/auth/drive"}}
	g.grants["jdoe@acme.test"] = []map[string]any{script,
		{"clientId": "slack.apps", "displayText": "Slack", "anonymous": false, "nativeApp": false, "scopes": []string{"openid"}}}
	g.grants["alice@acme.test"] = []map[string]any{{"clientId": "slack.apps", "displayText": "Slack", "nativeApp": false},
		{"clientId": "sync-bot.apps", "displayText": "Sheets Sync Bot", "nativeApp": false}}

	src := pgrolestest.NewSource()
	d := discoverers.NewGoogle(src, nil, g.srv.URL+"/token", g.srv.URL, nil)
	if res := d.Discover(bg); res[0].Status != shadow.ScanNotConfigured {
		t.Fatalf("not configured: %+v", res)
	}
	src.Put(g.resolved())
	svc, _, _ := newService(t, d)
	rep, err := svc.Scan(bg, "user:sec@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	var res shadow.ScanResult
	for _, r := range rep.Systems {
		if r.System == shadow.SystemGoogle {
			res = r
		}
	}
	if res.Status != shadow.ScanScanned || res.Found != 3 || res.Flagged != 2 {
		t.Fatalf("google result: %+v", res)
	}
	sc := findByRef(t, svc, shadow.SystemGoogle, shadow.KindOAuthGrant, "1234-script.apps.googleusercontent.com")
	if !sc.UsedBySoftware || sc.Status != shadow.StatusFlagged || sc.Holder != "jdoe@acme.test" {
		t.Fatalf("anonymous script client: %+v", sc)
	}
	sl := findByRef(t, svc, shadow.SystemGoogle, shadow.KindOAuthGrant, "slack.apps")
	if sl.UsedBySoftware || sl.Holder != "2 users" {
		t.Fatalf("slack: %+v", sl)
	}
	if !findByRef(t, svc, shadow.SystemGoogle, shadow.KindOAuthGrant, "sync-bot.apps").UsedBySoftware {
		t.Fatal("sync bot not software")
	}
	if strings.Contains(string(sc.Evidence), "ya29.") || strings.Contains(res.Detail, "PRIVATE KEY") {
		t.Fatal("token or key leaked")
	}
	_, out, err := svc.Revoke(bg, sc.FindingID, "user:sec@example.com", "unregistered script client")
	g.mu.Lock()
	deleted := append([]string(nil), g.deleted...)
	g.mu.Unlock()
	if err != nil || out.Outcome != shadow.OutcomeRevoked || len(deleted) != 1 || deleted[0] != "jdoe@acme.test/tokens/1234-script.apps.googleusercontent.com" {
		t.Fatalf("revoke: %v %+v %v", err, out, deleted)
	}

	// A user whose tokens cannot be listed makes the scan partial, not clean.
	g.mu.Lock()
	g.failUser = "alice@acme.test"
	g.mu.Unlock()
	if r := d.Discover(bg); r[0].Status != shadow.ScanPartial || !strings.Contains(r[0].Detail, "NOT scanned") {
		t.Fatalf("partial: %+v", r)
	}
	// Delegation refused for the subject: not scanned.
	g.mu.Lock()
	g.admin = "someone-else@acme.test"
	g.mu.Unlock()
	if r := d.Discover(bg); r[0].Status != shadow.ScanError || !strings.Contains(r[0].Detail, "domain-wide delegation") {
		t.Fatalf("refused token: %+v", r)
	}
}

// Phase 5 review M2: the finding's users are a snapshot of the last scan.
// Revoke enumerates the holders again: a grant made after the scan is
// deleted too, and a user who cannot be checked means NOT revoked.
func TestGoogleRevokeVerifiesEveryHolder(t *testing.T) {
	g := newFakeAdminSDK(t)
	script := map[string]any{"clientId": "1234-script.apps.googleusercontent.com", "anonymous": true, "scopes": []string{"https://www.googleapis.com/auth/drive"}}
	bot := map[string]any{"clientId": "sync-bot.apps", "displayText": "Sheets Sync Bot"}
	g.grants["jdoe@acme.test"] = []map[string]any{script}
	g.grants["alice@acme.test"] = []map[string]any{bot}
	src := pgrolestest.NewSource()
	src.Put(g.resolved())
	d := discoverers.NewGoogle(src, nil, g.srv.URL+"/token", g.srv.URL, nil)
	svc, _, _ := newService(t, d)
	if _, err := svc.Scan(bg, "user:sec@example.com", ""); err != nil {
		t.Fatal(err)
	}
	// alice grants the script client after the scan.
	g.mu.Lock()
	g.grants["alice@acme.test"] = append(g.grants["alice@acme.test"], script)
	g.mu.Unlock()
	sc := findByRef(t, svc, shadow.SystemGoogle, shadow.KindOAuthGrant, "1234-script.apps.googleusercontent.com")
	_, out, err := svc.Revoke(bg, sc.FindingID, "user:sec@example.com", "script client")
	g.mu.Lock()
	deleted := strings.Join(g.deleted, ",")
	g.mu.Unlock()
	if err != nil || out.Outcome != shadow.OutcomeRevoked || !strings.Contains(deleted, "jdoe@acme.test/tokens/1234-script") ||
		!strings.Contains(deleted, "alice@acme.test/tokens/1234-script") {
		t.Fatalf("revoke: %v %+v deleted=%s", err, out, deleted)
	}

	// A user whose grants cannot be listed: the revoke is NOT claimed.
	g.mu.Lock()
	g.failUser = "admin@acme.test"
	g.mu.Unlock()
	sb := findByRef(t, svc, shadow.SystemGoogle, shadow.KindOAuthGrant, "sync-bot.apps")
	f, out, err := svc.Revoke(bg, sb.FindingID, "user:sec@example.com", "sync bot")
	if err != nil || out.Outcome != shadow.OutcomeNotRevoked || !strings.Contains(out.Detail, "could not be checked") || f.Status == shadow.StatusRevoked {
		t.Fatalf("unverifiable revoke: %v %+v %s", err, out, f.Status)
	}
}
