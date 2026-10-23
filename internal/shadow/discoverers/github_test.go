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
	"time"

	"github.com/golang-jwt/jwt/v5"

	"fortik/internal/broker/pgroles/pgrolestest"
	"fortik/internal/control"
	"fortik/internal/integrations"
	"fortik/internal/shadow"
	"fortik/internal/shadow/discoverers"
)

// fakeGitHub is a LOCAL FAKE of the GitHub endpoints shadow discovery uses:
// app JWT auth, installation tokens (narrowed to the requested org
// permission, refused beyond the installation's), the org fine-grained PAT
// list and revoke, and the org installation list. It is not GitHub.
type fakeGitHub struct {
	srv *httptest.Server
	pub *rsa.PublicKey
	pem string

	mu           sync.Mutex
	installPerms map[string]string
	tokens       map[string]map[string]string // token -> permissions
	pats         []map[string]any
	installs     []map[string]any
	revokedPATs  []string
	liveTokens   int
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGitHub{pub: &key.PublicKey, tokens: map[string]map[string]string{},
		pem:          string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		installPerms: map[string]string{"organization_personal_access_tokens": "write", "organization_administration": "read", "metadata": "read"}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) resolved() integrations.Resolved {
	cm := map[string]any{"api_base_url": f.srv.URL, "app_id": "4242", "installation_id": "777"}
	raw, _ := json.Marshal(cm)
	return integrations.Resolved{Integration: integrations.Integration{Key: "github", System: "github", Config: raw, Status: "configured",
		SecretFields: []string{"private_key_pem"}}, ConfigMap: cm, Secrets: map[string]string{"private_key_pem": f.pem}}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeGitHub) jwtOK(r *http.Request) bool {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	tok, err := jwt.ParseWithClaims(raw, &jwt.RegisteredClaims{}, func(*jwt.Token) (any, error) { return f.pub, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("4242"), jwt.WithExpirationRequired())
	return err == nil && tok.Valid
}

func (f *fakeGitHub) perm(r *http.Request, perm, level string) bool {
	raw, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.tokens[raw]
	if !ok {
		return false
	}
	rank := map[string]int{"read": 1, "write": 2}
	return rank[p[perm]] >= rank[level]
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/app/installations/777" && r.Method == "GET":
		if !f.jwtOK(r) {
			writeJSON(w, 401, map[string]string{"message": "bad jwt"})
			return
		}
		writeJSON(w, 200, map[string]any{"id": 777, "account": map[string]any{"login": "acme"}, "permissions": f.installPerms})
	case path == "/app/installations/777/access_tokens" && r.Method == "POST":
		if !f.jwtOK(r) {
			writeJSON(w, 401, map[string]string{"message": "bad jwt"})
			return
		}
		var req struct {
			Permissions map[string]string `json:"permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		rank := map[string]int{"read": 1, "write": 2}
		f.mu.Lock()
		for k, v := range req.Permissions {
			if rank[v] == 0 || rank[v] > rank[f.installPerms[k]] {
				f.mu.Unlock()
				writeJSON(w, 422, map[string]string{"message": "The permissions requested are not granted to this installation."})
				return
			}
		}
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		tok := "ghs_fake" + hex.EncodeToString(b)
		f.tokens[tok] = req.Permissions
		f.liveTokens++
		f.mu.Unlock()
		writeJSON(w, 201, map[string]any{"token": tok, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"permissions": req.Permissions, "repository_selection": "all"})
	case path == "/installation/token" && r.Method == "DELETE":
		raw, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		if _, ok := f.tokens[raw]; ok {
			delete(f.tokens, raw)
			f.liveTokens--
		}
		f.mu.Unlock()
		w.WriteHeader(204)
	case path == "/orgs/acme/personal-access-tokens" && r.Method == "GET":
		if !f.perm(r, "organization_personal_access_tokens", "read") {
			writeJSON(w, 403, map[string]string{"message": "Resource not accessible by integration"})
			return
		}
		f.mu.Lock()
		out := f.pats
		f.mu.Unlock()
		if r.URL.Query().Get("page") != "1" {
			out = nil
		}
		writeJSON(w, 200, out)
	case strings.HasPrefix(path, "/orgs/acme/personal-access-tokens/") && r.Method == "POST":
		if !f.perm(r, "organization_personal_access_tokens", "write") {
			writeJSON(w, 403, map[string]string{"message": "Resource not accessible by integration"})
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["action"] != "revoke" {
			writeJSON(w, 422, map[string]string{"message": "bad action"})
			return
		}
		f.mu.Lock()
		f.revokedPATs = append(f.revokedPATs, strings.TrimPrefix(path, "/orgs/acme/personal-access-tokens/"))
		f.mu.Unlock()
		w.WriteHeader(204)
	case path == "/orgs/acme/installations" && r.Method == "GET":
		if !f.perm(r, "organization_administration", "read") {
			writeJSON(w, 403, map[string]string{"message": "Resource not accessible by integration"})
			return
		}
		f.mu.Lock()
		out := f.installs
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"total_count": len(out), "installations": out})
	default:
		writeJSON(w, 404, map[string]string{"message": "Not Found"})
	}
}

func (f *fakeGitHub) live() int { f.mu.Lock(); defer f.mu.Unlock(); return f.liveTokens }

func (f *fakeGitHub) revoked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revokedPATs...)
}

func pat(id, tokenID int, name, owner, ownerType string) map[string]any {
	return map[string]any{"id": id, "owner": map[string]any{"login": owner, "type": ownerType}, "repository_selection": "all",
		"permissions": map[string]any{"repository": map[string]any{"contents": "write"}}, "access_granted_at": "2026-01-02T00:00:00Z",
		"token_id": tokenID, "token_name": name, "token_expired": false, "token_expires_at": nil, "token_last_used_at": "2026-10-19T02:00:00Z"}
}

// The GitHub analogue of scenario 7: a script running on someone's
// fine-grained personal token.
func TestGitHubScriptUsingPersonalToken(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.pats = []map[string]any{
		pat(501, 9001, "nightly-sync-script", "jdoe", "User"),
		pat(502, 9002, "laptop", "alice", "User"),
		pat(503, 9003, "expired", "bob", "User"),
	}
	gh.pats[2]["token_expired"] = true
	gh.installs = []map[string]any{
		{"id": 777, "app_id": 4242, "app_slug": "fortik", "account": map[string]any{"login": "acme"}},
		{"id": 801, "app_id": 99, "app_slug": "data-exporter", "account": map[string]any{"login": "acme"}, "permissions": map[string]string{"contents": "read"}},
		{"id": 802, "app_id": 98, "app_slug": "approved-ci", "account": map[string]any{"login": "acme"}},
		{"id": 803, "app_id": 97, "app_slug": "old", "account": map[string]any{"login": "acme"}, "suspended_at": "2026-01-01T00:00:00Z"},
	}
	src := pgrolestest.NewSource()
	src.Put(gh.resolved())
	d := discoverers.NewGitHub(src, nil, []string{"approved-ci"}, nil)
	svc, pool, _ := newService(t, d)

	rep, err := svc.Scan(bg, "user:sec@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	var res shadow.ScanResult
	for _, r := range rep.Systems {
		if r.System == shadow.SystemGitHub {
			res = r
		}
	}
	if res.Status != shadow.ScanScanned || res.Found != 4 || res.Flagged != 2 {
		t.Fatalf("github result: %+v", res)
	}
	script := findByRef(t, svc, shadow.SystemGitHub, shadow.KindPAT, "pat:9001")
	if !script.UsedBySoftware || script.Status != shadow.StatusFlagged || script.Holder != "jdoe" || script.AgentID == "" {
		t.Fatalf("script PAT: %+v", script)
	}
	if st, _ := control.Get(bg, pool, script.AgentID); !st.Discovered || st.Level != control.Isolated || st.Sponsor != "" {
		t.Fatalf("discovered agent: %+v", st)
	}
	if p := findByRef(t, svc, shadow.SystemGitHub, shadow.KindPAT, "pat:9002"); p.UsedBySoftware || p.Status != shadow.StatusOpen {
		t.Fatalf("person PAT: %+v", p)
	}
	if _, err := svc.Get(bg, shadow.FindingID(shadow.SystemGitHub, shadow.KindPAT, "pat:9003")); err == nil {
		t.Fatal("expired PAT recorded")
	}
	app := findByRef(t, svc, shadow.SystemGitHub, shadow.KindAppInstallation, "installation:801")
	if !app.UsedBySoftware || app.Status != shadow.StatusFlagged {
		t.Fatalf("third-party app: %+v", app)
	}
	if ci := findByRef(t, svc, shadow.SystemGitHub, shadow.KindAppInstallation, "installation:802"); ci.UsedBySoftware {
		t.Fatalf("approved app flagged: %+v", ci)
	}
	for _, id := range []string{"installation:777", "installation:803"} {
		if _, err := svc.Get(bg, shadow.FindingID(shadow.SystemGitHub, shadow.KindAppInstallation, id)); err == nil {
			t.Fatalf("%s recorded (Fortik's own app / suspended)", id)
		}
	}
	// Every installation token minted for the scan was revoked.
	if gh.live() != 0 {
		t.Fatalf("%d installation tokens left live", gh.live())
	}

	// Revoke the script's PAT through the org API.
	_, out, err := svc.Revoke(bg, script.FindingID, "user:sec@example.com", "script on a personal token")
	if err != nil || out.Outcome != shadow.OutcomeRevoked || len(gh.revoked()) != 1 || gh.revoked()[0] != "501" {
		t.Fatalf("revoke PAT: %v %+v %v", err, out, gh.revoked())
	}
	// An app installation cannot be removed by Fortik: honest manual result.
	f, out, err := svc.Revoke(bg, app.FindingID, "user:sec@example.com", "unknown app")
	if err != nil || out.Outcome != shadow.OutcomeManualRequired || f.Status != shadow.StatusFlagged {
		t.Fatalf("revoke app: %v %+v %+v", err, out, f)
	}
	if gh.live() != 0 {
		t.Fatalf("%d installation tokens left live after revoke", gh.live())
	}
}

func TestGitHubPartialAndNotConfigured(t *testing.T) {
	src := pgrolestest.NewSource()
	d := discoverers.NewGitHub(src, nil, nil, nil)
	if res := d.Discover(bg); len(res) != 1 || res[0].Status != shadow.ScanNotConfigured {
		t.Fatalf("not configured: %+v", res)
	}
	gh := newFakeGitHub(t)
	gh.installPerms = map[string]string{"organization_personal_access_tokens": "read"} // no org administration
	gh.pats = []map[string]any{pat(1, 2, "deploy-bot", "ci-user", "Bot")}
	src.Put(gh.resolved())
	res := d.Discover(bg)
	if len(res) != 1 || res[0].Status != shadow.ScanPartial || len(res[0].Credentials) != 1 || !strings.Contains(res[0].Detail, "app installations NOT scanned") {
		t.Fatalf("partial: %+v", res)
	}
	if !res[0].Credentials[0].Software {
		t.Fatal("bot PAT not software")
	}
	// Revoking needs write: refused honestly.
	f := shadow.Finding{Kind: shadow.KindPAT, Holder: "ci-user", CredentialRef: "pat:2", Evidence: json.RawMessage(`{"org":"acme","pat_id":1}`)}
	if out := d.Revoke(bg, f); out.Outcome != shadow.OutcomeNotRevoked {
		t.Fatalf("revoke without write: %+v", out)
	}
	if strings.Contains(res[0].Detail, gh.pem) {
		t.Fatal("key in detail")
	}
}
