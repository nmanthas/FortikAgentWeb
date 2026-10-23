package google

// FAKES. Everything in this file is a local stand-in for Google, used only by
// tests. fakeGoogle implements the subset of the real APIs the adapter uses:
//   - OAuth 2.0 token endpoint (JWT bearer grant): verifies the RS256
//     assertion against the test service account's public key and checks
//     iss / aud / sub / scope, as Google does for domain-wide delegation;
//   - Gmail: users.messages.send (multipart upload), users.getProfile,
//     users.messages.list, users.drafts.get / delete;
//   - Drive: files.list, permissions.create / get / delete.
// No real Google endpoint is ever contacted.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"fortik/internal/broker"
)

const fakeSAEmail = "fortik-dwd@fake-project.iam.gserviceaccount.com"

type fakeSentMessage struct {
	Subject  string // impersonated user
	Raw      []byte
	ThreadID string
}

type fakePermission struct {
	FileID string
	ID     string
	Body   map[string]any
}

type fakeTokenGrant struct {
	sub    string
	scopes map[string]bool
}

type fakeGoogle struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	mu          sync.Mutex
	mints       int
	tokens      map[string]fakeTokenGrant
	denySubject map[string]bool // subjects the DWD grant refuses (unauthorized_client)
	sent        []fakeSentMessage
	drafts      map[string][]byte // draft id -> raw
	deleted     []string          // deleted draft ids
	perms       map[string]fakePermission
	permSeq     int
	requests    []string // "METHOD path" of every API (non-token) request
	sendStatus  int      // non-zero: users.messages.send answers with this status
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGoogle{t: t, key: key, tokens: map[string]fakeTokenGrant{}, denySubject: map[string]bool{},
		drafts: map[string][]byte{}, perms: map[string]fakePermission{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGoogle) tokenURL() string { return f.srv.URL + "/token" }

// serviceAccountJSON is a service account key for the fake. Its token_uri
// points at an unroutable address: the adapter must use the configured URL.
func (f *fakeGoogle) serviceAccountJSON() string {
	der, err := x509.MarshalPKCS8PrivateKey(f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "fake-project", "private_key_id": "fakekid1",
		"private_key": string(p), "client_email": fakeSAEmail, "client_id": "1234567890",
		"token_uri": "http://127.0.0.1:1/never-used",
	})
	return string(b)
}

func (f *fakeGoogle) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		f.serveToken(w, r)
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	grant, ok := f.auth(r)
	if !ok {
		http.Error(w, `{"error":{"code":401}}`, http.StatusUnauthorized)
		return
	}
	p := r.URL.Path
	switch {
	case r.Method == "POST" && p == "/upload/gmail/v1/users/me/messages/send" && r.URL.Query().Get("uploadType") == "multipart":
		if f.need(w, grant, ScopeGmailSend, ScopeGmailCompose, ScopeGmailFull) {
			f.serveSend(w, r, grant)
		}
	case r.Method == "GET" && strings.HasSuffix(p, "/profile") && strings.HasPrefix(p, "/gmail/v1/users/"):
		if f.need(w, grant, ScopeGmailReadonly, ScopeGmailModify, ScopeGmailFull) {
			writeFakeJSON(w, 200, map[string]any{"emailAddress": grant.sub, "messagesTotal": 3})
		}
	case r.Method == "GET" && strings.HasPrefix(p, "/gmail/v1/users/") && strings.HasSuffix(p, "/messages"):
		if f.need(w, grant, ScopeGmailReadonly) {
			w.Header().Set("Set-Cookie", "GAPS=upstream-cookie")
			writeFakeJSON(w, 200, map[string]any{"messages": []any{map[string]string{"id": "m1"}}, "resultSizeEstimate": 1})
		}
	case strings.HasPrefix(p, "/gmail/v1/users/me/drafts/"):
		id := strings.TrimPrefix(p, "/gmail/v1/users/me/drafts/")
		if !f.need(w, grant, ScopeGmailCompose) {
			return
		}
		f.mu.Lock()
		raw, ok := f.drafts[id]
		if ok && r.Method == "DELETE" {
			delete(f.drafts, id)
			f.deleted = append(f.deleted, id)
		}
		f.mu.Unlock()
		switch {
		case !ok:
			writeFakeJSON(w, 404, map[string]any{"error": map[string]any{"code": 404}})
		case r.Method == "DELETE":
			w.WriteHeader(204)
		default:
			writeFakeJSON(w, 200, map[string]any{"id": id, "message": map[string]any{"id": "dm-" + id, "threadId": "thr1",
				"raw": base64.URLEncoding.EncodeToString(raw)}})
		}
	case r.Method == "GET" && p == "/drive/v3/files":
		if f.need(w, grant, ScopeDriveReadonly, ScopeDrive) {
			writeFakeJSON(w, 200, map[string]any{"files": []any{}})
		}
	case strings.HasPrefix(p, "/drive/v3/files/") && strings.Contains(p, "/permissions"):
		f.servePermissions(w, r, grant)
	default:
		writeFakeJSON(w, 404, map[string]any{"error": map[string]any{"code": 404, "message": "fake: not implemented"}})
	}
}

func (f *fakeGoogle) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		writeFakeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(r.PostForm.Get("assertion"), claims, func(tok *jwt.Token) (any, error) {
		if tok.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("unexpected alg %s", tok.Method.Alg())
		}
		return &f.key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(f.tokenURL()), jwt.WithIssuer(fakeSAEmail), jwt.WithExpirationRequired())
	if err != nil {
		writeFakeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "fake: bad assertion: " + err.Error()})
		return
	}
	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	if sub == "" || scope == "" {
		writeFakeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "fake: sub and scope required"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.denySubject[sub] {
		writeFakeJSON(w, 401, map[string]string{"error": "unauthorized_client", "error_description": "Client is unauthorized to retrieve access tokens using this method"})
		return
	}
	f.mints++
	tok := fmt.Sprintf("ya29.fake-%d", f.mints)
	g := fakeTokenGrant{sub: sub, scopes: map[string]bool{}}
	for _, s := range strings.Fields(scope) {
		g.scopes[s] = true
	}
	f.tokens[tok] = g
	writeFakeJSON(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600})
}

func (f *fakeGoogle) auth(r *http.Request) (fakeTokenGrant, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.tokens[tok]
	return g, ok
}

// need checks the token carries one of the scopes Google accepts for the method.
func (f *fakeGoogle) need(w http.ResponseWriter, g fakeTokenGrant, anyOf ...string) bool {
	for _, s := range anyOf {
		if g.scopes[s] {
			return true
		}
	}
	writeFakeJSON(w, 403, map[string]any{"error": map[string]any{"code": 403, "message": "fake: insufficient scope"}})
	return false
}

func (f *fakeGoogle) serveSend(w http.ResponseWriter, r *http.Request, g fakeTokenGrant) {
	f.mu.Lock()
	status := f.sendStatus
	f.mu.Unlock()
	if status != 0 {
		writeFakeJSON(w, status, map[string]any{"error": map[string]any{"code": status}})
		return
	}
	mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/related" {
		writeFakeJSON(w, 400, map[string]string{"error": "fake: want multipart/related"})
		return
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	var meta struct {
		ThreadID string `json:"threadId"`
	}
	p1, err := mr.NextPart()
	if err != nil || json.NewDecoder(p1).Decode(&meta) != nil {
		writeFakeJSON(w, 400, map[string]string{"error": "fake: bad metadata part"})
		return
	}
	p2, err := mr.NextPart()
	if err != nil || p2.Header.Get("Content-Type") != "message/rfc822" {
		writeFakeJSON(w, 400, map[string]string{"error": "fake: bad media part"})
		return
	}
	raw, _ := io.ReadAll(p2)
	f.mu.Lock()
	f.sent = append(f.sent, fakeSentMessage{Subject: g.sub, Raw: raw, ThreadID: meta.ThreadID})
	id := fmt.Sprintf("msg-%d", len(f.sent))
	f.mu.Unlock()
	writeFakeJSON(w, 200, map[string]any{"id": id, "threadId": "thr-" + id, "labelIds": []string{"SENT"}})
}

func (f *fakeGoogle) servePermissions(w http.ResponseWriter, r *http.Request, g fakeTokenGrant) {
	rest := strings.TrimPrefix(r.URL.Path, "/drive/v3/files/")
	parts := strings.Split(rest, "/")
	fileID := parts[0]
	switch {
	case r.Method == "POST" && len(parts) == 2:
		if !f.need(w, g, ScopeDrive) {
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeFakeJSON(w, 400, map[string]string{"error": "fake: bad json"})
			return
		}
		f.mu.Lock()
		f.permSeq++
		id := fmt.Sprintf("perm-%d", f.permSeq)
		f.perms[id] = fakePermission{FileID: fileID, ID: id, Body: body}
		f.mu.Unlock()
		resp := map[string]any{"kind": "drive#permission", "id": id}
		for k, v := range body {
			resp[k] = v
		}
		writeFakeJSON(w, 200, resp)
	case len(parts) == 3:
		id := parts[2]
		f.mu.Lock()
		perm, ok := f.perms[id]
		if ok && r.Method == "DELETE" {
			delete(f.perms, id)
		}
		f.mu.Unlock()
		if !ok || perm.FileID != fileID {
			writeFakeJSON(w, 404, map[string]any{"error": map[string]any{"code": 404}})
			return
		}
		if r.Method == "DELETE" {
			if f.need(w, g, ScopeDrive) {
				w.WriteHeader(204)
			}
			return
		}
		out := map[string]any{"id": id}
		for k, v := range perm.Body {
			out[k] = v
		}
		writeFakeJSON(w, 200, out)
	default:
		writeFakeJSON(w, 404, map[string]any{"error": map[string]any{"code": 404}})
	}
}

func (f *fakeGoogle) snapshot() (sent []fakeSentMessage, perms map[string]fakePermission, requests []string, mints int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	perms = map[string]fakePermission{}
	for k, v := range f.perms {
		perms[k] = v
	}
	return append([]fakeSentMessage(nil), f.sent...), perms, append([]string(nil), f.requests...), f.mints
}

func writeFakeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// --- other test doubles --------------------------------------------------------

// recorder captures issuance records (stands in for broker.Broker).
type recorder struct {
	mu    sync.Mutex
	creds []broker.Credential
}

func (r *recorder) RecordIssuance(_ context.Context, c broker.Credential, _, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.creds = append(r.creds, c)
	return nil
}
