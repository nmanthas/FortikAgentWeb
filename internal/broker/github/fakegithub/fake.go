// Package fakegithub is a LOCAL FAKE of the subset of the GitHub REST API
// that Fortik's GitHub broker and gateway use. It exists only for tests: it
// never talks to GitHub and implements just enough behaviour to exercise the
// real code paths:
//
//   - GitHub App auth: RS256 app JWTs verified against the test key
//     (iss = app id, iat/exp present, lifetime <= 10 min + drift).
//   - GET /app/installations/{id}
//   - POST /app/installations/{id}/access_tokens with repository and
//     permission checks against the installation (narrowing enforced).
//   - DELETE /installation/token
//   - Repository endpoints authorised by token (repository and permission
//     checked per endpoint): repo get/delete, branches (protection flag),
//     git refs get/create/update/delete, git commits get, contents put, pulls get/patch/merge,
//     issue comments.
//
// It is clearly not GitHub: there is no git object model (commit SHAs are a
// counter), no fast-forward checks and no pagination.
package fakegithub

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Server is the fake. Its identity fields are fixed at New; state changes go
// through methods (safe for concurrent use).
type Server struct {
	*httptest.Server

	AppID          string
	InstallationID string
	Account        string
	PrivateKeyPEM  string

	pub *rsa.PublicKey

	mu sync.Mutex
	// InstallPerms are the permissions the app installation holds (set
	// before the first request).
	InstallPerms map[string]string
	repos        map[string]*Repo // lower(owner/name)
	tokens       map[string]*Token
	calls        []Call
	sha          int
	parents      map[string]string // commit sha -> first parent (commits the fake created)
	grantExtra   bool
	failBranches bool
}

// SetGrantExtra makes access_tokens grant more than requested (a misbehaving
// upstream), to test that clients detect and revoke it.
func (s *Server) SetGrantExtra(v bool) { s.mu.Lock(); s.grantExtra = v; s.mu.Unlock() }

// SetFailBranches makes branch lookups answer 500.
func (s *Server) SetFailBranches(v bool) { s.mu.Lock(); s.failBranches = v; s.mu.Unlock() }

// Repo is one fake repository.
type Repo struct {
	Owner, Name   string
	DefaultBranch string
	Branches      map[string]*Branch
	Pulls         map[int]*Pull
	Deleted       bool
}

type Branch struct {
	SHA       string
	Protected bool
}

type Pull struct {
	Number int
	State  string // open | closed
	Base   string
	Head   string
	Merged bool
}

// Token is one minted installation token (the fake keeps the value so it can
// authenticate requests; tests use Tokens() to check no value leaked).
type Token struct {
	Value       string
	Repos       map[string]bool // lower(name); nil = all
	Permissions map[string]string
	ExpiresAt   time.Time
	Revoked     bool
}

// Call is one request the fake served (no credentials recorded).
type Call struct {
	Method string
	Path   string
	Auth   string // "jwt" | "token" | "none"
	Status int
}

// New starts a fake with a fresh 2048-bit app key, app id 4242, installation
// 777 on account "acme", and installation permissions contents/pull_requests/
// issues write + metadata read.
func New(t testing.TB) *Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("fakegithub: generate key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	s := &Server{
		AppID: "4242", InstallationID: "777", Account: "acme", PrivateKeyPEM: string(pemBytes), pub: &key.PublicKey,
		InstallPerms: map[string]string{"contents": "write", "pull_requests": "write", "issues": "write", "metadata": "read"},
		repos:        map[string]*Repo{},
		tokens:       map[string]*Token{},
		parents:      map[string]string{},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// NextSHA returns a new fake 40-hex commit sha.
func (s *Server) NextSHA() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextSHALocked()
}

func (s *Server) nextSHALocked() string {
	s.sha++
	return fmt.Sprintf("%040x", s.sha)
}

// AddRepo creates owner/name with default branch "main" at a fresh sha.
func (s *Server) AddRepo(owner, name string) *Repo {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := &Repo{Owner: owner, Name: name, DefaultBranch: "main", Branches: map[string]*Branch{"main": {SHA: s.nextSHALocked()}}, Pulls: map[int]*Pull{}}
	s.repos[strings.ToLower(owner+"/"+name)] = r
	return r
}

// SetBranch creates or moves a branch.
func (s *Server) SetBranch(repo, branch, sha string, protected bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[strings.ToLower(repo)].Branches[branch] = &Branch{SHA: sha, Protected: protected}
}

// BranchSHA returns the branch sha ("" if missing).
func (s *Server) BranchSHA(repo, branch string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.repos[strings.ToLower(repo)]
	if r == nil || r.Branches[branch] == nil {
		return ""
	}
	return r.Branches[branch].SHA
}

// PushCommit creates a new commit on top of the branch (as a person or CI
// pushing outside Fortik would) and returns its sha.
func (s *Server) PushCommit(repo, branch string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitLocked(s.repos[strings.ToLower(repo)].Branches[branch])
}

// commitLocked moves br to a new commit whose first parent is its old sha.
func (s *Server) commitLocked(br *Branch) string {
	sha := s.nextSHALocked()
	s.parents[sha] = br.SHA
	br.SHA = sha
	return sha
}

// AddPull adds an open pull request.
func (s *Server) AddPull(repo string, n int, base, head string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[strings.ToLower(repo)].Pulls[n] = &Pull{Number: n, State: "open", Base: base, Head: head}
}

// PullState returns the pull request state.
func (s *Server) PullState(repo string, n int) (state string, merged bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.repos[strings.ToLower(repo)].Pulls[n]
	return p.State, p.Merged
}

// RepoDeleted reports whether DELETE /repos/{o}/{r} reached the fake.
func (s *Server) RepoDeleted(repo string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repos[strings.ToLower(repo)].Deleted
}

// Tokens returns copies of every token minted so far.
func (s *Server) Tokens() []Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, *t)
	}
	return out
}

// LiveTokens counts minted, unrevoked, unexpired tokens.
func (s *Server) LiveTokens() int {
	n := 0
	for _, t := range s.Tokens() {
		if !t.Revoked && time.Now().Before(t.ExpiresAt) {
			n++
		}
	}
	return n
}

// Calls returns the requests served so far.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// CallsMatching counts calls with method and a path prefix.
func (s *Server) CallsMatching(method, pathPrefix string) int {
	n := 0
	for _, c := range s.Calls() {
		if c.Method == method && strings.HasPrefix(c.Path, pathPrefix) {
			n++
		}
	}
	return n
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) { w.code = code; w.ResponseWriter.WriteHeader(code) }

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	sw := &statusWriter{ResponseWriter: w, code: 200}
	auth := "none"
	defer func() {
		s.mu.Lock()
		s.calls = append(s.calls, Call{Method: r.Method, Path: r.URL.Path, Auth: auth, Status: sw.code})
		s.mu.Unlock()
	}()
	segs, ok := segments(r.URL.EscapedPath())
	if !ok {
		writeErr(sw, 404, "Not Found")
		return
	}
	switch {
	case len(segs) >= 3 && segs[0] == "app" && segs[1] == "installations":
		auth = "jwt"
		if !s.checkJWT(r) {
			writeErr(sw, 401, "A JSON web token could not be decoded")
			return
		}
		if segs[2] != s.InstallationID {
			writeErr(sw, 404, "Not Found")
			return
		}
		switch {
		case len(segs) == 3 && r.Method == http.MethodGet:
			s.mu.Lock()
			perms := copyMap(s.InstallPerms)
			s.mu.Unlock()
			id, _ := strconv.ParseInt(s.InstallationID, 10, 64)
			writeJSON(sw, 200, map[string]any{"id": id, "account": map[string]any{"login": s.Account}, "permissions": perms})
		case len(segs) == 4 && segs[3] == "access_tokens" && r.Method == http.MethodPost:
			s.mintToken(sw, r)
		default:
			writeErr(sw, 404, "Not Found")
		}
	case len(segs) == 2 && segs[0] == "installation" && segs[1] == "token" && r.Method == http.MethodDelete:
		auth = "token"
		s.mu.Lock()
		tok := s.tokenLocked(r)
		if tok != nil {
			tok.Revoked = true
		}
		s.mu.Unlock()
		if tok == nil {
			writeErr(sw, 401, "Bad credentials")
			return
		}
		sw.WriteHeader(204)
	case len(segs) >= 3 && segs[0] == "repos":
		auth = "token"
		s.repo(sw, r, segs[1], segs[2], segs[3:])
	default:
		writeErr(sw, 404, "Not Found")
	}
}

func segments(escaped string) ([]string, bool) {
	parts := strings.Split(strings.Trim(escaped, "/"), "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		u, err := url.PathUnescape(p)
		if err != nil {
			return nil, false
		}
		out = append(out, u)
	}
	return out, true
}

func (s *Server) checkJWT(r *http.Request) bool {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	claims := &jwt.RegisteredClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) { return s.pub, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.AppID), jwt.WithIssuedAt(), jwt.WithExpirationRequired())
	if err != nil || !tok.Valid || claims.IssuedAt == nil {
		return false
	}
	return claims.ExpiresAt.Sub(claims.IssuedAt.Time) <= 11*time.Minute
}

func (s *Server) tokenLocked(r *http.Request) *Token {
	h := r.Header.Get("Authorization")
	v, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		v, ok = strings.CutPrefix(h, "token ")
	}
	if !ok {
		return nil
	}
	t := s.tokens[v]
	if t == nil || t.Revoked || time.Now().After(t.ExpiresAt) {
		return nil
	}
	return t
}

func (s *Server) mintToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Repositories []string          `json:"repositories"`
		Permissions  map[string]string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "Problems parsing JSON")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	perms := req.Permissions
	if len(perms) == 0 {
		perms = copyMap(s.InstallPerms)
	}
	for k, v := range perms {
		if rank(v) == 0 || rank(v) > rank(s.InstallPerms[k]) {
			writeErr(w, 422, fmt.Sprintf("The permissions requested are not granted to this installation (%s:%s)", k, v))
			return
		}
	}
	var repoSet map[string]bool
	var repoOut []map[string]any
	selection := "all"
	if len(req.Repositories) > 0 {
		selection = "selected"
		repoSet = map[string]bool{}
		for _, name := range req.Repositories {
			rp := s.repos[strings.ToLower(s.Account+"/"+name)]
			if rp == nil || rp.Deleted {
				writeErr(w, 422, "There is at least one repository that does not exist or is not accessible to the parent installation.")
				return
			}
			repoSet[strings.ToLower(name)] = true
			repoOut = append(repoOut, map[string]any{"name": rp.Name, "full_name": rp.Owner + "/" + rp.Name})
		}
	}
	granted := copyMap(perms)
	if s.grantExtra {
		granted["administration"] = "write"
	}
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	t := &Token{Value: "ghs_fake" + hex.EncodeToString(b), Repos: repoSet, Permissions: granted, ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second)}
	s.tokens[t.Value] = t
	writeJSON(w, 201, map[string]any{"token": t.Value, "expires_at": t.ExpiresAt.UTC().Format(time.RFC3339), "permissions": granted,
		"repositories": repoOut, "repository_selection": selection})
}

// need checks the token may act on repo with perm at level.
func (s *Server) need(w http.ResponseWriter, tok *Token, rp *Repo, perm, level string) bool {
	if tok.Repos != nil && !tok.Repos[strings.ToLower(rp.Name)] {
		writeErr(w, 404, "Not Found")
		return false
	}
	have := tok.Permissions[perm]
	if perm == "metadata" && len(tok.Permissions) > 0 {
		have = "read"
	}
	if rank(have) < rank(level) {
		w.Header().Set("X-Accepted-GitHub-Permissions", perm+"="+level)
		writeErr(w, 403, "Resource not accessible by integration")
		return false
	}
	return true
}

func (s *Server) repo(w http.ResponseWriter, r *http.Request, owner, name string, rest []string) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.mu.Lock()
	defer s.mu.Unlock()
	tok := s.tokenLocked(r)
	if tok == nil {
		writeErr(w, 401, "Bad credentials")
		return
	}
	rp := s.repos[strings.ToLower(owner+"/"+name)]
	if rp == nil || rp.Deleted || !strings.EqualFold(owner, s.Account) {
		writeErr(w, 404, "Not Found")
		return
	}
	m := r.Method
	at := func(i int) string {
		if i < len(rest) {
			return rest[i]
		}
		return ""
	}
	switch {
	case len(rest) == 0 && (m == http.MethodGet || m == http.MethodHead):
		if s.need(w, tok, rp, "metadata", "read") {
			writeJSON(w, 200, map[string]any{"full_name": rp.Owner + "/" + rp.Name, "default_branch": rp.DefaultBranch, "private": true})
		}
	case len(rest) == 0 && m == http.MethodDelete:
		if s.need(w, tok, rp, "administration", "write") {
			rp.Deleted = true
			w.WriteHeader(204)
		}
	case at(0) == "branches" && len(rest) >= 2 && m == http.MethodGet:
		if !s.need(w, tok, rp, "contents", "read") {
			return
		}
		if s.failBranches {
			writeErr(w, 500, "Server Error")
			return
		}
		b := strings.Join(rest[1:], "/")
		br := rp.Branches[b]
		if br == nil {
			writeErr(w, 404, "Branch not found")
			return
		}
		writeJSON(w, 200, map[string]any{"name": b, "protected": br.Protected, "commit": map[string]any{"sha": br.SHA}})
	case at(0) == "git" && at(1) == "ref" && at(2) == "heads" && len(rest) >= 4 && m == http.MethodGet:
		if !s.need(w, tok, rp, "contents", "read") {
			return
		}
		b := strings.Join(rest[3:], "/")
		br := rp.Branches[b]
		if br == nil {
			writeErr(w, 404, "Not Found")
			return
		}
		writeJSON(w, 200, refJSON(rp, b, br.SHA))
	case at(0) == "git" && at(1) == "commits" && len(rest) == 3 && m == http.MethodGet:
		if !s.need(w, tok, rp, "contents", "read") {
			return
		}
		p, ok := s.parents[rest[2]]
		if !ok {
			writeErr(w, 404, "Not Found")
			return
		}
		writeJSON(w, 200, map[string]any{"sha": rest[2], "parents": []map[string]any{{"sha": p}}})
	case at(0) == "git" && at(1) == "refs" && len(rest) == 2 && m == http.MethodPost:
		if !s.need(w, tok, rp, "contents", "write") {
			return
		}
		var req struct{ Ref, SHA string }
		if json.Unmarshal(body, &req) != nil || !strings.HasPrefix(req.Ref, "refs/heads/") || req.SHA == "" {
			writeErr(w, 422, "Invalid request")
			return
		}
		b := strings.TrimPrefix(req.Ref, "refs/heads/")
		if rp.Branches[b] != nil {
			writeErr(w, 422, "Reference already exists")
			return
		}
		rp.Branches[b] = &Branch{SHA: req.SHA}
		writeJSON(w, 201, refJSON(rp, b, req.SHA))
	case at(0) == "git" && at(1) == "refs" && at(2) == "heads" && len(rest) >= 4 && (m == http.MethodPatch || m == http.MethodDelete):
		if !s.need(w, tok, rp, "contents", "write") {
			return
		}
		b := strings.Join(rest[3:], "/")
		br := rp.Branches[b]
		if br == nil {
			writeErr(w, 422, "Reference does not exist")
			return
		}
		if m == http.MethodDelete {
			delete(rp.Branches, b)
			w.WriteHeader(204)
			return
		}
		var req struct {
			SHA   string `json:"sha"`
			Force bool   `json:"force"`
		}
		if json.Unmarshal(body, &req) != nil || req.SHA == "" {
			writeErr(w, 422, "Invalid request")
			return
		}
		br.SHA = req.SHA
		writeJSON(w, 200, refJSON(rp, b, br.SHA))
	case at(0) == "contents" && len(rest) >= 2 && m == http.MethodPut:
		path := strings.Join(rest[1:], "/")
		if !s.need(w, tok, rp, "contents", "write") {
			return
		}
		if strings.HasPrefix(path, ".github/workflows/") && !s.need(w, tok, rp, "workflows", "write") {
			return
		}
		var req struct {
			Message string `json:"message"`
			Content string `json:"content"`
			Branch  string `json:"branch"`
		}
		if json.Unmarshal(body, &req) != nil || req.Message == "" {
			writeErr(w, 422, "Invalid request")
			return
		}
		b := req.Branch
		if b == "" {
			b = rp.DefaultBranch
		}
		br := rp.Branches[b]
		if br == nil {
			writeErr(w, 404, "Branch not found")
			return
		}
		s.commitLocked(br)
		writeJSON(w, 201, map[string]any{"content": map[string]any{"path": path}, "commit": map[string]any{"sha": br.SHA}})
	case at(0) == "pulls" && len(rest) >= 2:
		n, err := strconv.Atoi(rest[1])
		pr := rp.Pulls[n]
		if err != nil || pr == nil {
			writeErr(w, 404, "Not Found")
			return
		}
		switch {
		case len(rest) == 2 && m == http.MethodGet:
			if s.need(w, tok, rp, "pull_requests", "read") {
				writeJSON(w, 200, pullJSON(pr))
			}
		case len(rest) == 2 && m == http.MethodPatch:
			if !s.need(w, tok, rp, "pull_requests", "write") {
				return
			}
			var req struct {
				State string `json:"state"`
			}
			_ = json.Unmarshal(body, &req)
			if req.State != "" {
				if pr.Merged && req.State == "open" {
					writeErr(w, 422, "Cannot reopen a merged pull request")
					return
				}
				pr.State = req.State
			}
			writeJSON(w, 200, pullJSON(pr))
		case len(rest) == 3 && rest[2] == "merge" && m == http.MethodPut:
			if !s.need(w, tok, rp, "contents", "write") {
				return
			}
			if pr.State != "open" {
				writeErr(w, 405, "Pull Request is not mergeable")
				return
			}
			base := rp.Branches[pr.Base]
			if base == nil {
				writeErr(w, 422, "Base branch missing")
				return
			}
			s.commitLocked(base)
			pr.State, pr.Merged = "closed", true
			writeJSON(w, 200, map[string]any{"merged": true, "sha": base.SHA, "message": "Pull Request successfully merged"})
		default:
			writeErr(w, 404, "Not Found")
		}
	case at(0) == "issues" && len(rest) == 3 && rest[2] == "comments" && m == http.MethodPost:
		if s.need(w, tok, rp, "issues", "write") {
			writeJSON(w, 201, map[string]any{"id": 1, "body_bytes": len(body)})
		}
	case at(0) == "fortik-test" && at(1) == "echo-auth":
		// Deliberately misbehaving endpoint (test only): echoes the
		// credential it received, so tests can prove the gateway never lets
		// a token reach the agent even when the upstream leaks it.
		writeJSON(w, 200, map[string]any{"authorization": r.Header.Get("Authorization")})
	default:
		writeErr(w, 404, "Not Found")
	}
}

func refJSON(rp *Repo, branch, sha string) map[string]any {
	return map[string]any{"ref": "refs/heads/" + branch, "object": map[string]any{"type": "commit", "sha": sha},
		"url": "/repos/" + rp.Owner + "/" + rp.Name + "/git/refs/heads/" + branch}
}

func pullJSON(p *Pull) map[string]any {
	return map[string]any{"number": p.Number, "state": p.State, "merged": p.Merged,
		"base": map[string]any{"ref": p.Base}, "head": map[string]any{"ref": p.Head}}
}

func rank(l string) int {
	switch l {
	case "read":
		return 1
	case "write":
		return 2
	case "admin":
		return 3
	}
	return 0
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"message": msg, "documentation_url": "https://docs.github.com/rest"})
}
