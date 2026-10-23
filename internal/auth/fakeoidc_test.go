package auth

// fakeOIDC is a LOCAL FAKE identity provider for tests. It implements only
// the subset of OpenID Connect that Fortik uses: discovery, JWKS, the
// authorization endpoint (auto-consents and redirects back with a code), and
// the token endpoint (authorization_code grant with PKCE S256 verification
// and client_secret_basic/post authentication), issuing RS256 ID tokens
// signed with go-jose. It is never a real provider.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type fakeOIDC struct {
	t        *testing.T
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	secret   string

	mu sync.Mutex
	// claims issued for the next login (email, groups, ...).
	claims map[string]any
	// nonceOverride replaces the nonce in the ID token (nonce mismatch test).
	nonceOverride string
	codes         map[string]fakeCode
	// lastChallengeMethod records what the client sent to /authorize.
	lastChallengeMethod string
	tokenCalls          int
	pkceFailures        int
}

type fakeCode struct {
	nonce, challenge, redirect string
	claims                     map[string]any
}

func newFakeOIDC(t *testing.T, clientID, secret string) *fakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOIDC{t: t, key: key, clientID: clientID, secret: secret, codes: map[string]fakeCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /jwks", f.jwks)
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOIDC) issuer() string { return f.srv.URL }

func (f *fakeOIDC) setClaims(c map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = c
}

func (f *fakeOIDC) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSONT(w, map[string]any{
		"issuer":                                f.issuer(),
		"authorization_endpoint":                f.issuer() + "/authorize",
		"token_endpoint":                        f.issuer() + "/token",
		"jwks_uri":                              f.issuer() + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (f *fakeOIDC) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSONT(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
}

func (f *fakeOIDC) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastChallengeMethod = q.Get("code_challenge_method")
	if q.Get("client_id") != f.clientID || q.Get("response_type") != "code" || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	code := randString()
	f.codes[code] = fakeCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), claims: f.claims}
	u, _ := url.Parse(q.Get("redirect_uri"))
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (f *fakeOIDC) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenCalls++
	id, sec, ok := r.BasicAuth()
	if !ok {
		id, sec = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != f.clientID || sec != f.secret {
		writeJSONCode(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	c, ok := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code")) // single use
	if !ok || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != c.redirect {
		writeJSONCode(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
		f.pkceFailures++
		writeJSONCode(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
	}
	nonce := c.nonce
	if f.nonceOverride != "" {
		nonce = f.nonceOverride
	}
	now := time.Now()
	claims := map[string]any{"iss": f.issuer(), "aud": f.clientID, "sub": "user-1", "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "nonce": nonce}
	for k, v := range c.claims {
		claims[k] = v
	}
	writeJSONT(w, map[string]any{"access_token": "fake-access-" + randString(), "token_type": "Bearer", "expires_in": 300,
		"id_token": f.sign(claims)})
}

func (f *fakeOIDC) sign(claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		f.t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		f.t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func randString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSONT(w http.ResponseWriter, v any) { writeJSONCode(w, http.StatusOK, v) }

func writeJSONCode(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
