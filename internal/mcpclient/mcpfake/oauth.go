package mcpfake

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// OAuthServer is a LOCAL FAKE of a provider's OAuth 2.0 endpoints in front
// of a fake MCP server. By default it has a full NetSuite account's paths for
// the AI Connector Service and Oracle's documented behaviour for public
// clients: authorization code + PKCE (S256), client_id in the body,
// one-time-use refresh tokens, and a revoke endpoint. Paths and a client
// secret (a confidential client, as Salesforce and ServiceNow use) are
// configurable. It is not any provider.
type OAuthServer struct {
	MCP         *Server // its Token is set to the current access token
	ClientID    string
	RedirectURI string
	// RefuseRefresh answers every refresh with invalid_grant (revoked or
	// expired authorization); RevokeStatus overrides the revoke answer.
	RefuseRefresh bool
	RevokeStatus  int
	// ClientSecret, when set, must accompany every token and revoke request.
	ClientSecret string
	// Paths (default: NetSuite's). MCPPrefix routes to the MCP server.
	AuthorizePath, TokenPath, RevokePath, MCPPrefix string
	// NoRefresh issues no refresh token (a client without that scope).
	NoRefresh bool
	// ClientCredsForMCP: tokens of the client credentials grant are the ones
	// the MCP server accepts (otherwise only user-authorized tokens are).
	ClientCredsForMCP bool

	mu       sync.Mutex
	codes    map[string]codeGrant
	refresh  map[string]bool
	revoked  []string
	issued   int
	lastAuth url.Values
	ccTokens []string
}

// ValidClientToken reports whether t was issued by the client credentials
// grant (for a fake REST API sharing this server).
func (o *OAuthServer) ValidClientToken(t string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, x := range o.ccTokens {
		if x == t {
			return true
		}
	}
	return false
}

type codeGrant struct {
	challenge, redirect string
}

func (o *OAuthServer) init() {
	if o.codes == nil {
		o.codes, o.refresh = map[string]codeGrant{}, map[string]bool{}
	}
}

func fakeToken(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// Revoked returns the refresh tokens the revoke endpoint received.
func (o *OAuthServer) Revoked() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.revoked...)
}

// Issued counts the access tokens issued.
func (o *OAuthServer) Issued() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.issued
}

// LastAuthorize returns the query of the last authorization request.
func (o *OAuthServer) LastAuthorize() url.Values {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastAuth
}

func def(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func (o *OAuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == def(o.AuthorizePath, "/app/login/oauth2/authorize.nl") && r.Method == http.MethodGet:
		o.authorize(w, r)
	case r.URL.Path == def(o.TokenPath, "/services/rest/auth/oauth2/v1/token") && r.Method == http.MethodPost:
		o.token(w, r)
	case r.URL.Path == def(o.RevokePath, "/services/rest/auth/oauth2/v1/revoke") && r.Method == http.MethodPost:
		o.revoke(w, r)
	case strings.HasPrefix(r.URL.Path, def(o.MCPPrefix, "/services/mcp/v1/")):
		o.MCP.ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

// authorize stands in for the NetSuite login and consent screen: it consents
// at once and redirects back with a code.
func (o *OAuthServer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	o.mu.Lock()
	o.init()
	o.lastAuth = q
	o.mu.Unlock()
	if q.Get("response_type") != "code" || q.Get("client_id") != o.ClientID || q.Get("redirect_uri") != o.RedirectURI ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || len(q.Get("state")) < 22 {
		http.Error(w, "LOCAL FAKE: invalid authorization request", http.StatusBadRequest)
		return
	}
	code := fakeToken("code-")
	o.mu.Lock()
	o.codes[code] = codeGrant{challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	o.mu.Unlock()
	v := url.Values{"code": {code}, "state": {q.Get("state")}}
	http.Redirect(w, r, o.RedirectURI+"?"+v.Encode(), http.StatusFound)
}

func (o *OAuthServer) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f := r.PostForm
	fail := func(code int, e string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": e, "error_description": "LOCAL FAKE"})
	}
	if f.Get("client_id") != o.ClientID || r.Header.Get("Authorization") != "" || f.Get("client_secret") != o.ClientSecret {
		fail(http.StatusUnauthorized, "invalid_client")
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.init()
	switch f.Get("grant_type") {
	case "authorization_code":
		g, ok := o.codes[f.Get("code")]
		delete(o.codes, f.Get("code"))
		sum := sha256.Sum256([]byte(f.Get("code_verifier")))
		if !ok || g.redirect != f.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			fail(http.StatusBadRequest, "invalid_grant")
			return
		}
	case "client_credentials":
		// a confidential client authenticating as itself
		if o.ClientSecret == "" {
			fail(http.StatusBadRequest, "unauthorized_client")
			return
		}
	case "refresh_token":
		if o.RefuseRefresh || !o.refresh[f.Get("refresh_token")] {
			fail(http.StatusBadRequest, "invalid_grant")
			return
		}
		delete(o.refresh, f.Get("refresh_token")) // one-time use
	default:
		fail(http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	access, refresh := fakeToken("fake-access-"), fakeToken("fake-refresh-")
	if o.NoRefresh || f.Get("grant_type") == "client_credentials" {
		refresh = ""
	} else {
		o.refresh[refresh] = true
	}
	o.issued++
	if f.Get("grant_type") != "client_credentials" || o.ClientCredsForMCP {
		o.MCP.SetToken(access)
	} else {
		o.ccTokens = append(o.ccTokens, access)
	}
	w.Header().Set("Content-Type", "application/json")
	out := map[string]any{"access_token": access, "expires_in": 3600, "token_type": "bearer"}
	if refresh != "" {
		out["refresh_token"] = refresh
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (o *OAuthServer) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	o.mu.Lock()
	defer o.mu.Unlock()
	o.init()
	if r.PostForm.Get("client_id") != o.ClientID || r.PostForm.Get("client_secret") != o.ClientSecret {
		http.Error(w, "LOCAL FAKE: invalid client", http.StatusUnauthorized)
		return
	}
	if o.RevokeStatus != 0 {
		w.WriteHeader(o.RevokeStatus)
		return
	}
	t := r.PostForm.Get("token")
	o.revoked = append(o.revoked, t)
	delete(o.refresh, t)
	o.MCP.SetToken("revoked-" + fakeToken(""))
	w.WriteHeader(http.StatusOK)
}
