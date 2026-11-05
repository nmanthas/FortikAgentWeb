package nsquickstart

// OAuth 2.0 authorization code + PKCE for a full NetSuite account's AI
// Connector Service (connection type netsuite_mcp). Facts from Oracle's
// NetSuite help (read 2026-10-27):
//   - authorize: https://<account>.app.netsuite.com/app/login/oauth2/authorize.nl
//     (response_type=code, client_id, redirect_uri, scope, state 22..1024
//     printable chars, code_challenge S256 required for public clients);
//   - token: https://<account>.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token
//     (public clients send client_id in the body); access tokens last 60
//     minutes; a public client's refresh token lasts 2 days by default
//     (1 h..30 days on the integration record) and is ONE-TIME USE;
//   - revoke: .../services/rest/auth/oauth2/v1/revoke (token=<refresh token>).
// The AI Connector Service needs an integration record with Public Client,
// Authorization Code Grant and the "NetSuite AI Connector Service" scope; the
// scope's value is not given by Oracle (configurable; third-party guides use
// "mcp"). Every tool call runs with the authorizing user's role, which must
// not be Administrator.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"fortik/internal/authz"
	"fortik/internal/diary"
	"fortik/internal/httpx"
	"fortik/internal/integrations"
	"fortik/internal/secrets"
)

// OAuth paths and limits.
const (
	authorizePath   = "/app/login/oauth2/authorize.nl"
	tokenPath       = "/services/rest/auth/oauth2/v1/token"
	revokePath      = "/services/rest/auth/oauth2/v1/revoke"
	CallbackPath    = "/v1/oauth/netsuite/callback"
	pendingTTL      = 10 * time.Minute
	refreshSkew     = time.Minute
	maxTokenBody    = 64 << 10
	tokenSecretName = "oauth_tokens"
)

// Diary events of OAuth.
const (
	EventOAuthStarted    = "mcp.oauth.started"
	EventOAuthAuthorized = "mcp.oauth.authorized"
	EventOAuthRevoked    = "mcp.oauth.revoked"
	EventOAuthRefreshed  = "mcp.oauth.refresh_failed"
)

var (
	errNotAuthorized = errors.New("no user has authorized Fortik for this connection yet: click Authorize")
	errAuthExpired   = errors.New("the authorization expired or was revoked: authorize Fortik again")
)

func oauthState(err error) string {
	switch {
	case errors.Is(err, errNotAuthorized):
		return StateAuthRequired
	case errors.Is(err, errAuthExpired):
		return StateAuthFailed
	}
	return StateUnavailable
}

// oauthTokens is the managed secret (integration/<key>/oauth_tokens).
type oauthTokens struct {
	AccessToken     string    `json:"access_token"`
	AccessExpiresAt time.Time `json:"access_expires_at"`
	RefreshToken    string    `json:"refresh_token"`
	AccountID       string    `json:"account_id"`
	ClientID        string    `json:"client_id"`
	Scope           string    `json:"scope"`
	AuthorizedAt    time.Time `json:"authorized_at"`
	AuthorizedBy    string    `json:"authorized_by"` // the Fortik administrator who started it
	RefreshedAt     time.Time `json:"refreshed_at"`
}

// OAuthView is the authorization state shown in the status (no tokens).
type OAuthView struct {
	Authorized      bool       `json:"authorized"`
	AuthorizedAt    *time.Time `json:"authorized_at,omitempty"`
	AuthorizedBy    string     `json:"authorized_by,omitempty"`
	AccessExpiresAt *time.Time `json:"access_expires_at,omitempty"`
	RefreshedAt     *time.Time `json:"refreshed_at,omitempty"`
	Stale           bool       `json:"stale,omitempty"` // tokens were issued for another account or client
	Scope           string     `json:"scope,omitempty"`
}

func (s *Service) keyLock(key string) *sync.Mutex {
	s.oauthMu.Lock()
	defer s.oauthMu.Unlock()
	m := s.oauthLock[key]
	if m == nil {
		m = &sync.Mutex{}
		s.oauthLock[key] = m
	}
	return m
}

func (s *Service) loadTokens(ctx context.Context, key string) (*oauthTokens, error) {
	if s.secrets == nil {
		return nil, errors.New("the secret store is not available")
	}
	b, err := s.secrets.Get(ctx, integrations.SecretName(key, tokenSecretName))
	if errors.Is(err, secrets.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var t oauthTokens
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, errors.New("stored OAuth tokens are unreadable")
	}
	return &t, nil
}

func (s *Service) saveTokens(ctx context.Context, key string, t *oauthTokens) error {
	b, _ := json.Marshal(t)
	return s.secrets.Put(ctx, integrations.SecretName(key, tokenSecretName), b)
}

// oauthView reports a connection's authorization without any token.
func (s *Service) oauthView(ctx context.Context, st Settings) *OAuthView {
	if st.Auth != AuthOAuth {
		return nil
	}
	v := &OAuthView{}
	t, err := s.loadTokens(ctx, st.Key)
	if err != nil || t == nil {
		return v
	}
	v.Authorized, v.AuthorizedBy, v.Scope = true, t.AuthorizedBy, t.Scope
	v.AuthorizedAt, v.AccessExpiresAt = &t.AuthorizedAt, &t.AccessExpiresAt
	if !t.RefreshedAt.IsZero() {
		v.RefreshedAt = &t.RefreshedAt
	}
	if t.AccountID != st.AccountID || t.ClientID != st.ClientID {
		v.Authorized, v.Stale = false, true
	}
	return v
}

// bearer fills st.Token for an OAuth connection: the stored access token,
// refreshed (once, serialised per connection) when it is about to expire.
// PAT connections already carry their token.
func (s *Service) bearer(ctx context.Context, st *Settings) error {
	if st.Auth == AuthClientCreds {
		return s.clientCredentials(ctx, st)
	}
	if st.Auth != AuthOAuth {
		return nil
	}
	mu := s.keyLock(st.Key)
	mu.Lock()
	defer mu.Unlock()
	t, err := s.loadTokens(ctx, st.Key)
	if err != nil {
		return err
	}
	if t == nil {
		return errNotAuthorized
	}
	if t.AccountID != st.AccountID || t.ClientID != st.ClientID {
		return fmt.Errorf("%w (the stored authorization is for another account or client)", errNotAuthorized)
	}
	if time.Until(t.AccessExpiresAt) > refreshSkew {
		st.Token = t.AccessToken
		return nil
	}
	if t.RefreshToken == "" {
		return fmt.Errorf("%w (the access token expired and the provider issued no refresh token)", errAuthExpired)
	}
	tr, err := s.tokenRequest(ctx, *st, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {t.RefreshToken}, "client_id": {st.ClientID}})
	if err != nil {
		if errors.Is(err, errAuthExpired) {
			s.appendDiary(ctx, diary.Event{EventType: EventOAuthRefreshed, Actor: "system:netsuite_mcp", Data: map[string]any{
				"connection": st.Key, "integration_id": st.IntegrationID, "reason": clip(err.Error(), 200)}})
		}
		return err
	}
	t.AccessToken, t.AccessExpiresAt, t.RefreshedAt = tr.AccessToken, time.Now().Add(tr.expiresIn()), time.Now().UTC()
	if tr.RefreshToken != "" {
		t.RefreshToken = tr.RefreshToken // one-time use: the old one is spent
	}
	if err := s.saveTokens(ctx, st.Key, t); err != nil {
		return fmt.Errorf("store refreshed OAuth tokens: %w", err)
	}
	st.Token = t.AccessToken
	return nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (t tokenResponse) expiresIn() time.Duration {
	if t.ExpiresIn <= 0 || t.ExpiresIn > 24*3600 {
		return time.Hour // Oracle: always 3600
	}
	return time.Duration(t.ExpiresIn) * time.Second
}

// tokenRequest POSTs to the token endpoint (a public client: client_id in
// the body, no secret). invalid_grant is errAuthExpired.
func (s *Service) tokenRequest(ctx context.Context, st Settings, form url.Values) (tokenResponse, error) {
	endpoint := st.TokenURL
	if st.ClientSecret != "" && form.Get("client_secret") == "" {
		form.Set("client_secret", st.ClientSecret) // a confidential client
	}
	if reason := s.endpointRefused(ctx, endpoint, st.System); reason != "" {
		return tokenResponse{}, errors.New("token endpoint not permitted: " + reason)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("token endpoint unreachable: %s", clip(err.Error(), 200))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenBody))
	var tr tokenResponse
	_ = json.Unmarshal(b, &tr)
	switch {
	case resp.StatusCode == http.StatusOK && tr.AccessToken != "":
		return tr, nil
	case tr.Error == "invalid_grant" || resp.StatusCode == http.StatusUnauthorized:
		return tokenResponse{}, fmt.Errorf("%w (%s)", errAuthExpired, clip(strings.TrimSpace(tr.Error+" "+tr.ErrorDesc), 160))
	case tr.Error != "":
		return tokenResponse{}, fmt.Errorf("token endpoint refused: %s %s", clip(tr.Error, 60), clip(tr.ErrorDesc, 160))
	}
	return tokenResponse{}, fmt.Errorf("token endpoint answered HTTP %d", resp.StatusCode)
}

// pending is one authorization in flight (secret oauth_pending/<state hash>).
type pending struct {
	Key       string    `json:"key"`
	Verifier  string    `json:"verifier"`
	Version   time.Time `json:"version"`
	Actor     string    `json:"actor"`
	ExpiresAt time.Time `json:"expires_at"`
}

func pendingName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return "oauth_pending/" + hex.EncodeToString(sum[:16])
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b) // [A-Za-z0-9_-]: valid verifier and state characters
}

// StartOAuth begins authorization: it returns the NetSuite URL the
// administrator opens; the code comes back to CallbackPath.
func (s *Service) StartOAuth(ctx context.Context, key, actor string) (string, error) {
	r, err := s.store.Resolve(ctx, key)
	if err != nil {
		return "", err
	}
	if !isMCPSystem(r.System) {
		return "", fmt.Errorf("%w: %s is not an MCP connection", integrations.ErrInvalid, key)
	}
	st, err := settingsFrom(r)
	if err != nil {
		return "", err
	}
	if st.Auth != AuthOAuth {
		return "", fmt.Errorf("%w: %s does not use the OAuth authorization code flow", integrations.ErrInvalid, key)
	}
	if s.secrets == nil {
		return "", errors.New("the secret store is not available")
	}
	state, verifier := randomString(32), randomString(48) // 43 and 64 characters
	sum := sha256.Sum256([]byte(verifier))
	p, _ := json.Marshal(pending{Key: key, Verifier: verifier, Version: st.Version, Actor: actor, ExpiresAt: time.Now().Add(pendingTTL)})
	if err := s.secrets.Put(ctx, pendingName(state), p); err != nil {
		return "", fmt.Errorf("store pending authorization: %w", err)
	}
	q := url.Values{"response_type": {"code"}, "client_id": {st.ClientID}, "redirect_uri": {st.RedirectURI}, "scope": {st.Scope},
		"state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "prompt": {"consent"}}
	s.appendDiary(ctx, diary.Event{EventType: EventOAuthStarted, Actor: actor, Data: map[string]any{
		"connection": key, "integration_id": st.IntegrationID, "account_id": st.AccountID, "scope": st.Scope}})
	sep := "?"
	if strings.Contains(st.AuthorizeURL, "?") {
		sep = "&"
	}
	if reason := s.endpointRefused(ctx, st.AuthorizeURL, st.System); reason != "" {
		return "", fmt.Errorf("%w: the authorization URL is not permitted: %s", integrations.ErrInvalid, reason)
	}
	return st.AuthorizeURL + sep + q.Encode(), nil
}

// CompleteOAuth exchanges the code of a pending authorization, stores the
// tokens and runs a live check. It returns the connection key.
func (s *Service) CompleteOAuth(ctx context.Context, state, code, actor string) (string, error) {
	if s.secrets == nil {
		return "", errors.New("the secret store is not available")
	}
	name := pendingName(state)
	b, err := s.secrets.Get(ctx, name)
	if err != nil {
		return "", errors.New("unknown or already used authorization: start again from the console")
	}
	_ = s.secrets.Delete(ctx, name) // one-time
	var p pending
	if json.Unmarshal(b, &p) != nil || time.Now().After(p.ExpiresAt) {
		return "", errors.New("the authorization expired: start again from the console")
	}
	r, err := s.store.Resolve(ctx, p.Key)
	if err != nil {
		return p.Key, err
	}
	st, err := settingsFrom(r)
	if err != nil {
		return p.Key, err
	}
	if !st.Version.Equal(p.Version) {
		return p.Key, errors.New("the connection's settings changed during authorization: start again")
	}
	tr, err := s.tokenRequest(ctx, st, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {st.RedirectURI},
		"client_id": {st.ClientID}, "code_verifier": {p.Verifier}})
	if err != nil {
		return p.Key, err
	}
	if tr.RefreshToken == "" && st.System == integrations.SystemNetSuiteMCP {
		return p.Key, errors.New("NetSuite issued no refresh token: check the integration record (authorization code grant)")
	}
	now := time.Now().UTC()
	t := &oauthTokens{AccessToken: tr.AccessToken, AccessExpiresAt: now.Add(tr.expiresIn()), RefreshToken: tr.RefreshToken,
		AccountID: st.AccountID, ClientID: st.ClientID, Scope: st.Scope, AuthorizedAt: now, AuthorizedBy: p.Actor}
	mu := s.keyLock(p.Key)
	mu.Lock()
	err = s.saveTokens(ctx, p.Key, t)
	mu.Unlock()
	if err != nil {
		return p.Key, fmt.Errorf("store OAuth tokens: %w", err)
	}
	s.up(p.Key).drop()
	s.appendDiary(ctx, diary.Event{EventType: EventOAuthAuthorized, Actor: actor, Data: map[string]any{
		"connection": p.Key, "integration_id": st.IntegrationID, "account_id": st.AccountID, "started_by": p.Actor}})
	if err := s.check(ctx, r, actor); err != nil {
		s.log.Warn("netsuite mcp: check after authorization", "key", p.Key, "err", err)
	}
	return p.Key, nil
}

// beforeDisconnect revokes an OAuth grant with the provider before the
// tokens are deleted (integrations.PGStore.Disconnect); for other
// credentials it says what is NOT revoked. The note says what the provider
// confirmed.
func (s *Service) beforeDisconnect(ctx context.Context, key, actor string) string {
	system, err := integrations.ParseKey(key)
	if err != nil || !isMCPSystem(system) {
		return ""
	}
	if system == integrations.SystemNetSuiteQuickStart {
		return "The QuickStart personal access token was removed from Fortik but NOT revoked: revoke it in QuickStart > Menu > Administration > QuickStart settings > Personal access tokens."
	}
	who := kindTitle(system)
	if system == integrations.SystemNetSuiteMCP {
		who = "NetSuite"
	}
	r, err := s.store.Resolve(ctx, key)
	if err != nil {
		return who + " credentials NOT revoked (the connection could not be read): revoke Fortik's access with the provider."
	}
	st, err := settingsFrom(r)
	switch {
	case st.Auth == AuthBearer:
		return "The bearer token was removed from Fortik but NOT revoked: revoke it where it was issued."
	case st.Auth == AuthClientCreds:
		return "Fortik's tokens were deleted, but the OAuth client stays valid: disable it or rotate its secret with the provider."
	case err != nil && st.Auth != AuthOAuth:
		return who + " credentials NOT revoked: revoke Fortik's access with the provider."
	}
	t, err := s.loadTokens(ctx, key)
	if err != nil || t == nil {
		return "No " + who + " authorization was stored: nothing to revoke."
	}
	if st.RevokeURL == "" {
		return who + " OAuth grant NOT revoked (no revocation URL is configured): revoke Fortik's access with the provider."
	}
	tok := t.RefreshToken
	if tok == "" {
		tok = t.AccessToken
	}
	ok, detail := s.revoke(ctx, st, tok)
	s.appendDiary(ctx, diary.Event{EventType: EventOAuthRevoked, Actor: actor, Data: map[string]any{
		"connection": key, "integration_id": st.IntegrationID, "revoked": ok, "detail": detail}})
	if ok {
		return who + " confirmed the revocation of Fortik's OAuth grant (refresh token and its access tokens)."
	}
	return who + " OAuth grant NOT confirmed revoked (" + detail + "): revoke Fortik's access with the provider."
}

func (s *Service) revoke(ctx context.Context, st Settings, refresh string) (bool, string) {
	endpoint := st.RevokeURL
	if reason := s.endpointRefused(ctx, endpoint, st.System); reason != "" {
		return false, "revoke endpoint not permitted: " + reason
	}
	form := url.Values{"token": {refresh}, "client_id": {st.ClientID}}
	if st.ClientSecret != "" {
		form.Set("client_secret", st.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, "invalid revoke request"
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.http.Do(req)
	if err != nil {
		return false, "revoke endpoint unreachable"
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxTokenBody))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
}

func (s *Service) appendDiary(ctx context.Context, ev diary.Event) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if _, err := s.diary.Append(dctx, ev); err != nil {
		s.log.Error("netsuite mcp: diary", "event", ev.EventType, "err", err)
	}
}

// registerOAuth mounts:
//
//	POST /v1/integrations/{key}/oauth/start  security  {authorize_url}
//	GET  /v1/oauth/netsuite/callback         security (the console session in the browser)
//	GET  /v1/oauth/mcp/callback              the same, for Salesforce, ServiceNow and SAP MCP connections
func (s *Service) registerOAuth(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/integrations/{key}/oauth/start", func(w http.ResponseWriter, r *http.Request) {
		p, ok := authz.Require(w, r, authz.RoleSecurity)
		if !ok {
			return
		}
		u, err := s.StartOAuth(r.Context(), r.PathValue("key"), p.Actor())
		switch {
		case errors.Is(err, integrations.ErrInvalid):
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, integrations.ErrNotConfigured):
			httpx.WriteError(w, http.StatusNotFound, "connection not configured")
		case err != nil:
			s.log.Error("netsuite mcp: start authorization", "err", err)
			httpx.WriteError(w, http.StatusInternalServerError, "could not start the authorization (see server log)")
		default:
			httpx.WriteJSON(w, http.StatusOK, map[string]any{"authorize_url": u, "expires_in": int(pendingTTL.Seconds())})
		}
	})
	callback := func(w http.ResponseWriter, r *http.Request) {
		p, ok := authz.Require(w, r, authz.RoleSecurity)
		if !ok {
			return
		}
		q := r.URL.Query()
		back := func(key, errText string) {
			v := url.Values{}
			if key != "" {
				v.Set("oauth", key)
			}
			if errText != "" {
				v.Set("oauth_error", clip(errText, 200))
			} else {
				v.Set("oauth_ok", "1")
			}
			http.Redirect(w, r, "/integrations?"+v.Encode(), http.StatusFound)
		}
		if e := q.Get("error"); e != "" {
			// The NetSuite user refused, or NetSuite rejected the request.
			_ = s.secrets.Delete(r.Context(), pendingName(q.Get("state")))
			back("", "NetSuite answered "+clip(e, 60)+": "+clip(q.Get("error_description"), 120))
			return
		}
		state, code := q.Get("state"), q.Get("code")
		if len(state) < 22 || len(state) > 1024 || code == "" || len(code) > 4096 {
			back("", "the callback has no valid state or code")
			return
		}
		key, err := s.CompleteOAuth(context.WithoutCancel(r.Context()), state, code, p.Actor())
		if err != nil {
			back(key, err.Error())
			return
		}
		back(key, "")
	}
	mux.HandleFunc("GET "+CallbackPath, callback)
	mux.HandleFunc("GET "+integrations.MCPCallbackPath, callback)
}

// clientCredentials fills st.Token from the OAuth client credentials grant,
// reusing the stored access token until it is about to expire.
func (s *Service) clientCredentials(ctx context.Context, st *Settings) error {
	mu := s.keyLock(st.Key)
	mu.Lock()
	defer mu.Unlock()
	t, err := s.loadTokens(ctx, st.Key)
	if err != nil {
		return err
	}
	if t != nil && t.AccountID == st.AccountID && t.ClientID == st.ClientID && time.Until(t.AccessExpiresAt) > refreshSkew {
		st.Token = t.AccessToken
		return nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {st.ClientID}}
	if st.Scope != "" {
		form.Set("scope", st.Scope)
	}
	tr, err := s.tokenRequest(ctx, *st, form)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	t = &oauthTokens{AccessToken: tr.AccessToken, AccessExpiresAt: now.Add(tr.expiresIn()), AccountID: st.AccountID, ClientID: st.ClientID,
		Scope: st.Scope, AuthorizedAt: now, AuthorizedBy: "client_credentials"}
	if err := s.saveTokens(ctx, st.Key, t); err != nil {
		return fmt.Errorf("store OAuth tokens: %w", err)
	}
	st.Token = t.AccessToken
	return nil
}
