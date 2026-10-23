package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	flowCookie = "fortik_oidc"
	flowTTL    = 10 * time.Minute
)

type oidcClient struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// flowData is the login-in-progress state kept in a signed cookie: the
// state and nonce the callback must see again, and the PKCE verifier.
type flowData struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Exp      int64  `json:"e"`
}

// provider discovers the issuer once (lazily, so Fortik starts even when the
// IdP is briefly unreachable); failures are retried on the next login.
func (s *Service) provider() (*oidcClient, error) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if s.oidc != nil {
		return s.oidc, nil
	}
	// go-oidc keeps this context for later JWKS refreshes, so it must not be
	// request-scoped; the client's own timeout bounds each call.
	ctx := oidc.ClientContext(context.Background(), s.http)
	p, err := oidc.NewProvider(ctx, s.cfg.OIDC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	s.oidc = &oidcClient{provider: p, verifier: p.Verifier(&oidc.Config{ClientID: s.cfg.OIDC.ClientID, Now: s.now})}
	return s.oidc, nil
}

func (s *Service) oauthConfig(ctx context.Context, oc *oidcClient) (*oauth2.Config, error) {
	var secret string
	if name := s.cfg.OIDC.ClientSecretSecret; name != "" {
		b, err := s.sec.Get(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("oidc client secret: %w", err)
		}
		secret = strings.TrimSpace(string(b))
	}
	return &oauth2.Config{
		ClientID: s.cfg.OIDC.ClientID, ClientSecret: secret, Endpoint: oc.provider.Endpoint(),
		RedirectURL: s.cfg.OIDC.RedirectURL, Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
	}, nil
}

// handleLogin starts authorization code + PKCE (S256).
func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.oidcOn {
		page(w, http.StatusNotFound, "Single sign-on is not configured", "Ask an administrator to configure auth.oidc.")
		return
	}
	oc, err := s.provider()
	if err != nil {
		s.log.Error("auth: oidc provider unavailable", "err", err)
		page(w, http.StatusServiceUnavailable, "Identity provider unavailable", "Fortik could not reach the identity provider. Try again shortly.")
		return
	}
	cfg, err := s.oauthConfig(r.Context(), oc)
	if err != nil {
		s.log.Error("auth: oidc client secret unavailable", "err", err)
		page(w, http.StatusServiceUnavailable, "Login unavailable", "The OIDC client secret could not be read from the secret store.")
		return
	}
	state, _, err1 := randomToken(32)
	nonce, _, err2 := randomToken(32)
	if err1 != nil || err2 != nil {
		page(w, http.StatusInternalServerError, "Login unavailable", "Could not generate login state.")
		return
	}
	verifier := oauth2.GenerateVerifier()
	if err := s.setFlowCookie(w, flowData{State: state, Nonce: nonce, Verifier: verifier, Exp: s.now().Add(flowTTL).Unix()}); err != nil {
		page(w, http.StatusInternalServerError, "Login unavailable", "Could not start login.")
		return
	}
	http.Redirect(w, r, cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

var idpErrorCode = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// handleCallback completes the login: state, PKCE exchange, ID token
// signature/audience/expiry, nonce, then role mapping.
func (s *Service) handleCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(code int, reason, title, msg, email string) {
		s.recordFailure(r.Context(), MethodOIDC, reason, email)
		page(w, code, title, msg)
	}
	if !s.oidcOn {
		page(w, http.StatusNotFound, "Single sign-on is not configured", "")
		return
	}
	flow, ok := s.readFlowCookie(r)
	s.clearFlowCookie(w) // single use, whatever happens next
	if !ok {
		fail(http.StatusBadRequest, "bad_state", "Login expired", "This login attempt is missing, expired or was tampered with. Start again.", "")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		if !idpErrorCode.MatchString(e) {
			e = "invalid"
		}
		fail(http.StatusBadRequest, "idp_error:"+e, "Login refused", "The identity provider refused the login ("+e+").", "")
		return
	}
	if st := q.Get("state"); st == "" || subtle.ConstantTimeCompare([]byte(st), []byte(flow.State)) != 1 {
		fail(http.StatusBadRequest, "bad_state", "Login expired", "The login state did not match. Start again.", "")
		return
	}
	code := q.Get("code")
	if code == "" {
		fail(http.StatusBadRequest, "missing_code", "Login failed", "The identity provider returned no authorization code.", "")
		return
	}
	oc, err := s.provider()
	if err != nil {
		s.log.Error("auth: oidc provider unavailable", "err", err)
		fail(http.StatusServiceUnavailable, "idp_unavailable", "Identity provider unavailable", "Try again shortly.", "")
		return
	}
	cfg, err := s.oauthConfig(r.Context(), oc)
	if err != nil {
		s.log.Error("auth: oidc client secret unavailable", "err", err)
		fail(http.StatusServiceUnavailable, "client_secret_unavailable", "Login unavailable", "The OIDC client secret could not be read.", "")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithValue(r.Context(), oauth2.HTTPClient, s.http), 20*time.Second)
	defer cancel()
	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		// Never log the code or the response body; the error code is enough.
		var re *oauth2.RetrieveError
		reason := "transport"
		if errors.As(err, &re) && idpErrorCode.MatchString(re.ErrorCode) {
			reason = re.ErrorCode
		}
		s.log.Warn("auth: oidc token exchange failed", "reason", reason)
		fail(http.StatusBadGateway, "token_exchange_failed", "Login failed", "The authorization code could not be exchanged.", "")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		fail(http.StatusBadGateway, "no_id_token", "Login failed", "The identity provider returned no ID token.", "")
		return
	}
	idt, err := oc.verifier.Verify(ctx, rawID)
	if err != nil {
		s.log.Warn("auth: id token rejected", "err", err)
		fail(http.StatusUnauthorized, "id_token_invalid", "Login failed", "The ID token could not be verified.", "")
		return
	}
	if idt.Nonce == "" || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(flow.Nonce)) != 1 {
		fail(http.StatusUnauthorized, "nonce_mismatch", "Login failed", "The ID token was not issued for this login attempt.", "")
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		fail(http.StatusBadGateway, "bad_claims", "Login failed", "The ID token claims could not be read.", "")
		return
	}
	email, _ := claims["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		fail(http.StatusForbidden, "no_email", "Login refused", "Your identity has no email address; Fortik needs one to identify you.", "")
		return
	}
	if v, present := claims["email_verified"]; present {
		if b, ok := v.(bool); !ok || !b {
			fail(http.StatusForbidden, "email_unverified", "Login refused", "Your email address is not verified by the identity provider.", email)
			return
		}
	}
	name := firstString(claims, "name", "preferred_username")
	if name == "" {
		name = email
	}
	roles := s.mapRoles(email, claims)
	if len(roles) == 0 {
		fail(http.StatusForbidden, "no_roles", "No Fortik access",
			"You signed in as "+email+", but no Fortik role is mapped to your account. Ask a Fortik administrator to grant you a role.", email)
		return
	}
	cookie, _, err := s.createSession(r.Context(), email, name, roles, MethodOIDC)
	if err != nil {
		s.log.Error("auth: create session failed", "err", err)
		page(w, http.StatusInternalServerError, "Login failed", "The session could not be created.")
		return
	}
	s.setSessionCookie(w, cookie)
	http.Redirect(w, r, s.redirect, http.StatusFound)
}

// mapRoles unions role_map[claim values] and email_roles[email].
func (s *Service) mapRoles(email string, claims map[string]any) []string {
	set := map[string]bool{}
	if c := s.cfg.OIDC.RoleClaim; c != "" {
		for _, v := range claimValues(claims, c) {
			for _, r := range s.cfg.OIDC.RoleMap[v] {
				set[r] = true
			}
		}
	}
	for _, r := range s.emailRoles[email] {
		set[r] = true
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// claimValues reads a string or string-array claim; a dotted path walks
// nested objects (e.g. "realm_access.roles").
func claimValues(claims map[string]any, path string) []string {
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if v, ok := m[part]; ok {
			cur = v
			continue
		}
		// A literal dotted key (some IdPs use URLs as claim names).
		if v, ok := claims[path]; ok {
			cur = v
			break
		}
		return nil
	}
	switch v := cur.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func firstString(claims map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := claims[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// --- signed flow cookie -----------------------------------------------------------

func (s *Service) sign(payload string) string {
	m := hmac.New(sha256.New, s.flowKey)
	m.Write([]byte(flowCookie + "|" + payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Service) setFlowCookie(w http.ResponseWriter, f flowData) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	payload := base64.RawURLEncoding.EncodeToString(b)
	// SameSite=Lax (not Strict): the callback is a top-level navigation from
	// the IdP's site, on which Strict cookies are withheld.
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: payload + "." + s.sign(payload), Path: "/auth/",
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteLaxMode, MaxAge: int(flowTTL / time.Second)})
	return nil
}

func (s *Service) clearFlowCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: "", Path: "/auth/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (s *Service) readFlowCookie(r *http.Request) (flowData, bool) {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		return flowData{}, false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.sign(payload))) {
		return flowData{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return flowData{}, false
	}
	var f flowData
	if err := json.Unmarshal(b, &f); err != nil || f.State == "" || f.Nonce == "" || f.Verifier == "" {
		return flowData{}, false
	}
	if s.now().Unix() > f.Exp {
		return flowData{}, false
	}
	return f, true
}
