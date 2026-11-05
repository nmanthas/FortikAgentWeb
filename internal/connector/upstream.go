package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fortik/internal/config"
)

// Upstreams.
const (
	UpstreamGoogle = "google_workspace"
	UpstreamGitHub = "github"
)

// UpstreamSystems are the Fortik systems an upstream's connector reaches
// (timed suspensions of these systems apply to the connector too).
var UpstreamSystems = map[string][]string{
	UpstreamGoogle: {"gmail", "drive"},
	UpstreamGitHub: {"github"},
}

// Token is what an upstream token endpoint returned.
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// Upstream is Fortik's own OAuth client at one provider.
type Upstream struct {
	Name         string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	RevokeURL    string
	APIBaseURL   string
	AuditOrg     string
	HTTP         *http.Client
}

// NewUpstream builds an upstream from config (provider defaults for empty URLs).
func NewUpstream(name string, c config.ConnectorUpstreamConfig, secret string) (*Upstream, error) {
	if c.ClientID == "" || secret == "" {
		return nil, fmt.Errorf("connector upstream %s: client_id and client secret are required", name)
	}
	u := &Upstream{Name: name, ClientID: c.ClientID, ClientSecret: secret, AuthURL: c.AuthURL, TokenURL: c.TokenURL,
		RevokeURL: c.RevokeURL, APIBaseURL: c.APIBaseURL, AuditOrg: c.AuditOrg, HTTP: &http.Client{Timeout: 15 * time.Second}}
	switch name {
	case UpstreamGoogle:
		def(&u.AuthURL, "https://accounts.google.com/o/oauth2/v2/auth")
		def(&u.TokenURL, "https://oauth2.googleapis.com/token")
		def(&u.RevokeURL, "https://oauth2.googleapis.com/revoke")
		def(&u.APIBaseURL, "https://admin.googleapis.com")
	case UpstreamGitHub:
		def(&u.AuthURL, "https://github.com/login/oauth/authorize")
		def(&u.TokenURL, "https://github.com/login/oauth/access_token")
		def(&u.APIBaseURL, "https://api.github.com")
	default:
		return nil, fmt.Errorf("connector upstream: unknown %q", name)
	}
	return u, nil
}

func def(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

// AuthorizeURL sends the user to the upstream's consent page with Fortik's
// client, asking only for scopes.
func (u *Upstream) AuthorizeURL(state, redirect string, scopes []string) string {
	q := url.Values{"client_id": {u.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "state": {state}}
	switch u.Name {
	case UpstreamGoogle:
		q.Set("scope", strings.Join(scopes, " "))
		q.Set("access_type", "offline") // a refresh token: Fortik keeps the grant
		q.Set("prompt", "consent")
		q.Set("include_granted_scopes", "false")
	case UpstreamGitHub:
		// GitHub App user tokens: permissions come from the app, not scopes.
	}
	return u.AuthURL + "?" + q.Encode()
}

// Exchange trades the upstream authorization code for tokens; a grant
// without a refresh token is refused (Fortik must be able to stop it).
func (u *Upstream) Exchange(ctx context.Context, code, redirect string) (Token, error) {
	t, err := u.token(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}})
	if err != nil {
		return Token{}, err
	}
	if t.RefreshToken == "" {
		return Token{}, errors.New("upstream returned no refresh token (Google: offline access; GitHub: expiring user tokens must be enabled)")
	}
	return t, nil
}

// Refresh obtains a new access token (and possibly a rotated refresh token).
func (u *Upstream) Refresh(ctx context.Context, refresh string) (Token, error) {
	return u.token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
}

func (u *Upstream) token(ctx context.Context, form url.Values) (Token, error) {
	form.Set("client_id", u.ClientID)
	form.Set("client_secret", u.ClientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := u.HTTP.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("upstream token endpoint: %w", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var t Token
	var e struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	_ = json.Unmarshal(b, &e)
	if res.StatusCode != http.StatusOK || e.Error != "" {
		return Token{}, fmt.Errorf("upstream token endpoint: HTTP %d %s", res.StatusCode, clip(e.Error+" "+e.Desc, 200))
	}
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
		return Token{}, errors.New("upstream token endpoint: malformed response")
	}
	return t, nil
}

// Revoke ends the upstream grant so the copilot's tokens stop working now,
// not at expiry. Google revokes by refresh token; GitHub deletes the app
// grant (which needs a current access token).
func (u *Upstream) Revoke(ctx context.Context, refresh string) error {
	switch u.Name {
	case UpstreamGoogle:
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.RevokeURL, strings.NewReader(url.Values{"token": {refresh}}.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return u.expect(req, http.StatusOK)
	case UpstreamGitHub:
		t, err := u.Refresh(ctx, refresh)
		if err != nil {
			return fmt.Errorf("github: cannot obtain a token to revoke the grant: %w", err)
		}
		body, _ := json.Marshal(map[string]string{"access_token": t.AccessToken})
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, strings.TrimRight(u.APIBaseURL, "/")+"/applications/"+url.PathEscape(u.ClientID)+"/grant",
			bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.SetBasicAuth(u.ClientID, u.ClientSecret)
		req.Header.Set("Accept", "application/vnd.github+json")
		return u.expect(req, http.StatusNoContent)
	}
	return fmt.Errorf("revoke: unknown upstream %q", u.Name)
}

func (u *Upstream) expect(req *http.Request, ok int) error {
	res, err := u.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("upstream revoke: %w", err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != ok {
		return fmt.Errorf("upstream revoke: HTTP %d", res.StatusCode)
	}
	return nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
